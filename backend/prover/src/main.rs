// Huma prover: one process that schedules every server-side proof by memory.
//
//   POST /v1/pages/prove    opt-in page proofs from a writer's private signed session (rate limited per address)
//   GET  /healthz           what this instance can prove and how busy it is
//
// The heavy work is barretenberg; this server keeps it fed without running out of memory, uses
// every core for each proof, and never keeps or logs a writer's session.
mod jobs;
mod page;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Config {
    addr: SocketAddr,
    engine: Option<PathBuf>,
    memory_gb: u32,
    threads: usize,
    queue: usize,
    pages_per_hour: u32,
    workspace: PathBuf,
}

// Measured peaks (PROVER-PERFORMANCE.md): short pages < 2 GB, long pages ~3 GB.
const SHORT_PAGE_GB: u32 = 2;
const LONG_PAGE_GB: u32 = 3;

fn setting<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Config {
    fn from_env() -> Self {
        let path = |name: &str, default: PathBuf| std::env::var(name).map(PathBuf::from).unwrap_or(default);
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        // Three quarters of physical memory unless told otherwise.
        let physical = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) as u64 * libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        Self {
            addr: setting("HUMA_PROVER_ADDR", SocketAddr::from(([127, 0, 0, 1], 4330))),
            engine: std::env::var("HUMA_ENGINE_DIR").ok().map(PathBuf::from),
            memory_gb: setting("HUMA_PROVER_MEMORY_GB", ((physical / (1 << 30)) * 3 / 4).max(2) as u32),
            threads: setting("HUMA_PROVER_THREADS", cores).clamp(1, 256),
            queue: setting("HUMA_PROVER_QUEUE", 32),
            pages_per_hour: setting("HUMA_PROVER_PAGES_PER_HOUR", 30),
            workspace: path("HUMA_PROVER_WORKSPACE", std::env::temp_dir()),
        }
    }
}

struct App {
    jobs: jobs::Jobs,
    pages: Option<page::PageProver>,
    limiter: Limiter,
}

/// Page proofs per client address per hour. Behind a proxy every client shares the proxy's address.
struct Limiter { per_hour: u32, seen: Mutex<HashMap<IpAddr, (Instant, u32)>> }
impl Limiter {
    fn allow(&self, address: IpAddr) -> bool {
        let mut seen = self.seen.lock().unwrap();
        let now = Instant::now();
        if seen.len() > 10_000 { seen.retain(|_, (since, _)| now.duration_since(*since) < Duration::from_secs(3600)); }
        let entry = seen.entry(address).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(3600) { *entry = (now, 0); }
        entry.1 += 1;
        entry.1 <= self.per_hour
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    let mut response = (status, Json(json!({ "error": message }))).into_response();
    if matches!(status, StatusCode::SERVICE_UNAVAILABLE | StatusCode::TOO_MANY_REQUESTS) {
        response.headers_mut().insert(header::RETRY_AFTER, "30".parse().unwrap());
    }
    response
}

fn log(message: impl std::fmt::Display) {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    eprintln!("{seconds} {message}");
}

async fn health(State(app): State<Arc<App>>) -> Json<Value> {
    Json(json!({ "ok": true, "pageProving": app.pages.is_some(),
        "running": app.jobs.running(), "waiting": app.jobs.waiting(), "memoryGb": app.jobs.total_gb }))
}

async fn prove_page(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, body: axum::body::Bytes) -> Response {
    let Some(prover) = &app.pages else { return error(StatusCode::NOT_FOUND, "This prover does not make page proofs.") };
    if !app.limiter.allow(peer.ip()) { return error(StatusCode::TOO_MANY_REQUESTS, "Too many proofs from this address. Try again later.") };
    let request: page::PageRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "Malformed proof request."),
    };
    drop(body);
    let long = request.command == "prove-long";
    let started = Instant::now();
    let result = prover.prove(&app.jobs, request, if long { LONG_PAGE_GB } else { SHORT_PAGE_GB }).await;
    // Only the outcome and timing are logged; never the session, text or proof.
    log(format_args!("page {} {} in {:.1} s", if long { "long" } else { "short" },
        if result.is_ok() { "proved" } else { "failed" }, started.elapsed().as_secs_f64()));
    match result {
        Ok(proof) => Json(proof).into_response(),
        Err(page::PageError::Invalid(why)) => error(StatusCode::BAD_REQUEST, &format!("Invalid proof request ({why}).")),
        Err(page::PageError::Busy) => error(StatusCode::SERVICE_UNAVAILABLE, "The prover is busy. Try again shortly, or prove on your Mac."),
        Err(page::PageError::Timeout) => error(StatusCode::GATEWAY_TIMEOUT, "The proof took too long."),
        Err(page::PageError::Unavailable) => error(StatusCode::SERVICE_UNAVAILABLE, "The prover could not start this proof."),
        Err(page::PageError::Failed) => error(StatusCode::UNPROCESSABLE_ENTITY, "This recording did not produce a valid proof."),
    }
}

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let pages = config.engine.as_ref().map(|engine| page::PageProver::open(engine, config.threads, config.workspace.clone()));
    let pages = match pages {
        Some(Ok(prover)) => Some(prover),
        Some(Err(why)) => { log(format_args!("page proving off: {why}")); None }
        None => { log("page proving off: set HUMA_ENGINE_DIR to a staged engine (backend/integrations/noir/package.py)"); None }
    };
    let app = Arc::new(App { jobs: jobs::Jobs::new(config.memory_gb, config.queue), pages,
        limiter: Limiter { per_hour: config.pages_per_hour, seen: Mutex::new(HashMap::new()) } });
    let router = Router::new()
        .route("/healthz", get(health))
        .route("/v1/pages/prove", post(prove_page).layer(DefaultBodyLimit::max(page::MAX_INPUT_BASE64 + 4 * 1024 * 1024)))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(config.addr).await.expect("bind");
    log(format_args!("huma-prover on http://{} · {} GB · {} threads per proof · pages {}", config.addr, config.memory_gb,
        config.threads, if app.pages.is_some() { "on" } else { "off" }));
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_address() {
        let limiter = Limiter { per_hour: 2, seen: Mutex::new(HashMap::new()) };
        let (a, b) = (IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2]));
        assert!(limiter.allow(a) && limiter.allow(a) && !limiter.allow(a));
        assert!(limiter.allow(b));
    }
}
