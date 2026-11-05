// Admission by memory, private workspaces, and child processes that die with their request.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Proving is bounded by memory, not request count: each job holds its estimated peak in GB.
/// Waiting is first come, first served, and the wait list itself is bounded.
pub struct Jobs {
    memory: Arc<Semaphore>,
    pub total_gb: u32,
    waiting: AtomicUsize,
    running: Arc<AtomicUsize>,
    queue_limit: usize,
}

pub struct Permit { _memory: OwnedSemaphorePermit, running: Arc<AtomicUsize>, pub queued: Duration }
impl Drop for Permit {
    fn drop(&mut self) { self.running.fetch_sub(1, Ordering::SeqCst); }
}

#[derive(Debug, PartialEq)]
pub struct Busy;

struct Waiting<'a>(&'a AtomicUsize);
impl Drop for Waiting<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}

impl Jobs {
    pub fn new(total_gb: u32, queue_limit: usize) -> Self {
        let total_gb = total_gb.max(1);
        Self { memory: Arc::new(Semaphore::new(total_gb as usize)), total_gb, waiting: AtomicUsize::new(0),
            running: Arc::new(AtomicUsize::new(0)), queue_limit }
    }
    /// Waits for `gb` of the budget (capped at the whole budget, so a large job runs alone).
    /// A caller that disconnects while waiting leaves the line.
    pub async fn admit(&self, gb: u32) -> Result<Permit, Busy> {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.queue_limit {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(Busy);
        }
        let started = Instant::now();
        let permit = {
            let _line = Waiting(&self.waiting);
            self.memory.clone().acquire_many_owned(gb.clamp(1, self.total_gb)).await.map_err(|_| Busy)?
        };
        self.running.fetch_add(1, Ordering::SeqCst);
        Ok(Permit { _memory: permit, running: self.running.clone(), queued: started.elapsed() })
    }
    pub fn waiting(&self) -> usize { self.waiting.load(Ordering::SeqCst) }
    pub fn running(&self) -> usize { self.running.load(Ordering::SeqCst) }
}

/// An empty, owner-only directory removed with everything in it when dropped.
pub struct Workspace(pub PathBuf);
impl Workspace {
    pub fn create(parent: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let path = parent.join(format!("huma-prover-{}-{}-{nanos}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Workspace {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

pub struct Command<'a> {
    pub program: &'a Path,
    pub args: Vec<String>,
    pub env: Vec<(&'static str, String)>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub stdout_limit: usize,
}

#[derive(Debug)]
pub enum RunError { Spawn, Timeout, Failed, TooLarge }

/// Kills the whole process group (node and the bb it starts) unless the run finished.
struct Group { pid: Option<i32> }
impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pid) = self.pid { unsafe { libc::killpg(pid, libc::SIGKILL); } }
    }
}

/// Runs a tool with a cleared environment. Its stderr is discarded: page proving tools may
/// print private witness values in their diagnostics, and nothing private is ever logged.
pub async fn run(command: Command<'_>) -> Result<Vec<u8>, RunError> {
    let mut child = tokio::process::Command::new(command.program)
        .args(&command.args).env_clear().env("PATH", "/usr/bin:/bin").envs(command.env.iter().map(|(k, v)| (*k, v)))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .process_group(0).kill_on_drop(true).spawn().map_err(|_| RunError::Spawn)?;
    let mut group = Group { pid: child.id().map(|id| id as i32) };
    let mut stdin = child.stdin.take().ok_or(RunError::Spawn)?;
    let mut stdout = child.stdout.take().ok_or(RunError::Spawn)?;
    let input = command.stdin;
    let limit = command.stdout_limit;
    let work = async move {
        // Write and read together so a large request and a large reply can't deadlock the pipes.
        let writer = async move { let _ = stdin.write_all(&input).await; drop(stdin); };
        let reader = async {
            let mut output = Vec::new();
            (&mut stdout).take(limit as u64 + 1).read_to_end(&mut output).await.map(|_| output)
        };
        let ((), output) = tokio::join!(writer, reader);
        let output = output.map_err(|_| RunError::Failed)?;
        if output.len() > limit { return Err(RunError::TooLarge); }
        let status = child.wait().await.map_err(|_| RunError::Failed)?;
        if status.success() { Ok(output) } else { Err(RunError::Failed) }
    };
    let result = tokio::time::timeout(command.timeout, work).await.map_err(|_| RunError::Timeout)?;
    if result.is_ok() { group.pid = None; }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounds_memory_and_the_wait_list() {
        let jobs = Arc::new(Jobs::new(4, 1));
        let big = jobs.admit(3).await.unwrap();
        let small = jobs.admit(1).await.unwrap();
        assert_eq!(jobs.running(), 2);
        let waiting = { let jobs = jobs.clone(); tokio::spawn(async move { jobs.admit(2).await.map(|_| ()) }) };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(jobs.waiting(), 1);
        assert_eq!(jobs.admit(1).await.err(), Some(Busy)); // the line is full
        drop(big);
        assert!(waiting.await.unwrap().is_ok());
        drop(small);
        assert_eq!((jobs.running(), jobs.waiting()), (0, 0));
        // A job larger than the whole budget runs alone instead of waiting forever.
        assert!(jobs.admit(64).await.is_ok());
    }

    #[tokio::test]
    async fn a_dropped_waiter_leaves_the_line() {
        let jobs = Jobs::new(1, 4);
        let held = jobs.admit(1).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(10), jobs.admit(1)).await;
        assert_eq!(jobs.waiting(), 0);
        drop(held);
    }

    #[tokio::test]
    async fn runs_tools_with_limits() {
        let sh = Path::new("/bin/sh");
        let echo = |script: &str, limit, timeout| Command { program: sh, args: vec!["-c".into(), script.into()], env: vec![],
            stdin: b"private".to_vec(), timeout: Duration::from_millis(timeout), stdout_limit: limit };
        assert_eq!(run(echo("cat", 64, 5000)).await.unwrap(), b"private");
        assert!(matches!(run(echo("cat", 3, 5000)).await, Err(RunError::TooLarge)));
        assert!(matches!(run(echo("exit 3", 64, 5000)).await, Err(RunError::Failed)));
        assert!(matches!(run(echo("sleep 5", 64, 100)).await, Err(RunError::Timeout)));
        assert!(matches!(run(echo("echo $HOME", 64, 5000)).await, Ok(out) if out == b"\n")); // cleared environment
    }

    #[test]
    fn workspaces_are_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let space = Workspace::create(&std::env::temp_dir()).unwrap();
        let path = space.0.clone();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::write(path.join("witness"), b"x").unwrap();
        drop(space);
        assert!(!path.exists());
    }
}
