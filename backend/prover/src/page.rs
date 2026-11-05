// Opt-in page proving. The request is the writer's private signed session, exactly what the Mac
// would give its own bundled worker; this runs the same pinned engine and returns only the public
// proof. The Mac checks that proof locally before using it. Nothing from the request is stored or
// logged, and its workspace is deleted when the request ends, however it ends.
use crate::jobs::{self, Command, Jobs, RunError, Workspace};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_INPUT_BASE64: usize = 64 * 1024 * 1024;
const MAX_CHUNKS: usize = 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageRequest {
    pub command: String,
    pub input: String,
    #[serde(default)]
    pub chunk_proofs: Option<Vec<Option<ChunkProof>>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChunkProof { index: u32, proof: String, public_inputs: String, #[serde(default, skip_serializing_if = "Option::is_none")] tier: Option<u32> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageProof { pub proof: String, pub backend: String, pub prove_ms: f64, pub queued_ms: f64 }

#[derive(Debug, PartialEq)]
pub enum PageError { Invalid(&'static str), Busy, Failed, Timeout, Unavailable }

pub struct PageProver { engine: PathBuf, threads: usize, workspace_parent: PathBuf, sandbox: Option<PathBuf> }

impl PageRequest {
    pub fn validate(&self) -> Result<bool, PageError> {
        let long = match self.command.as_str() { "prove" => false, "prove-long" => true, _ => return Err(PageError::Invalid("command")) };
        if self.input.is_empty() || self.input.len() > MAX_INPUT_BASE64 { return Err(PageError::Invalid("input size")); }
        if !self.input.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
            return Err(PageError::Invalid("input encoding"));
        }
        match &self.chunk_proofs {
            Some(_) if !long => return Err(PageError::Invalid("chunk proofs")),
            Some(chunks) if chunks.len() > MAX_CHUNKS => return Err(PageError::Invalid("chunk proofs")),
            _ => {}
        }
        Ok(long)
    }
}

impl PageProver {
    /// Checks every engine file against the engine's own manifest before serving.
    pub fn open(engine: &Path, threads: usize, workspace_parent: PathBuf) -> Result<Self, String> {
        let manifest: BTreeMap<String, String> = serde_json::from_slice(&std::fs::read(engine.join("manifest.json"))
            .map_err(|_| "engine manifest.json is missing")?).map_err(|_| "engine manifest.json is malformed")?;
        for required in ["node", "bb", "capture-input", "witness", "worker.mjs"] {
            if !manifest.contains_key(required) { return Err(format!("engine is missing {required}")); }
        }
        for (name, digest) in &manifest {
            if name.contains("..") { return Err("engine manifest names a path outside the engine".into()); }
            let bytes = std::fs::read(engine.join(name)).map_err(|_| format!("engine file {name} is missing"))?;
            if hex::encode(Sha256::digest(&bytes)) != *digest { return Err(format!("engine file {name} does not match its manifest")); }
        }
        // On macOS the worker runs without network access, as it does in the app.
        let sandbox = Some(PathBuf::from("/usr/bin/sandbox-exec")).filter(|p| cfg!(target_os = "macos") && p.exists());
        Ok(Self { engine: engine.to_path_buf(), threads, workspace_parent, sandbox })
    }

    pub async fn prove(&self, jobs: &Jobs, request: PageRequest, memory_gb: u32) -> Result<PageProof, PageError> {
        let long = request.validate()?;
        let permit = jobs.admit(memory_gb).await.map_err(|_| PageError::Busy)?;
        let work = Workspace::create(&self.workspace_parent).map_err(|_| PageError::Unavailable)?;
        let chunks = request.chunk_proofs.as_ref().map_or(0, |c| c.iter().filter(|c| c.is_none()).count());
        let mut worker = serde_json::json!({ "command": request.command, "input": request.input,
            "workDirectory": work.0.to_str().ok_or(PageError::Unavailable)? });
        if let Some(chunks) = request.chunk_proofs { worker["chunkProofs"] = serde_json::to_value(chunks).map_err(|_| PageError::Failed)?; }
        let stdin = serde_json::to_vec(&worker).map_err(|_| PageError::Failed)?;
        drop(worker);
        let node = self.engine.join("node").to_string_lossy().into_owned();
        let mut args = vec!["--no-addons".into(), "--disable-proto=throw".into(), "--max-old-space-size=4096".into(),
            self.engine.join("worker.mjs").to_string_lossy().into_owned()];
        let program = match &self.sandbox {
            Some(sandbox) => { args.splice(0..0, ["-p".into(), "(version 1)(allow default)(deny network-outbound)".into(), node]); sandbox.clone() }
            None => PathBuf::from(node),
        };
        let threads = self.threads.to_string();
        let started = std::time::Instant::now();
        // The app allows ~6 s per unproved part and up to 180 s for the rest on two threads.
        let timeout = Duration::from_secs(if long { 300 + 15 * chunks as u64 } else { 180 });
        let output = jobs::run(Command { program: &program, args, stdin, timeout, stdout_limit: 96 * 1024 * 1024,
            env: vec![("HOME", work.0.to_string_lossy().into_owned()), ("HUMA_PROVER_THREADS", threads)] }).await
            .map_err(|e| match e { RunError::Timeout => PageError::Timeout, _ => PageError::Failed })?;
        drop(work);
        #[derive(Deserialize)]
        struct Reply { ok: bool, proof: String, backend: String }
        let reply: Reply = serde_json::from_slice(&output).map_err(|_| PageError::Failed)?;
        if !reply.ok { return Err(PageError::Failed); }
        Ok(PageProof { proof: reply.proof, backend: reply.backend, prove_ms: started.elapsed().as_secs_f64() * 1e3,
            queued_ms: permit.queued.as_secs_f64() * 1e3 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> Result<PageRequest, serde_json::Error> { serde_json::from_str(json) }

    #[test]
    fn accepts_only_the_app_request_shape() {
        assert_eq!(request(r#"{"command":"prove","input":"e30="}"#).unwrap().validate(), Ok(false));
        assert_eq!(request(r#"{"command":"prove-long","input":"e30=","chunkProofs":[null]}"#).unwrap().validate(), Ok(true));
        assert!(request(r#"{"command":"prove","input":"e30=","workDirectory":"/tmp"}"#).is_err());
        assert_eq!(request(r#"{"command":"verify","input":"e30="}"#).unwrap().validate(), Err(PageError::Invalid("command")));
        assert_eq!(request(r#"{"command":"prove","input":"e30=","chunkProofs":[]}"#).unwrap().validate(), Err(PageError::Invalid("chunk proofs")));
        assert_eq!(request(r#"{"command":"prove","input":"{\"a\":1}"}"#).unwrap().validate(), Err(PageError::Invalid("input encoding")));
        assert_eq!(request(r#"{"command":"prove","input":""}"#).unwrap().validate(), Err(PageError::Invalid("input size")));
    }
}
