// Batch proofs for HumaRegistry: up to two small and two large published page proofs, one EVM proof.
// Every input is already public. The commitment is computed here natively and must equal the
// circuit's own output and the proof's public input before a proof is returned.
use crate::commit::{self, from_hex, to_hex};
use crate::jobs::{self, Command, Jobs, Workspace};
use ark_bn254::Fr;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SMALL_SLOTS: usize = 2;
pub const LARGE_SLOTS: usize = 2;
const SMALL: usize = 94;
const LARGE: usize = 142;
const PROOF_FIELDS: usize = 458;
const KEY_FIELDS: usize = 115;
const WITNESS: &str = include_str!("../witness.mjs");
// Pins shared with integrations/noir/batch/prove.mjs and the deployed verifier contract.
const CIRCUIT_SHA256: &str = "0da9427cd43a38e5c5d63e4c462ac2f22fbaea9308f49eb8771a7e55e29d31de";
const VK_SHA256: &str = "854715ce8482322d12147e28b50b86330a944d0e1b5819693bfce554aa1f2712";
// Pinned page circuits (backend/integrations/noir/batch/src/main.nr).
const KEY_HASHES: [(&str, &str, bool); 5] = [
    ("assurance64-v1", "0x17c103561f785a7b80c1d917db2612f276a1583d532f8935229bd4de5b04b30d", false),
    ("assurance256-v1", "0x0157685ede27f32fdd79223af0fa1033773fcf97c772fe24f3351d41e002a5d0", false),
    ("assurance256-v2", "0x12c5717ae7f3a2e98da5f6c6ae373c4999a9272679274b820aa3e3f05d18478a", false),
    ("assurance128-cp32-v1", "0x218201853a8bf4dcf363c65ffaf94f94134fc3f576c9e1c43770d1e7dc32979d", true),
    ("assurance256-cp32-v1", "0x194304d383ebb642f24f36ab60799f5b8586d6e817d9a7ceb86f1f9e87f9a924", true),
];

struct Key { hash: Fr, large: bool, fields: Vec<String> }

#[derive(Clone)]
pub struct Slot { pub profile: String, pub large: bool, key_hash: Fr, proof: Vec<Fr>, statement: Vec<Fr> }

pub struct Layout { slots: Vec<Slot>, pub leaves: Vec<Fr>, pub root: Fr, pub filler: Vec<bool> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProof { pub root: String, pub leaves: Vec<String>, pub filler: Vec<bool>, pub profiles: Vec<String>,
    pub proof: String, pub prove_ms: f64, pub queued_ms: f64 }

#[derive(Debug, PartialEq)]
pub enum BatchError { Invalid(String), Busy, Failed(&'static str) }

pub struct BatchProver {
    dir: PathBuf, crs: PathBuf, node: PathBuf, bb: PathBuf, noir_js: PathBuf,
    threads: usize, workspace_parent: PathBuf, keys: HashMap<String, Key>, fillers: [Slot; 2],
}

fn pinned(path: &Path, digest: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|_| format!("{} is missing", path.display()))?;
    if hex::encode(Sha256::digest(&bytes)) != digest { return Err(format!("{} does not match its pin", path.display())); }
    Ok(bytes)
}

impl BatchProver {
    pub fn open(dir: &Path, crs: &Path, engine: &Path, threads: usize, workspace_parent: PathBuf) -> Result<Self, String> {
        pinned(&dir.join("circuit.json"), CIRCUIT_SHA256)?;
        pinned(&dir.join("batch.vk"), VK_SHA256)?;
        if !crs.join("bn254_g1.dat").exists() { return Err(format!("batch CRS is missing in {}", crs.display())); }
        #[derive(Deserialize)]
        struct Profile { hash: String, #[serde(rename = "publicInputs")] public_inputs: usize, fields: Vec<String> }
        #[derive(Deserialize)]
        struct Keys { profiles: HashMap<String, Profile> }
        let file: Keys = serde_json::from_slice(&std::fs::read(dir.join("keys.json")).map_err(|_| "keys.json is missing")?)
            .map_err(|_| "keys.json is malformed")?;
        let mut keys = HashMap::new();
        for (profile, hash, large) in KEY_HASHES {
            let entry = file.profiles.get(profile).ok_or(format!("keys.json lacks {profile}"))?;
            // The key fields themselves are hashed in the circuit; here they must at least agree with the pins.
            let fields: Option<Vec<Fr>> = entry.fields.iter().map(|f| from_hex(f)).collect();
            let fields = fields.filter(|f| f.len() == KEY_FIELDS).ok_or(format!("{profile} key is malformed"))?;
            if entry.hash != hash || to_hex(commit::hash(&fields)) != hash || entry.public_inputs != if large { LARGE } else { SMALL } {
                return Err(format!("{profile} key does not match its pin"));
            }
            keys.insert(profile.to_string(), Key { hash: from_hex(hash).unwrap(), large, fields: entry.fields.clone() });
        }
        let mut prover = Self { dir: dir.into(), crs: crs.into(), node: engine.join("node"), bb: engine.join("bb"),
            noir_js: engine.join("acvm/node_modules/@noir-lang/noir_js/lib/index.mjs"),
            threads, workspace_parent, keys, fillers: [Self::placeholder(), Self::placeholder()] };
        for (i, size) in ["small", "large"].iter().enumerate() {
            let filler: Value = serde_json::from_slice(&std::fs::read(dir.join("fillers").join(format!("{size}.json")))
                .map_err(|_| format!("{size} filler is missing"))?).map_err(|_| "filler is malformed")?;
            prover.fillers[i] = prover.slot(&filler).map_err(|_| format!("{size} filler is not a valid page proof"))?;
        }
        for (name, path) in [("node", &prover.node), ("bb", &prover.bb), ("noir_js", &prover.noir_js)] {
            if !path.exists() { return Err(format!("{name} is missing at {}", path.display())); }
        }
        Ok(prover)
    }
    fn placeholder() -> Slot { Slot { profile: String::new(), large: false, key_hash: Fr::from(0u64), proof: vec![], statement: vec![] } }

    /// The slot a published page proof occupies, or why it can't be batched (long pages, other kinds).
    pub fn slot(&self, page: &Value) -> Result<Slot, BatchError> {
        let invalid = |why: &str| BatchError::Invalid(why.to_string());
        let profile = page.get("profile").and_then(Value::as_str).ok_or(invalid("page proof has no profile"))?;
        let key = self.keys.get(profile).ok_or(invalid("this kind of page is not batched"))?;
        let field = |name| page.get(name).and_then(Value::as_str).and_then(commit::fields_of);
        let proof = field("proof").filter(|p| p.len() == PROOF_FIELDS).ok_or(invalid("malformed page proof"))?;
        let statement = field("publicInputs").filter(|s| s.len() == if key.large { LARGE } else { SMALL })
            .ok_or(invalid("malformed page statement"))?;
        Ok(Slot { profile: profile.into(), large: key.large, key_hash: key.hash, proof, statement })
    }

    /// Small pages fill slots 0–1, large pages slots 2–3; empty slots get the public filler proofs.
    pub fn layout(&self, pages: Vec<Slot>) -> Result<Layout, BatchError> {
        let (large, small): (Vec<Slot>, Vec<Slot>) = pages.into_iter().partition(|p| p.large);
        if small.len() > SMALL_SLOTS || large.len() > LARGE_SLOTS { return Err(BatchError::Invalid("too many pages for one batch".into())); }
        let mut slots = Vec::new(); let mut filler = Vec::new();
        for (pages, count, pad) in [(small, SMALL_SLOTS, &self.fillers[0]), (large, LARGE_SLOTS, &self.fillers[1])] {
            let used = pages.len();
            slots.extend(pages); filler.extend(std::iter::repeat_n(false, used));
            slots.extend(std::iter::repeat_n(pad.clone(), count - used)); filler.extend(std::iter::repeat_n(true, count - used));
        }
        let leaves: Vec<Fr> = slots.iter().map(|s| commit::leaf(s.key_hash, &s.statement)).collect();
        Ok(Layout { root: commit::root(&leaves), slots, leaves, filler })
    }

    pub async fn prove(&self, jobs: &Jobs, pages: &[Value], memory_gb: u32) -> Result<BatchProof, BatchError> {
        if pages.is_empty() { return Err(BatchError::Invalid("no pages".into())); }
        let slots = pages.iter().map(|p| self.slot(p)).collect::<Result<Vec<_>, _>>()?;
        let layout = self.layout(slots)?;
        let permit = jobs.admit(memory_gb).await.map_err(|_| BatchError::Busy)?;
        let started = std::time::Instant::now();
        let work = Workspace::create(&self.workspace_parent).map_err(|_| BatchError::Failed("workspace"))?;
        // bb and the witness step read private copies of the pinned files, never the shared paths.
        let circuit = work.0.join("circuit.json"); let vk = work.0.join("batch.vk");
        std::fs::write(&circuit, pinned(&self.dir.join("circuit.json"), CIRCUIT_SHA256).map_err(|_| BatchError::Failed("circuit pin"))?)
            .map_err(|_| BatchError::Failed("workspace"))?;
        std::fs::write(&vk, pinned(&self.dir.join("batch.vk"), VK_SHA256).map_err(|_| BatchError::Failed("key pin"))?)
            .map_err(|_| BatchError::Failed("workspace"))?;
        let hex = |values: &[Fr]| values.iter().map(|v| to_hex(*v)).collect::<Vec<_>>();
        let part = |range: std::ops::Range<usize>| &layout.slots[range];
        let key_fields = |slots: &[Slot]| slots.iter().map(|s| &self.keys[&s.profile].fields).collect::<Vec<_>>();
        let (small, large) = (part(0..SMALL_SLOTS), part(SMALL_SLOTS..SMALL_SLOTS + LARGE_SLOTS));
        let inputs = json!({
            "small_keys": key_fields(small), "small_proofs": small.iter().map(|s| hex(&s.proof)).collect::<Vec<_>>(),
            "small": small.iter().map(|s| hex(&s.statement)).collect::<Vec<_>>(),
            "large_keys": key_fields(large), "large_proofs": large.iter().map(|s| hex(&s.proof)).collect::<Vec<_>>(),
            "large": large.iter().map(|s| hex(&s.statement)).collect::<Vec<_>>(),
        });
        let witness = work.0.join("witness.gz"); let script = work.0.join("witness.mjs");
        std::fs::write(&script, WITNESS).map_err(|_| BatchError::Failed("workspace"))?;
        let path = |p: &Path| p.to_string_lossy().into_owned();
        let output = jobs::run(Command { program: &self.node, stdin: serde_json::to_vec(&inputs).unwrap(),
            args: vec!["--no-addons".into(), path(&script), path(&self.noir_js), path(&circuit), path(&witness)],
            env: vec![], timeout: Duration::from_secs(60), stdout_limit: 4096 }).await.map_err(|_| BatchError::Failed("witness"))?;
        #[derive(Deserialize)]
        struct Witness { #[serde(rename = "returnValue")] return_value: String }
        let returned: Witness = serde_json::from_slice(&output).map_err(|_| BatchError::Failed("witness"))?;
        if from_hex(&returned.return_value) != Some(layout.root) {
            return Err(BatchError::Failed("the circuit committed to a different batch"));
        }
        let out = work.0.join("proof");
        let threads = self.threads.to_string();
        jobs::run(Command { program: &self.bb, stdin: vec![], timeout: Duration::from_secs(600), stdout_limit: 1 << 20,
            env: vec![("HOME", path(&work.0)), ("HARDWARE_CONCURRENCY", threads.clone()), ("RAYON_NUM_THREADS", threads)],
            args: ["prove", "-b", &path(&circuit), "-w", &path(&witness), "-k", &path(&vk), "-t", "evm-no-zk",
                "-c", &path(&self.crs), "-o", &path(&out)].map(String::from).to_vec() }).await.map_err(|_| BatchError::Failed("prove"))?;
        let proof = std::fs::read(out.join("proof")).map_err(|_| BatchError::Failed("prove"))?;
        let public = std::fs::read(out.join("public_inputs")).map_err(|_| BatchError::Failed("prove"))?;
        if commit::from_bytes(&public) != Some(layout.root) { return Err(BatchError::Failed("the proof commits to a different batch")); }
        Ok(BatchProof { root: to_hex(layout.root), leaves: layout.leaves.iter().map(|l| to_hex(*l)).collect(), filler: layout.filler,
            profiles: layout.slots.iter().map(|s| s.profile.clone()).collect(), proof: format!("0x{}", hex::encode(proof)),
            prove_ms: started.elapsed().as_secs_f64() * 1e3, queued_ms: permit.queued.as_secs_f64() * 1e3 })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn repo() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }
    pub fn fixture(name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(repo().join("extra/experiments/noir-compact/browser/test/fixtures").join(format!("{name}.json"))).unwrap()).unwrap()
    }
    /// Commitment checks need only the batch directory; the engine paths are checked by `open`.
    pub fn prover() -> Option<BatchProver> {
        let engine = std::env::var("HUMA_ENGINE_DIR").map(PathBuf::from).unwrap_or(repo().join("build/prover-engine"));
        let crs = std::env::var("HUMA_BATCH_CRS").map(PathBuf::from).unwrap_or(repo().join("build/research/batch-crs"));
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        match BatchProver::open(&repo().join("backend/integrations/noir/batch"), &crs, &engine, cores, std::env::temp_dir()) {
            Ok(prover) => Some(prover),
            Err(why) => { eprintln!("batch prover unavailable: {why}"); None }
        }
    }

    #[test]
    fn commitment_matches_the_reader() {
        let Some(prover) = prover() else { return };
        let pages = vec![prover.slot(&fixture("AssuranceV5")).unwrap(), prover.slot(&fixture("AssuranceCP32")).unwrap()];
        let layout = prover.layout(pages).unwrap();
        // From integrations/noir/batch/commit.mjs layout() over the same two fixtures.
        assert_eq!(to_hex(layout.root), "0x2450f46965a33e24f767899d09f86e129ed72431ec36f00a5e47884e15f175c8");
        assert_eq!(layout.leaves.iter().map(|l| to_hex(*l)).collect::<Vec<_>>(), [
            "0x23a396b91c4745e9e364c770d257006d8fb5e66027a5bc24dea6646d3141ec5d",
            "0x0591eaa8da879577f0d1d4c5d98b2125b6b5ffe493302a399be2f91a9ce3e6a4",
            "0x0c0fe07899fc96ceec361b050920f091197850747c858b318777a7096e693956",
            "0x1380dd5a561154d807da3c169fbdc0964aa4e752a643abb67bfc3db084e4dabc"]);
        assert_eq!(layout.filler, [false, true, false, true]);
    }

    #[test]
    fn refuses_pages_it_cannot_batch() {
        let Some(prover) = prover() else { return };
        for (name, large) in [("Assurance64Unicode", false), ("AssuranceV5", false), ("Assurance250", false),
            ("Assurance128Unicode", true), ("AssuranceCP32", true)] {
            assert_eq!(prover.slot(&fixture(name)).unwrap().large, large, "{name}");
        }
        assert!(prover.slot(&fixture("Bucket50")).is_err());
        assert!(prover.slot(&json!({"profile": "assurance-long-v1", "proof": "", "publicInputs": ""})).is_err());
        let mut tampered = fixture("AssuranceV5");
        tampered["publicInputs"] = json!(fixture("AssuranceCP32")["publicInputs"]); // a large statement in a small circuit
        assert!(prover.slot(&tampered).is_err());
        let three = ["AssuranceV5", "Assurance250", "Assurance64Unicode"].map(|n| prover.slot(&fixture(n)).unwrap());
        assert!(prover.layout(three.to_vec()).is_err());
    }

    /// HUMA_PROVER_E2E=1 cargo test --release -- --nocapture  (about 6 s and 5.4 GB)
    #[tokio::test]
    async fn proves_a_real_batch() {
        if std::env::var("HUMA_PROVER_E2E").is_err() { return; }
        let prover = prover().expect("batch prover");
        let jobs = Jobs::new(8, 4);
        let pages = ["AssuranceV5", "Assurance64Unicode", "AssuranceCP32"].map(fixture);
        let batch = prover.prove(&jobs, &pages, 6).await.unwrap();
        eprintln!("batch proved in {:.1} s; proof {} bytes; root {}", batch.prove_ms / 1e3, (batch.proof.len() - 2) / 2, batch.root);
        assert_eq!(batch.filler, [false, false, false, true]);
        std::fs::write(std::env::temp_dir().join("huma-prover-batch.json"), serde_json::to_vec(&json!({"root": batch.root, "proof": batch.proof})).unwrap()).unwrap();
    }
}
