use huma_replay_core::{replay, Journal, Session, Witness, RELATION, TEXT_POLICY};
use huma_replay_methods::{HUMA_REPLAY_GUEST_ELF, HUMA_REPLAY_GUEST_ID};
use huma_replay_verifier::{
    image_id, public_document, verify_bundle, verify_input, Bundle, PublicSigningKey, VerificationInput, SYSTEM,
};
use risc0_zkvm::{Digest, Executor, ExecutorEnv, ExternalProver, Prover, ProverOpts};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

const MAX_REQUEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CYCLES: u64 = 256 * 1024 * 1024;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Prove {
        witness: Witness,
    },
    Execute {
        witness: Witness,
    },
    Verify {
        text: String,
        bundle: Bundle,
        #[serde(rename = "expectedCaptureKeyHash")]
        expected_capture_key_hash: Option<String>,
        #[serde(rename = "capturePublicKey")]
        capture_public_key: Option<PublicSigningKey>,
        session: Option<Session>,
    },
    Info,
    Public { document: String },
}
fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn local_prover() -> Result<ExternalProver> {
    // An explicit local executable is used. No default-prover/remote-service fallback.
    let path = match std::env::var_os("HUMA_R0VM") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?
            .parent()
            .ok_or("Missing worker directory")?
            .join("r0vm"),
    };
    require(path.is_file(), "Local r0vm executable is missing")?;
    Ok(ExternalProver::new("huma-local", path))
}
fn run(request: Request) -> Result<Value> {
    match request {
        Request::Public { document } => Ok(json!({"document": public_document(&document)?})),
        Request::Info => Ok(
            json!({"system": SYSTEM, "imageID": image_id(), "relation": RELATION,
            "textPolicy": TEXT_POLICY, "localOnly": true, "trustedCalendarTime": false}),
        ),
        Request::Verify {
            text,
            bundle,
            expected_capture_key_hash,
            capture_public_key,
            session,
        } => {
            let result = verify_input(&VerificationInput {
                text,
                bundle,
                expected_capture_key_hash,
                capture_public_key,
                session,
            })?;
            Ok(serde_json::to_value(result)?)
        }
        Request::Execute { witness } => run_witness(witness, false),
        Request::Prove { witness } => run_witness(witness, true),
    }
}
fn run_witness(witness: Witness, prove: bool) -> Result<Value> {
    // Reject invalid private inputs before expensive proving; the guest repeats every check.
    let expected_journal = replay(&witness).map_err(|message| message.to_owned())?;
    let mut builder = ExecutorEnv::builder();
    builder
        .write(&witness)?
        .segment_limit_po2(20)
        .session_limit(Some(MAX_CYCLES));
    let env = builder.build()?;
    let prover = local_prover()?;
    if !prove {
        let session = prover.execute(env, HUMA_REPLAY_GUEST_ELF)?;
        let journal: Journal = serde_json::from_slice(&session.journal.bytes)?;
        require(
            journal == expected_journal,
            "Guest replay disagrees with native replay",
        )?;
        return Ok(
            json!({"verified": false, "executionOnly": true, "journal": journal,
            "cycles": session.cycles(), "segments": session.segments.len()}),
        );
    }
    eprintln!("Generating local replay proof; private history stays on this Mac.");
    let info = prover.prove_with_opts(
        env,
        HUMA_REPLAY_GUEST_ELF,
        &ProverOpts::succinct().with_dev_mode(false),
    )?;
    let bundle = Bundle {
        version: 1,
        system: SYSTEM.into(),
        image_id: image_id(),
        receipt: info.receipt,
    };
    let journal = verify_bundle(
        &bundle,
        &witness.text,
        expected_journal.capture_key_hash.as_deref(),
    )?;
    require(
        journal == expected_journal,
        "Proved journal differs from requested session",
    )?;
    Ok(json!({"verified": true, "bundle": bundle, "journal": journal, "stats": info.stats}))
}

fn main() {
    let result = (|| -> Result<Value> {
        let dev = std::env::var("RISC0_DEV_MODE")
            .unwrap_or_default()
            .to_lowercase();
        require(
            !["1", "true", "yes"].contains(&dev.as_str()),
            "Development/fake proof mode is disabled",
        )?;
        let mut bytes = Vec::new();
        io::stdin()
            .take(MAX_REQUEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() as u64 <= MAX_REQUEST_BYTES,
            "Replay request exceeds size limit",
        )?;
        require(
            Digest::from(HUMA_REPLAY_GUEST_ID).to_string() == image_id(),
            "Guest image does not match released verifier pin",
        )?;
        let request: Request = serde_json::from_slice(&bytes)?;
        run(request)
    })();
    match result {
        Ok(value) => {
            serde_json::to_writer(io::stdout().lock(), &json!({"ok": true, "result": value}))
                .unwrap();
        }
        Err(error) => {
            // Library errors never include the serialized witness. Keep private input off stdout/stderr.
            let _ = writeln!(io::stderr(), "Huma replay worker: {error}");
            let _ = serde_json::to_writer(
                io::stdout().lock(),
                &json!({"ok": false, "error": error.to_string()}),
            );
            std::process::exit(1);
        }
    }
}
