use base64::{engine::general_purpose::STANDARD, Engine};
use huma_replay_core::{
    hash, replay, verification_text, Journal, Session, Witness, LEGACY_RELATION, RELATION, TEXT_POLICY,
};
use risc0_zkvm::{Digest, InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};

// A verifier never accepts a program ID supplied by the receipt as its trust root.
// Changing this pin is a protocol release, checked against the native methods by the host.
pub const IMAGE_ID: [u32; 8] = [
    3048196739, 1933343384, 2783541971, 295771555, 941556348, 2669306392, 2647331225, 3565928223,
];
// Preserve the earlier assurance program while sharing policy evaluation with
// experimental callers. Its signatures and journal remain subject to all checks.
pub const PREVIOUS_IMAGE_ID: [u32; 8] = [
    2341496841, 3117012284, 2268031324, 2429801094, 678944326, 2575563303, 1514797357, 3915760754,
];
pub const LEGACY_IMAGE_ID: [u32; 8] = [
    1034267101, 2966544004, 1170188293, 3133969345, 2073898485, 1004074338, 2157433172, 2500991548,
];
pub const SYSTEM: &str = "risc0-3.0.6";
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
// A public export is a typed projection, never a copy of arbitrary producer
// metadata. Shared by browser publication and the native envelope exporter.
pub fn public_document(document: &str) -> Result<String, String> {
    require(document.len() <= MAX_DOCUMENT_BYTES, "Proof file exceeds 32 MB")?;
    let mut value: serde_json::Value = serde_json::from_str(document).map_err(|_| "Invalid replay proof file")?;
    let root = value.as_object_mut().ok_or("Invalid public record")?;
    root.retain(|key, _| key == "text" || key == "bundle");
    let bundle = root.get_mut("bundle").and_then(|v| v.as_object_mut()).ok_or("Invalid public bundle")?;
    bundle.retain(|key, _| ["version", "system", "imageId", "receipt"].contains(&key.as_str()));
    let input: VerificationInput = serde_json::from_value(value).map_err(|_| "Invalid public replay proof")?;
    verify_bundle(&input.bundle, &input.text, None)?;
    serde_json::to_string(&serde_json::json!({"text": input.text, "bundle": input.bundle})).map_err(|_| "Could not encode public record".into())
}
pub fn image_id() -> String {
    Digest::from(IMAGE_ID).to_string()
}
fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub version: u32,
    pub system: String,
    pub image_id: String,
    pub receipt: Receipt,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSigningKey {
    pub format: String,
    pub value: String,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationInput {
    pub text: String,
    pub bundle: Bundle,
    pub expected_capture_key_hash: Option<String>,
    pub capture_public_key: Option<PublicSigningKey>,
    pub session: Option<Session>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checks {
    pub proof: bool,
    pub text: bool,
    pub checkpoint_signatures: bool,
    pub expected_key: Option<bool>,
    pub revealed_key: Option<bool>,
    pub revealed_history: Option<bool>,
    pub hardware_attestation: &'static str,
    pub account_association: &'static str,
    pub trusted_calendar_time: bool,
    pub human_typing: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeDisplay {
    pub start_unix_milliseconds: String,
    pub end_unix_milliseconds: String,
    pub elapsed_milliseconds: String,
    pub clock_moved_backwards: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub verified: bool,
    pub proof_identity: String,
    pub journal: Journal,
    pub checks: Checks,
    // Decimal strings preserve even large signed u64 elapsed readings across JS JSON parsing.
    pub reported_time: Option<TimeDisplay>,
}

pub fn verify_bundle(
    bundle: &Bundle,
    text: &str,
    expected_key: Option<&str>,
) -> Result<Journal, String> {
    require(
        bundle.version == 1 && bundle.system == SYSTEM,
        "Unsupported replay program",
    )?;
    let legacy = bundle.image_id == Digest::from(LEGACY_IMAGE_ID).to_string();
    let previous = bundle.image_id == Digest::from(PREVIOUS_IMAGE_ID).to_string();
    require(legacy || previous || bundle.image_id == image_id(), "Unsupported replay program")?;
    require(
        !matches!(bundle.receipt.inner, InnerReceipt::Fake(_)),
        "Fake receipts are never accepted",
    )?;
    bundle
        .receipt
        .verify(if legacy { LEGACY_IMAGE_ID } else if previous { PREVIOUS_IMAGE_ID } else { IMAGE_ID })
        .map_err(|_| "Replay proof cryptographic verification failed")?;
    let journal: Journal = serde_json::from_slice(&bundle.receipt.journal.bytes)
        .map_err(|_| "Invalid verified journal")?;
    require(
        journal.text_policy == TEXT_POLICY &&
            ((journal.version == 2 && journal.relation == LEGACY_RELATION && journal.assurance.is_none()) ||
             (!legacy && journal.version == 3 && journal.relation == RELATION && journal.assurance.is_some())),
        "Unsupported replay relation",
    )?;
    require(text.len() <= 65536, "Text exceeds verification input limit")?;
    let canonical = verification_text(text);
    require(
        canonical.len() == journal.byte_length
            && hash(canonical.as_bytes()) == journal.verified_text_hash,
        "Text does not match replay proof",
    )?;
    if let Some(expected) = expected_key {
        require(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "Invalid expected key fingerprint",
        )?;
        require(
            journal.capture_key_hash.as_deref() == Some(expected),
            "Capture key does not match expected fingerprint",
        )?;
    }
    Ok(journal)
}

// Materialize the revealed log's own raw text, rather than using the reader's
// potentially trailing-whitespace-adjusted copy. The pinned replay validator below
// then checks every edit hash, signature and public journal field independently.
fn revealed_text(session: &Session) -> Result<String, String> {
    require(
        session.events.len() <= 16384 && session.initial_text.len() <= 65536,
        "Revealed history exceeds bounds",
    )?;
    let mut text = session.initial_text.clone();
    for edit in &session.events {
        require(
            edit.inserted_text.len() <= 65536,
            "Revealed edit exceeds bounds",
        )?;
        let mut units: Vec<u16> = text.encode_utf16().collect();
        let end = edit
            .location
            .checked_add(edit.removed_length)
            .ok_or("Revealed edit range overflow")?;
        require(
            edit.location <= units.len() && end <= units.len(),
            "Revealed edit lies outside text",
        )?;
        units.splice(edit.location..end, edit.inserted_text.encode_utf16());
        text = String::from_utf16(&units).map_err(|_| "Invalid revealed UTF-16 edit")?;
        require(text.len() <= 65536, "Revealed text exceeds bounds")?;
    }
    Ok(text)
}

pub fn verify_input(input: &VerificationInput) -> Result<Verification, String> {
    let journal = verify_bundle(
        &input.bundle,
        &input.text,
        input.expected_capture_key_hash.as_deref(),
    )?;
    let mut revealed_key = None;
    if let Some(key) = &input.capture_public_key {
        let bytes = STANDARD
            .decode(&key.value)
            .map_err(|_| "Invalid revealed public key")?;
        require(
            key.format == "p256-x963-base64"
                && bytes.len() == 65
                && bytes[0] == 4
                && STANDARD.encode(&bytes) == key.value,
            "Invalid revealed public key",
        )?;
        require(
            journal.capture_key_hash.as_deref() == Some(hash(&bytes).as_str()),
            "Revealed public key does not match proof",
        )?;
        revealed_key = Some(true);
    }
    let mut revealed_history = None;
    if let Some(session) = &input.session {
        let revealed = replay(&Witness {
            text: revealed_text(session)?,
            session: session.clone(),
        })
        .map_err(str::to_owned)?;
        require(revealed == journal, "Revealed session does not match proof")?;
        revealed_history = Some(true);
    }
    let reported_time = journal
        .device_reported_time
        .as_ref()
        .map(|time| TimeDisplay {
            start_unix_milliseconds: time.start_unix_milliseconds.to_string(),
            end_unix_milliseconds: time.end_unix_milliseconds.to_string(),
            elapsed_milliseconds: time.elapsed_milliseconds.to_string(),
            clock_moved_backwards: time.clock_moved_backwards,
        });
    let signatures = journal.signed_checkpoint_count > 0;
    Ok(Verification {
        verified: true,
        proof_identity: hash(
            format!(
                "huma-replay-identity-v1\n{}\n{}",
                input.bundle.image_id,
                hash(&input.bundle.receipt.journal.bytes)
            )
            .as_bytes(),
        ),
        journal,
        reported_time,
        checks: Checks {
            proof: true,
            text: true,
            checkpoint_signatures: signatures,
            expected_key: input.expected_capture_key_hash.as_ref().map(|_| true),
            revealed_key,
            revealed_history,
            hardware_attestation: "not-checked",
            account_association: "not-provided",
            trusted_calendar_time: false,
            human_typing: "not-established",
        },
    })
}
