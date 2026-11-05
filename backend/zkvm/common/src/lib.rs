use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod human;
pub const RELATION: &str = "huma-native-replay-v3";
pub const LEGACY_RELATION: &str = "huma-native-replay-v2";
pub const TEXT_POLICY: &str = "trailing-ascii-space-tab-v1";
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn verification_text(text: &str) -> &str {
    text.trim_end_matches([' ', '\t'])
}
// The native format uses JSONEncoder's string-array encoding, including escaped
// forward slashes. No object-key ordering or Unicode normalization is involved.
pub fn swift_array(values: &[String]) -> Vec<u8> {
    serde_json::to_string(values)
        .unwrap()
        .replace('/', "\\/")
        .into_bytes()
}
fn array_hash(values: &[String]) -> String {
    hash(&swift_array(values))
}
fn check(condition: bool, message: &'static str) -> Result<(), &'static str> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}
fn binary(value: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    let data = STANDARD
        .decode(value)
        .map_err(|_| "Invalid binary encoding")?;
    check(
        data.len() <= max && STANDARD.encode(&data) == value,
        "Noncanonical binary encoding",
    )?;
    Ok(data)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Witness {
    pub text: String,
    pub session: Session,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub initial_text: String,
    pub events: Vec<Edit>,
    pub input_samples: Option<Vec<Sample>>,
    pub capture_records: Option<Vec<Capture>>,
    pub signed_checkpoints: Option<Vec<Checkpoint>>,
    pub presence_protocol: Option<String>,
    pub presence_events: Option<Vec<human::Presence>>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Edit {
    pub sequence: usize,
    pub elapsed_milliseconds: u64,
    pub source: String,
    pub location: usize,
    pub removed_length: usize,
    pub inserted_text: String,
    pub previous_head: String,
    pub text_hash: String,
    pub head: String,
}
impl Edit {
    fn digest(&self) -> String {
        array_hash(&[
            self.sequence.to_string(),
            self.elapsed_milliseconds.to_string(),
            self.source.clone(),
            self.location.to_string(),
            self.removed_length.to_string(),
            self.inserted_text.clone(),
            self.previous_head.clone(),
            self.text_hash.clone(),
        ])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub kind: String,
    pub key_code: u16,
    pub modifiers: u64,
    pub elapsed_milliseconds: u64,
    pub origin: Option<human::Origin>,
}
impl Sample {
    fn digest(&self) -> String {
        let mut fields = vec![
            self.kind.clone(),
            self.key_code.to_string(),
            self.modifiers.to_string(),
            self.elapsed_milliseconds.to_string(),
        ];
        if let Some(origin) = &self.origin { fields.extend(origin.fields()); }
        array_hash(&fields)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub sequence: usize,
    pub kind: String,
    pub index: usize,
    pub payload_hash: String,
    pub previous_head: String,
    pub head: String,
}
impl Capture {
    fn digest(&self) -> String {
        array_hash(&[
            self.sequence.to_string(),
            self.kind.clone(),
            self.index.to_string(),
            self.payload_hash.clone(),
            self.previous_head.clone(),
        ])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub version: u32,
    pub kind: String,
    pub is_final: bool,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub sequence: usize,
    pub capture_count: usize,
    pub edit_count: usize,
    pub sample_count: usize,
    pub capture_head: String,
    pub edit_head: String,
    pub text_hash: String,
    pub previous_checkpoint: String,
    pub challenge: String,
    pub public_key: String,
    pub signature: String,
    pub reported_time: Option<CaptureTime>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureTime {
    pub unix_milliseconds: u64,
    pub elapsed_milliseconds: u64,
}
impl Checkpoint {
    fn payload(&self) -> Vec<u8> {
        let mut fields = vec![
            format!("huma-signed-checkpoint-v{}", self.version),
            self.kind.clone(),
            self.session_id.clone(),
            self.sequence.to_string(),
            self.is_final.to_string(),
            self.capture_count.to_string(),
            self.edit_count.to_string(),
            self.sample_count.to_string(),
            self.capture_head.clone(),
            self.edit_head.clone(),
            self.text_hash.clone(),
            self.previous_checkpoint.clone(),
            self.challenge.clone(),
            self.public_key.clone(),
        ];
        if let Some(time) = &self.reported_time {
            fields.extend([
                "device-clock-v1".into(),
                time.unix_milliseconds.to_string(),
                time.elapsed_milliseconds.to_string(),
            ]);
        }
        swift_array(&fields)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReportedWindow {
    pub start_unix_milliseconds: u64,
    pub end_unix_milliseconds: u64,
    pub elapsed_milliseconds: u64,
    pub clock_moved_backwards: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    pub version: u32,
    pub relation: String,
    pub text_policy: String,
    pub verified_text_hash: String,
    pub raw_text_hash: String,
    #[serde(rename = "sessionIDHash")]
    pub session_id_hash: String,
    pub edit_head: String,
    pub capture_head: String,
    pub checkpoint_hash: Option<String>,
    pub capture_key_hash: Option<String>,
    pub device_reported_time: Option<ReportedWindow>,
    pub byte_length: usize,
    pub raw_byte_length: usize,
    pub initial_byte_length: usize,
    pub edit_count: usize,
    pub paste_edit_count: usize,
    pub typing_labeled_edits: usize,
    pub bound_input_samples: usize,
    pub capture_record_count: usize,
    pub signed_checkpoint_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance: Option<human::Assurance>,
}

// This entire function executes inside the pinned zkVM guest, including SHA-256
// chain reconstruction and P-256 signature verification. Host validation is optional.
// Source labels/key events are evidence supplied by the capture, not proof of a human.
pub fn replay(w: &Witness) -> Result<Journal, &'static str> {
    replay_bounded(w, &DEFAULT_BOUNDS)
}

/// History and verified-text bounds. The default is the original short-session
/// relation; long sessions use the same chain checks with larger bounds.
pub struct Bounds {
    pub verified_bytes: usize,
    pub events: usize,
    pub samples: usize,
    pub records: usize,
    pub checkpoints: usize,
}
pub const DEFAULT_BOUNDS: Bounds = Bounds { verified_bytes: 1024, events: 16384, samples: 65536, records: 81920, checkpoints: 4096 };
pub const LONG_BOUNDS: Bounds = Bounds { verified_bytes: 40000, events: 65536, samples: 262144, records: 327680, checkpoints: 65536 };

pub fn replay_bounded(w: &Witness, bounds: &Bounds) -> Result<Journal, &'static str> {
    let s = &w.session;
    let samples = s.input_samples.as_deref().unwrap_or(&[]);
    let records = s.capture_records.as_deref().unwrap_or(&[]);
    let checkpoints = s.signed_checkpoints.as_deref().unwrap_or(&[]);
    check(
        !s.id.is_empty()
            && s.id.len() <= 128
            && s.initial_text.len() <= 65536
            && w.text.len() <= 65536,
        "Session exceeds bounds",
    )?;
    check(
        s.events.len() <= bounds.events
            && samples.len() <= bounds.samples
            && records.len() <= bounds.records
            && checkpoints.len() <= bounds.checkpoints,
        "History exceeds bounds",
    )?;
    let canonical = verification_text(&w.text);
    check(
        !canonical.is_empty() && canonical.len() <= bounds.verified_bytes,
        if bounds.verified_bytes == 1024 { "Verified text must contain 1-1024 UTF-8 bytes" } else { "Verified text exceeds the session bound" },
    )?;
    let initial_head = hash(format!("huma-session-v1:{}:{}", s.id, s.initial_text).as_bytes());
    let mut edit_head = initial_head.clone();
    let mut text = s.initial_text.clone();
    let mut elapsed = 0;
    let mut text_hashes = vec![hash(text.as_bytes())];
    for (index, event) in s.events.iter().enumerate() {
        check(
            event.sequence == index
                && event.previous_head == edit_head
                && event.head == event.digest()
                && event.elapsed_milliseconds >= elapsed,
            "Invalid edit chain",
        )?;
        check(
            event.source.len() <= 64 && event.inserted_text.len() <= 65536,
            "Edit exceeds bounds",
        )?;
        let mut units: Vec<u16> = text.encode_utf16().collect();
        let end = event
            .location
            .checked_add(event.removed_length)
            .ok_or("Edit range overflow")?;
        check(
            event.location <= units.len() && end <= units.len(),
            "Edit outside text",
        )?;
        let boundary =
            |i: usize| i == 0 || i == units.len() || !(0xdc00..=0xdfff).contains(&units[i]);
        check(
            boundary(event.location) && boundary(end),
            "Edit splits a surrogate boundary",
        )?;
        units.splice(event.location..end, event.inserted_text.encode_utf16());
        text = String::from_utf16(&units).map_err(|_| "Edit splits a surrogate pair")?;
        check(
            text.len() <= 65536 && hash(text.as_bytes()) == event.text_hash,
            "Edit text hash mismatch",
        )?;
        text_hashes.push(event.text_hash.clone());
        edit_head = event.head.clone();
        elapsed = event.elapsed_milliseconds;
    }
    check(
        text.as_bytes() == w.text.as_bytes(),
        "Replay does not produce final text",
    )?;
    let seed = hash(format!("huma-capture-v1:{}:{}", s.id, initial_head).as_bytes());
    let mut capture_head = seed.clone();
    let (mut edits, mut keys, mut presences, mut last_time) = (0, 0, 0, 0);
    let presence_events = s.presence_events.as_deref().unwrap_or(&[]);
    check(presence_events.len() <= 2048, "Presence history exceeds bounds")?;
    let mut counts = vec![(0usize, 0usize)];
    for (sequence, record) in records.iter().enumerate() {
        check(
            record.sequence == sequence
                && record.previous_head == capture_head
                && record.head == record.digest(),
            "Invalid capture chain",
        )?;
        let time = match record.kind.as_str() {
            "edit" => {
                check(
                    record.index == edits && edits < s.events.len(),
                    "Invalid capture edit reference",
                )?;
                let edit = &s.events[edits];
                check(record.payload_hash == edit.head, "Capture edit mismatch")?;
                edits += 1;
                edit.elapsed_milliseconds
            }
            "key" => {
                check(
                    record.index == keys && keys < samples.len(),
                    "Invalid key sample reference",
                )?;
                let sample = &samples[keys];
                check(
                    ["down", "up"].contains(&sample.kind.as_str())
                        && record.payload_hash == sample.digest(),
                    "Capture sample mismatch",
                )?;
                keys += 1;
                sample.elapsed_milliseconds
            }
            "presence" => {
                check(record.index == presences && presences < presence_events.len(), "Invalid presence reference")?;
                let event = &presence_events[presences];
                check(record.payload_hash == event.digest(&s.id), "Presence record mismatch")?;
                presences += 1;
                event.elapsed_milliseconds
            }
            _ => return Err("Unknown capture record kind"),
        };
        check(time >= last_time, "Capture time moved backwards")?;
        last_time = time;
        capture_head = record.head.clone();
        counts.push((edits, keys));
    }
    // Legacy unsigned edit logs may lack a unified key chain. Never describe
    // their unbound timing samples as checked capture evidence.
    if !records.is_empty() || !checkpoints.is_empty() {
        check(
            edits == s.events.len() && keys == samples.len() && presences == presence_events.len(),
            "Capture does not cover every event",
        )?;
    }
    let mut previous = String::new();
    let mut previous_count = 0;
    let mut public_key: Option<Vec<u8>> = None;
    let mut previous_elapsed = 0;
    let mut previous_unix = None;
    let mut rollback = false;
    for (index, cp) in checkpoints.iter().enumerate() {
        check(
            [1, 2].contains(&cp.version)
                && cp.version == checkpoints[0].version
                && cp.kind == "unattested-p256"
                && cp.sequence == index
                && cp.session_id == s.id
                && cp.previous_checkpoint == previous,
            "Invalid checkpoint identity or sequence",
        )?;
        check(
            cp.capture_count >= previous_count && cp.capture_count <= records.len(),
            "Invalid checkpoint coverage",
        )?;
        let (edit_count, key_count) = counts[cp.capture_count];
        let expected_capture = if cp.capture_count == 0 {
            &seed
        } else {
            &records[cp.capture_count - 1].head
        };
        let expected_edit = if edit_count == 0 {
            &initial_head
        } else {
            &s.events[edit_count - 1].head
        };
        check(
            cp.capture_head == *expected_capture
                && cp.edit_head == *expected_edit
                && cp.edit_count == edit_count
                && cp.sample_count == key_count
                && cp.text_hash == text_hashes[edit_count],
            "Checkpoint prefix mismatch",
        )?;
        check(
            (cp.version == 1 && cp.reported_time.is_none())
                || (cp.version == 2 && cp.reported_time.is_some()),
            "Checkpoint time version mismatch",
        )?;
        if let Some(time) = &cp.reported_time {
            let edit_time = if edit_count == 0 {
                0
            } else {
                s.events[edit_count - 1].elapsed_milliseconds
            };
            let key_time = if key_count == 0 {
                0
            } else {
                samples[key_count - 1].elapsed_milliseconds
            };
            check(
                time.unix_milliseconds <= 253_402_300_799_999
                    && time.elapsed_milliseconds >= previous_elapsed
                    && time.elapsed_milliseconds >= edit_time.max(key_time)
                    && time.elapsed_milliseconds >= records[..cp.capture_count].iter().rev().find(|r| r.kind == "presence")
                        .map_or(0, |r| presence_events[r.index].elapsed_milliseconds)
                    && (index != 0 || (cp.capture_count == 0 && time.elapsed_milliseconds == 0)),
                "Invalid device-reported checkpoint time",
            )?;
            rollback |= previous_unix.is_some_and(|unix| time.unix_milliseconds < unix);
            previous_unix = Some(time.unix_milliseconds);
            previous_elapsed = time.elapsed_milliseconds;
        }
        let key = binary(&cp.public_key, 65)?;
        check(
            key.len() == 65 && key[0] == 4 && public_key.as_ref().is_none_or(|old| old == &key),
            "Checkpoint signing key changed",
        )?;
        let signature = binary(&cp.signature, 80)?;
        let verifying = VerifyingKey::from_sec1_bytes(&key).map_err(|_| "Invalid P-256 key")?;
        let sig = Signature::from_der(&signature).map_err(|_| "Invalid P-256 signature")?;
        let payload = cp.payload();
        verifying
            .verify(&payload, &sig)
            .map_err(|_| "Checkpoint signature mismatch")?;
        let mut signed = payload;
        signed.extend_from_slice(&signature);
        previous = hash(&signed);
        public_key = Some(key);
        previous_count = cp.capture_count;
    }
    if let Some(last) = checkpoints.last() {
        check(
            checkpoints[0].capture_count == 0
                && last.is_final
                && last.capture_count == records.len()
                && last.text_hash == hash(w.text.as_bytes()),
            "Signed session lacks final coverage",
        )?;
    }
    let assurance = human::evaluate(s, public_key.as_deref(), keys, previous_elapsed)?;
    let device_reported_time = checkpoints
        .first()
        .and_then(|cp| cp.reported_time.as_ref())
        .map(|start| {
            let end = checkpoints.last().unwrap().reported_time.as_ref().unwrap();
            ReportedWindow {
                start_unix_milliseconds: start.unix_milliseconds,
                end_unix_milliseconds: end.unix_milliseconds,
                elapsed_milliseconds: end.elapsed_milliseconds,
                clock_moved_backwards: rollback,
            }
        });
    Ok(Journal {
        version: if assurance.is_some() { 3 } else { 2 },
        relation: if assurance.is_some() { RELATION } else { LEGACY_RELATION }.into(),
        text_policy: TEXT_POLICY.into(),
        verified_text_hash: hash(canonical.as_bytes()),
        raw_text_hash: hash(w.text.as_bytes()),
        session_id_hash: hash(s.id.as_bytes()),
        edit_head,
        capture_head,
        checkpoint_hash: (!checkpoints.is_empty()).then_some(previous),
        capture_key_hash: public_key.map(|key| hash(&key)),
        device_reported_time,
        byte_length: canonical.len(),
        raw_byte_length: w.text.len(),
        initial_byte_length: s.initial_text.len(),
        edit_count: s.events.len(),
        paste_edit_count: s.events.iter().filter(|e| e.source == "paste").count(),
        typing_labeled_edits: s.events.iter().filter(|e| e.source == "typing").count(),
        bound_input_samples: keys,
        capture_record_count: records.len(),
        signed_checkpoint_count: checkpoints.len(),
        assurance,
    })
}
