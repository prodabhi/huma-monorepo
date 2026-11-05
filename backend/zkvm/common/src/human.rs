//! Experimental, deterministic writing rules over the authenticated trace.
//! No raw timing vector or per-event OS metadata is emitted in the journal.
use crate::{binary, check, hash, swift_array, Session};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Origin {
    #[serde(rename = "sourceUnixProcessID")]
    pub source_unix_process_id: i64,
    #[serde(rename = "sourceStateID")]
    pub source_state_id: i64,
    pub keyboard_type: i64,
    pub is_repeat: bool,
}
impl Origin {
    pub fn fields(&self) -> Vec<String> {
        vec!["mac-event-origin-v1".into(), self.source_unix_process_id.to_string(),
            self.source_state_id.to_string(), self.keyboard_type.to_string(), self.is_repeat.to_string()]
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Presence {
    pub sequence: usize,
    pub kind: String,
    pub nonce: String,
    pub reason: String,
    pub capture_head: String,
    pub issued_elapsed_milliseconds: u64,
    pub elapsed_milliseconds: u64,
    pub outcome: String,
    pub signature: String,
}
impl Presence {
    pub fn payload(&self, id: &str) -> Vec<u8> {
        swift_array(&["huma-presence-v1".into(), id.into(), self.sequence.to_string(), self.kind.clone(),
            self.nonce.clone(), self.reason.clone(), self.capture_head.clone(), self.issued_elapsed_milliseconds.to_string(),
            self.elapsed_milliseconds.to_string(), self.outcome.clone(), "10000".into()])
    }
    pub fn digest(&self, id: &str) -> String {
        let mut bytes = self.payload(id);
        // Invalid encoding is rejected by evaluate, never treated as an approval.
        bytes.extend(binary(&self.signature, 80).unwrap_or_default());
        hash(&bytes)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputReport {
    pub with_origin: usize,
    pub hid_state_reported: usize,
    pub other_state_reported: usize,
    pub missing_origin: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceReport {
    pub schedule: String,
    pub challenges: usize,
    pub approved: usize,
    pub on_time: usize,
    pub missed: usize,
    // Decimal strings survive JS parsing without rounding u64 clocks.
    pub median_response_milliseconds: Option<String>,
    pub longest_gap_milliseconds: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    pub blank_baseline: bool,
    pub typing_edits_only: bool,
    pub minimum_duration: bool,
    pub minimum_keys: bool,
    pub paired_keys: bool,
    pub dwell_bounds: bool,
    pub interval_bounds: bool,
    pub pause_present: bool,
    pub rate_bound: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BehaviorReport {
    #[serde(rename = "policyID")]
    pub policy_id: String,
    pub experimental: bool,
    pub satisfied: bool,
    pub rules: Rules,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assurance {
    pub input: InputReport,
    pub presence: Option<PresenceReport>,
    pub behavior: BehaviorReport,
}

pub fn evaluate(s: &Session, key: Option<&[u8]>, bound_keys: usize, duration: u64) -> Result<Option<Assurance>, &'static str> {
    let events = s.presence_events.as_deref().unwrap_or(&[]);
    let samples = s.input_samples.as_deref().unwrap_or(&[]);
    check(s.presence_protocol.as_deref().is_none_or(|p| p == "local-presence-v1"), "Unsupported presence protocol")?;
    check(events.is_empty() || s.presence_protocol.is_some(), "Presence protocol missing")?;
    let fresh = s.presence_protocol.is_some() || samples.iter().any(|e| e.origin.is_some());
    if !fresh { return Ok(None); }
    check(key.is_some() && bound_keys == samples.len(), "Assurance requires signed, bound capture")?;
    let presence = if s.presence_protocol.is_some() {
        let verifying = VerifyingKey::from_sec1_bytes(key.unwrap()).map_err(|_| "Invalid presence key")?;
        let mut pending: Option<&Presence> = None;
        let mut seen = BTreeSet::new();
        let mut index = 0;
        let (mut approved, mut on_time, mut last_approval, mut longest) = (0, 0, 0, 0);
        let mut latencies = vec![];
        for record in s.capture_records.as_deref().unwrap_or(&[]) {
            if record.kind != "presence" {
                check(pending.is_none(), "Input occurred during presence challenge")?;
                continue;
            }
            let e = events.get(index).ok_or("Missing presence event")?;
            check(e.sequence == index && record.index == index && ["interval", "seal"].contains(&e.reason.as_str())
                && e.nonce.len() == 64 && e.nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "Invalid presence identity")?;
            if e.kind == "challenge" {
                check(pending.is_none() && seen.insert(e.nonce.clone()) && e.capture_head == record.previous_head
                    && e.elapsed_milliseconds == e.issued_elapsed_milliseconds && e.outcome == "pending" && e.signature.is_empty(), "Invalid presence issue")?;
                pending = Some(e);
            } else {
                let issue = pending.ok_or("Response without challenge")?;
                check(e.kind == "response" && e.nonce == issue.nonce && e.reason == issue.reason && e.capture_head == issue.capture_head
                    && e.issued_elapsed_milliseconds == issue.elapsed_milliseconds && e.elapsed_milliseconds >= issue.elapsed_milliseconds,
                    "Presence response binding mismatch")?;
                if e.outcome == "approved" {
                    let der = binary(&e.signature, 80)?;
                    let sig = Signature::from_der(&der).map_err(|_| "Invalid presence signature")?;
                    verifying.verify(&e.payload(&s.id), &sig).map_err(|_| "Presence signature mismatch")?;
                    approved += 1;
                    let latency = e.elapsed_milliseconds - issue.elapsed_milliseconds;
                    if latency <= 10_000 { on_time += 1; }
                    latencies.push(latency);
                    longest = longest.max(e.elapsed_milliseconds - last_approval);
                    last_approval = e.elapsed_milliseconds;
                } else {
                    check(["cancelled", "timedOut", "interrupted"].contains(&e.outcome.as_str()) && e.signature.is_empty(), "Invalid missed presence event")?;
                }
                pending = None;
            }
            index += 1;
        }
        check(index == events.len() && pending.is_none(), "Unresolved presence challenge")?;
        let last = events.last().ok_or("Missing seal presence challenge")?;
        check(last.kind == "response" && last.reason == "seal" && last.outcome == "approved"
            && last.elapsed_milliseconds - last.issued_elapsed_milliseconds <= 10_000
            && s.capture_records.as_ref().and_then(|r| r.last()).is_some_and(|r| r.kind == "presence"), "Seal presence missing")?;
        check(duration >= last_approval, "Presence exceeds signed duration")?;
        longest = longest.max(duration - last_approval);
        latencies.sort_unstable();
        Some(PresenceReport { schedule: "local-unattested-shifted-exponential-v1".into(), challenges: events.len() / 2,
            approved, on_time, missed: events.len() / 2 - on_time,
            median_response_milliseconds: latencies.get(latencies.len()/2).map(u64::to_string),
            longest_gap_milliseconds: longest.to_string() })
    } else { None };
    let with_origin = samples.iter().filter(|s| s.origin.is_some()).count();
    let hid = samples.iter().filter(|s| s.origin.as_ref().is_some_and(|o| o.source_state_id == 1)).count();
    let input = InputReport { with_origin, hid_state_reported: hid, other_state_reported: with_origin - hid,
        missing_origin: samples.len() - with_origin };
    let behavior = writing_policy(&s.initial_text, &s.events, samples, duration)?;
    Ok(Some(Assurance { input, presence, behavior }))
}

/// Shared deterministic policy, called only after each protocol authenticates its
/// trace. Validate ordering here too so independent callers cannot cause underflow.
pub fn writing_policy(initial_text: &str, edits: &[crate::Edit], samples: &[crate::Sample], duration: u64) -> Result<BehaviorReport, &'static str> {
    // Callers bound their own histories (replay_bounded); this is the long-session ceiling.
    check(samples.len() <= 262144 && edits.len() <= 65536, "Policy trace exceeds bounds")?;
    let mut previous_time = 0;
    for sample in samples {
        check(["down", "up"].contains(&sample.kind.as_str()) && sample.elapsed_milliseconds >= previous_time,
            "Invalid policy key sequence")?;
        previous_time = sample.elapsed_milliseconds;
    }
    let mut held = BTreeMap::new();
    let mut window = VecDeque::new();
    let (mut downs, mut pairs, mut good_dwells, mut anomalies, mut max_rate, mut good_intervals) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut previous_down: Option<u64> = None;
    let mut pause = false;
    for sample in samples {
        let t = sample.elapsed_milliseconds;
        if sample.kind == "down" {
            if sample.origin.as_ref().is_some_and(|o| o.is_repeat) {
                if !held.contains_key(&sample.key_code) { anomalies += 1; }
                continue;
            }
            downs += 1;
            if let Some(previous) = previous_down {
                let interval = t - previous;
                pause |= interval >= 500;
                if (5..=30_000).contains(&interval) { good_intervals += 1; }
            }
            previous_down = Some(t);
            if held.insert(sample.key_code, t).is_some() { anomalies += 1; }
            while window.front().is_some_and(|old| t - old >= 1000) { window.pop_front(); }
            window.push_back(t); max_rate = max_rate.max(window.len());
        } else if let Some(down) = held.remove(&sample.key_code) {
            pairs += 1;
            if (10..=2000).contains(&(t-down)) { good_dwells += 1; }
        } else { anomalies += 1; }
    }
    let rules = Rules {
        blank_baseline: initial_text.is_empty(),
        typing_edits_only: !edits.is_empty() && edits.iter().all(|e| e.source == "typing"),
        minimum_duration: duration >= 20_000,
        minimum_keys: downs >= 30,
        paired_keys: anomalies == 0 && pairs * 100 >= downs * 90,
        dwell_bounds: pairs > 0 && good_dwells * 100 >= pairs * 90,
        interval_bounds: downs > 1 && good_intervals * 100 >= (downs - 1) * 90,
        pause_present: pause,
        rate_bound: downs > 0 && max_rate <= 20,
    };
    let satisfied = rules.blank_baseline && rules.typing_edits_only && rules.minimum_duration && rules.minimum_keys
        && rules.paired_keys && rules.dwell_bounds && rules.interval_bounds && rules.pause_present && rules.rate_bound;
    Ok(BehaviorReport { policy_id: "huma-writing-rules-v1".into(), experimental: true, satisfied, rules })
}
