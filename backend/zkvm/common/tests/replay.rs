use huma_replay_core::{hash, replay, verification_text, Witness};
fn fixture(name: &str) -> Witness {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    serde_json::from_slice(&data).unwrap()
}
#[test]
fn swift_signatures_unicode_edits_and_hashes_interoperate() {
    let witness = fixture("swift-signed");
    let journal = replay(&witness).unwrap();
    assert_eq!(journal.edit_count, 5);
    assert_eq!(journal.bound_input_samples, 10);
    assert_eq!(journal.signed_checkpoint_count, 3);
    assert_eq!(journal.paste_edit_count, 1);
    assert_eq!(
        journal.verified_text_hash,
        hash(verification_text(&witness.text).as_bytes())
    );
    assert_ne!(journal.raw_text_hash, journal.verified_text_hash);
    assert!(journal.capture_key_hash.is_some());
}
#[test]
fn edit_capture_signature_final_coverage_and_time_tampering_fail() {
    let original = fixture("swift-signed");
    let mut w = original.clone();
    w.text.push('!');
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.events[0].inserted_text.push('!');
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.events.remove(0);
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.input_samples.as_mut().unwrap()[0].key_code += 1;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.capture_records.as_mut().unwrap().pop();
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap().pop();
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[2].signature = "AA==".into();
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.id.push('!');
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[2].capture_count -= 1;
    assert!(replay(&w).is_err());
}
#[test]
fn unsigned_and_legacy_logs_cannot_claim_signed_or_bound_key_evidence() {
    let unsigned = replay(&fixture("swift-unsigned")).unwrap();
    assert_eq!(unsigned.signed_checkpoint_count, 0);
    assert_eq!(unsigned.capture_key_hash, None);
    assert_eq!(unsigned.bound_input_samples, 10);
    let legacy = replay(&fixture("swift-legacy")).unwrap();
    assert_eq!(legacy.signed_checkpoint_count, 0);
    assert_eq!(legacy.bound_input_samples, 0);
    assert_eq!(legacy.capture_record_count, 0);
}
#[test]
fn canonicalization_preserves_the_versioned_rule() {
    assert_eq!(verification_text("x \t "), "x");
    for text in [" x", "a b", "x \n", "x\r\n", "x\u{a0}", "e\u{301}"] {
        assert_eq!(verification_text(text), text);
    }
    assert_eq!(verification_text("x\n \t"), "x\n");
}

#[test]
fn device_reported_window_is_signed_and_legacy_time_is_absent() {
    let original = fixture("swift-timed");
    let journal = replay(&original).unwrap();
    let time = journal.device_reported_time.unwrap();
    assert_eq!(time.start_unix_milliseconds, 1_792_627_200_000);
    assert_eq!(time.end_unix_milliseconds, 1_792_627_200_015);
    assert_eq!(time.elapsed_milliseconds, 15);
    assert!(!time.clock_moved_backwards);
    assert!(replay(&fixture("swift-signed"))
        .unwrap()
        .device_reported_time
        .is_none());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[2]
        .reported_time
        .as_mut()
        .unwrap()
        .unix_milliseconds += 1;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[2]
        .reported_time
        .as_mut()
        .unwrap()
        .elapsed_milliseconds = 0;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[1].reported_time = None;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.signed_checkpoints.as_mut().unwrap()[1].version = 1;
    assert!(replay(&w).is_err());
    let mut w = fixture("swift-signed");
    w.session.signed_checkpoints.as_mut().unwrap()[0].reported_time =
        original.session.signed_checkpoints.unwrap()[0]
            .reported_time
            .clone();
    assert!(replay(&w).is_err());
}

#[test]
fn presence_and_writing_policy_are_derived_from_the_same_swift_signed_trace() {
    let typed = replay(&fixture("presence-typed")).unwrap();
    assert_eq!(typed.version, 3);
    let assurance = typed.assurance.unwrap();
    assert_eq!(assurance.input.hid_state_reported, 80);
    assert_eq!(assurance.input.missing_origin, 0);
    assert_eq!(assurance.presence.as_ref().unwrap().on_time, 2);
    assert_eq!(assurance.presence.as_ref().unwrap().missed, 0);
    assert_eq!(assurance.presence.as_ref().unwrap().longest_gap_milliseconds, "22900");
    assert!(assurance.behavior.satisfied);
    assert!(assurance.behavior.experimental);
    // This deliberately regular software trace passes these illustrative rules.
    // A valid policy result is NOT a calibrated human classification.
    let pasted = replay(&fixture("presence-paste-missed")).unwrap().assurance.unwrap();
    assert!(!pasted.behavior.satisfied);
    assert!(!pasted.behavior.rules.typing_edits_only);
    assert_eq!(pasted.input.other_state_reported, 80);
    assert_eq!(pasted.presence.unwrap().missed, 1);
}

#[test]
fn provenance_presence_signature_and_challenge_transplants_are_rejected() {
    let original = fixture("presence-typed");
    let mut w = original.clone();
    w.session.input_samples.as_mut().unwrap()[0].origin.as_mut().unwrap().source_state_id = -1;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.input_samples.as_mut().unwrap()[0].origin = None;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.presence_events.as_mut().unwrap()[1].signature = "AA==".into();
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.presence_events.as_mut().unwrap()[1].nonce = "0".repeat(64);
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.presence_events = None;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.presence_protocol = None;
    assert!(replay(&w).is_err());
    let mut w = original.clone();
    w.session.presence_events = fixture("presence-paste-missed").session.presence_events;
    assert!(replay(&w).is_err());
}

#[test]
fn policy_feature_checks_handle_repeats_unpaired_keys_and_high_rates() {
    use huma_replay_core::human::evaluate;
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut w = fixture("presence-typed");
    // Scope this unit test to the feature evaluator; replay authenticates first.
    w.session.presence_protocol = None;
    w.session.presence_events = None;
    w.session.capture_records.as_mut().unwrap().retain(|r| r.kind != "presence");
    let key = STANDARD.decode(&w.session.signed_checkpoints.as_ref().unwrap()[0].public_key).unwrap();
    let count = w.session.input_samples.as_ref().unwrap().len();
    let report = evaluate(&w.session, Some(&key), count, 34401).unwrap().unwrap();
    assert!(report.behavior.satisfied);
    let mut short = w.session.clone();
    assert!(!evaluate(&short, Some(&key), count, 100).unwrap().unwrap().behavior.rules.minimum_duration);
    short.input_samples.as_mut().unwrap()[0].origin.as_mut().unwrap().is_repeat = true;
    assert!(!evaluate(&short, Some(&key), count, 34401).unwrap().unwrap().behavior.rules.paired_keys);
    let mut fast = w.session.clone();
    for (i, sample) in fast.input_samples.as_mut().unwrap().iter_mut().enumerate() { sample.elapsed_milliseconds = i as u64; }
    let rules = evaluate(&fast, Some(&key), count, 34401).unwrap().unwrap().behavior.rules;
    assert!(!rules.rate_bound && !rules.dwell_bounds && !rules.pause_present && !rules.interval_bounds);
    assert!(evaluate(&w.session, None, count, 34401).is_err());
    assert!(evaluate(&w.session, Some(&key), 0, 34401).is_err());
}
