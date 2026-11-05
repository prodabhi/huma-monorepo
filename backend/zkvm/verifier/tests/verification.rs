use huma_replay_core::Witness;
use huma_replay_verifier::{verify_input, PublicSigningKey, VerificationInput};
fn input() -> VerificationInput {
    serde_json::from_str(include_str!("fixtures/timed-receipt.json")).unwrap()
}
#[test]
fn real_receipt_binds_text_key_time_and_optional_disclosures() {
    let mut record = input();
    let result = verify_input(&record).unwrap();
    assert!(result.verified && result.checks.checkpoint_signatures);
    assert!(result.checks.expected_key.is_none() && result.checks.revealed_history.is_none());
    assert!(!result.checks.trusted_calendar_time);
    assert_eq!(result.reported_time.unwrap().elapsed_milliseconds, "15");
    record.expected_capture_key_hash = result.journal.capture_key_hash;
    let witness: Witness =
        serde_json::from_str(include_str!("../../common/tests/fixtures/swift-timed.json")).unwrap();
    record.capture_public_key = Some(PublicSigningKey {
        format: "p256-x963-base64".into(),
        value: witness.session.signed_checkpoints.as_ref().unwrap()[0]
            .public_key
            .clone(),
    });
    record.session = Some(witness.session);
    let result = verify_input(&record).unwrap();
    assert_eq!(result.checks.expected_key, Some(true));
    assert_eq!(result.checks.revealed_key, Some(true));
    assert_eq!(result.checks.revealed_history, Some(true));
    record.text.push_str(" \t");
    assert!(verify_input(&record).is_ok()); // Reader whitespace does not rewrite revealed capture.
    record.session.as_mut().unwrap().events[0]
        .inserted_text
        .push('!');
    assert!(verify_input(&record).is_err());
}
#[test]
fn public_verifier_rejects_altered_receipts_pins_and_claims() {
    let mut record = input();
    record.text.push_str(" \t");
    assert!(verify_input(&record).is_ok());
    let mut record = input();
    record.text.push('!');
    assert!(verify_input(&record).is_err());
    let mut record = input();
    record.expected_capture_key_hash = Some("0".repeat(64));
    assert!(verify_input(&record).is_err());
    let mut record = input();
    record.bundle.image_id = "0".repeat(64);
    assert!(verify_input(&record).is_err());
    let mut record = input();
    record.bundle.receipt.journal.bytes[0] ^= 1;
    assert!(verify_input(&record).is_err());
    let mut json: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/timed-receipt.json")).unwrap();
    let claim = json["bundle"]["receipt"]["inner"]["Succinct"]["claim"].clone();
    json["bundle"]["receipt"]["inner"] = serde_json::json!({"Fake": {"claim": claim}});
    let record = serde_json::from_value(json).unwrap();
    assert!(verify_input(&record).is_err());
}
