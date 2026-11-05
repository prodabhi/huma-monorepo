use huma_replay_verifier::{
    image_id, public_document, verify_input, VerificationInput, MAX_DOCUMENT_BYTES, SYSTEM,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn replay_info() -> String {
    serde_json::json!({"system": SYSTEM, "imageID": image_id(), "verificationOnly": true})
        .to_string()
}

#[wasm_bindgen]
pub fn verify_replay(
    document: &str,
    text: Option<String>,
    expected_key: Option<String>,
) -> Result<String, JsValue> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(JsValue::from_str("Proof file exceeds 32 MB"));
    }
    let mut input: VerificationInput = serde_json::from_str(document)
        .map_err(|_| JsValue::from_str("Invalid replay proof file"))?;
    if let Some(text) = text {
        input.text = text;
    }
    // A file cannot supply its own 'known' key. Only the reader's separate input is used.
    input.expected_capture_key_hash = expected_key.filter(|value| !value.is_empty());
    let result = verify_input(&input).map_err(|message| JsValue::from_str(&message))?;
    serde_json::to_string(&result)
        .map_err(|_| JsValue::from_str("Could not encode verified report"))
}

// Publication is a separate operation from optional disclosure verification. Only
// the public text and typed receipt survive; caller metadata/history never does.
#[wasm_bindgen]
pub fn public_replay(document: &str) -> Result<String, JsValue> {
    public_document(document).map_err(|message| JsValue::from_str(&message))
}
