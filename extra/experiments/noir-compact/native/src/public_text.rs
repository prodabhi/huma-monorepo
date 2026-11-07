//! Versioned public-text linkage. The complete verifier checks this commitment
//! AND the existing signed SHA-256 against the same canonical UTF-8 text.
use crate::{commit,protocol,assurance_input};
use ark_bn254::Fr;
use serde_json::{json,Value};

pub const DOMAIN:u64=0x48554d410501;
pub const BYTES:usize=1024;
pub fn commitment(text:&str)->Result<String,String> {
    let bytes=protocol::canonical(text).as_bytes();
    if bytes.is_empty()||bytes.len()>BYTES {return Err("Public text exceeds the V5 profile".into());}
    let mut input=vec![Fr::from(DOMAIN),Fr::from(bytes.len() as u64)];
    for block in 0..BYTES.div_ceil(31) {
        let mut value=Fr::from(0u64);
        for i in 0..31 {value=value*Fr::from(256u64)+Fr::from(*bytes.get(block*31+i).unwrap_or(&0) as u64);}
        input.push(value);
    }
    Ok(commit::hash(&input).to_string())
}
pub fn worker_input(w:&huma_replay_core::Witness,snapshot:&assurance_input::Snapshot)->Result<Value,String> {
    let mut out=assurance_input::worker_input(w,snapshot)?;
    let text=commitment(&snapshot.text)?;
    let expected=out["inputs"]["expected"].take();
    out["inputs"]["expected"]=json!({"capture":expected,"text_commitment":text});
    let prefix=out["publicInputsHex"].as_str().ok_or("Missing public input")?;
    out["publicInputsHex"]=Value::String(format!("{}{}",prefix,hex::encode(commit::bytes(commit::parse(&text)?))));
    out["textCommitment"]=Value::String(text);
    Ok(out)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn text_framing_has_exact_canonicalization_and_length() {
        let root=commitment("a").unwrap();assert_eq!(root,commitment("a \t").unwrap());
        for text in [" a","a\n","a\0","a\u{a0}","e\u{301}","é","a\0\0"] {
            assert_ne!(root,commitment(text).unwrap());
        }
        assert_ne!(commitment("é").unwrap(),commitment("e\u{301}").unwrap());
        assert!(commitment("").is_err());assert!(commitment(" \t").is_err());
        assert!(commitment(&"x".repeat(1025)).is_err());assert!(commitment(&"x".repeat(1024)).is_ok());
    }
    #[test] fn public_text_input_preserves_the_entire_original_signed_prefix() {
        let input:assurance_input::Input=serde_json::from_str(include_str!("../tests/fixtures/live-assurance.json")).unwrap();
        let v4=assurance_input::worker_input(&input.witness,&input.snapshot).unwrap();
        let v5=worker_input(&input.witness,&input.snapshot).unwrap();
        let original=v4["publicInputsHex"].as_str().unwrap();let next=v5["publicInputsHex"].as_str().unwrap();
        assert_eq!(next.len(),3040*2);assert!(next.starts_with(original));
        for field in ["signaturesHex","presenceSignaturesHex","publicKeyHex","journal"] {assert_eq!(v4[field],v5[field]);}
        assert_eq!(v5["inputs"]["expected"]["capture"],v4["inputs"]["expected"]);
    }
}
