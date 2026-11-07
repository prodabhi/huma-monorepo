use crate::{commit,ops};
use ark_bn254::Fr;
use p256::ecdsa::{signature::{Signer,Verifier},Signature,SigningKey,VerifyingKey};
use rand_core::{OsRng,RngCore};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};

pub const KIND: &str="huma-compact-replay-experiment-v3";
pub const SIGN_DOMAIN: &[u8]=b"HUMA_COMPACT_EXPERIMENT_CHECKPOINT_V3\0";
#[derive(Clone,Debug,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint { pub offset: usize,pub unix: u64,pub elapsed: u64 }
#[derive(Clone,Debug,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub session_nonce: [String;2], pub capture_root: String, pub text_hash: [u8;32],
    pub byte_length: u32,pub raw_byte_length: u32,pub initial_bytes: u32,
    pub edits: u32,pub samples: u32,pub captures: u32,pub typing: u32,pub paste: u32,pub op_count: u32,
    pub start_unix: u64,pub end_unix: u64,pub elapsed: u64,pub clock_back: bool,
    pub checkpoint_roots: Vec<String>,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule { pub kind: String,pub journal: Journal,pub public_key: Vec<u8>,pub signatures: Vec<Vec<u8>> }
#[derive(Clone,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWitness {
    pub nonce: [String;2],pub salt: [String;2],pub words: Vec<u64>,pub checkpoints: Vec<Checkpoint>,
}
pub fn canonical(text: &str) -> &str { text.trim_end_matches([' ','\t']) }
fn need(value: bool) -> Result<(),String> { if value {Ok(())} else {Err("Invalid compact session".into())} }

pub fn checkpoint_root(prefix: Fr,sequence: usize,c: &Checkpoint,edits: u32,samples: u32,
                       previous: Fr,final_hash: Option<&[u8;32]>) -> Fr {
    checkpoint_root_bound(prefix,sequence,c,edits,samples,previous,final_hash.map(commit::halves))
}
/// The final checkpoint binds two text fields: SHA-256 halves (V3/V4) or Poseidon commitments (long).
pub fn checkpoint_root_bound(prefix: Fr,sequence: usize,c: &Checkpoint,edits: u32,samples: u32,
                       previous: Fr,final_text: Option<[Fr;2]>) -> Fr {
    let halves=final_text.unwrap_or([Fr::from(0u64);2]);
    commit::hash(&[Fr::from(commit::CHECKPOINT),prefix,Fr::from(sequence as u64),
        Fr::from((edits+samples) as u64),Fr::from(edits as u64),Fr::from(samples as u64),
        Fr::from(c.unix),Fr::from(c.elapsed),Fr::from(final_text.is_some() as u64),previous,halves[0],halves[1]])
}

pub fn statement(w: &PrivateWitness,capacity: usize) -> Result<Journal,String> {
    let nonce=[commit::parse(&w.nonce[0])?,commit::parse(&w.nonce[1])?];
    let salt=[commit::parse(&w.salt[0])?,commit::parse(&w.salt[1])?];
    for field in nonce.iter().chain(salt.iter()) {
        need(commit::bytes(*field)[..16].iter().all(|b|*b==0))?;
    }
    need(salt.iter().any(|f|*f!=Fr::from(0u64)))?;
    let replay=ops::replay(&w.words,capacity)?;
    let text=canonical(&replay.text);need(!text.is_empty())?;
    let text_hash:[u8;32]=Sha256::digest(text.as_bytes()).into();
    let transcript=commit::Transcript::new(nonce,salt,&w.words);
    need(w.checkpoints.len()>=2)?;
    let mut previous=Fr::from(0u64);let mut prior_offset=0;let mut prior_elapsed=0;let mut prior_unix=0;
    let mut clock_back=false;let mut roots=Vec::new();
    for (i,c) in w.checkpoints.iter().enumerate() {
        need(c.offset>=prior_offset && c.offset<=w.words.len() && c.unix<=253402300799999 && c.elapsed>=prior_elapsed)?;
        let p=&replay.prefixes[c.offset];need(p.phase==1 && c.elapsed>=p.elapsed)?;
        if i==0 {need(c.offset==replay.baseline_end && c.elapsed==0)?;}
        else {clock_back|=c.unix<prior_unix;}
        let last=i+1==w.checkpoints.len();if last {need(c.offset==w.words.len())?;}
        let prefix=transcript.prefix(&w.words,c.offset);
        previous=checkpoint_root(prefix,i,c,p.edits,p.samples,previous,if last {Some(&text_hash)}else{None});
        roots.push(previous.to_string());prior_offset=c.offset;prior_elapsed=c.elapsed;prior_unix=c.unix;
    }
    let end=replay.prefixes.last().unwrap();
    Ok(Journal { session_nonce:w.nonce.clone(),capture_root:transcript.prefix(&w.words,w.words.len()).to_string(),text_hash,
        byte_length:text.len() as u32,raw_byte_length:replay.text.len() as u32,initial_bytes:end.initial_bytes,
        edits:end.edits,samples:end.samples,captures:end.edits+end.samples,typing:end.typing,paste:end.paste,
        op_count:w.words.len() as u32,start_unix:w.checkpoints[0].unix,end_unix:prior_unix,elapsed:prior_elapsed,clock_back,
        checkpoint_roots:roots })
}
pub fn message(root: Fr) -> Vec<u8> { let mut out=SIGN_DOMAIN.to_vec();out.extend_from_slice(&commit::bytes(root));out }
pub fn verify_signatures(c: &Capsule,expected_key: Option<&str>,text: Option<&str>) -> Result<String,String> {
    need(c.kind==KIND && c.public_key.len()==65 && c.public_key[0]==4 && (2..=1024).contains(&c.signatures.len()) && c.signatures.len()==c.journal.checkpoint_roots.len())?;
    let key=VerifyingKey::from_sec1_bytes(&c.public_key).map_err(|_|"Invalid P256 key")?;
    let key_hash=hex::encode(Sha256::digest(&c.public_key));
    if let Some(expected)=expected_key {need(expected==key_hash)?;}
    for (root,raw) in c.journal.checkpoint_roots.iter().zip(&c.signatures) {
        need(raw.len()<=72)?;
        let sig=Signature::from_der(raw).map_err(|_|"Invalid DER signature")?;
        key.verify(&message(commit::parse(root)?),&sig).map_err(|_|"Invalid checkpoint signature")?;
    }
    if let Some(text)=text {
        let canonical=canonical(text);
        need(canonical.len()==c.journal.byte_length as usize && <[u8;32]>::from(Sha256::digest(canonical.as_bytes()))==c.journal.text_hash)?;
    }
    Ok(key_hash)
}

// Public synthetic fixture adapter ONLY. Uses a fresh disposable SOFTWARE key;
// does not reuse/migrate any existing signing identity or claim device evidence.
pub fn synthetic_fixture(legacy: &huma_replay_core::Witness,capacity: usize) -> Result<(PrivateWitness,Capsule),String> {
    let compiled=ops::compile(legacy)?;
    let mut nonce=[0u8;32];let mut salt=[0u8;32];OsRng.fill_bytes(&mut nonce);OsRng.fill_bytes(&mut salt);
    let mut checkpoints=Vec::new();
    for cp in legacy.session.signed_checkpoints.as_ref().ok_or("Missing checkpoints")? {
        let time=cp.reported_time.as_ref().ok_or("Prototype needs V2 timed fixtures")?;
        checkpoints.push(Checkpoint {offset:compiled.capture_offsets[cp.capture_count],unix:time.unix_milliseconds,elapsed:time.elapsed_milliseconds});
    }
    let private=PrivateWitness {nonce:commit::halves(&nonce).map(|f|f.to_string()),salt:commit::halves(&salt).map(|f|f.to_string()),words:compiled.words,checkpoints};
    let journal=statement(&private,capacity)?;
    need(journal.text_hash==<[u8;32]>::from(Sha256::digest(canonical(&legacy.text).as_bytes())))?;
    let key=SigningKey::random(&mut OsRng);
    let signatures=journal.checkpoint_roots.iter().map(|root| {
        let sig:Signature=key.sign(&message(commit::parse(root).unwrap()));sig.to_der().as_bytes().to_vec()
    }).collect();
    let capsule=Capsule {kind:KIND.into(),journal,public_key:key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),signatures};
    verify_signatures(&capsule,None,Some(&legacy.text))?;
    Ok((private,capsule))
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn synthetic_fixture_signatures_and_mutations() {
        let w:huma_replay_core::Witness=serde_json::from_str(include_str!("../../../../../backend/zkvm/common/tests/fixtures/swift-timed.json")).unwrap();
        let (private,capsule)=synthetic_fixture(&w,128).unwrap();
        assert_eq!(statement(&private,128).unwrap(),capsule.journal);
        let key=verify_signatures(&capsule,None,Some(&w.text)).unwrap();
        assert!(verify_signatures(&capsule,Some(&key),Some(&(w.text.clone()+" \t"))).is_ok());
        for mode in 0..5 {
            let mut bad=capsule.clone();
            match mode {0=>bad.signatures[1][15]^=1,1=>{bad.signatures.swap(0,1);},
                2=>bad.journal.checkpoint_roots[1]="1".into(),3=>bad.public_key[20]^=1,_=>{bad.signatures.pop();}}
            assert!(verify_signatures(&bad,None,None).is_err());
        }
        assert!(verify_signatures(&capsule,Some(&"0".repeat(64)),None).is_err());
        assert!(verify_signatures(&capsule,None,Some(&(w.text+"!"))).is_err());
    }
}
