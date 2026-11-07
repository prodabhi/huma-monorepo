//! New live sessions only. The caller owns signing; this module never receives a private key.
use crate::{commit,ops,protocol::{self,Capsule,Checkpoint,PrivateWitness}};
use ark_bn254::Fr;
use p256::ecdsa::{signature::Verifier,Signature,VerifyingKey};
use rand_core::{OsRng,RngCore};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};

pub const PROFILE: &str="cast256-v1";
pub const OPERATIONS: usize=1536;
pub const SCALARS: usize=256;
pub const CHECKPOINTS: usize=8;
const MAX_UNIX: u64=253402300799999;

struct Pending { checkpoint: Checkpoint,root: Fr,is_final: bool }
pub struct LiveCapture {
    builder: ops::Builder,
    nonce: [Fr;2],salt: [Fr;2],public_key: Vec<u8>,
    checkpoints: Vec<Checkpoint>,roots: Vec<Fr>,signatures: Vec<Vec<u8>>,
    pending: Option<Pending>,sealed: bool,
}
impl LiveCapture {
    pub fn new(initial: &str,public_key: Vec<u8>,unix: u64)->Result<Self,String> {
        if public_key.len()!=65 || public_key[0]!=4 || VerifyingKey::from_sec1_bytes(&public_key).is_err() {return Err("Invalid capture public key".into());}
        let mut nonce=[0u8;32];let mut salt=[0u8;32];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_|"Secure session randomness unavailable")?;
        loop {OsRng.try_fill_bytes(&mut salt).map_err(|_|"Secure session randomness unavailable")?;if salt.iter().any(|x|*x!=0){break;}}
        let mut capture=Self {builder:ops::Builder::new(initial,SCALARS,OPERATIONS)?,nonce:commit::halves(&nonce),salt:commit::halves(&salt),public_key,
            checkpoints:Vec::new(),roots:Vec::new(),signatures:Vec::new(),pending:None,sealed:false};
        capture.prepare(unix,0,false,initial)?;Ok(capture)
    }
    fn can_append(&self,elapsed: u64)->Result<(),String> {
        if self.sealed || self.pending.is_some() {return Err("Capture is sealed or waiting for its checkpoint signature".into());}
        if elapsed<self.checkpoints.last().map(|c|c.elapsed).unwrap_or(0) {return Err("Input predates the last signed checkpoint".into());}
        Ok(())
    }
    pub fn edit(&mut self,location: usize,removed: usize,inserted: &str,source: &str,elapsed: u64)->Result<(),String> {
        self.can_append(elapsed)?;self.builder.edit(location,removed,inserted,source,elapsed)
    }
    pub fn sample(&mut self,kind: &str,key: u16,modifiers: u64,elapsed: u64)->Result<(),String> {
        self.can_append(elapsed)?;self.builder.sample(kind,key,modifiers,elapsed)
    }
    pub fn pending_message(&self)->Result<Vec<u8>,String> {
        self.pending.as_ref().map(|p|protocol::message(p.root)).ok_or("No checkpoint is awaiting a signature".into())
    }
    pub fn prepare(&mut self,unix: u64,elapsed: u64,is_final: bool,text: &str)->Result<Vec<u8>,String> {
        let count=self.checkpoints.len();
        if self.sealed || self.pending.is_some() || unix>MAX_UNIX || elapsed<self.builder.elapsed() ||
            elapsed<self.checkpoints.last().map(|c|c.elapsed).unwrap_or(0) || count>=CHECKPOINTS ||
            (!is_final && count>=CHECKPOINTS-1) || self.builder.text().as_bytes()!=text.as_bytes() {
            return Err("Invalid compact checkpoint or profile capacity".into());
        }
        if count==0 && (is_final || self.builder.captures()!=0 || elapsed!=0) {return Err("Invalid initial checkpoint".into());}
        if count>0 && !is_final && self.checkpoints.last().is_some_and(|c|c.offset==self.builder.words.len()) {return Err("No new capture for an intermediate checkpoint".into());}
        let replay=ops::replay(&self.builder.words,SCALARS)?;
        if replay.text.as_bytes()!=text.as_bytes() {return Err("Independent replay differs from live capture".into());}
        let p=replay.prefixes.last().ok_or("Missing capture prefix")?;
        let checkpoint=Checkpoint {offset:self.builder.words.len(),unix,elapsed};
        let transcript=commit::Transcript::new(self.nonce,self.salt,&self.builder.words);
        let hash=if is_final {
            let canonical=protocol::canonical(text);if canonical.is_empty() {return Err("Cannot seal empty verification text".into());}
            Some(<[u8;32]>::from(Sha256::digest(canonical.as_bytes())))
        }else{None};
        let root=protocol::checkpoint_root(transcript.prefix(&self.builder.words,self.builder.words.len()),count,
            &checkpoint,p.edits,p.samples,*self.roots.last().unwrap_or(&Fr::from(0u64)),hash.as_ref());
        let message=protocol::message(root);
        self.pending=Some(Pending {checkpoint,root,is_final});Ok(message)
    }
    pub fn accept(&mut self,signature: Vec<u8>)->Result<(),String> {
        let pending=self.pending.as_ref().ok_or("No checkpoint is awaiting a signature")?;
        if signature.len()>72 {return Err("Checkpoint signature exceeds bounds".into());}
        let parsed=Signature::from_der(&signature).map_err(|_|"Invalid checkpoint DER signature")?;
        let key=VerifyingKey::from_sec1_bytes(&self.public_key).map_err(|_|"Invalid capture key")?;
        key.verify(&protocol::message(pending.root),&parsed).map_err(|_|"Checkpoint signature rejected")?;
        let pending=self.pending.take().unwrap();
        self.checkpoints.push(pending.checkpoint);self.roots.push(pending.root);self.signatures.push(signature);self.sealed=pending.is_final;Ok(())
    }
    pub fn info(&self)->Value {
        json!({"profile":PROFILE,"sealed":self.sealed,"operations":self.builder.words.len(),"captures":self.builder.captures(),
            "checkpoints":self.checkpoints.len(),"pendingMessage":self.pending.as_ref().map(|p|protocol::message(p.root)),
            "keyHash":hex::encode(Sha256::digest(&self.public_key)),"experimental":true,"attestationVerified":false,"trustedTime":false})
    }
    pub fn snapshot(&self)->Result<Value,String> {
        if !self.sealed || self.pending.is_some() {return Err("Seal and sign the complete session before exporting proof input".into());}
        let private=PrivateWitness {nonce:self.nonce.map(|x|x.to_string()),salt:self.salt.map(|x|x.to_string()),
            words:self.builder.words.clone(),checkpoints:self.checkpoints.clone()};
        let journal=protocol::statement(&private,SCALARS)?;
        if journal.checkpoint_roots!=self.roots.iter().map(|x|x.to_string()).collect::<Vec<_>>() {return Err("Signed checkpoints differ from replayed session".into());}
        let capsule=Capsule {kind:protocol::KIND.into(),journal,public_key:self.public_key.clone(),signatures:self.signatures.clone()};
        protocol::verify_signatures(&capsule,None,Some(&self.builder.text()))?;
        Ok(json!({"profile":PROFILE,"sealed":true,"private":private,"capsule":capsule,"text":self.builder.text(),"experimental":true}))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer,SigningKey};
    fn new(initial: &str)->(LiveCapture,SigningKey) {
        let key=SigningKey::random(&mut OsRng);
        let capture=LiveCapture::new(initial,key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),10).unwrap();
        (capture,key)
    }
    fn approve(c: &mut LiveCapture,key: &SigningKey) {
        let signature:Signature=key.sign(&c.pending_message().unwrap());c.accept(signature.to_der().as_bytes().to_vec()).unwrap();
    }
    #[test] fn live_unicode_movements_flags_long_delta_and_final_signatures() {
        let (mut c,key)=new("a😀z");approve(&mut c,&key);
        c.sample("down",65535,0x8000000100000002,(1u64<<40)+2).unwrap();
        c.edit(1,2,"e\u{301}","composition",(1u64<<40)+70000).unwrap();
        c.edit(0,1,"é","paste",(1u64<<40)+70001).unwrap();
        c.edit(4,0,"!","typing",(1u64<<40)+70002).unwrap(); // Right movement after the prior edit.
        c.sample("up",65535,0,(1u64<<40)+70003).unwrap();
        c.prepare(9,(1u64<<40)+70003,true,"ée\u{301}z!").unwrap();approve(&mut c,&key);
        let snap=c.snapshot().unwrap();
        assert_eq!(snap["capsule"]["journal"]["clock_back"],true);
        assert_eq!(snap["capsule"]["journal"]["paste"],1);
        assert!(c.sample("down",1,0,u64::MAX).is_err());
    }
    #[test] fn signature_gate_and_failures_are_atomic() {
        let (mut c,key)=new("a");let before=c.info();
        assert!(c.edit(1,0,"b","typing",1).is_err());
        let wrong=SigningKey::random(&mut OsRng);let sig:Signature=wrong.sign(&c.pending_message().unwrap());
        assert!(c.accept(sig.to_der().as_bytes().to_vec()).is_err());assert_eq!(before,c.info());approve(&mut c,&key);
        let before=c.info();assert!(c.edit(2,0,"b","typing",1).is_err());assert_eq!(before,c.info());
        c.sample("down",1,0,1).unwrap();c.prepare(11,5,false,"a").unwrap();approve(&mut c,&key);
        let before=c.info();assert!(c.sample("up",1,0,4).is_err());assert_eq!(before,c.info());
        assert!(c.snapshot().is_err());assert!(c.prepare(12,5,true,"wrong").is_err());
        c.prepare(12,5,true,"a").unwrap();approve(&mut c,&key);assert!(c.snapshot().is_ok());
    }
    #[test] fn exact_profile_boundaries_reserve_final_checkpoint() {
        let initial="😀".repeat(SCALARS);let (mut c,key)=new(&initial);approve(&mut c,&key);
        let before=c.info();assert!(c.edit(512,0,"a","typing",0).is_err());assert_eq!(before,c.info());
        for i in 0..CHECKPOINTS-2 {
            c.sample("down",1,0,i as u64).unwrap();c.prepare(20+i as u64,i as u64,false,&initial).unwrap();approve(&mut c,&key);
        }
        c.sample("up",1,0,10).unwrap();assert!(c.prepare(30,10,false,&initial).is_err());
        c.prepare(30,10,true,&initial).unwrap();approve(&mut c,&key);
        let snap=c.snapshot().unwrap();assert_eq!(snap["capsule"]["journal"]["raw_byte_length"],1024);
        assert_eq!(snap["capsule"]["signatures"].as_array().unwrap().len(),8);
    }
    #[test] fn operation_limit_and_u64_time_remain_exact() {
        let mut b=ops::Builder::new("a",256,1536).unwrap();
        for _ in 0..1534 {b.sample("down",1,0,0).unwrap();}
        assert_eq!(b.words.len(),1536);let before=b.words.clone();assert!(b.sample("up",1,0,0).is_err());assert_eq!(before,b.words);
        let (mut c,key)=new("a");approve(&mut c,&key);c.sample("down",1,0,u64::MAX).unwrap();
        c.prepare(11,u64::MAX,true,"a").unwrap();approve(&mut c,&key);
        assert_eq!(c.snapshot().unwrap()["capsule"]["journal"]["elapsed"].as_u64(),Some(u64::MAX));
    }
}
