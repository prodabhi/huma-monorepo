//! Live V4 collector. Receives signatures, never a signing key or imported history.
//! The long profile records the same evidence with larger bounds and long-profile
//! signing domains; its sealed snapshot is checked against the independent chain.
use crate::{assurance::{self,Origin,OriginTranscript,Presence},capture::{OPERATIONS,SCALARS,CHECKPOINTS},commit,long,ops,protocol};
use ark_bn254::Fr;
use p256::ecdsa::{signature::Verifier,Signature,VerifyingKey};
use rand_core::{OsRng,RngCore};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::collections::BTreeSet;

pub const PROFILE:&str="assurance256-v1";
pub const EXTENDED_PROFILE:&str="assurance256-cp32-v1";
pub const LONG_PROFILE:&str=long::PROFILE;
pub fn checkpoint_limit(profile:&str)->Option<usize> {
    match profile {PROFILE=>Some(CHECKPOINTS),EXTENDED_PROFILE=>Some(32),_=>None}
}
pub const SAMPLES:usize=516;
pub const PRESENCE:usize=8;
const MAX_UNIX:u64=253402300799999;
#[derive(Clone,Copy)]
struct Limits {scalars:usize,operations:usize,samples:usize,presence:usize,checkpoints:usize}
fn limits(profile:&str)->Option<(&'static str,Limits)> {
    match profile {
        PROFILE=>Some((PROFILE,Limits {scalars:SCALARS,operations:OPERATIONS,samples:SAMPLES,presence:PRESENCE,checkpoints:CHECKPOINTS})),
        EXTENDED_PROFILE=>Some((EXTENDED_PROFILE,Limits {scalars:SCALARS,operations:OPERATIONS,samples:SAMPLES,presence:PRESENCE,checkpoints:32})),
        LONG_PROFILE=>Some((LONG_PROFILE,Limits {scalars:long::CAPACITY,operations:long::OPERATIONS,samples:long::SAMPLES,
            presence:long::PRESENCE,checkpoints:long::CHECKPOINTS})),
        _=>None,
    }
}
struct Issued {offset:usize,nonce:[String;2],reason:u8,elapsed:u64,root:Fr}
enum Pending {
    Checkpoint {value:protocol::Checkpoint,replay_root:Fr,bound_root:Fr,is_final:bool},
    Response {value:Presence,root:Fr},
}
pub struct LiveAssuranceCapture {
    profile:&'static str,limits:Limits,
    builder:ops::Builder,nonce:[Fr;2],salt:[Fr;2],public_key:Vec<u8>,
    origins:Vec<Origin>,presence:Vec<Presence>,seen:BTreeSet<[u8;32]>,issued:Option<Issued>,
    presence_head:Fr,presence_roots:Vec<Fr>,presence_signatures:Vec<Vec<u8>>,
    checkpoints:Vec<protocol::Checkpoint>,checkpoint_presence:Vec<usize>,
    replay_roots:Vec<Fr>,checkpoint_roots:Vec<Fr>,signatures:Vec<Vec<u8>>,
    pending:Option<Pending>,sealed:bool,
    transcript:commit::Transcript,origin_transcript:OriginTranscript,
    // Long profile: accepted events in signed order, and the chain after the last exported chunk.
    events:Vec<long::Event>,cursor:Option<(usize,long::State)>,closed:Vec<long::Chunk>,
}
impl LiveAssuranceCapture {
    pub fn new(initial:&str,public_key:Vec<u8>,unix:u64)->Result<Self,String> {
        Self::with_profile(initial,public_key,unix,PROFILE)
    }
    pub fn with_profile(initial:&str,public_key:Vec<u8>,unix:u64,profile:&str)->Result<Self,String> {
        Self::with_seed(initial,public_key,unix,profile,None)
    }
    /// `seed` (long profile only): 16 bytes someone else chose, such as a server's session nonce, that become the
    /// session's public nonce[0] in place of fresh randomness. Must not be all zero.
    pub fn with_seed(initial:&str,public_key:Vec<u8>,unix:u64,profile:&str,seed:Option<[u8;16]>)->Result<Self,String> {
        let (profile,limits)=limits(profile).ok_or("Unsupported assurance profile")?;
        if seed.is_some_and(|s|profile!=LONG_PROFILE || s.iter().all(|b|*b==0)) {return Err("Invalid session nonce".into());}
        if public_key.len()!=65 || public_key[0]!=4 || VerifyingKey::from_sec1_bytes(&public_key).is_err() {return Err("Invalid V4 capture key".into());}
        let mut nonce=[0u8;32];let mut salt=[0u8;32];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_|"Secure randomness unavailable")?;
        loop {OsRng.try_fill_bytes(&mut salt).map_err(|_|"Secure randomness unavailable")?;if salt.iter().any(|b|*b!=0){break;}}
        // A long session's nonce commits to its capture key (long::bound_nonce), which readers check.
        let nonce=if profile==LONG_PROFILE {
            let mut seed32=[0u8;32];seed32[16..].copy_from_slice(seed.as_ref().map_or(&nonce[16..],|s|&s[..]));
            if seed32.iter().all(|b|*b==0) {seed32[31]=1;}
            long::bound_nonce(commit::halves(&seed32)[1],&public_key)?
        } else {commit::halves(&nonce)};
        let salt=commit::halves(&salt);
        let head=commit::hash(&[Fr::from(0x48554d410404u64),nonce[0],nonce[1],salt[0],salt[1]]);
        let mut state=Self {profile,limits,builder:ops::Builder::new(initial,limits.scalars,limits.operations)?,nonce,salt,public_key,
            origins:vec![],presence:vec![],seen:BTreeSet::new(),issued:None,presence_head:head,
            presence_roots:vec![],presence_signatures:vec![],checkpoints:vec![],checkpoint_presence:vec![],
            replay_roots:vec![],checkpoint_roots:vec![],signatures:vec![],pending:None,sealed:false,
            transcript:commit::Transcript::new(nonce,salt,&[]),origin_transcript:OriginTranscript::new(nonce,salt,&[])?,
            events:vec![],cursor:None,closed:vec![]};
        state.prepare(unix,0,false,initial)?;Ok(state)
    }
    fn is_long(&self)->bool {self.profile==LONG_PROFILE}
    fn domains(&self)->(&'static [u8],&'static [u8]) {
        if self.is_long() {(long::CP_DOMAIN,long::PRESENCE_DOMAIN)}else{(assurance::CP_DOMAIN,assurance::PRESENCE_DOMAIN)}
    }
    fn latest_time(&self)->u64 {
        self.builder.elapsed().max(self.checkpoints.last().map_or(0,|c|c.elapsed))
            .max(self.presence.last().map_or(0,|p|p.answered))
    }
    fn has_seal(&self)->bool {
        self.presence.last().is_some_and(|p|p.reason==2 && p.outcome==1 && p.answered-p.issued<=10000)
    }
    fn can_input(&self,elapsed:u64)->Result<(),String> {
        if self.sealed || self.pending.is_some() || self.issued.is_some() || self.has_seal() || elapsed<self.latest_time() {
            return Err("V4 capture is sealed, awaiting approval, or input time moved backwards".into());
        }Ok(())
    }
    /// Capture and origin prefixes at the current end, from append-only transcripts.
    fn prefixes(&mut self)->Result<(Fr,Fr),String> {
        self.transcript.extend(&self.builder.words);self.origin_transcript.extend(&self.origins)?;
        Ok((self.transcript.prefix(&self.builder.words,self.builder.words.len()),self.origin_transcript.prefix(self.origins.len())))
    }
    pub fn edit(&mut self,location:usize,removed:usize,inserted:&str,source:&str,elapsed:u64)->Result<(),String> {
        self.can_input(elapsed)?;self.builder.edit(location,removed,inserted,source,elapsed)
    }
    pub fn sample(&mut self,kind:&str,key:u16,modifiers:u64,elapsed:u64,origin:Origin)->Result<(),String> {
        self.can_input(elapsed)?;
        if key>=256 || self.origins.len()>=self.limits.samples {return Err("Complete session exceeds V4 key-event profile".into());}
        origin.packed()?;self.builder.sample(kind,key,modifiers,elapsed)?;self.origins.push(origin);Ok(())
    }
    pub fn issue(&mut self,nonce:[u8;32],reason:u8,elapsed:u64)->Result<(),String> {
        self.can_input(elapsed)?;let limit=self.limits.presence;
        if self.presence.len()>=limit || (reason==1 && self.presence.len()>=limit-1)
            || !matches!(reason,1|2) || nonce.iter().all(|b|*b==0) || self.seen.contains(&nonce) {
            return Err("Invalid, reused or over-capacity V4 presence challenge".into());
        }
        let n=commit::halves(&nonce);let replay=ops::replay(&self.builder.words,self.limits.scalars)?;
        let prefix=replay.prefixes.last().ok_or("Missing replay prefix")?.clone();
        let (capture,origin)=self.prefixes()?;
        let root=commit::hash(&[Fr::from(0x48554d410405u64),self.nonce[0],self.nonce[1],Fr::from(self.presence.len() as u64),
            self.presence_head,capture,origin,Fr::from(prefix.edits as u64),Fr::from(prefix.samples as u64),n[0],n[1],Fr::from(reason),Fr::from(elapsed)]);
        self.issued=Some(Issued {offset:self.builder.words.len(),nonce:n.map(|x|x.to_string()),reason,elapsed,root});
        self.seen.insert(nonce);Ok(())
    }
    /// Approval exposes a signing request and freezes capture until accepted.
    /// Missed/cancelled outcomes append immediately and are bound by later checkpoints.
    pub fn respond(&mut self,outcome:u8,elapsed:u64)->Result<(),String> {
        let root=self.response_root(outcome,elapsed)?;let issue=self.issued.as_ref().ok_or("No V4 presence challenge")?;
        let value=Presence {offset:issue.offset,nonce:issue.nonce.clone(),reason:issue.reason,issued:issue.elapsed,answered:elapsed,outcome};
        if outcome==1 {self.pending=Some(Pending::Response {value,root});}
        else {self.append_response(value,root,None)?;}
        Ok(())
    }
    fn response_root(&self,outcome:u8,elapsed:u64)->Result<Fr,String> {
        let issue=self.issued.as_ref().ok_or("No V4 presence challenge")?;
        if self.sealed || self.pending.is_some() || !matches!(outcome,1..=4) || elapsed<issue.elapsed {return Err("Invalid V4 presence response".into());}
        Ok(commit::hash(&[Fr::from(0x48554d410406u64),issue.root,Fr::from(elapsed),Fr::from(outcome)]))
    }
    /// The 32 big-endian bytes of the root `respond(outcome,elapsed)` would ask to sign, changing nothing.
    pub fn preview_response_root(&self,outcome:u8,elapsed:u64)->Result<[u8;32],String> {self.response_root(outcome,elapsed).map(commit::bytes)}
    fn append_response(&mut self,value:Presence,root:Fr,signature:Option<Vec<u8>>)->Result<(),String> {
        let issue=self.issued.take().ok_or("Missing issued V4 challenge")?;
        self.presence_head=commit::hash(&[Fr::from(0x48554d410407u64),self.presence_head,issue.root,root]);
        if let Some(signature)=signature {self.presence_roots.push(root);self.presence_signatures.push(signature);}
        if self.is_long() {self.events.push(long::Event::Presence(value.clone()));}
        self.presence.push(value);Ok(())
    }
    pub fn prepare(&mut self,unix:u64,elapsed:u64,is_final:bool,text:&str)->Result<(),String> {
        let count=self.checkpoints.len();let limit=self.limits.checkpoints;
        if self.sealed || self.pending.is_some() || self.issued.is_some() || unix>MAX_UNIX || elapsed<self.latest_time()
            || count>=limit || (!is_final && count>=limit-1) || self.builder.text().as_bytes()!=text.as_bytes()
            || (is_final && (!self.has_seal() || count==0)) || (!is_final && self.has_seal()) {
            return Err("Invalid V4 checkpoint, unresolved seal or profile capacity".into());
        }
        if count==0 && (is_final || self.builder.captures()!=0 || !self.presence.is_empty() || elapsed!=0) {return Err("Invalid V4 start".into());}
        if count>0 && !is_final && self.checkpoints.last().is_some_and(|c|c.offset==self.builder.words.len())
            && self.checkpoint_presence.last()==Some(&self.presence.len()) {return Err("No new V4 capture".into());}
        let replay=ops::replay(&self.builder.words,self.limits.scalars)?;
        if replay.text.as_bytes()!=text.as_bytes() {return Err("V4 independent replay differs".into());}
        let p=replay.prefixes.last().ok_or("Missing V4 replay prefix")?;
        let cp=protocol::Checkpoint {offset:self.builder.words.len(),unix,elapsed};
        let binding=if !is_final {None} else if self.is_long() {Some(long::text_binding_at(text,long::session_tier(&self.builder.words)?)?)} else {
            let text=protocol::canonical(text);if text.is_empty(){return Err("Empty verification text".into());}
            Some(commit::halves(&<[u8;32]>::from(Sha256::digest(text.as_bytes()))))
        };
        let (edits,samples)=(p.edits,p.samples);let (capture,origin)=self.prefixes()?;
        let replay_root=protocol::checkpoint_root_bound(capture,count,&cp,edits,samples,
            *self.replay_roots.last().unwrap_or(&Fr::from(0u64)),binding);
        let bound_root=commit::hash(&[Fr::from(0x48554d410408u64),replay_root,origin,self.presence_head,Fr::from(self.presence.len() as u64)]);
        self.pending=Some(Pending::Checkpoint {value:cp,replay_root,bound_root,is_final});Ok(())
    }
    pub fn pending_message(&self)->Result<Vec<u8>,String> {
        let (checkpoint,presence)=self.domains();
        match self.pending.as_ref().ok_or("No V4 signing request")? {
            Pending::Checkpoint {bound_root,..}=>assurance::message(checkpoint,&bound_root.to_string()),
            Pending::Response {root,..}=>assurance::message(presence,&root.to_string()),
        }
    }
    pub fn accept(&mut self,der:Vec<u8>)->Result<(),String> {
        let message=self.pending_message()?;
        if der.len()>72 {return Err("V4 signature exceeds bounds".into());}
        let signature=Signature::from_der(&der).map_err(|_|"Invalid V4 DER signature")?;
        VerifyingKey::from_sec1_bytes(&self.public_key).map_err(|_|"Invalid V4 key")?.verify(&message,&signature).map_err(|_|"V4 signature rejected")?;
        match self.pending.take().ok_or("Missing V4 pending signature")? {
            Pending::Checkpoint {value,replay_root,bound_root,is_final}=>{
                if self.is_long() {self.events.push(long::Event::Checkpoint {offset:value.offset,unix:value.unix,elapsed:value.elapsed,last:is_final});}
                self.checkpoints.push(value);self.checkpoint_presence.push(self.presence.len());self.replay_roots.push(replay_root);
                self.checkpoint_roots.push(bound_root);self.signatures.push(der);self.sealed=is_final;
            },
            Pending::Response {value,root}=>self.append_response(value,root,Some(der))?,
        }Ok(())
    }
    /// Long profile: chunks whose operations and events can no longer change.
    pub fn long_chunks(&self)->Vec<long::Chunk> {
        if !self.is_long() {return vec![];}
        long::plan(&self.closed,self.builder.words.len(),&self.events,self.sealed,long::Format::V3).map(|p|p.chunks).unwrap_or_default()
    }
    /// Closes the open part at the current end (a pause, or Finish), so it can be proved now.
    pub fn long_cut(&mut self)->Result<(),String> {
        if !self.is_long() || self.sealed || self.pending.is_some() || self.issued.is_some() {return Err("No open long-session part to close".into());}
        let mut closed=self.long_chunks();
        let (s,e)=closed.last().map_or((0,0),|c|(c.ops.1,c.events.1));
        if self.builder.words.len()==s && self.events.len()==e {return Ok(());}
        closed.push(long::Chunk {ops:(s,self.builder.words.len()),events:(e,self.events.len())});
        long::plan(&closed,self.builder.words.len(),&self.events,false,long::Format::V3)?;
        self.closed=closed;Ok(())
    }
    fn private(&self)->assurance::Private {
        assurance::Private {replay:protocol::PrivateWitness {nonce:self.nonce.map(|n|n.to_string()),salt:self.salt.map(|n|n.to_string()),
            words:self.builder.words.clone(),checkpoints:self.checkpoints.clone()},origins:self.origins.clone(),presence:self.presence.clone(),
            checkpoint_presence:self.checkpoint_presence.clone()}
    }
    /// Private proof input for one closed chunk, at the session's current text tier (v3). Sequential requests
    /// reuse the chain state; any other index, or a new tier, is recomputed from genesis. Once the text outgrows
    /// its tier every part is proved again at the next one, so the app keeps only proofs whose `tier` matches.
    /// Contains raw writing history.
    pub fn long_chunk(&mut self,index:usize)->Result<Value,String> {
        let chunks=self.long_chunks();let chunk=*chunks.get(index).ok_or("Long-session chunk is not closed yet")?;
        let private=self.private();let session=long::Session::new(&private,self.sealed,&self.closed,long::Format::V3)?;
        let mut state=match self.cursor.take() {
            Some((at,state)) if at==index && state.replay.buffer.len()==session.capacity=>state,
            _=>{let mut state=session.genesis();
                for c in &chunks[..index] {state=session.step(&state,c)?.0;}state},
        };
        let (input,after)=session.chunk_input(&state,&chunk,None)?;
        state=after;self.cursor=Some((index+1,state));
        Ok(json!({"index":index,"chunks":chunks.len(),"sealed":self.sealed,"tier":session.capacity,"input":input}))
    }
    #[cfg(test)] pub fn snapshot_words(&self)->Vec<u64> {self.builder.words.clone()}
    pub fn info(&self)->Value {
        let pending_kind=self.pending.as_ref().map(|p|match p {Pending::Checkpoint {..}=>"checkpoint",Pending::Response {..}=>"presence"});
        let mut info=json!({"profile":self.profile,"sealed":self.sealed,"operations":self.builder.words.len(),"captures":self.builder.captures(),
            "checkpoints":self.checkpoints.len(),"origins":self.origins.len(),"presenceCount":self.presence.len(),"presencePending":self.issued.is_some(),
            "pendingKind":pending_kind,"pendingMessage":self.pending.as_ref().map(|_|self.pending_message().unwrap()),
            "keyHash":hex::encode(Sha256::digest(&self.public_key)),"experimental":true,"attestationVerified":false,"trustedTime":false});
        if self.is_long() {
            let chunks=self.long_chunks();
            info["closedChunks"]=json!(chunks.len());
            info["openOperations"]=json!(self.builder.words.len()-chunks.last().map_or(0,|c|c.ops.1));
        }
        info
    }
    pub fn snapshot(&self)->Result<Value,String> {
        if !self.sealed || self.pending.is_some() || self.issued.is_some() {return Err("Complete and sign V4 capture before exporting".into());}
        let private=self.private();
        if self.is_long() {
            // Independent check: the chain must reproduce every root the live capture signed.
            let session=long::Session::new(&private,true,&self.closed,long::Format::V3)?;let (chunks,signed,_,statement)=session.run()?;
            let (checkpoints,presence)=long::split(&signed);
            if checkpoints!=self.checkpoint_roots || presence!=self.presence_roots {return Err("Live long-session commitments differ from the chain".into());}
            long::verify_signatures(&self.public_key,&checkpoints,&self.signatures,&presence,&self.presence_signatures)?;
            let capsule=long::Capsule {kind:long::KIND.into(),statement,public_key:self.public_key.clone(),
                checkpoint_roots:checkpoints.iter().map(|r|r.to_string()).collect(),signatures:self.signatures.clone(),
                presence_roots:presence.iter().map(|r|r.to_string()).collect(),presence_signatures:self.presence_signatures.clone()};
            return Ok(json!({"profile":self.profile,"sealed":true,"private":private,"capsule":capsule,"text":self.builder.text(),
                "chunks":chunks.len(),"plan":chunks,"experimental":true,"format":long::Format::V3}));
        }
        let journal=assurance::statement(&private,SCALARS)?;
        if journal.replay.checkpoint_roots!=self.replay_roots.iter().map(|r|r.to_string()).collect::<Vec<_>>()
            || journal.checkpoint_roots!=self.checkpoint_roots.iter().map(|r|r.to_string()).collect::<Vec<_>>()
            || journal.presence_roots!=self.presence_roots.iter().map(|r|r.to_string()).collect::<Vec<_>>() {return Err("Live V4 commitments differ from independent replay".into());}
        let capsule=assurance::Capsule {kind:assurance::KIND.into(),journal,public_key:self.public_key.clone(),signatures:self.signatures.clone(),presence_signatures:self.presence_signatures.clone()};
        assurance::verify(&capsule)?;
        Ok(json!({"profile":self.profile,"sealed":true,"private":private,"capsule":capsule,"text":self.builder.text(),"experimental":true}))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer,SigningKey};
    fn new(initial:&str)->(LiveAssuranceCapture,SigningKey) {
        let key=SigningKey::random(&mut OsRng);
        (LiveAssuranceCapture::new(initial,key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),1000).unwrap(),key)
    }
    fn approve(c:&mut LiveAssuranceCapture,key:&SigningKey) {
        let signature:Signature=key.sign(&c.pending_message().unwrap());c.accept(signature.to_der().as_bytes().to_vec()).unwrap();
    }
    fn seal(c:&mut LiveAssuranceCapture,key:&SigningKey,time:u64,text:&str) {
        c.issue([250;32],2,time).unwrap();c.respond(1,time+100).unwrap();approve(c,key);
        c.prepare(999,time+200,true,text).unwrap();approve(c,key);
    }
    #[test] fn extended_profile_keeps_all_32_signatures_and_reserves_the_seal_slot() {
        let key=SigningKey::random(&mut OsRng);
        let mut c=LiveAssuranceCapture::with_profile("a",key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),1000,EXTENDED_PROFILE).unwrap();
        approve(&mut c,&key);
        for i in 0..30 {
            c.sample("down",(i%128) as u16,0,i*100+1,Origin::default()).unwrap();
            c.prepare(1000+i*100,i*100+1,false,"a").unwrap();approve(&mut c,&key);
        }
        c.sample("up",0,0,3100,Origin::default()).unwrap();
        let before=c.info();assert!(c.prepare(5000,3100,false,"a").is_err());assert_eq!(before,c.info());
        seal(&mut c,&key,4000,"a");
        let snapshot=c.snapshot().unwrap();assert_eq!(snapshot["profile"],EXTENDED_PROFILE);
        let capsule:assurance::Capsule=serde_json::from_value(snapshot["capsule"].clone()).unwrap();
        assert_eq!(capsule.signatures.len(),32);assert_eq!(capsule.journal.checkpoint_roots.len(),32);
        for index in 0..32 {let mut bad=capsule.clone();bad.signatures[index][10]^=1;assert!(assurance::verify(&bad).is_err());}
    }
    #[test] fn live_policy_origin_and_signatures_match_independent_full_replay() {
        let (mut c,key)=new("");approve(&mut c,&key);let mut text=String::new();
        for i in 0..40 {
            let t=100+i*550;
            let origin=Origin {present:true,pid:u32::MAX,state:1,keyboard:40,repeated:false};
            c.sample("down",(i%8) as u16,0,t,origin.clone()).unwrap();
            c.edit(text.len(),0,"a","typing",t+1).unwrap();text.push('a');
            c.sample("up",(i%8) as u16,0,t+65,origin).unwrap();
            if i==20 {c.prepare(1000+t+65,t+65,false,&text).unwrap();approve(&mut c,&key);}
        }
        seal(&mut c,&key,26000,&text);let snap=c.snapshot().unwrap();
        let capsule:assurance::Capsule=serde_json::from_value(snap["capsule"].clone()).unwrap();
        let private:assurance::Private=serde_json::from_value(snap["private"].clone()).unwrap();
        assert_eq!(capsule.journal,assurance::statement(&private,SCALARS).unwrap());
        assert!(capsule.journal.policy_satisfied);assert_eq!(capsule.journal.origin_present,80);
        assert_eq!(capsule.journal.origin_hid,80);assert_eq!(capsule.journal.on_time,1);
        assert_eq!(capsule.signatures.len(),3);assert_eq!(capsule.presence_signatures.len(),1);
        assert!(capsule.journal.replay.clock_back);
        for index in 0..capsule.signatures.len() {let mut bad=capsule.clone();bad.signatures[index][10]^=1;assert!(assurance::verify(&bad).is_err());}
        let mut bad=capsule;bad.presence_signatures[0][10]^=1;assert!(assurance::verify(&bad).is_err());
    }
    #[test] fn rejected_events_and_signatures_are_atomic() {
        let (mut c,key)=new("a");let before=c.info();assert!(c.edit(1,0,"b","typing",1).is_err());
        let wrong=SigningKey::random(&mut OsRng);let signature:Signature=wrong.sign(&c.pending_message().unwrap());
        assert!(c.accept(signature.to_der().as_bytes().to_vec()).is_err());assert_eq!(before,c.info());approve(&mut c,&key);
        let before=c.info();
        for origin in [Origin {pid:1,..Origin::default()},Origin {repeated:true,..Origin::default()}] {
            assert!(c.sample("down",0,0,1,origin).is_err());assert_eq!(before,c.info());
        }
        assert!(c.sample("down",256,0,1,Origin::default()).is_err());assert_eq!(before,c.info());
        assert!(c.edit(5,0,"x","typing",1).is_err());assert_eq!(before,c.info());
        assert!(c.issue([0;32],1,1).is_err());assert_eq!(before,c.info());assert!(c.snapshot().is_err());
    }
    #[test] fn presence_domain_pause_late_and_cancelled_outcomes_are_preserved() {
        let (mut c,key)=new("x");approve(&mut c,&key);c.issue([1;32],1,10).unwrap();
        assert!(c.edit(1,0,"y","typing",11).is_err());assert!(c.prepare(1010,11,false,"x").is_err());
        for (outcome,time) in [(0,10),(5,10),(1,9)] {let before=c.info();assert!(c.respond(outcome,time).is_err());assert_eq!(before,c.info());}
        c.respond(1,20).unwrap();let before=c.info();
        let wrong_domain=assurance::message(assurance::CP_DOMAIN,&match c.pending.as_ref().unwrap(){Pending::Response {root,..}=>root.to_string(),_=>unreachable!()}).unwrap();
        let signature:Signature=key.sign(&wrong_domain);assert!(c.accept(signature.to_der().as_bytes().to_vec()).is_err());assert_eq!(before,c.info());
        approve(&mut c,&key);assert!(c.issue([1;32],1,21).is_err());assert!(c.sample("up",1,0,19,Origin::default()).is_err());
        c.issue([2;32],1,22).unwrap();c.respond(2,23).unwrap();assert!(c.pending_message().is_err());
        c.issue([3;32],2,24).unwrap();c.respond(1,10025).unwrap();approve(&mut c,&key);
        assert!(c.prepare(2000,10025,true,"x").is_err()); // Late seal remains in history; it cannot finish the session.
        seal(&mut c,&key,10026,"x");let snap=c.snapshot().unwrap();let j=&snap["capsule"]["journal"];
        assert_eq!(j["presence_count"],4);assert_eq!(j["approved"],3);assert_eq!(j["on_time"],2);assert_eq!(j["missed"],2);
        assert_eq!(snap["capsule"]["presence_signatures"].as_array().unwrap().len(),3);
        assert!(c.issue([4;32],1,20000).is_err());assert!(c.sample("down",0,0,20000,Origin::default()).is_err());
    }
    #[test] fn profile_caps_reserve_final_presence_and_never_truncate_input() {
        let (mut c,key)=new("x");approve(&mut c,&key);
        for i in 0..SAMPLES {c.sample(if i%2==0 {"down"}else{"up"},0,0,i as u64,Origin::default()).unwrap();}
        let before=c.info();assert!(c.sample("up",0,0,600,Origin::default()).is_err());assert_eq!(before,c.info());
        for i in 0..PRESENCE-1 {c.issue([i as u8+1;32],1,600+i as u64*2).unwrap();c.respond(2,601+i as u64*2).unwrap();}
        let before=c.info();assert!(c.issue([90;32],1,700).is_err());assert_eq!(before,c.info());
        seal(&mut c,&key,700,"x");let snap=c.snapshot().unwrap();
        assert_eq!(snap["private"]["origins"].as_array().unwrap().len(),SAMPLES);
        assert_eq!(snap["private"]["presence"].as_array().unwrap().len(),PRESENCE);
    }
}
