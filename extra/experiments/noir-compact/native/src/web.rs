//! The browser's recorder: the signed session log the Mac keeps (SessionLog, CaptureSigner) and its long-profile
//! capture, kept in step in one place, with the same hashes the prover checks (huma_replay_core). The page feeds it
//! text and key events and signs what it asks with the browser's own non-extractable key; it never holds a key.
//! Once sealed, `prove_input` gives the same proof inputs `capture-input long-worker-input` gives the Mac.
use crate::assurance::Origin;
use crate::assurance_capture::{LiveAssuranceCapture,LONG_PROFILE};
use crate::long;
use crate::commit;
use base64::{engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD},Engine};
use huma_replay_core::{hash,human::Presence,swift_array,Capture,CaptureTime,Checkpoint,Edit,Sample,Session,Witness};
use p256::ecdsa::{signature::Verifier,Signature,VerifyingKey};
use rand_core::{OsRng,RngCore};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};

/// The Mac's checkpoint cadence (CheckpointCadence.swift): after 256 new records, or 10 s after the last checkpoint.
const NEW_RECORDS:usize=256;
const INTERVAL:u64=10_000;
/// The most text one key press may add (HumaTextView.keyPressLimit); the page refuses more before it gets here.
pub const KEY_PRESS_LIMIT:usize=16;

/// Labels the proof counts as typing; the log keeps the exact label (ExperimentalCompactRecorder.provedSource).
pub fn proved_source(source:&str)->&str {
    if ["typing","typing-external","undo-redo","input-method","format-insert"].contains(&source) {"typing"} else {source}
}
fn digest(fields:&[String])->String {hash(&swift_array(fields))}
fn edit_digest(e:&Edit)->String {
    digest(&[e.sequence.to_string(),e.elapsed_milliseconds.to_string(),e.source.clone(),e.location.to_string(),
        e.removed_length.to_string(),e.inserted_text.clone(),e.previous_head.clone(),e.text_hash.clone()])
}
fn sample_digest(s:&Sample)->String {
    digest(&[s.kind.clone(),s.key_code.to_string(),s.modifiers.to_string(),s.elapsed_milliseconds.to_string()])
}
fn checkpoint_payload(c:&Checkpoint)->Vec<u8> {
    let mut fields=vec![format!("huma-signed-checkpoint-v{}",c.version),c.kind.clone(),c.session_id.clone(),c.sequence.to_string(),
        c.is_final.to_string(),c.capture_count.to_string(),c.edit_count.to_string(),c.sample_count.to_string(),c.capture_head.clone(),
        c.edit_head.clone(),c.text_hash.clone(),c.previous_checkpoint.clone(),c.challenge.clone(),c.public_key.clone()];
    if let Some(t)=&c.reported_time {fields.extend(["device-clock-v1".into(),t.unix_milliseconds.to_string(),t.elapsed_milliseconds.to_string()]);}
    swift_array(&fields)
}
/// A passkey check-in's WebAuthn challenge: SHA-256 of this domain and the approved response root's 32 bytes, the
/// root the capture signs next (presenceRoots[i]). The passkey sits outside the proof; readers check it beside it.
const PASSKEY_DOMAIN:&[u8]=b"HUMA_PASSKEY_PRESENCE_V1\0";
pub fn passkey_challenge(root:&[u8;32])->[u8;32] {let mut h=Sha256::new();h.update(PASSKEY_DOMAIN);h.update(root);h.finalize().into()}
/// What the writing key signs after each passkey answer, so a passkey's approvals can't be added to someone else's
/// page (its roots are public): this domain, the same root, and SHA-256 of the passkey's 65-byte public key.
const PASSKEY_BIND_DOMAIN:&[u8]=b"HUMA_PASSKEY_BIND_V1\0";
pub fn passkey_binding(root:&[u8;32],passkey:&[u8])->Vec<u8> {
    let mut out=PASSKEY_BIND_DOMAIN.to_vec();out.extend_from_slice(root);out.extend_from_slice(&Sha256::digest(passkey));out
}
/// Passkey check-ins: the relying party, the account's passkey (fixed by its first answer), its answers in order,
/// the highest signature counter seen, and whether a check-in went ahead without it.
struct Passkey {rp_hash:[u8;32],origin:String,key:Option<Vec<u8>>,assertions:Vec<Value>,challenges:Vec<[u8;32]>,count:u32,skipped:bool}
/// One WebAuthn assertion for `challenge` (webauthn.get, this origin and relying party, user present and verified,
/// by the session's passkey, its counter moving forward). Returns its counter.
fn check_assertion(p:&Passkey,challenge:&[u8;32],key:&[u8],auth:&[u8],client:&[u8],der:&[u8])->Result<u32,String> {
    if key.len()!=65 || key[0]!=4 || p.key.as_deref().is_some_and(|k|k!=key) {return Err("Not this recording's passkey".into());}
    let verifying=VerifyingKey::from_sec1_bytes(key).map_err(|_|"Invalid passkey")?;
    if auth.len()<37 || auth.len()>1024 || client.len()>4096 || der.len()>72 {return Err("Invalid passkey answer".into());}
    let data:Value=serde_json::from_slice(client).map_err(|_|"Invalid passkey answer")?;
    if !data.is_object() || data["type"]!="webauthn.get" || data["challenge"]!=URL_SAFE_NO_PAD.encode(challenge) || data["origin"]!=p.origin.as_str()
        || !matches!(data.get("crossOrigin"),None|Some(Value::Bool(false))) {return Err("The passkey answered something else".into());}
    if auth[..32]!=p.rp_hash || auth[32]&0x05!=0x05 {return Err("The passkey answered for another site or without verifying".into());}
    let count=u32::from_be_bytes([auth[33],auth[34],auth[35],auth[36]]);
    if count!=0 && count<=p.count {return Err("The passkey's counter went backwards".into());}
    let signature=Signature::from_der(der).map_err(|_|"Invalid passkey signature")?;
    let mut signed=auth.to_vec();signed.extend_from_slice(&Sha256::digest(client));
    verifying.verify(&signed,&signature).map_err(|_|"Passkey signature doesn't match")?;
    Ok(count)
}

/// What the recorder waits to have signed before anything else may happen.
enum Waiting {
    LogCheckpoint {checkpoint:Checkpoint},
    CaptureCheckpoint {is_final:bool},
    LogPresence {event:Presence},
    CapturePresence,
    /// An approval held until the passkey answers its challenge (or is skipped); nothing is recorded yet.
    Passkey {elapsed:u64,root:[u8;32]},
    /// A good passkey answer, held until the writing key signs its binding; then the approval goes on.
    PasskeyBind {elapsed:u64,root:[u8;32],key:Vec<u8>,assertion:Value,count:u32},
}
pub struct WebSession {
    w:Witness,capture:LiveAssuranceCapture,public_key:Vec<u8>,waiting:Option<Waiting>,sealed:bool,
    passkey:Option<Passkey>,
}
impl WebSession {
    /// A new session over `initial_text` (kept as "before", never counted as typed). Returns the first thing to sign.
    pub fn new(id:&str,public_key:Vec<u8>,unix:u64,initial_text:&str)->Result<(Self,Value),String> {
        Self::with_nonce(id,public_key,unix,initial_text,None)
    }
    /// As `new`, with the session's public nonce[0] set to `nonce` (16 bytes the server issued at Start, so it can
    /// later tell when this writing began) in place of one the page makes.
    pub fn with_nonce(id:&str,public_key:Vec<u8>,unix:u64,initial_text:&str,nonce:Option<[u8;16]>)->Result<(Self,Value),String> {
        if id.is_empty() || id.len()>128 || !id.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'-') {return Err("Invalid session id".into());}
        let capture=LiveAssuranceCapture::with_seed(initial_text,public_key.clone(),unix,LONG_PROFILE,nonce)?;
        let session=Session {id:id.into(),initial_text:initial_text.into(),events:vec![],input_samples:Some(vec![]),capture_records:Some(vec![]),
            signed_checkpoints:Some(vec![]),presence_protocol:Some("local-presence-v1".into()),presence_events:Some(vec![])};
        let mut web=Self {w:Witness {text:initial_text.into(),session},capture,public_key,waiting:None,sealed:false,passkey:None};
        let request=web.begin_checkpoint(unix,0,false)?;
        Ok((web,request))
    }
    /// Passkey check-ins for this recording: each approval first asks the passkey at `rp_id` (from `origin`).
    pub fn use_passkey(&mut self,rp_id:&str,origin:&str)->Result<(),String> {
        if self.passkey.is_some() || !self.presence_events().is_empty() {return Err("Passkey check-ins start with the recording".into());}
        if rp_id.is_empty() || rp_id.len()>253 || origin.is_empty() || origin.len()>512 {return Err("Invalid passkey site".into());}
        self.passkey=Some(Passkey {rp_hash:Sha256::digest(rp_id.as_bytes()).into(),origin:origin.into(),key:None,assertions:vec![],challenges:vec![],count:0,skipped:false});
        Ok(())
    }
    fn s(&self)->&Session {&self.w.session}
    fn records(&self)->&[Capture] {self.s().capture_records.as_deref().unwrap_or(&[])}
    fn initial_head(&self)->String {hash(format!("huma-session-v1:{}:{}",self.s().id,self.s().initial_text).as_bytes())}
    fn edit_head(&self)->String {self.s().events.last().map_or_else(||self.initial_head(),|e|e.head.clone())}
    fn capture_head(&self)->String {
        self.records().last().map_or_else(||hash(format!("huma-capture-v1:{}:{}",self.s().id,self.initial_head()).as_bytes()),|r|r.head.clone())
    }
    fn presence_events(&self)->&[Presence] {self.s().presence_events.as_deref().unwrap_or(&[])}
    fn challenge_open(&self)->bool {self.presence_events().last().is_some_and(|e|e.kind=="challenge")}
    pub fn latest_elapsed(&self)->u64 {
        let s=self.s();
        s.events.last().map_or(0,|e|e.elapsed_milliseconds)
            .max(s.input_samples.as_ref().and_then(|v|v.last()).map_or(0,|e|e.elapsed_milliseconds))
            .max(self.presence_events().last().map_or(0,|e|e.elapsed_milliseconds))
    }
    fn can_input(&self)->Result<(),String> {
        if self.sealed || self.waiting.is_some() || self.challenge_open() {return Err("Input is paused".into());}
        Ok(())
    }
    fn append_record(&mut self,kind:&str,index:usize,payload_hash:String) {
        let previous_head=self.capture_head();let sequence=self.records().len();
        let mut record=Capture {sequence,kind:kind.into(),index,payload_hash,previous_head,head:String::new()};
        record.head=digest(&[record.sequence.to_string(),record.kind.clone(),record.index.to_string(),record.payload_hash.clone(),record.previous_head.clone()]);
        self.w.session.capture_records.get_or_insert_with(Vec::new).push(record);
    }

    /// The page's text after an edit, and what made it. Unchanged text records nothing.
    pub fn edit(&mut self,after:&str,source:&str,elapsed:u64)->Result<Value,String> {
        self.can_input()?;
        if source.is_empty() || source.len()>64 || after.len()>65536 {return Err("Invalid edit".into());}
        if self.w.text.as_bytes()==after.as_bytes() {return Ok(json!({"recorded":false}));}
        // The Mac's diff (SessionLog.record): UTF-16 offsets, never splitting a surrogate pair.
        let a:Vec<u16>=self.w.text.encode_utf16().collect();let b:Vec<u16>=after.encode_utf16().collect();
        let mut prefix=0;while prefix<a.len().min(b.len()) && a[prefix]==b[prefix] {prefix+=1;}
        if prefix>0 && prefix<a.len() && (0xdc00..=0xdfff).contains(&a[prefix]) {prefix-=1;}
        let mut suffix=0;while suffix<a.len().min(b.len())-prefix && a[a.len()-1-suffix]==b[b.len()-1-suffix] {suffix+=1;}
        if suffix>0 && (0xdc00..=0xdfff).contains(&a[a.len()-suffix]) {suffix-=1;}
        let inserted=String::from_utf16(&b[prefix..b.len()-suffix]).map_err(|_|"Invalid edit text")?;
        let removed=a.len()-prefix-suffix;
        // The capture checks time and capacity first, so a refused edit leaves both records as they were.
        self.capture.edit(prefix,removed,&inserted,proved_source(source),elapsed)?;
        let mut event=Edit {sequence:self.s().events.len(),elapsed_milliseconds:elapsed,source:source.into(),location:prefix,removed_length:removed,
            inserted_text:inserted,previous_head:self.edit_head(),text_hash:hash(after.as_bytes()),head:String::new()};
        event.head=edit_digest(&event);
        let (index,head)=(event.sequence,event.head.clone());
        self.w.session.events.push(event);self.w.text=after.into();
        self.append_record("edit",index,head);
        Ok(json!({"recorded":true}))
    }
    /// A key going down or up, by its Mac key code (under 256) and Mac modifier flags.
    pub fn key(&mut self,kind:&str,code:u16,modifiers:u64,elapsed:u64)->Result<Value,String> {
        self.can_input()?;
        if !["down","up"].contains(&kind) {return Err("Invalid key".into());}
        self.capture.sample(kind,code,modifiers,elapsed,Origin::default())?;
        let sample=Sample {kind:kind.into(),key_code:code,modifiers,elapsed_milliseconds:elapsed,origin:None};
        let payload=sample_digest(&sample);
        let samples=self.w.session.input_samples.get_or_insert_with(Vec::new);samples.push(sample);let index=samples.len()-1;
        self.append_record("key",index,payload);
        Ok(json!({}))
    }
    /// A checkpoint when one is due (or `force`); returns what to sign, or nothing.
    pub fn checkpoint(&mut self,unix:u64,elapsed:u64,force:bool)->Result<Value,String> {
        self.can_input()?;
        let last=self.s().signed_checkpoints.as_ref().and_then(|c|c.last()).ok_or("Missing first checkpoint")?;
        let new=self.records().len()-last.capture_count;
        let since=elapsed.checked_sub(last.reported_time.as_ref().map_or(0,|t|t.elapsed_milliseconds)).ok_or("Time moved backwards")?;
        if new==0 || (!force && new<NEW_RECORDS && since<INTERVAL) {return Ok(json!({}));}
        self.begin_checkpoint(unix,elapsed,false)
    }
    fn begin_checkpoint(&mut self,unix:u64,elapsed:u64,is_final:bool)->Result<Value,String> {
        let s=self.s();let checkpoints=s.signed_checkpoints.as_deref().unwrap_or(&[]);
        let previous=checkpoints.last().map_or(String::new(),|c|{
            let mut signed=checkpoint_payload(c);signed.extend(STANDARD.decode(&c.signature).unwrap_or_default());hash(&signed)});
        let checkpoint=Checkpoint {version:2,kind:"unattested-p256".into(),is_final,session_id:s.id.clone(),sequence:checkpoints.len(),
            capture_count:self.records().len(),edit_count:s.events.len(),sample_count:s.input_samples.as_ref().map_or(0,Vec::len),
            capture_head:self.capture_head(),edit_head:self.edit_head(),text_hash:hash(self.w.text.as_bytes()),previous_checkpoint:previous,
            challenge:String::new(),public_key:STANDARD.encode(&self.public_key),signature:String::new(),
            reported_time:Some(CaptureTime {unix_milliseconds:unix,elapsed_milliseconds:elapsed})};
        let payload=checkpoint_payload(&checkpoint);
        self.waiting=Some(Waiting::LogCheckpoint {checkpoint});
        Ok(json!({"sign":STANDARD.encode(payload)}))
    }
    /// Starts a presence check ("interval" at random times, "seal" at Finish). Input pauses until it's answered.
    pub fn presence_issue(&mut self,reason:&str,elapsed:u64)->Result<Value,String> {
        self.can_input()?;
        let code=match reason {"interval"=>1,"seal"=>2,_=>return Err("Invalid presence reason".into())};
        let elapsed=elapsed.max(self.latest_elapsed());
        let mut nonce=[0u8;32];OsRng.try_fill_bytes(&mut nonce).map_err(|_|"Secure randomness unavailable")?;
        self.capture.issue(nonce,code,elapsed)?;
        let event=Presence {sequence:self.presence_events().len(),kind:"challenge".into(),nonce:hex::encode(nonce),reason:reason.into(),
            capture_head:self.capture_head(),issued_elapsed_milliseconds:elapsed,elapsed_milliseconds:elapsed,outcome:"pending".into(),signature:String::new()};
        self.append_presence(event);
        Ok(json!({"issued":elapsed}))
    }
    fn append_presence(&mut self,event:Presence) {
        let payload=event.digest(&self.s().id);let index=event.sequence;
        self.w.session.presence_events.get_or_insert_with(Vec::new).push(event);
        self.append_record("presence",index,payload);
    }
    /// The answer to the open check: "approved" asks for two signatures; a miss is recorded as it is. With passkey
    /// check-ins an approval first returns the passkey's challenge and changes nothing; a miss then cancels it.
    pub fn presence_respond(&mut self,outcome:&str,elapsed:u64)->Result<Value,String> {
        let cancels=matches!(self.waiting,Some(Waiting::Passkey {..})) && outcome!="approved";
        if self.sealed || (self.waiting.is_some() && !cancels) {return Err("Not waiting for an answer".into());}
        let (event,code)=self.response(outcome,elapsed)?;
        if code==1 {
            if self.passkey.as_ref().is_some_and(|p|!p.skipped) {
                let root=self.capture.preview_response_root(1,elapsed)?;
                self.waiting=Some(Waiting::Passkey {elapsed,root});
                return Ok(json!({"passkey":STANDARD.encode(passkey_challenge(&root))}));
            }
            return Ok(self.approve(event));
        }
        self.capture.respond(code,elapsed)?;self.waiting=None;self.append_presence(event);
        Ok(json!({}))
    }
    fn response(&self,outcome:&str,elapsed:u64)->Result<(Presence,u8),String> {
        let issue=self.presence_events().last().filter(|e|e.kind=="challenge").ok_or("No open presence check")?.clone();
        let code=match outcome {"approved"=>1,"cancelled"=>2,"timedOut"=>3,"interrupted"=>4,_=>return Err("Invalid presence outcome".into())};
        if elapsed<issue.elapsed_milliseconds {return Err("Time moved backwards".into());}
        Ok((Presence {sequence:issue.sequence+1,kind:"response".into(),nonce:issue.nonce,reason:issue.reason,capture_head:issue.capture_head,
            issued_elapsed_milliseconds:issue.elapsed_milliseconds,elapsed_milliseconds:elapsed,outcome:outcome.into(),signature:String::new()},code))
    }
    fn approve(&mut self,event:Presence)->Value {
        let payload=event.payload(&self.s().id);
        self.waiting=Some(Waiting::LogPresence {event});
        json!({"sign":STANDARD.encode(payload)})
    }
    fn passkey_wait(&self)->Result<(u64,[u8;32]),String> {
        match &self.waiting {Some(Waiting::Passkey {elapsed,root})=>Ok((*elapsed,*root)),_=>Err("No passkey check-in open".into())}
    }
    /// The passkey's WebAuthn assertion for the open challenge: on success the writing key signs its binding, then
    /// the approval goes on as without one (at the elapsed time it was given); otherwise nothing changes and the page
    /// may try again or skip.
    pub fn passkey_assertion(&mut self,public_key:Vec<u8>,auth:Vec<u8>,client:Vec<u8>,der:Vec<u8>)->Result<Value,String> {
        let (elapsed,root)=self.passkey_wait()?;
        let count=check_assertion(self.passkey.as_ref().ok_or("No passkey check-ins")?,&passkey_challenge(&root),&public_key,&auth,&client,&der)?;
        let assertion=json!({"authenticatorData":STANDARD.encode(&auth),"clientDataJSON":STANDARD.encode(&client),"signature":STANDARD.encode(&der)});
        let message=passkey_binding(&root,&public_key);
        self.waiting=Some(Waiting::PasskeyBind {elapsed,root,key:public_key,assertion,count});
        Ok(json!({"sign":STANDARD.encode(message)}))
    }
    /// Approves the open check without the passkey: this recording's page then carries no passkey check, so later
    /// check-ins don't ask for one.
    pub fn passkey_skip(&mut self)->Result<Value,String> {
        let (elapsed,_)=self.passkey_wait()?;
        let (event,_)=self.response("approved",elapsed)?;let request=self.approve(event);
        if let Some(p)=self.passkey.as_mut() {p.skipped=true;}
        Ok(request)
    }
    /// Finish, after an approved "seal" check: the final checkpoint. Returns what to sign.
    pub fn finish(&mut self,unix:u64,elapsed:u64)->Result<Value,String> {
        self.can_input()?;
        let seal=self.presence_events().last().is_some_and(|e|e.kind=="response" && e.reason=="seal" && e.outcome=="approved"
            && e.elapsed_milliseconds-e.issued_elapsed_milliseconds<=10_000);
        if !seal {return Err("Finish needs a confirmed check first".into());}
        self.begin_checkpoint(unix,elapsed.max(self.latest_elapsed()),true)
    }
    /// A DER signature for what the recorder asked to sign. Returns the next thing to sign, if any.
    pub fn signed(&mut self,der:Vec<u8>)->Result<Value,String> {
        let key=VerifyingKey::from_sec1_bytes(&self.public_key).map_err(|_|"Invalid key")?;
        let signature=Signature::from_der(&der).map_err(|_|"Invalid signature")?;
        match self.waiting.take().ok_or("Nothing to sign")? {
            Waiting::LogCheckpoint {mut checkpoint}=>{
                if key.verify(&checkpoint_payload(&checkpoint),&signature).is_err() {
                    self.waiting=Some(Waiting::LogCheckpoint {checkpoint});return Err("Signature doesn't match".into());
                }
                checkpoint.signature=STANDARD.encode(&der);
                let (is_final,time)=(checkpoint.is_final,checkpoint.reported_time.clone().ok_or("Missing time")?);
                self.w.session.signed_checkpoints.get_or_insert_with(Vec::new).push(checkpoint);
                // The capture prepared its first checkpoint itself; later ones follow the log's.
                if self.s().signed_checkpoints.as_ref().map_or(0,Vec::len)>1 {
                    self.capture.prepare(time.unix_milliseconds,time.elapsed_milliseconds,is_final,&self.w.text)?;
                }
                self.waiting=Some(Waiting::CaptureCheckpoint {is_final});
                Ok(json!({"sign":STANDARD.encode(self.capture.pending_message()?)}))
            },
            Waiting::CaptureCheckpoint {is_final}=>{
                if let Err(error)=self.capture.accept(der) {self.waiting=Some(Waiting::CaptureCheckpoint {is_final});return Err(error);}
                if is_final {
                    huma_replay_core::replay_bounded(&self.w,&huma_replay_core::LONG_BOUNDS).map_err(str::to_string)?;
                    self.sealed=true;
                }
                Ok(json!({"sealed":self.sealed}))
            },
            Waiting::LogPresence {mut event}=>{
                if key.verify(&event.payload(&self.s().id),&signature).is_err() {
                    self.waiting=Some(Waiting::LogPresence {event});return Err("Signature doesn't match".into());
                }
                event.signature=STANDARD.encode(&der);let elapsed=event.elapsed_milliseconds;
                self.capture.respond(1,elapsed)?;self.append_presence(event);
                self.waiting=Some(Waiting::CapturePresence);
                Ok(json!({"sign":STANDARD.encode(self.capture.pending_message()?)}))
            },
            Waiting::CapturePresence=>{
                if let Err(error)=self.capture.accept(der) {self.waiting=Some(Waiting::CapturePresence);return Err(error);}
                Ok(json!({}))
            },
            waiting@Waiting::Passkey {..}=>{self.waiting=Some(waiting);Err("Waiting for the passkey".into())},
            Waiting::PasskeyBind {elapsed,root,key:passkey,mut assertion,count}=>{
                let event=match self.response("approved",elapsed) {Ok((event,_))=>event,Err(error)=>{
                    self.waiting=Some(Waiting::PasskeyBind {elapsed,root,key:passkey,assertion,count});return Err(error);}};
                if der.len()>72 || key.verify(&passkey_binding(&root,&passkey),&signature).is_err() {
                    self.waiting=Some(Waiting::PasskeyBind {elapsed,root,key:passkey,assertion,count});return Err("Signature doesn't match".into());
                }
                assertion["binding"]=json!(STANDARD.encode(&der));
                if let Some(p)=self.passkey.as_mut() {
                    p.key=Some(passkey);p.assertions.push(assertion);p.challenges.push(passkey_challenge(&root));p.count=p.count.max(count);
                }
                Ok(self.approve(event))
            },
        }
    }
    /// Closes the open part when it holds at least `minimum` operations, so it can be proved now.
    pub fn cut(&mut self,minimum:usize)->Result<Value,String> {
        if self.sealed || self.waiting.is_some() || self.challenge_open() {return Ok(json!({"closed":false}));}
        let open=self.capture.info()["openOperations"].as_u64().unwrap_or(0) as usize;
        if open==0 || open<minimum {return Ok(json!({"closed":false}));}
        self.capture.long_cut()?;Ok(json!({"closed":true}))
    }
    /// Private proof input for one closed part, with its text tier. The input is an exact JSON string: its 64-bit
    /// integers would round in JavaScript's numbers.
    pub fn chunk(&mut self,index:usize)->Result<Value,String> {
        let mut value=self.capture.long_chunk(index)?;value["input"]=json!(value["input"].to_string());Ok(value)
    }
    pub fn info(&self)->Value {
        let c=self.capture.info();let s=self.s();
        json!({"sealed":self.sealed,"waiting":self.waiting.is_some(),"presencePending":self.challenge_open(),
            "edits":s.events.len(),"samples":s.input_samples.as_ref().map_or(0,Vec::len),"records":self.records().len(),
            "checkpoints":s.signed_checkpoints.as_ref().map_or(0,Vec::len),"closedChunks":c["closedChunks"],"openOperations":c["openOperations"],
            "operations":c["operations"],"latestElapsed":self.latest_elapsed(),"characters":self.w.text.chars().count(),
            "passkeyPending":self.passkey_wait().is_ok(),"passkeyAssertions":self.passkey.as_ref().map(|p|p.assertions.len())})
    }
    /// After Finish: the complete signed recording (what the Mac saves) and the proof inputs made from it.
    pub fn prove_input(&self)->Result<Value,String> {
        if !self.sealed {return Err("Finish first".into());}
        let sealed=self.capture.snapshot()?;
        let snapshot:long::Snapshot=serde_json::from_value(sealed.clone()).map_err(|_|"Invalid snapshot")?;
        let mut summary=long::worker_input(&self.w,&snapshot,false)?;
        // Every approved check-in answered by the passkey, in presenceRoots order, each bound to its root.
        if let Some(p)=self.passkey.as_ref().filter(|p|!p.skipped) {
            let roots=summary["presenceRoots"].as_array().cloned().unwrap_or_default();
            let bound=roots.len()==p.challenges.len() && roots.iter().zip(&p.challenges)
                .all(|(r,c)|r.as_str().and_then(|r|commit::parse(r).ok()).is_some_and(|r|passkey_challenge(&commit::bytes(r))==*c));
            if let (true,Some(key))=(bound,&p.key) {summary["passkey"]=json!({"publicKey":STANDARD.encode(key),"assertions":p.assertions});}
        }
        // `recording` is what the Mac's prover takes (NoirWritingProofService.longInput): the log and its capture, as
        // exact JSON text, since its 64-bit integers would round in JavaScript's numbers. The summary's are strings.
        let recording=serde_json::to_string(&json!({"witness":self.w,"snapshot":{"ok":true,"result":sealed}})).map_err(|_|"Invalid recording")?;
        Ok(json!({"summary":summary,"recording":recording}))
    }
}

/// A server-issued session nonce, as the page sends it: 32 lowercase hex characters, not all zero.
pub fn session_nonce(value:&str)->Result<[u8;16],String> {
    let bytes:[u8;16]=hex::decode(value).ok().filter(|_|value.len()==32 && !value.bytes().any(|b|b.is_ascii_uppercase()))
        .and_then(|b|b.try_into().ok()).ok_or("Invalid session nonce")?;
    if bytes.iter().all(|b|*b==0) {return Err("Invalid session nonce".into());}
    Ok(bytes)
}
#[cfg(test)] mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer,SigningKey};
    fn sign(web:&mut WebSession,key:&SigningKey,mut request:Value) {
        while let Some(message)=request["sign"].as_str().map(|m|STANDARD.decode(m).unwrap()) {
            let signature:Signature=key.sign(&message);request=web.signed(signature.to_der().as_bytes().to_vec()).unwrap();
        }
    }
    /// Types `text` the way a person does: key down, the character, key up, about 180 ms a key, with pauses.
    fn type_text(web:&mut WebSession,key:&SigningKey,text:&str,clock:&mut u64,source:&str) {
        for (i,c) in text.chars().enumerate() {
            *clock+=if i%23==22 {900} else {150+(i as u64*37)%90};
            web.key("down",(c as u32 % 50) as u16,0,*clock).unwrap();
            let after=format!("{}{}",web.w.text,c);web.edit(&after,source,*clock+5).unwrap();
            web.key("up",(c as u32 % 50) as u16,0,*clock+60).unwrap();*clock+=60;
            let request=web.checkpoint(1_792_627_200_000+*clock,*clock,false).unwrap();sign(web,key,request);
            if i%40==39 {web.cut(450).unwrap();}
        }
    }
    fn start(source:&str,text:&str,site:Option<(&str,&str)>)->(WebSession,SigningKey,u64) {start_seeded(source,text,site,None)}
    fn start_seeded(source:&str,text:&str,site:Option<(&str,&str)>,nonce:Option<[u8;16]>)->(WebSession,SigningKey,u64) {
        let key=SigningKey::random(&mut OsRng);let public=key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let (mut web,request)=WebSession::with_nonce("web-test-session",public,1_792_627_200_000,"",nonce).unwrap();
        if let Some((rp,origin))=site {web.use_passkey(rp,origin).unwrap();}
        sign(&mut web,&key,request);
        let mut clock=0;type_text(&mut web,&key,text,&mut clock,source);
        (web,key,clock)
    }
    fn session(source:&str,text:&str)->(WebSession,SigningKey,u64) {session_with(source,text,None,&mut |_,r|r)}
    /// `answer` gets each approval's reply and returns what to sign (a passkey answers first in passkey mode).
    fn session_with(source:&str,text:&str,site:Option<(&str,&str)>,answer:&mut dyn FnMut(&mut WebSession,Value)->Value)->(WebSession,SigningKey,u64) {
        session_seeded(source,text,site,answer,None)
    }
    fn session_seeded(source:&str,text:&str,site:Option<(&str,&str)>,answer:&mut dyn FnMut(&mut WebSession,Value)->Value,
        nonce:Option<[u8;16]>)->(WebSession,SigningKey,u64) {
        let (mut web,key,mut clock)=start_seeded(source,text,site,nonce);
        // A check-in in the middle, answered in 2 s, then the seal at Finish.
        web.presence_issue("interval",clock+500).unwrap();
        let request=web.presence_respond("approved",clock+2500).unwrap();let request=answer(&mut web,request);sign(&mut web,&key,request);clock+=3000;
        type_text(&mut web,&key," and more.",&mut clock,source);
        web.cut(1).unwrap();web.presence_issue("seal",clock+300).unwrap();
        let request=web.presence_respond("approved",clock+1300).unwrap();let request=answer(&mut web,request);sign(&mut web,&key,request);
        let request=web.finish(1_792_627_200_000+clock+1400,clock+1400).unwrap();sign(&mut web,&key,request);
        (web,key,clock)
    }
    const RP:&str="huma.social";const ORIGIN:&str="https://huma.social";
    const SITE:Option<(&str,&str)>=Some((RP,ORIGIN));
    /// A software authenticator's assertion: [public key, authenticatorData, clientDataJSON, DER signature].
    fn assertion_of(key:&SigningKey,client:Value,rp:&str,flags:u8,count:u32)->[Vec<u8>;4] {
        let mut auth=Sha256::digest(rp.as_bytes()).to_vec();auth.push(flags);auth.extend(count.to_be_bytes());
        let client=serde_json::to_vec(&client).unwrap();
        let mut signed=auth.clone();signed.extend(Sha256::digest(&client));let signature:Signature=key.sign(&signed);
        [key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),auth,client,signature.to_der().as_bytes().to_vec()]
    }
    fn client(kind:&str,challenge:&[u8],origin:&str)->Value {
        json!({"type":kind,"challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":origin,"crossOrigin":false})
    }
    fn assertion(key:&SigningKey,challenge:&[u8],count:u32)->[Vec<u8>;4] {assertion_of(key,client("webauthn.get",challenge,ORIGIN),RP,0x05,count)}
    fn challenge(request:&Value)->Vec<u8> {STANDARD.decode(request["passkey"].as_str().expect("a passkey challenge")).unwrap()}
    fn answer(web:&mut WebSession,[k,d,c,s]:[Vec<u8>;4])->Result<Value,String> {web.passkey_assertion(k,d,c,s)}
    fn passkey_answers(passkey:&SigningKey)->impl FnMut(&mut WebSession,Value)->Value+'_ {
        let mut count=0;move |web,request|{count+=1;let c=challenge(&request);answer(web,assertion(passkey,&c,count)).unwrap()}
    }
    fn root_challenge(root:&Value)->Vec<u8> {passkey_challenge(&commit::bytes(commit::parse(root.as_str().unwrap()).unwrap())).to_vec()}
    #[test] fn a_browser_session_gives_the_same_proof_inputs_the_mac_check_accepts() {
        let text="The browser records the same signed log as the Mac does, ".repeat(3);
        let (web,_,_)=session("typing",&text);
        assert!(web.sealed);
        let input=web.prove_input().unwrap();let summary=&input["summary"];
        assert_eq!(summary["format"],"v3");assert_eq!(summary["tier"],1024);
        assert!(summary["chunks"].as_array().unwrap().len()>=2);
        // What the Mac's prover is handed: the same check passes from the serialized recording.
        let app:long::AppInput=serde_json::from_str(input["recording"].as_str().unwrap()).unwrap();
        assert_eq!(long::worker_input(&app.witness,&app.snapshot.result,false).unwrap(),*summary);
    }
    #[test] fn a_server_session_nonce_becomes_the_public_nonce_and_stays_bound_to_the_key() {
        let seed:[u8;16]=hex::decode("0123456789abcdef00112233445566ff").unwrap().try_into().unwrap();
        let text="Started with the nonce the server handed out. ".repeat(2);
        let (web,_,_)=session_seeded("typing",&text,None,&mut |_,r|r,Some(seed));
        let summary=&web.prove_input().unwrap()["summary"];let nonce=&summary["final"]["nonce"];
        // What a reader decodes as the page's public nonce[0] (decodeFinal) is the server's 16 bytes as a number.
        assert_eq!(nonce[0],json!(u128::from_be_bytes(seed).to_string()));
        assert_eq!(long::bound_nonce(commit::parse(nonce[0].as_str().unwrap()).unwrap(),&web.public_key).unwrap().map(|x|x.to_string()),
            [nonce[0].as_str().unwrap(),nonce[1].as_str().unwrap()].map(String::from));
        // Without one, each session makes its own 128-bit nonce, as before.
        let (a,_,_)=session("typing",&text);let (b,_,_)=session("typing",&text);
        let first=|w:&WebSession|w.prove_input().unwrap()["summary"]["final"]["nonce"][0].as_str().unwrap().parse::<u128>().unwrap();
        assert_ne!(first(&a),first(&b));assert_ne!(first(&a),u128::from_be_bytes(seed));
    }
    #[test] fn refuses_a_malformed_or_zero_session_nonce() {
        assert_eq!(session_nonce("0123456789abcdef00112233445566ff").unwrap()[15],0xff);
        for bad in ["","00000000000000000000000000000000","0123456789ABCDEF00112233445566FF","0123456789abcdef00112233445566","0123456789abcdef00112233445566ffaa","zz23456789abcdef00112233445566ff"] {
            assert!(session_nonce(bad).is_err(),"{bad}");
        }
        let key=SigningKey::random(&mut OsRng);let public=key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert!(WebSession::with_nonce("web-test-zero",public.clone(),1_000,"",Some([0;16])).is_err());
        assert!(LiveAssuranceCapture::with_seed("",public,1_000,crate::assurance_capture::PROFILE,Some([1;16])).is_err());
    }
    #[test] fn labels_the_proof_counts_as_typing_pass_the_finish_check() {
        for source in ["typing-external","undo-redo","input-method"] {
            let (web,_,_)=session(source,&"Typed with a label the proof counts as typing. ".repeat(2));
            web.prove_input().unwrap_or_else(|e|panic!("{source}: {e}"));
        }
    }
    #[test] fn refuses_input_while_a_check_or_a_signature_is_open() {
        let key=SigningKey::random(&mut OsRng);let public=key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let (mut web,request)=WebSession::new("web-test-2",public,1_000,"").unwrap();
        assert!(web.edit("a","typing",10).is_err()); // the first checkpoint isn't signed yet
        sign(&mut web,&key,request);
        web.key("down",0,0,100).unwrap();web.edit("a","typing",105).unwrap();web.key("up",0,0,160).unwrap();
        web.presence_issue("interval",200).unwrap();
        assert!(web.edit("ab","typing",300).is_err());assert!(web.key("down",1,0,300).is_err());
        assert!(web.finish(2_000,400).is_err());
        let request=web.presence_respond("approved",900).unwrap();
        assert!(web.edit("ab","typing",950).is_err()); // still signing
        sign(&mut web,&key,request);
        web.edit("ab","typing",1000).unwrap();
        assert!(web.signed(vec![0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01]).is_err());
        assert_eq!(web.info()["edits"],2);
    }
    #[test] fn a_passkey_challenge_binds_the_root_the_capture_then_signs() {
        let (mut web,key,clock)=start("typing","Typed before a passkey check-in. ",SITE);let passkey=SigningKey::random(&mut OsRng);
        web.presence_issue("interval",clock+500).unwrap();
        let (before,capture)=(web.info(),web.capture.info());
        let request=web.presence_respond("approved",clock+2500).unwrap();
        // Nothing is recorded until the passkey answers.
        assert_eq!(web.capture.info(),capture);assert_eq!(web.info()["records"],before["records"]);
        assert_eq!(web.s().presence_events.as_ref().unwrap().len(),1);assert_eq!(web.info()["passkeyPending"],true);
        let challenge=challenge(&request);
        let request=answer(&mut web,assertion(&passkey,&challenge,0)).unwrap();assert_eq!(web.info()["passkeyPending"],false);
        // The writing key binds the passkey to this root first; a signature by any other key changes nothing.
        let binding=STANDARD.decode(request["sign"].as_str().unwrap()).unwrap();let before=web.info();
        let wrong:Signature=SigningKey::random(&mut OsRng).sign(&binding);
        assert!(web.signed(wrong.to_der().as_bytes().to_vec()).is_err());assert_eq!(web.info(),before);assert_eq!(web.capture.info(),capture);
        let wrong:Signature=key.sign(b"something else");
        assert!(web.signed(wrong.to_der().as_bytes().to_vec()).is_err());assert_eq!(web.info(),before);
        let signature:Signature=key.sign(&binding);let request=web.signed(signature.to_der().as_bytes().to_vec()).unwrap();
        let log:Signature=key.sign(&STANDARD.decode(request["sign"].as_str().unwrap()).unwrap());
        let request=web.signed(log.to_der().as_bytes().to_vec()).unwrap();
        // The capture's request: its presence domain, then the very root the challenge and the binding were made from.
        let message=STANDARD.decode(request["sign"].as_str().unwrap()).unwrap();let (domain,root)=message.split_at(long::PRESENCE_DOMAIN.len());
        assert_eq!(domain,long::PRESENCE_DOMAIN);assert_eq!(passkey_challenge(root.try_into().unwrap()).to_vec(),challenge);
        assert_eq!(binding,passkey_binding(root.try_into().unwrap(),passkey.verifying_key().to_encoded_point(false).as_bytes()));
        assert_eq!(web.s().presence_events.as_ref().unwrap()[1].elapsed_milliseconds,clock+2500);
        sign(&mut web,&key,request);assert_eq!(web.info()["passkeyAssertions"],1);
    }
    #[test] fn passkey_check_ins_reach_the_summary_in_presence_root_order() {
        let passkey=SigningKey::random(&mut OsRng);
        let (web,key,_)=session_with("typing",&"Every check-in here is also a passkey check. ".repeat(2),SITE,&mut passkey_answers(&passkey));
        let input=web.prove_input().unwrap();let summary=&input["summary"];let roots=summary["presenceRoots"].as_array().unwrap();
        let p=&summary["passkey"];let assertions=p["assertions"].as_array().unwrap();
        assert_eq!(roots.len(),2);assert_eq!(assertions.len(),2);
        assert_eq!(p["publicKey"],STANDARD.encode(passkey.verifying_key().to_encoded_point(false).as_bytes()));
        for (root,a) in roots.iter().zip(assertions) {
            let client:Value=serde_json::from_slice(&STANDARD.decode(a["clientDataJSON"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(client["challenge"].as_str().unwrap()).unwrap(),root_challenge(root));
            let mut signed=STANDARD.decode(a["authenticatorData"].as_str().unwrap()).unwrap();
            signed.extend(Sha256::digest(STANDARD.decode(a["clientDataJSON"].as_str().unwrap()).unwrap()));
            let signature=Signature::from_der(&STANDARD.decode(a["signature"].as_str().unwrap()).unwrap()).unwrap();
            passkey.verifying_key().verify(&signed,&signature).unwrap();
            // Bound to this page's writing key (publicKeyHex) over the same root and this passkey.
            let mut keys:Vec<_>=a.as_object().unwrap().keys().cloned().collect();keys.sort();
            assert_eq!(keys,["authenticatorData","binding","clientDataJSON","signature"]);
            assert_eq!(summary["publicKeyHex"],hex::encode(key.verifying_key().to_encoded_point(false).as_bytes()));
            let message=passkey_binding(&commit::bytes(commit::parse(root.as_str().unwrap()).unwrap()),passkey.verifying_key().to_encoded_point(false).as_bytes());
            let binding=Signature::from_der(&STANDARD.decode(a["binding"].as_str().unwrap()).unwrap()).unwrap();
            key.verifying_key().verify(&message,&binding).unwrap();
        }
        // The recording the Mac's prover takes is unchanged; only the summary carries the passkey.
        let app:long::AppInput=serde_json::from_str(input["recording"].as_str().unwrap()).unwrap();
        let mut plain=summary.clone();plain.as_object_mut().unwrap().remove("passkey");
        assert_eq!(long::worker_input(&app.witness,&app.snapshot.result,false).unwrap(),plain);
    }
    #[test] fn wrong_passkey_answers_change_nothing() {
        let (mut web,key,mut clock)=start("typing","Typed before a passkey check-in. ",SITE);
        let (passkey,other)=(SigningKey::random(&mut OsRng),SigningKey::random(&mut OsRng));
        web.presence_issue("interval",clock+500).unwrap();
        let c=challenge(&web.presence_respond("approved",clock+2500).unwrap());let before=web.info();
        let mut wrong=c.clone();wrong[0]^=1;
        let mut forged=assertion(&passkey,&c,1);forged[3]=assertion(&passkey,&wrong,1)[3].clone();
        let mut cross=client("webauthn.get",&c,ORIGIN);cross["crossOrigin"]=json!(true);
        for bad in [assertion(&passkey,&wrong,1),assertion_of(&passkey,client("webauthn.get",&c,ORIGIN),RP,0x01,1),
            assertion_of(&passkey,client("webauthn.get",&c,ORIGIN),RP,0x04,1),assertion_of(&passkey,client("webauthn.get",&c,ORIGIN),"evil.social",0x05,1),
            assertion_of(&passkey,client("webauthn.get",&c,"https://evil.social"),RP,0x05,1),assertion_of(&passkey,client("webauthn.create",&c,ORIGIN),RP,0x05,1),
            assertion_of(&passkey,cross,RP,0x05,1),forged] {
            assert!(answer(&mut web,bad).is_err());assert_eq!(web.info(),before);
        }
        // Nothing else moves while the passkey is awaited.
        assert!(web.presence_respond("approved",clock+2600).is_err());assert!(web.signed(vec![0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01]).is_err());
        assert!(web.edit("x","typing",clock+2600).is_err());assert_eq!(web.info(),before);
        let request=answer(&mut web,assertion(&passkey,&c,5)).unwrap();sign(&mut web,&key,request);clock+=3000;
        // A second check-in: another passkey, or a counter that didn't move, is refused; the same passkey goes on.
        web.presence_issue("interval",clock).unwrap();let c=challenge(&web.presence_respond("approved",clock+1000).unwrap());let before=web.info();
        for bad in [assertion(&other,&c,6),assertion(&passkey,&c,5)] {assert!(answer(&mut web,bad).is_err());assert_eq!(web.info(),before);}
        let request=answer(&mut web,assertion(&passkey,&c,6)).unwrap();sign(&mut web,&key,request);
        assert_eq!(web.info()["passkeyAssertions"],2);
    }
    #[test] fn a_skipped_passkey_leaves_a_plain_page() {
        let mut first=true;
        let (web,_,_)=session_with("typing",&"A passkey check-in skipped once. ".repeat(2),SITE,&mut |web,request|{
            if std::mem::take(&mut first) {challenge(&request);web.passkey_skip().unwrap()}
            else {assert!(request.get("passkey").is_none());request} // later check-ins no longer ask
        });
        let summary=&web.prove_input().unwrap()["summary"];
        assert!(summary.get("passkey").is_none());assert_eq!(summary["presenceRoots"].as_array().unwrap().len(),2);
    }
    #[test] fn a_check_in_cancelled_at_the_passkey_is_recorded_and_the_next_goes_on() {
        let passkey=SigningKey::random(&mut OsRng);let mut first=true;let mut count=0;
        let (web,_,_)=session_with("typing",&"A check-in cancelled while the passkey asks. ".repeat(2),SITE,&mut |web,request|{
            let c=challenge(&request);
            if std::mem::take(&mut first) {
                // The person closes the passkey prompt: the check is a miss, then another check-in follows.
                let at=web.latest_elapsed();assert_eq!(web.presence_respond("cancelled",at+100).unwrap(),json!({}));
                assert!(web.passkey_skip().is_err() && !web.info()["passkeyPending"].as_bool().unwrap());
                web.presence_issue("interval",at+200).unwrap();
                let c=challenge(&web.presence_respond("approved",at+1200).unwrap());count+=1;return answer(web,assertion(&passkey,&c,count)).unwrap();
            }
            count+=1;answer(web,assertion(&passkey,&c,count)).unwrap()
        });
        let outcomes:Vec<_>=web.presence_events().iter().filter(|e|e.kind=="response").map(|e|e.outcome.clone()).collect();
        assert_eq!(outcomes,["cancelled","approved","approved"]);
        let summary=&web.prove_input().unwrap()["summary"];let roots=summary["presenceRoots"].as_array().unwrap();
        assert_eq!(roots.len(),2);assert_eq!(summary["passkey"]["assertions"].as_array().unwrap().len(),2);
    }
}

/// WebAssembly entry points for the page, without wasm-bindgen. The page copies a JSON command into memory from
/// `huma_alloc` and calls `huma_web`; the reply it points to is a little-endian u32 length (top bit set on failure)
/// then JSON, which the page frees with `huma_free`. One recording per page. Randomness comes from the page's
/// `crypto.getRandomValues` through the imported `env.huma_random`.
#[cfg(target_arch="wasm32")]
mod wasm {
    use super::WebSession;
    use base64::{engine::general_purpose::STANDARD,Engine};
    use serde::Deserialize;
    use serde_json::{json,Value};
    use std::cell::RefCell;
    extern "C" {fn huma_random(pointer:*mut u8,len:usize);}
    fn fill(dest:&mut [u8])->Result<(),getrandom::Error> {unsafe {huma_random(dest.as_mut_ptr(),dest.len())};Ok(())}
    getrandom::register_custom_getrandom!(fill);
    thread_local! {static SESSION:RefCell<Option<WebSession>>=const {RefCell::new(None)};}

    #[derive(Deserialize)]
    #[serde(tag="command",rename_all="snake_case",deny_unknown_fields)]
    enum Command {
        Start {id:String,public_key:String,unix:u64,initial_text:String,#[serde(default)] passkey:Option<PasskeySite>,
            #[serde(default)] nonce:Option<String>},
        Edit {text:String,source:String,elapsed:u64},
        Key {kind:String,code:u16,modifiers:u64,elapsed:u64},
        Checkpoint {unix:u64,elapsed:u64,force:bool},
        PresenceIssue {reason:String,elapsed:u64},
        PresenceRespond {outcome:String,elapsed:u64},
        Finish {unix:u64,elapsed:u64},
        Signed {signature:String},
        Cut {minimum:usize},
        Chunk {index:usize},
        Info {},
        ProveInput {},
        PasskeyAssertion {public_key:String,authenticator_data:String,client_data_json:String,signature:String},
        PasskeySkip {},
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PasskeySite {rp_id:String,origin:String}
    fn bytes(value:&str)->Result<Vec<u8>,String> {STANDARD.decode(value).map_err(|_|"Invalid passkey answer".into())}
    fn run(command:Command)->Result<Value,String> {
        if let Command::Start {id,public_key,unix,initial_text,passkey,nonce}=command {
            let key=STANDARD.decode(public_key).map_err(|_|"Invalid key")?;
            // The server's session nonce: 32 lowercase hex characters.
            let nonce=nonce.map(|n|super::session_nonce(&n)).transpose()?;
            let (mut session,request)=WebSession::with_nonce(&id,key,unix,&initial_text,nonce)?;
            if let Some(site)=passkey {session.use_passkey(&site.rp_id,&site.origin)?;}
            SESSION.with(|s|*s.borrow_mut()=Some(session));
            return Ok(request);
        }
        SESSION.with(|s|{
            let mut slot=s.borrow_mut();let web=slot.as_mut().ok_or("No recording")?;
            match command {
                Command::Start {..}=>unreachable!(),
                Command::Edit {text,source,elapsed}=>web.edit(&text,&source,elapsed),
                Command::Key {kind,code,modifiers,elapsed}=>web.key(&kind,code,modifiers,elapsed),
                Command::Checkpoint {unix,elapsed,force}=>web.checkpoint(unix,elapsed,force),
                Command::PresenceIssue {reason,elapsed}=>web.presence_issue(&reason,elapsed),
                Command::PresenceRespond {outcome,elapsed}=>web.presence_respond(&outcome,elapsed),
                Command::Finish {unix,elapsed}=>web.finish(unix,elapsed),
                Command::Signed {signature}=>web.signed(STANDARD.decode(signature).map_err(|_|"Invalid signature")?),
                Command::Cut {minimum}=>web.cut(minimum),
                Command::Chunk {index}=>web.chunk(index),
                Command::Info {}=>Ok(web.info()),
                Command::ProveInput {}=>web.prove_input(),
                Command::PasskeyAssertion {public_key,authenticator_data,client_data_json,signature}=>
                    web.passkey_assertion(bytes(&public_key)?,bytes(&authenticator_data)?,bytes(&client_data_json)?,bytes(&signature)?),
                Command::PasskeySkip {}=>web.passkey_skip(),
            }
        })
    }
    fn leak(bytes:Vec<u8>)->*mut u8 {Box::into_raw(bytes.into_boxed_slice()) as *mut u8}
    #[no_mangle]
    pub extern "C" fn huma_alloc(len:usize)->*mut u8 {leak(vec![0;len.max(1)])}
    /// # Safety
    /// `pointer` came from `huma_alloc(len)` or is a reply `len` bytes long, and isn't used afterwards.
    #[no_mangle]
    pub unsafe extern "C" fn huma_free(pointer:*mut u8,len:usize) {drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer,len.max(1))));}
    /// # Safety
    /// `pointer` holds `len` bytes from `huma_alloc`, which the caller frees afterwards.
    #[no_mangle]
    pub unsafe extern "C" fn huma_web(pointer:*const u8,len:usize)->*mut u8 {
        let result=serde_json::from_slice::<Command>(std::slice::from_raw_parts(pointer,len)).map_err(|_|"Invalid command".to_string()).and_then(run);
        let (flag,body)=match result {Ok(value)=>(0,serde_json::to_vec(&value).unwrap()),Err(error)=>(1u32<<31,serde_json::to_vec(&json!(error)).unwrap())};
        let mut reply=Vec::with_capacity(4+body.len());
        reply.extend_from_slice(&(body.len() as u32|flag).to_le_bytes());reply.extend_from_slice(&body);
        leak(reply)
    }
}
