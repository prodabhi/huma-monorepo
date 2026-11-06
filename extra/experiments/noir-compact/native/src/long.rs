//! Long sessions (the assurance-long-v1 capture), proved as parts plus one final proof. This is the native
//! mirror of the circuits: `integrations/noir/long3` (v3, current: independent parts at the session's text
//! tier) and `integrations/noir/long` (v2, 0.1 pages: folded parts at capacity 10000, read only).
//! The same carried state, roots, event rules and deterministic part plan.
//! Signed checkpoint/presence roots use the V4 formulas with long-profile domains;
//! the final checkpoint binds Poseidon text commitments instead of SHA-256.
use crate::{assurance::{Origin,Presence,Private},commit,ops,protocol};
use ark_bn254::Fr;
use p256::ecdsa::{signature::Verifier,Signature,VerifyingKey};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};

pub const PROFILE:&str="assurance-long-v1";
pub const KIND:&str="huma-long-assurance-v1";
pub const CAPACITY:usize=10000;
pub const OPERATIONS:usize=1<<20;
/// The most operations any format puts in one part (v2); see Format::chunk_ops.
pub const CHUNK_OPS:usize=528;
pub const SLOTS:usize=8;
pub const PRESENCE:usize=64;
pub const CHECKPOINTS:usize=65536;
pub const SAMPLES:usize=1<<19;
pub const CP_DOMAIN:&[u8]=b"HUMA_LONG_ASSURANCE_CHECKPOINT_V1\0";
pub const PRESENCE_DOMAIN:&[u8]=b"HUMA_LONG_ASSURANCE_PRESENCE_V1\0";
const MAX_UNIX:u64=253402300799999;
const DEVICE:u64=0x48554d410801;
const NONCE:u64=0x48554d410802;
const REPLAY_ROOT:u64=0x48554d410601;
const INTERACTION_ROOT:u64=0x48554d410603;
const TEXT:u64=0x48554d410604;
const STATE_ROOT:u64=0x48554d410702;
const DIGEST:u64=0x48554d410703;
const EVENTS_ROOT:u64=0x48554d410704;
const ORIGIN_SEED:u64=0x48554d410401;
const ORIGIN_BLOCK:u64=0x48554d410402;
const ORIGIN_PREFIX:u64=0x48554d410403;
const PRESENCE_SEED:u64=0x48554d410404;
const ISSUE:u64=0x48554d410405;
const RESPONSE:u64=0x48554d410406;
const PRESENCE_PREFIX:u64=0x48554d410407;
const BOUND:u64=0x48554d410408;
const CAPTURE:u64=0x48554d410409;
const CAPTURE_SEED:u64=0x48554d410301;
const CAPTURE_BLOCK:u64=0x48554d410302;
const CAPTURE_PREFIX:u64=0x48554d410303;
fn need(ok:bool,message:&str)->Result<(),String> {if ok {Ok(())}else{Err(message.into())}}
fn f(value:u64)->Fr {Fr::from(value)}

/// How a long session is proved. The capture is the same for both; only the proof differs.
/// V2 (0.1): parts folded into one proof, capacity 10000, 528 operations a part, signatures in-circuit.
/// V3: independent parts at the session's text tier, 600 operations a part (about half the proving work of 160-operation
/// parts, and a quarter of the proofs; 600 keeps every tier's part circuit within 2^19 or 2^20 gates), signatures checked by the reader.
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="lowercase")]
pub enum Format {V2,V3}
impl Format {
    pub fn chunk_ops(self)->usize {match self {Format::V2=>CHUNK_OPS,Format::V3=>600}}
    /// Signed events the final step applies; the planner moves earlier ones into a part with no operations.
    fn tail_slots(self)->usize {match self {Format::V2=>4,Format::V3=>SLOTS}}
}
/// The most text the session ever held, in scalars: its v3 tier must hold all of it.
pub fn peak(words:&[u64])->Result<usize,String> {
    let mut r=Replay::new([f(0);2],[f(0);2],CAPACITY);let mut most=0;
    for w in words {r.step(*w)?;most=most.max((r.left+CAPACITY as u32-r.right) as usize);}
    Ok(most)
}
/// The v3 tier for a session: the smallest that holds its peak text.
pub fn session_tier(words:&[u64])->Result<usize,String> {
    let most=peak(words)?;TIERS.into_iter().find(|t|most<=*t).ok_or("Text exceeds the long-session capacity".into())
}
/// A v3 session nonce: a random 128-bit seed, then 128 bits of a commitment to the seed and the capture key, so a
/// proof made for one key can't be shown with another key's signatures (readers check nonce[1]).
pub fn bound_nonce(seed:Fr,public_key:&[u8])->Result<[Fr;2],String> {
    need(commit::bytes(seed)[..16].iter().all(|b|*b==0) && seed!=f(0),"Invalid session nonce seed")?;
    Ok([seed,commit::halves(&commit::bytes(commit::hash(&[f(NONCE),device_root(public_key)?,seed])))[1]])
}

/// Final-step text tiers; the smallest that holds the sealed text is used.
pub const TIERS:[usize;3]=[1024,4096,CAPACITY];
pub fn tier(text:&str)->Result<usize,String> {
    let count=text.chars().count();TIERS.into_iter().find(|t|count<=*t).ok_or("Text exceeds the long-session capacity".into())
}
/// Canonical Poseidon commitment to a text, matched by the final circuit and the reader.
/// scope 0 is the raw master; scope 1 the canonical text without final ASCII space/tab.
pub fn text_commitment(text:&str,scope:u8,capacity:usize)->Result<Fr,String> {
    let scalars:Vec<u32>=text.chars().map(|c|c as u32).collect();
    need(scalars.len()<=capacity && TIERS.contains(&capacity),"Text exceeds the long-session capacity")?;
    let mut fields=vec![f(TEXT),f(capacity as u64),f(scope as u64),f(scalars.len() as u64),f(text.len() as u64)];
    for block in 0..capacity.div_ceil(12) {
        let (mut packed,mut scale)=(f(0),f(1));
        for i in 0..12 {packed+=f(*scalars.get(block*12+i).unwrap_or(&0) as u64)*scale;scale*=f(1<<21);}
        fields.push(packed);
    }
    Ok(commit::hash(&fields))
}
/// [canonical, raw] at the text's tier, the order bound by the final signed checkpoint (v2).
pub fn text_binding(text:&str)->Result<[Fr;2],String> {text_binding_at(text,tier(text)?)}
/// [canonical, raw] at a given tier: v3 binds the text at the session's tier, which can exceed the text's own.
pub fn text_binding_at(text:&str,capacity:usize)->Result<[Fr;2],String> {
    let canonical=protocol::canonical(text);need(!canonical.is_empty(),"Empty verification text")?;
    Ok([text_commitment(canonical,1,capacity)?,text_commitment(text,0,capacity)?])
}
pub fn message(domain:&[u8],root:Fr)->Vec<u8> {let mut out=domain.to_vec();out.extend_from_slice(&commit::bytes(root));out}

fn pack62(words:&[u64])->[Fr;3] {
    let mut result=[f(0);3];
    for (i,w) in words.iter().enumerate() {let mut scale=f(1);for _ in 0..i%4 {scale*=f(1<<62);}result[i/4]+=f(*w)*scale;}
    result
}
fn pack98(values:&[Fr])->[Fr;3] {
    let mut p=[f(0);3];
    for (i,v) in values.iter().enumerate() {p[i/2]+=*v*if i%2==0 {f(1)}else{Fr::from(1u128<<98)};}p
}

#[derive(Clone,Debug,PartialEq)]
pub struct Replay {
    pub buffer:Vec<u32>,pub left:u32,pub right:u32,pub cursor:u32,pub total:u32,pub target:u32,pub remaining:u32,
    pub phase:u8,pub elapsed:u64,pub edits:u32,pub samples:u32,pub typing:u32,pub paste:u32,pub source:u8,
    pub initial_bytes:u32,pub baseline_end:u32,pub offset:u32,pub head:Fr,pub tail:[u64;12],
}
impl Replay {
    fn new(nonce:[Fr;2],salt:[Fr;2],capacity:usize)->Self {
        Self {buffer:vec![0;capacity],left:0,right:capacity as u32,cursor:0,total:0,target:0,remaining:0,phase:0,elapsed:0,
            edits:0,samples:0,typing:0,paste:0,source:0,initial_bytes:0,baseline_end:0,offset:0,
            head:commit::hash(&[f(CAPTURE_SEED),nonce[0],nonce[1],salt[0],salt[1]]),tail:[0;12]}
    }
    fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        let mut values=vec![f(REPLAY_ROOT),nonce[0],nonce[1],salt[0],salt[1],f(self.buffer.len() as u64)];
        values.extend([self.left as u64,self.right as u64,self.cursor as u64,self.total as u64,self.target as u64,
            self.remaining as u64,self.phase as u64,self.elapsed,self.edits as u64,self.samples as u64,self.typing as u64,
            self.paste as u64,self.source as u64,self.initial_bytes as u64,self.baseline_end as u64,self.offset as u64].map(f));
        values.push(self.head);values.extend(self.tail.map(f));
        for group in self.buffer.chunks(12) {
            let (mut packed,mut scale)=(f(0),f(1));
            for value in group {packed+=f(*value as u64)*scale;scale*=f(1<<21);}
            values.push(packed);
        }
        commit::hash(&values)
    }
    /// Capture prefix commitment at the current offset (V4 Transcript::prefix).
    pub fn prefix(&self)->Fr {
        let p=pack62(&self.tail[..self.offset as usize%12]);
        commit::hash(&[f(CAPTURE_PREFIX),self.head,f(self.offset as u64),p[0],p[1],p[2]])
    }
    pub fn text(&self)->String {
        self.buffer[..self.left as usize].iter().chain(self.buffer[self.right as usize..].iter()).map(|n|char::from_u32(*n).unwrap()).collect()
    }
    fn width(&self,index:u32)->u32 {char::from_u32(self.buffer[index as usize]).map_or(1,|c|c.len_utf16() as u32)}
    fn step(&mut self,word:u64)->Result<(),String> {
        let bad="Invalid long-session operation";
        need(word<1u64<<62 && (self.offset as usize)<OPERATIONS,bad)?;
        let code=(word>>56) as u8;let arg=word&((1u64<<56)-1);let capacity=self.buffer.len() as u32;
        let scalar=||u32::try_from(arg).ok().and_then(char::from_u32).ok_or(bad.to_string());
        match code {
            ops::BASELINE=>{need(self.phase==0&&self.left<self.right,bad)?;let c=scalar()?;
                self.buffer[self.left as usize]=c as u32;self.left+=1;self.cursor+=c.len_utf16() as u32;
                self.total+=c.len_utf16() as u32;self.initial_bytes+=c.len_utf8() as u32;},
            ops::BASELINE_END=>{need(self.phase==0&&arg==0,bad)?;self.phase=1;self.baseline_end=self.offset+1;},
            ops::DOWN|ops::UP=>{need(self.phase==1,bad)?;self.elapsed=self.elapsed.checked_add(arg>>16).ok_or(bad)?;self.samples+=1;},
            ops::BEGIN=>{need(self.phase==1,bad)?;self.target=(arg&65535) as u32;self.remaining=((arg>>16)&65535) as u32;
                self.source=((arg>>32)&255) as u8;
                need(self.target<=self.total && self.remaining<=self.total-self.target && matches!(self.source,1..=6|255),bad)?;
                self.elapsed=self.elapsed.checked_add(arg>>40).ok_or(bad)?;self.phase=2;},
            ops::LEFT=>{need(arg==0&&self.phase==2&&self.cursor>self.target&&self.left>0,bad)?;
                self.left-=1;self.right-=1;self.buffer[self.right as usize]=self.buffer[self.left as usize];
                self.cursor-=self.width(self.right);},
            ops::RIGHT=>{need(arg==0&&self.phase==2&&self.cursor<self.target&&self.right<capacity,bad)?;
                self.buffer[self.left as usize]=self.buffer[self.right as usize];
                self.cursor+=self.width(self.left);self.left+=1;self.right+=1;},
            ops::DELETE=>{need(arg==0&&matches!(self.phase,2|3)&&self.cursor==self.target&&self.right<capacity,bad)?;
                let width=self.width(self.right);need(self.remaining>=width,bad)?;
                self.remaining-=width;self.total-=width;self.right+=1;self.phase=3;},
            ops::INSERT=>{need(matches!(self.phase,2..=4)&&self.remaining==0&&(self.phase==4||self.cursor==self.target)&&self.left<self.right,bad)?;
                let c=scalar()?;self.buffer[self.left as usize]=c as u32;self.left+=1;
                self.cursor+=c.len_utf16() as u32;self.total+=c.len_utf16() as u32;self.phase=4;},
            ops::END=>{need(arg==0&&matches!(self.phase,2..=4)&&self.remaining==0&&(self.phase==4||self.cursor==self.target),bad)?;
                self.phase=1;self.edits+=1;self.typing+=u32::from(self.source==1);self.paste+=u32::from(self.source==2);},
            ops::ADVANCE=>{need(self.phase==1&&arg>0,bad)?;self.elapsed=self.elapsed.checked_add(arg).ok_or(bad)?;},
            ops::FLAGS_LOW|ops::FLAGS_HIGH=>need(self.phase==1&&arg<=u32::MAX as u64,bad)?,
            _=>return Err(bad.into()),
        }
        self.tail[self.offset as usize%12]=word;self.offset+=1;
        if self.offset%12==0 {
            let p=pack62(&self.tail);self.head=commit::hash(&[f(CAPTURE_BLOCK),self.head,p[0],p[1],p[2]]);self.tail=[0;12];
        }
        Ok(())
    }
}

#[derive(Clone,Debug,PartialEq)]
pub struct Behavior {
    pub held:Vec<u128>,pub rate_ring:[u64;20],pub downs:u32,pub pairs:u32,pub good_dwells:u32,
    pub good_intervals:u32,pub anomalies:u32,pub previous_down:u64,pub pause:bool,pub rate_ok:bool,
}
impl Behavior {
    fn new()->Self {Self {held:vec![0;256],rate_ring:[0;20],downs:0,pairs:0,good_dwells:0,good_intervals:0,
        anomalies:0,previous_down:0,pause:false,rate_ok:true}}
    // Mirrors assurance.nr behavior_step (and the shared huma-writing-rules-v1 policy).
    fn step(&mut self,code:u8,key:usize,t:u64,o:&Origin)->Result<(),String> {
        if !matches!(code,ops::DOWN|ops::UP) {return Ok(());}
        need(key<256,"Key exceeds policy range")?;
        let old=self.held[key];
        if code==ops::DOWN {
            if o.repeated {self.anomalies+=u32::from(old==0);return Ok(());}
            self.anomalies+=u32::from(old!=0);
            if self.downs>0 {let interval=t.checked_sub(self.previous_down).ok_or("Time moved backwards")?;
                self.good_intervals+=u32::from((5..=30000).contains(&interval));self.pause|=interval>=500;}
            let ring=self.downs as usize%20;
            if self.downs>=20 {self.rate_ok&=t.checked_sub(self.rate_ring[ring]).ok_or("Bad rate history")?>=1000;}
            self.rate_ring[ring]=t;self.previous_down=t;self.downs+=1;self.held[key]=t as u128+1;
        } else if old!=0 {
            let dwell=t.checked_sub((old-1) as u64).ok_or("Bad held history")?;
            self.pairs+=1;self.good_dwells+=u32::from((10..=2000).contains(&dwell));self.held[key]=0;
        } else {self.anomalies+=1;}
        Ok(())
    }
    pub fn rules(&self,initial_bytes:u32,edits:u32,typing:u32,duration:u64)->[bool;9] {
        [initial_bytes==0,edits>0&&typing==edits,duration>=20000,self.downs>=30,
         self.anomalies==0&&self.pairs*100>=self.downs*90,self.pairs>0&&self.good_dwells*100>=self.pairs*90,
         self.downs>1&&self.good_intervals*100+90>=self.downs*90,self.pause,self.downs>0&&self.rate_ok]
    }
}

#[derive(Clone,Debug,PartialEq)]
pub struct Interaction {pub behavior:Behavior,pub origin_head:Fr,pub origin_tail:[Fr;6],pub origin_present:u32,pub origin_hid:u32}
impl Interaction {
    fn new(nonce:[Fr;2],salt:[Fr;2])->Self {Self {behavior:Behavior::new(),
        origin_head:commit::hash(&[f(ORIGIN_SEED),nonce[0],nonce[1],salt[0],salt[1]]),origin_tail:[f(0);6],origin_present:0,origin_hid:0}}
    fn sample(&mut self,code:u8,key:usize,t:u64,o:&Origin,count:u32)->Result<(),String> {
        self.behavior.step(code,key,t,o)?;
        self.origin_present+=u32::from(o.present);self.origin_hid+=u32::from(o.present&&o.state==1);
        self.origin_tail[count as usize%6]=o.packed()?;
        if (count+1)%6==0 {
            let p=pack98(&self.origin_tail);
            self.origin_head=commit::hash(&[f(ORIGIN_BLOCK),self.origin_head,p[0],p[1],p[2]]);self.origin_tail=[f(0);6];
        }
        Ok(())
    }
    pub fn prefix(&self,count:u32)->Fr {
        let p=pack98(&self.origin_tail[..count as usize%6]);
        commit::hash(&[f(ORIGIN_PREFIX),self.origin_head,f(count as u64),p[0],p[1],p[2]])
    }
    fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        let b=&self.behavior;
        let mut fields=vec![f(INTERACTION_ROOT),nonce[0],nonce[1],salt[0],salt[1],self.origin_head];
        fields.extend(self.origin_tail);
        fields.extend([self.origin_present,self.origin_hid,b.downs,b.pairs,b.good_dwells,b.good_intervals,b.anomalies].map(|v|f(v as u64)));
        fields.extend([f(b.previous_down),f(b.pause as u64),f(b.rate_ok as u64)]);
        for pair in b.held.chunks(2) {fields.push(Fr::from(pair[0])+Fr::from(pair[1])*Fr::from(1u128<<65));}
        for group in b.rate_ring.chunks(3) {
            let (mut value,mut scale)=(f(0),f(1));
            for t in group {value+=f(*t)*scale;scale*=Fr::from(1u128<<64);}fields.push(value);
        }
        commit::hash(&fields)
    }
}

#[derive(Clone,Debug,PartialEq)]
pub struct Events {
    pub checkpoints:u32,pub checkpoint_root:Fr,pub presence:u32,pub presence_head:Fr,pub approved:u32,pub on_time:u32,
    pub last_approval:u64,pub longest:u64,pub latencies:[u64;PRESENCE],pub nonces:[Fr;PRESENCE],
    pub last_reason:u8,pub last_outcome:u8,pub last_latency:u64,pub last_offset:u32,pub clock:u64,pub floor:u64,
    pub start_unix:u64,pub prior_unix:u64,pub rollback:bool,pub prior_offset:u32,pub sealed:bool,pub end_elapsed:u64,
    pub text:[Fr;2],pub digest:Fr,
}
impl Events {
    fn new(nonce:[Fr;2],salt:[Fr;2])->Self {
        Self {checkpoints:0,checkpoint_root:f(0),presence:0,presence_head:commit::hash(&[f(PRESENCE_SEED),nonce[0],nonce[1],salt[0],salt[1]]),
            approved:0,on_time:0,last_approval:0,longest:0,latencies:[0;PRESENCE],nonces:[f(0);PRESENCE],last_reason:0,last_outcome:0,
            last_latency:0,last_offset:0,clock:0,floor:0,start_unix:0,prior_unix:0,rollback:false,prior_offset:0,sealed:false,
            end_elapsed:0,text:[f(0);2],digest:f(0)}
    }
    fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        let mut fields=vec![f(EVENTS_ROOT),nonce[0],nonce[1],salt[0],salt[1],f(self.checkpoints as u64),self.checkpoint_root,
            f(self.presence as u64),self.presence_head,f(self.approved as u64),f(self.on_time as u64),f(self.last_approval),f(self.longest),
            f(self.last_reason as u64),f(self.last_outcome as u64),f(self.last_latency),f(self.last_offset as u64),f(self.clock),f(self.floor),
            f(self.start_unix),f(self.prior_unix),f(self.rollback as u64),f(self.prior_offset as u64),f(self.sealed as u64),f(self.end_elapsed),
            self.text[0],self.text[1],self.digest];
        for group in self.latencies.chunks(3) {
            let (mut value,mut scale)=(f(0),f(1));
            for t in group {value+=f(*t)*scale;scale*=Fr::from(1u128<<64);}fields.push(value);
        }
        fields.extend(self.nonces);
        commit::hash(&fields)
    }
}

#[derive(Clone,Debug,PartialEq)]
pub struct State {pub replay:Replay,pub interaction:Interaction,pub events:Events}
impl State {
    pub fn genesis(nonce:[Fr;2],salt:[Fr;2],capacity:usize)->Self {
        Self {replay:Replay::new(nonce,salt,capacity),interaction:Interaction::new(nonce,salt),events:Events::new(nonce,salt)}
    }
    pub fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        commit::hash(&[f(STATE_ROOT),self.replay.root(nonce,salt),self.interaction.root(nonce,salt),self.events.root(nonce,salt)])
    }
    /// Noir input encoding. Every integer is a decimal string so u64 values stay exact in JavaScript.
    pub fn input(&self)->Value {
        let r=&self.replay;let i=&self.interaction;let b=&i.behavior;let e=&self.events;
        let s=|v:u64|Value::String(v.to_string());
        let behavior=json!({"held":b.held.iter().map(|v|v.to_string()).collect::<Vec<_>>(),"rate_ring":b.rate_ring.map(s),
            "downs":s(b.downs as u64),"pairs":s(b.pairs as u64),"good_dwells":s(b.good_dwells as u64),"good_intervals":s(b.good_intervals as u64),
            "anomalies":s(b.anomalies as u64),"previous_down":s(b.previous_down),"pause":b.pause,"rate_ok":b.rate_ok});
        let interaction=json!({"behavior":behavior,"origin_head":i.origin_head.to_string(),"origin_tail":i.origin_tail.map(|v|v.to_string()),
            "origin_present":s(i.origin_present as u64),"origin_hid":s(i.origin_hid as u64)});
        let mut events=json!({"checkpoints":s(e.checkpoints as u64),"checkpoint_root":e.checkpoint_root.to_string(),"presence":s(e.presence as u64),
            "presence_head":e.presence_head.to_string(),"approved":s(e.approved as u64),"on_time":s(e.on_time as u64),
            "last_approval":s(e.last_approval),"longest":s(e.longest),"latencies":e.latencies.map(s).to_vec(),
            "nonces":e.nonces.iter().map(|v|v.to_string()).collect::<Vec<_>>(),"last_reason":s(e.last_reason as u64),
            "last_outcome":s(e.last_outcome as u64),"last_latency":s(e.last_latency),"last_offset":s(e.last_offset as u64)});
        let more=json!({"clock":s(e.clock),"floor":s(e.floor),"start_unix":s(e.start_unix),"prior_unix":s(e.prior_unix),"rollback":e.rollback,
            "prior_offset":s(e.prior_offset as u64),"sealed":e.sealed,"end_elapsed":s(e.end_elapsed),
            "text":e.text.map(|v|v.to_string()),"digest":e.digest.to_string()});
        for (k,v) in more.as_object().unwrap() {events[k]=v.clone();}
        let mut state=json!({"buffer":r.buffer.iter().map(|v|s(*v as u64)).collect::<Vec<_>>(),"left":s(r.left as u64),"right":s(r.right as u64),
            "cursor":s(r.cursor as u64),"total":s(r.total as u64),"target":s(r.target as u64),"remaining":s(r.remaining as u64),
            "phase":s(r.phase as u64),"elapsed":s(r.elapsed),"edits":s(r.edits as u64),"samples":s(r.samples as u64)});
        let rest=json!({"typing":s(r.typing as u64),"paste":s(r.paste as u64),"source":s(r.source as u64),"initial_bytes":s(r.initial_bytes as u64),
            "baseline_end":s(r.baseline_end as u64),"offset":s(r.offset as u64),"head":r.head.to_string(),"tail":r.tail.map(s),
            "interaction":interaction,"events":events});
        for (k,v) in rest.as_object().unwrap() {state[k]=v.clone();}
        state
    }
}

/// One checkpoint or presence response, in signed order.
#[derive(Clone,Debug,PartialEq)]
pub enum Event {
    Checkpoint {offset:usize,unix:u64,elapsed:u64,last:bool},
    Presence(Presence),
}
impl Event {
    pub fn offset(&self)->usize {match self {Self::Checkpoint {offset,..}=>*offset,Self::Presence(p)=>p.offset}}
    fn input(&self)->Result<Value,String> {
        let s=|v:u64|Value::String(v.to_string());
        Ok(match self {
            Self::Checkpoint {offset,unix,elapsed,last}=>json!({"kind":"1","offset":s(*offset as u64),"unix":s(*unix),"elapsed":s(*elapsed),
                "last":last,"nonce":["0","0"],"reason":"0","issued":"0","answered":"0","outcome":"0"}),
            Self::Presence(p)=>json!({"kind":"2","offset":s(p.offset as u64),"unix":"0","elapsed":"0","last":false,
                "nonce":[commit::parse(&p.nonce[0])?.to_string(),commit::parse(&p.nonce[1])?.to_string()],
                "reason":s(p.reason as u64),"issued":s(p.issued),"answered":s(p.answered),"outcome":s(p.outcome as u64)}),
        })
    }
    fn empty()->Value {
        json!({"kind":"0","offset":"0","unix":"0","elapsed":"0","last":false,"nonce":["0","0"],"reason":"0","issued":"0","answered":"0","outcome":"0"})
    }
}
/// Checkpoint i follows exactly checkpoint_presence[i] presence responses (V4 ordering).
pub fn ordered_events(p:&Private,sealed:bool)->Result<Vec<Event>,String> {
    let cps=&p.replay.checkpoints;
    need(cps.len()==p.checkpoint_presence.len(),"Checkpoint presence counts differ")?;
    let mut events=vec![];let mut used=0;
    for (i,(c,count)) in cps.iter().zip(&p.checkpoint_presence).enumerate() {
        need(*count>=used && *count<=p.presence.len(),"Invalid checkpoint presence order")?;
        events.extend(p.presence[used..*count].iter().cloned().map(Event::Presence));used=*count;
        events.push(Event::Checkpoint {offset:c.offset,unix:c.unix,elapsed:c.elapsed,last:sealed && i+1==cps.len() && *count==p.presence.len()});
    }
    events.extend(p.presence[used..].iter().cloned().map(Event::Presence));
    Ok(events)
}

/// A signed root produced by the chain, in order: kind 1 checkpoint, kind 2 approved presence.
pub type Signed=(u8,Fr);

fn packed_nonce(n:&[String;2])->Result<(Fr,Fr,Fr),String> {
    let a=commit::parse(&n[0])?;let b=commit::parse(&n[1])?;
    for x in [a,b] {need(commit::bytes(x)[..16].iter().all(|v|*v==0),"Presence nonce exceeds 128 bits")?;}
    need(a!=f(0)||b!=f(0),"Zero presence nonce")?;
    Ok((a,b,a+b*Fr::from(1u128<<64)*Fr::from(1u128<<64)))
}

impl State {
    /// One chunk transition: exactly the constraints of the chunk circuit.
    pub fn advance(&self,nonce:[Fr;2],words:&[u64],origins:&[Origin],events:&[Event],text:[Fr;2])->Result<(State,Vec<Signed>),String> {
        // The planner holds each format to its own part size (Format::chunk_ops); this is the largest of them.
        need(words.len()<=CHUNK_OPS.max(Format::V3.chunk_ops()) && events.len()<=SLOTS && !self.events.sealed,"Invalid long chunk shape")?;
        let mut next=self.clone();let n=words.len();
        // Per local offset 0..=n: phase, elapsed, edits, samples; prefixes at event offsets only.
        let mut at=vec![(next.replay.phase,next.replay.elapsed,next.replay.edits,next.replay.samples)];
        let mut prefixes=std::collections::BTreeMap::new();
        let wanted:std::collections::BTreeSet<usize>=events.iter().map(|e|e.offset().wrapping_sub(self.replay.offset as usize)).collect();
        if wanted.contains(&0) {prefixes.insert(0,(next.replay.prefix(),next.interaction.prefix(next.replay.samples)));}
        let mut used=0;let mut input_times=vec![None;n+1];
        for (i,word) in words.iter().enumerate() {
            let code=(word>>56) as u8;let before=next.replay.samples;next.replay.step(*word)?;
            if matches!(code,ops::DOWN|ops::UP) {
                let o=origins.get(used).ok_or("Missing key origin")?;used+=1;
                next.interaction.sample(code,(*word&65535) as usize,next.replay.elapsed,o,before)?;
            }
            if matches!(code,ops::DOWN|ops::UP|ops::BEGIN) {input_times[i]=Some(next.replay.elapsed);}
            at.push((next.replay.phase,next.replay.elapsed,next.replay.edits,next.replay.samples));
            if wanted.contains(&(i+1)) {prefixes.insert(i+1,(next.replay.prefix(),next.interaction.prefix(next.replay.samples)));}
        }
        need(used==origins.len(),"Unused key origin")?;
        // next_times[l]: elapsed after the first DOWN/UP/BEGIN at local index >= l.
        let mut next_times=vec![None;n+1];
        for l in (0..n).rev() {next_times[l]=input_times[l].or(next_times[l+1]);}
        let e=&mut next.events;
        let mut floor=e.floor;
        if let Some(first)=next_times[0] {need(first>=floor,"Input resumed before a presence answer")?;floor=0;}
        let mut signed=vec![];
        for event in events {
            let offset=event.offset();
            need(offset>=self.replay.offset as usize && offset<=self.replay.offset as usize+n && offset>=e.prior_offset as usize && !e.sealed,
                "Long-session event out of order")?;
            let l=offset-self.replay.offset as usize;let (phase,t,edits,samples)=at[l];let (prefix,origin)=prefixes[&l];
            need(phase==1,"Event inside an edit")?;
            match event {
                Event::Checkpoint {unix,elapsed,last,..}=>{
                    let first=e.checkpoints==0;
                    need(*unix<=MAX_UNIX && *elapsed>=e.clock && *elapsed>=t,"Invalid checkpoint time")?;
                    need(!first || (offset==next.replay.baseline_end as usize && *elapsed==0 && e.presence==0),"Invalid first checkpoint")?;
                    if *last {need(l==n && e.checkpoints>=1 && e.presence>0 && e.last_reason==2 && e.last_outcome==1
                        && e.last_latency<=10000 && e.last_offset as usize==offset,"Invalid sealing checkpoint")?;}
                    e.rollback|=!first && *unix<e.prior_unix;
                    let base=commit::hash(&[f(commit::CHECKPOINT),prefix,f(e.checkpoints as u64),f((edits+samples) as u64),f(edits as u64),
                        f(samples as u64),f(*unix),f(*elapsed),f(*last as u64),e.checkpoint_root,if *last {text[0]}else{f(0)},if *last {text[1]}else{f(0)}]);
                    let bound=commit::hash(&[f(BOUND),base,origin,e.presence_head,f(e.presence as u64)]);
                    e.digest=commit::hash(&[f(DIGEST),e.digest,f(1),bound]);signed.push((1,bound));
                    if first {e.start_unix=*unix;}
                    e.checkpoints+=1;e.checkpoint_root=base;e.prior_unix=*unix;e.clock=*elapsed;e.prior_offset=offset as u32;
                    if *last {e.sealed=true;e.end_elapsed=*elapsed;e.text=text;}
                },
                Event::Presence(p)=>{
                    let (n0,n1,packed)=packed_nonce(&p.nonce)?;
                    need((e.presence as usize)<PRESENCE && !e.nonces.contains(&packed),"Reused or over-capacity presence")?;
                    need(p.offset==offset && p.issued>=e.clock && p.answered>=p.issued && matches!(p.reason,1|2)
                        && matches!(p.outcome,1..=4) && p.issued>=t,"Invalid presence event")?;
                    match next_times[l] {Some(next_input)=>need(p.answered<=next_input,"Input during presence challenge")?,None=>floor=floor.max(p.answered)}
                    let issue=commit::hash(&[f(ISSUE),nonce[0],nonce[1],f(e.presence as u64),e.presence_head,prefix,origin,
                        f(edits as u64),f(samples as u64),n0,n1,f(p.reason as u64),f(p.issued)]);
                    let response=commit::hash(&[f(RESPONSE),issue,f(p.answered),f(p.outcome as u64)]);
                    e.presence_head=commit::hash(&[f(PRESENCE_PREFIX),e.presence_head,issue,response]);
                    if p.outcome==1 {
                        let latency=p.answered-p.issued;e.on_time+=u32::from(latency<=10000);
                        e.longest=e.longest.max(p.answered-e.last_approval);e.last_approval=p.answered;
                        e.latencies[e.approved as usize]=latency;e.approved+=1;
                        e.digest=commit::hash(&[f(DIGEST),e.digest,f(2),response]);signed.push((2,response));
                    }
                    e.nonces[e.presence as usize]=packed;e.last_reason=p.reason;e.last_outcome=p.outcome;
                    e.last_latency=p.answered-p.issued;e.last_offset=offset as u32;e.presence+=1;e.clock=p.answered;e.prior_offset=offset as u32;
                },
            }
        }
        e.floor=floor;
        Ok((next,signed))
    }
}

/// Chunk boundaries: at most the format's operations and SLOTS events each. `fixed` are chunks
/// already closed while writing (full, or cut at a pause); the rest follows greedily. Events at
/// an offset equal to a full chunk's end belong to the next chunk, so closed chunks never change.
/// When sealed, events at the very end (the seal) go to the final step instead of a chunk.
#[derive(Clone,Copy,Debug,PartialEq,Serialize,Deserialize)]
pub struct Chunk {pub ops:(usize,usize),pub events:(usize,usize)}
pub struct Plan {pub chunks:Vec<Chunk>,pub tail:(usize,usize)}
pub fn plan(fixed:&[Chunk],total:usize,events:&[Event],sealed:bool,format:Format)->Result<Plan,String> {
    let (mut s,mut e)=(0,0);let mut chunks=vec![];let (ops,tail)=(format.chunk_ops(),format.tail_slots());
    for c in fixed {
        need(c.ops.0==s && c.events.0==e && c.ops.1>=s && c.ops.1-s<=ops && c.ops.1<=total && c.events.1>=e
            && c.events.1-e<=SLOTS && c.events.1<=events.len() && (c.ops.1>s || c.events.1>e)
            && events[e..c.events.1].iter().all(|x|x.offset()>=s && x.offset()<=c.ops.1),"Invalid long-session chunk plan")?;
        chunks.push(*c);s=c.ops.1;e=c.events.1;
    }
    loop {
        let candidates=events[e..].iter().take_while(|x|x.offset()<s+ops).count();
        let chunk=if candidates>SLOTS {Chunk {ops:(s,events[e+SLOTS].offset()),events:(e,e+SLOTS)}}
            else if s+ops<=total {Chunk {ops:(s,s+ops),events:(e,e+candidates)}}
            else if sealed && s<total {Chunk {ops:(s,total),events:(e,e+events[e..].iter().take_while(|x|x.offset()<total).count())}}
            // The final step applies at most `tail` events; earlier trailing ones get a part with no operations.
            else if sealed && events.len()-e>tail {Chunk {ops:(s,s),events:(e,e+(events.len()-e-tail).min(SLOTS))}}
            else {break};
        chunks.push(chunk);s=chunk.ops.1;e=chunk.events.1;
    }
    Ok(Plan {chunks,tail:(e,if sealed {events.len()}else{e})})
}

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Final {
    pub nonce:[String;2],pub state_root:String,pub capture_root:String,pub origin_root:String,pub presence_root:String,
    pub bound_root:String,pub op_count:u32,pub raw_scalars:u32,pub canonical_scalars:u32,pub raw_bytes:u32,pub canonical_bytes:u32,
    pub raw_commitment:String,pub canonical_commitment:String,pub text_capacity:u32,pub initial_bytes:u32,pub edits:u32,pub samples:u32,
    pub typing:u32,pub paste:u32,pub start_unix:u64,pub end_unix:u64,pub elapsed:u64,pub clock_back:bool,
    pub checkpoint_count:u32,pub presence_count:u32,pub approved:u32,pub on_time:u32,pub missed:u32,
    pub median_response:u64,pub longest_gap:u64,pub origin_present:u32,pub origin_hid:u32,
    pub rules:[bool;9],pub policy_satisfied:bool,pub event_digest:String,
    // Capture key commitment (assurance-long-v2 only); absent before it, and in v3, where the nonce binds the key.
    #[serde(default,skip_serializing_if="String::is_empty")] pub device:String,
}
/// Public statement of a sealed terminal state, as constrained by the final circuit.
/// `chain_root` is the last chunk's end state, before the seal events the final step applies.
/// `device` is the v2 capture key commitment (None in v3); `capacity` the text tier the final step states.
pub fn finalize(state:&State,chain_root:Fr,nonce:[Fr;2],_salt:[Fr;2],device:Option<Fr>,capacity:usize)->Result<Final,String> {
    let r=&state.replay;let e=&state.events;let i=&state.interaction;
    need(e.sealed && r.phase==1 && r.baseline_end>0 && r.remaining==0 && e.end_elapsed>=e.last_approval && e.approved>0,"Unsealed long session")?;
    let text=r.text();let canonical=protocol::canonical(&text);
    need(e.text==text_binding_at(&text,capacity)?,"Signed text binding differs")?;
    let mut latencies:Vec<u64>=e.latencies[..e.approved as usize].to_vec();latencies.sort_unstable();
    let capture_root=r.prefix();let origin_root=i.prefix(r.samples);
    let rules=i.behavior.rules(r.initial_bytes,r.edits,r.typing,e.end_elapsed);
    Ok(Final {nonce:nonce.map(|n|n.to_string()),state_root:chain_root.to_string(),capture_root:capture_root.to_string(),
        origin_root:origin_root.to_string(),presence_root:e.presence_head.to_string(),
        bound_root:commit::hash(&[f(CAPTURE),capture_root,origin_root,e.presence_head]).to_string(),op_count:r.offset,
        raw_scalars:text.chars().count() as u32,canonical_scalars:canonical.chars().count() as u32,raw_bytes:text.len() as u32,
        canonical_bytes:canonical.len() as u32,raw_commitment:e.text[1].to_string(),canonical_commitment:e.text[0].to_string(),
        text_capacity:capacity as u32,
        initial_bytes:r.initial_bytes,edits:r.edits,samples:r.samples,typing:r.typing,paste:r.paste,start_unix:e.start_unix,
        end_unix:e.prior_unix,elapsed:e.end_elapsed,clock_back:e.rollback,checkpoint_count:e.checkpoints,presence_count:e.presence,
        approved:e.approved,on_time:e.on_time,missed:e.presence-e.on_time,median_response:latencies[latencies.len()/2],
        longest_gap:e.longest.max(e.end_elapsed-e.last_approval),origin_present:i.origin_present,origin_hid:i.origin_hid,
        policy_satisfied:rules.iter().all(|x|*x),rules,event_digest:e.digest.to_string(),device:device.map_or(String::new(),|d|d.to_string())})
}

/// Parsed session secrets shared by capture, chain and inputs, for one proof format at one text tier.
pub struct Session<'a> {pub private:&'a Private,pub nonce:[Fr;2],pub salt:[Fr;2],pub events:Vec<Event>,pub text:[Fr;2],pub plan:Plan,pub device:Fr,
    pub format:Format,pub capacity:usize}
impl<'a> Session<'a> {
    pub fn new(private:&'a Private,sealed:bool,fixed:&[Chunk],format:Format)->Result<Self,String> {
        let r=&private.replay;
        let nonce=[commit::parse(&r.nonce[0])?,commit::parse(&r.nonce[1])?];let salt=[commit::parse(&r.salt[0])?,commit::parse(&r.salt[1])?];
        for x in nonce.iter().chain(&salt) {need(commit::bytes(*x)[..16].iter().all(|b|*b==0),"Session secret exceeds 128 bits")?;}
        need(salt.iter().any(|x|*x!=f(0)),"Zero session salt")?;
        need(r.words.len()<=OPERATIONS && private.origins.len()<=SAMPLES && private.presence.len()<=PRESENCE
            && r.checkpoints.len()<=CHECKPOINTS,"Long session exceeds its profile")?;
        let events=ordered_events(private,sealed)?;
        // v2 states the text at its own tier with a 10000 buffer; v3 holds the whole session at its tier.
        let capacity=match format {Format::V2=>CAPACITY,Format::V3=>session_tier(&r.words)?};
        let text=if !sealed {[f(0);2]} else {
            let text=ops::replay(&r.words,CAPACITY)?.text;
            match format {Format::V2=>text_binding(&text)?,Format::V3=>text_binding_at(&text,capacity)?}
        };
        if sealed {need(matches!(events.last(),Some(Event::Checkpoint {last:true,..})),"Session is not sealed by its final checkpoint")?;}
        let plan=plan(fixed,r.words.len(),&events,sealed,format)?;
        Ok(Self {private,nonce,salt,events,text,plan,device:f(0),format,capacity})
    }
    pub fn genesis(&self)->State {State::genesis(self.nonce,self.salt,self.capacity)}
    /// The text tier the final step states: v2 the text's own, v3 the session's.
    fn text_capacity(&self,state:&State)->Result<usize,String> {
        match self.format {Format::V2=>tier(&state.replay.text()),Format::V3=>Ok(self.capacity)}
    }
    /// Binds the capture key, so statements carry its commitment.
    pub fn bind(mut self,public_key:&[u8])->Result<Self,String> {self.device=device_root(public_key)?;Ok(self)}
    fn origins_for(&self,state:&State,words:&[u64])->&'a [Origin] {
        let start=state.replay.samples as usize;
        let count=words.iter().filter(|w|matches!((**w>>56) as u8,ops::DOWN|ops::UP)).count();
        let end=(start+count).min(self.private.origins.len());&self.private.origins[start.min(end)..end]
    }
    /// Advance from `state` through one planned chunk.
    pub fn step(&self,state:&State,chunk:&Chunk)->Result<(State,Vec<Signed>),String> {
        let words=&self.private.replay.words[chunk.ops.0..chunk.ops.1];
        need(state.replay.offset as usize==chunk.ops.0,"Chunk does not continue the chain")?;
        state.advance(self.nonce,words,self.origins_for(state,words),&self.events[chunk.events.0..chunk.events.1],self.text)
    }
    /// Noir input of one chunk proof and its public boundary. v2 parts also carry the capture key and the
    /// signatures of their signed events (`signer`); v3 parts carry neither.
    pub fn chunk_input(&self,state:&State,chunk:&Chunk,signer:Option<&SignatureSet>)->Result<(Value,State),String> {
        let words=&self.private.replay.words[chunk.ops.0..chunk.ops.1];
        let (after,signed)=self.step(state,chunk)?;let width=self.format.chunk_ops();
        let mut ops=words.iter().map(|w|json!({"code":(w>>56).to_string(),"arg":(w&((1u64<<56)-1)).to_string()})).collect::<Vec<_>>();
        ops.resize(width,json!({"code":"0","arg":"0"}));
        let mut supplied=vec![];let mut used=self.origins_for(state,words).iter();
        for w in words {
            let o=if matches!((w>>56) as u8,ops::DOWN|ops::UP) {used.next().cloned().ok_or("Missing key origin")?}else{Origin::default()};
            supplied.push(json!({"present":o.present,"pid":o.pid.to_string(),"state":o.state.to_string(),"keyboard":o.keyboard.to_string(),"repeated":o.repeated}));
        }
        supplied.resize(width,json!({"present":false,"pid":"0","state":"0","keyboard":"0","repeated":false}));
        let mut events=self.events[chunk.events.0..chunk.events.1].iter().map(Event::input).collect::<Result<Vec<_>,_>>()?;
        events.resize(SLOTS,Event::empty());
        let sealing=after.events.sealed;
        let mut input=json!({"nonce":self.nonce.map(|x|x.to_string()),"salt":self.salt.map(|x|x.to_string()),"state":state.input(),
            "ops":ops,"origins":supplied,"op_count":words.len().to_string(),"events":events,
            "text":if sealing {self.text.map(|x|x.to_string())}else{["0".into(),"0".into()]},
            "expected":{"start_root":state.root(self.nonce,self.salt).to_string(),"end_root":after.root(self.nonce,self.salt).to_string(),
                "genesis":state.replay.offset==0}});
        if self.format==Format::V2 {
            let signer=signer.ok_or("A v2 part needs its signatures")?;
            input["device"]=signer.device_input()?;input["signatures"]=signer.slots(&self.events[chunk.events.0..chunk.events.1],&signed,SLOTS)?;
            input["link"]=json!({"end_root":after.root(self.nonce,self.salt).to_string(),"device":device_root(signer.public_key)?.to_string()});
        }
        Ok((input,after))
    }
    /// The seal events after the last chunk, applied by the final step.
    pub fn tail(&self,state:&State)->Result<State,String> {
        need(state.replay.offset as usize==self.private.replay.words.len(),"Chain did not reach the sealed end")?;
        Ok(state.advance(self.nonce,&[],&[],&self.events[self.plan.tail.0..self.plan.tail.1],self.text)?.0)
    }
    pub fn final_input(&self,state:&State,signer:Option<&SignatureSet>)->Result<(Value,Final),String> {
        need(state.replay.offset as usize==self.private.replay.words.len(),"Chain did not reach the sealed end")?;
        let tail=&self.events[self.plan.tail.0..self.plan.tail.1];
        let (sealed,signed)=state.advance(self.nonce,&[],&[],tail,self.text)?;
        let device=match (self.format,signer) {(Format::V2,Some(s))=>Some(device_root(s.public_key)?),(Format::V2,None)=>return Err("A v2 final step needs its signatures".into()),_=>None};
        let statement=finalize(&sealed,state.root(self.nonce,self.salt),self.nonce,self.salt,device,self.text_capacity(&sealed)?)?;
        let mut events=self.events[self.plan.tail.0..self.plan.tail.1].iter().map(Event::input).collect::<Result<Vec<_>,_>>()?;
        events.resize(SLOTS,Event::empty());
        let s=|v:u64|Value::String(v.to_string());
        let mut expected=serde_json::to_value(&statement).map_err(|_|"Invalid final statement")?;
        for key in ["op_count","raw_scalars","canonical_scalars","raw_bytes","canonical_bytes","text_capacity","initial_bytes","edits","samples","typing",
            "paste","start_unix","end_unix","elapsed","checkpoint_count","presence_count","approved","on_time","missed","median_response",
            "longest_gap","origin_present","origin_hid"] {
            let v=expected[key].as_u64().ok_or("Invalid final integer")?;expected[key]=s(v);
        }
        // The final checkpoint signs the text binding, so it is always supplied here.
        let mut input=json!({"nonce":self.nonce.map(|x|x.to_string()),"salt":self.salt.map(|x|x.to_string()),"state":state.input(),
            "events":events,"text":self.text.map(|x|x.to_string()),"expected":expected});
        if let (Format::V2,Some(signer))=(self.format,signer) {
            input["device"]=signer.device_input()?;input["signatures"]=signer.slots(tail,&signed,self.format.tail_slots())?;
        }
        Ok((input,statement))
    }
    /// The whole chain from genesis: every chunk, signed root and the terminal statement.
    pub fn run(&self)->Result<(Vec<Chunk>,Vec<Signed>,State,Final),String> {
        let chunks=self.plan.chunks.clone();
        let mut state=self.genesis();let mut signed=vec![];
        for chunk in &chunks {let (next,roots)=self.step(&state,chunk)?;signed.extend(roots);state=next;}
        let chain_end=state.clone();
        let (sealed,roots)=state.advance(self.nonce,&[],&[],&self.events[self.plan.tail.0..self.plan.tail.1],self.text)?;
        signed.extend(roots);state=sealed;
        let device=if self.format==Format::V2 {Some(self.device)}else{None};
        let statement=finalize(&state,chain_end.root(self.nonce,self.salt),self.nonce,self.salt,device,self.text_capacity(&state)?)?;
        need(state.replay.offset as usize==self.private.replay.words.len() && state.events.checkpoints as usize==self.private.replay.checkpoints.len()
            && state.events.presence as usize==self.private.presence.len(),"Chain did not consume the complete session")?;
        Ok((chunks,signed,chain_end,statement))
    }
}

#[derive(Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {pub profile:String,pub sealed:bool,pub private:Private,pub capsule:Capsule,pub text:String,pub chunks:usize,pub plan:Vec<Chunk>,pub experimental:bool,
    /// How the session is proved; snapshots from before v3 have none and are v2.
    #[serde(default,skip_serializing_if="Option::is_none")] pub format:Option<Format>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {pub ok:bool,pub result:Snapshot}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppInput {pub witness:huma_replay_core::Witness,pub snapshot:SnapshotEnvelope}

/// Binds a sealed long snapshot to the complete signed Swift session, then emits the
/// public signature set and (unless `statement_only`) every chunk and final proof input, in the snapshot's format.
pub fn worker_input(w:&huma_replay_core::Witness,snapshot:&Snapshot,statement_only:bool)->Result<Value,String> {
    let format=snapshot.format.unwrap_or(Format::V2);
    let bad="Long-session input differs from its complete signed session";
    need(snapshot.profile==PROFILE && snapshot.sealed && snapshot.experimental && snapshot.text.as_bytes()==w.text.as_bytes()
        && w.session.presence_protocol.as_deref()==Some("local-presence-v1") && snapshot.capsule.kind==KIND,bad)?;
    let legacy=huma_replay_core::replay_bounded(w,&huma_replay_core::LONG_BOUNDS).map_err(str::to_string)?;
    let r=&snapshot.private.replay;
    let expected=crate::assurance_input::rebuild(w,&r.nonce,&r.salt,CAPACITY,OPERATIONS)?;
    need(expected==snapshot.private,bad)?;
    let c=&snapshot.capsule;
    let session=Session::new(&expected,true,&snapshot.plan,format)?.bind(&c.public_key)?;let (chunks,signed,_,statement)=session.run()?;
    if format==Format::V3 {need(bound_nonce(session.nonce[0],&c.public_key)?==session.nonce,"This session's nonce isn't bound to its capture key")?;}
    need(chunks==snapshot.plan && chunks.len()==snapshot.chunks,bad)?;
    let (checkpoints,presence)=split(&signed);
    // Statements sealed before the capture key commitment existed carry none; every other field must match.
    let mut recorded=c.statement.clone();if recorded.device.is_empty() {recorded.device=statement.device.clone();}
    need(statement==recorded && checkpoints.iter().map(|x|x.to_string()).collect::<Vec<_>>()==c.checkpoint_roots
        && presence.iter().map(|x|x.to_string()).collect::<Vec<_>>()==c.presence_roots,bad)?;
    let key=verify_signatures(&c.public_key,&checkpoints,&c.signatures,&presence,&c.presence_signatures)?;
    need(legacy.capture_key_hash.as_deref()==Some(key.as_str()),bad)?;
    let mut out=json!({"profile":PROFILE,"format":format,"tier":session.capacity,"statement":statement,"publicKeyHex":hex::encode(&c.public_key),
        "events":signed.iter().map(|(k,_)|if *k==1 {'1'}else{'2'}).collect::<String>(),
        "checkpointRoots":c.checkpoint_roots,"presenceRoots":c.presence_roots,
        "signaturesHex":c.signatures.iter().map(hex::encode).collect::<Vec<_>>(),
        "presenceSignaturesHex":c.presence_signatures.iter().map(hex::encode).collect::<Vec<_>>(),
        "text":snapshot.text,"chunkCount":chunks.len()});
    if !statement_only {
        let signer=SignatureSet {public_key:&c.public_key,checkpoint_roots:&checkpoints,checkpoint:&c.signatures,presence_roots:&presence,presence:&c.presence_signatures};
        let mut inputs=vec![];let mut s=session.genesis();
        for chunk in &chunks {let (input,next)=session.chunk_input(&s,chunk,Some(&signer))?;inputs.push(input);s=next;}
        out["chunks"]=json!(inputs);out["final"]=session.final_input(&s,Some(&signer))?.0;
    }
    Ok(out)
}

/// Public signature capsule of a sealed long session (no private history).
#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {
    pub kind:String,pub statement:Final,pub public_key:Vec<u8>,pub checkpoint_roots:Vec<String>,pub signatures:Vec<Vec<u8>>,
    pub presence_roots:Vec<String>,pub presence_signatures:Vec<Vec<u8>>,
}

pub fn digest(signed:&[Signed])->Fr {signed.iter().fold(f(0),|d,(kind,root)|commit::hash(&[f(DIGEST),d,f(*kind as u64),*root]))}

/// Every signed root must carry a valid P-256 signature by the capture key.
pub fn verify_signatures(public_key:&[u8],checkpoint_roots:&[Fr],checkpoint_signatures:&[Vec<u8>],
                         presence_roots:&[Fr],presence_signatures:&[Vec<u8>])->Result<String,String> {
    need(public_key.len()==65 && public_key[0]==4 && checkpoint_roots.len()==checkpoint_signatures.len() && checkpoint_roots.len()>=2
        && presence_roots.len()==presence_signatures.len() && !presence_roots.is_empty(),"Invalid long-session signature set")?;
    let key=VerifyingKey::from_sec1_bytes(public_key).map_err(|_|"Invalid long-session key")?;
    for (domain,roots,signatures) in [(CP_DOMAIN,checkpoint_roots,checkpoint_signatures),(PRESENCE_DOMAIN,presence_roots,presence_signatures)] {
        for (root,der) in roots.iter().zip(signatures) {
            need(der.len()<=72,"Invalid long-session signature")?;
            let sig=Signature::from_der(der).map_err(|_|"Invalid long-session DER")?;
            key.verify(&message(domain,*root),&sig).map_err(|_|"Invalid long-session signature")?;
        }
    }
    Ok(hex::encode(Sha256::digest(public_key)))
}
/// Commitment to an uncompressed P-256 capture key, as `device_root` in prover.nr.
pub fn device_root(public_key:&[u8])->Result<Fr,String> {
    need(public_key.len()==65 && public_key[0]==4,"Invalid long-session key")?;
    let x:[u8;32]=public_key[1..33].try_into().unwrap();let y:[u8;32]=public_key[33..65].try_into().unwrap();
    let (hx,hy)=(commit::halves(&x),commit::halves(&y));
    Ok(commit::hash(&[f(DEVICE),hx[0],hx[1],hy[0],hy[1]]))
}
/// A session's signatures by signed root, supplied to the circuits so they check each one (assurance-long-v2).
pub struct SignatureSet<'a> {
    pub public_key:&'a [u8],pub checkpoint_roots:&'a [Fr],pub checkpoint:&'a [Vec<u8>],pub presence_roots:&'a [Fr],pub presence:&'a [Vec<u8>],
}
impl SignatureSet<'_> {
    fn bytes(values:&[u8])->Value {json!(values.iter().map(|b|b.to_string()).collect::<Vec<_>>())}
    fn device_input(&self)->Result<Value,String> {
        device_root(self.public_key)?;
        Ok(json!({"x":Self::bytes(&self.public_key[1..33]),"y":Self::bytes(&self.public_key[33..65])}))
    }
    /// P1363 r || s with low s; ECDSA accepts both s and n - s, and the circuit gadget needs neither form specifically.
    fn signature(&self,kind:u8,root:Fr)->Result<Value,String> {
        let (roots,signatures)=if kind==1 {(self.checkpoint_roots,self.checkpoint)}else{(self.presence_roots,self.presence)};
        let index=roots.iter().position(|r|*r==root).ok_or("Signed root has no signature")?;
        let der=signatures.get(index).ok_or("Signed root has no signature")?;
        let sig=Signature::from_der(der).map_err(|_|"Invalid long-session DER")?;
        let sig=sig.normalize_s().unwrap_or(sig);
        let domain=if kind==1 {CP_DOMAIN}else{PRESENCE_DOMAIN};
        VerifyingKey::from_sec1_bytes(self.public_key).map_err(|_|"Invalid long-session key")?.verify(&message(domain,root),&sig)
            .map_err(|_|"Invalid long-session signature")?;
        Ok(Self::bytes(&sig.to_bytes()))
    }
    /// One signature per event slot: the signed events' own, a well-formed non-signature (r = s = 1) elsewhere.
    fn slots(&self,events:&[Event],signed:&[Signed],count:usize)->Result<Value,String> {
        let mut unsigned=[0u8;64];unsigned[31]=1;unsigned[63]=1;
        let mut roots=signed.iter();let mut out=vec![];
        for event in events {
            let kind=match event {Event::Checkpoint {..}=>1,Event::Presence(p) if p.outcome==1=>2,_=>{out.push(Self::bytes(&unsigned));continue;}};
            let (k,root)=roots.next().ok_or("Signed roots differ from events")?;
            need(*k==kind,"Signed roots differ from events")?;out.push(self.signature(kind,*root)?);
        }
        need(roots.next().is_none(),"Signed roots differ from events")?;
        need(out.len()<=count,"Too many signed events for this step")?;
        out.resize(count,Self::bytes(&unsigned));Ok(json!(out))
    }
}
/// Splits chain roots by kind, preserving order within each kind.
pub fn split(signed:&[Signed])->(Vec<Fr>,Vec<Fr>) {
    (signed.iter().filter(|s|s.0==1).map(|s|s.1).collect(),signed.iter().filter(|s|s.0==2).map(|s|s.1).collect())
}

#[cfg(test)] mod tests {
    use super::*;
    use crate::assurance_capture::{LiveAssuranceCapture,LONG_PROFILE};
    use p256::ecdsa::{signature::Signer,SigningKey};
    use rand_core::OsRng;

    /// The nine writing rules for keys pressed at (down, up) milliseconds, all from the keyboard.
    fn typing_rules(keys:&[(u64,u64)])->[bool;9] {
        let (mut b,o)=(Behavior::new(),Origin {present:true,pid:0,state:1,keyboard:91,repeated:false});
        let mut events:Vec<(u64,u8,usize)>=keys.iter().enumerate().flat_map(|(i,&(down,up))|[(down,ops::DOWN,4+i%26),(up,ops::UP,4+i%26)]).collect();
        events.sort_by_key(|e|e.0);
        for (t,code,key) in events {b.step(code,key,t,&o).unwrap();}
        let n=keys.len() as u32;b.rules(0,n,n,keys.last().unwrap().1)
    }
    /// What the typing checks can and can't say (HUMAN-PRESENCE.md §1). They catch timing no person types with:
    /// no key holds, more than 19 keys a second, or no pause at all. A few lines that copy human timing pass every
    /// one, so the checks raise the cost of faking; they never show by themselves that a person typed.
    #[test] fn typing_checks_catch_machine_timing_but_not_imitation() {
        let (holds,rhythm,pause,speed)=(5,6,7,8);
        // A plain script: each key pressed and released in the same millisecond, 500 keys a second.
        let script:Vec<_>=(0..300).map(|i|(i*2,i*2)).collect();
        let r=typing_rules(&script);assert!(!r[holds]&&!r[rhythm]&&!r[pause]&&!r[speed]);
        // A macro at a fixed 25 keys a second with 30 ms holds: too fast, and never pauses.
        let macro_:Vec<_>=(0..300).map(|i|(i*40,i*40+30)).collect();
        let r=typing_rules(&macro_);assert!(r[holds]&&r[rhythm]&&!r[pause]&&!r[speed]);
        // A steady bot at human speed (one key every 150 ms, 80 ms holds) is caught only by never pausing.
        let steady:Vec<_>=(0..300).map(|i|(i*150,i*150+80)).collect();
        let r=typing_rules(&steady);assert!(r[holds]&&r[rhythm]&&!r[pause]&&r[speed]);
        // Imitation: random 60–140 ms holds, 90–300 ms gaps and a 0.8–2 s pause every 40 keys passes all nine.
        let mut seed=0x9E3779B97F4A7C15u64;
        let mut next=|range:u64|{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed%range};
        let mut at=0;let imitation:Vec<_>=(0..300).map(|i|{at+=90+next(211)+if i%40==39 {800+next(1201)}else{0};(at,at+60+next(81))}).collect();
        assert_eq!(typing_rules(&imitation),[true;9]);
    }

    struct Recorded {capture:LiveAssuranceCapture,background:Vec<Value>,text:String}
    fn approve(c:&mut LiveAssuranceCapture,key:&SigningKey) {
        let signature:Signature=key.sign(&c.pending_message().unwrap());c.accept(signature.to_der().as_bytes().to_vec()).unwrap();
    }
    /// Synthetic software-key session: typing with periodic revisions, checkpoints every
    /// `every` characters, presence checks (one missed) and closed chunks exported as capture grows.
    fn record(chars:usize,every:usize,initial:&str)->Recorded {record_with(chars,every,initial,false)}
    /// `cuts`: close the open part at pauses (every 150 characters) and at Finish, as the app does.
    fn record_with(chars:usize,every:usize,initial:&str,cuts:bool)->Recorded {
        let key=SigningKey::random(&mut OsRng);
        let mut c=LiveAssuranceCapture::with_profile(initial,key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),1000,LONG_PROFILE).unwrap();
        approve(&mut c,&key);let mut text=initial.to_string();let mut background=vec![];let mut t=100u64;let mut nonce=1u8;
        // As the app does: inputs of closed parts as they close, and all of them again when the text tier grows.
        let mut tier=0;
        let mut export=|c:&mut LiveAssuranceCapture,background:&mut Vec<Value>| {
            while c.long_chunks().len()>background.len() {
                let part=c.long_chunk(background.len()).unwrap();
                if part["tier"].as_u64().unwrap()!=tier {tier=part["tier"].as_u64().unwrap();background.clear();continue;}
                background.push(part["input"].clone());
            }
        };
        for i in 0..chars {
            let origin=Origin {present:true,pid:0,state:1,keyboard:40,repeated:false};
            let key_code=(i%40) as u16;
            c.sample("down",key_code,0,t,origin.clone()).unwrap();
            let units=text.encode_utf16().count();
            if i%97==96 {c.edit(units-1,1,"","typing",t+1).unwrap();text.pop();}
            else {let s=if i%50==7 {"é"}else if i%333==5 {"😀"}else{"a"};c.edit(units,0,s,"typing",t+1).unwrap();text.push_str(s);}
            c.sample("up",key_code,0,t+60,origin).unwrap();t+=if i%40==39 {700}else{160};
            if i%every==every-1 {c.prepare(1000+t,t,false,&text).unwrap();approve(&mut c,&key);}
            if i%600==300 {c.issue([nonce;32],1,t).unwrap();nonce+=1;c.respond(if i%1200==300 {2}else{1},t+900).unwrap();
                if c.pending_message().is_ok() {approve(&mut c,&key);}t+=1000;}
            if cuts && i%150==149 {c.long_cut().unwrap();}
            export(&mut c,&mut background);
        }
        if cuts {c.long_cut().unwrap();export(&mut c,&mut background);}
        c.issue([200;32],2,t).unwrap();c.respond(1,t+500).unwrap();approve(&mut c,&key);
        c.prepare(5000+t,t+600,true,&text).unwrap();approve(&mut c,&key);
        export(&mut c,&mut background);
        Recorded {capture:c,background,text}
    }
    fn private(r:&Recorded)->(Private,Capsule,Vec<Chunk>) {
        let snapshot=r.capture.snapshot().unwrap();
        (serde_json::from_value(snapshot["private"].clone()).unwrap(),serde_json::from_value(snapshot["capsule"].clone()).unwrap(),
         serde_json::from_value(snapshot["plan"].clone()).unwrap())
    }
    fn roots(c:&Capsule)->(Vec<Fr>,Vec<Fr>) {
        let parse=|v:&Vec<String>|v.iter().map(|r|commit::parse(r).unwrap()).collect();(parse(&c.checkpoint_roots),parse(&c.presence_roots))
    }

    #[test] fn live_long_capture_matches_chain_and_background_chunks_are_final() {
        let r=record(1500,40,"");let (p,capsule,fixed)=private(&r);
        let session=Session::new(&p,true,&fixed,Format::V3).unwrap();let (chunks,signed,state,statement)=session.run().unwrap();
        assert_eq!(state.replay.text(),r.text);assert!(r.text.chars().count()>1400);
        assert_eq!(chunks.len(),r.background.len());assert_eq!(session.capacity,4096);
        // Every chunk exported while writing, at the tier the session has now, is identical to the one derived after sealing.
        let mut s=session.genesis();
        for (chunk,earlier) in chunks.iter().zip(&r.background) {let (input,next)=session.chunk_input(&s,chunk,None).unwrap();assert_eq!(&input,earlier);s=next;}
        assert_eq!(statement,capsule.statement);assert!(statement.policy_satisfied,"{:?}",statement.rules);
        assert_eq!(statement.presence_count,3);assert_eq!(statement.approved,2);assert_eq!(statement.missed,1);
        assert_eq!(statement.event_digest,digest(&signed).to_string());
        assert_eq!([statement.canonical_commitment.clone(),statement.raw_commitment.clone()],text_binding_at(&r.text,4096).unwrap().map(|x|x.to_string()));
        // The nonce commits to the capture key, and the statement names no key (v3).
        assert_eq!(bound_nonce(session.nonce[0],&capsule.public_key).unwrap(),session.nonce);assert!(statement.device.is_empty());
        let other=SigningKey::random(&mut OsRng);
        assert_ne!(bound_nonce(session.nonce[0],other.verifying_key().to_encoded_point(false).as_bytes()).unwrap(),session.nonce);
        let (cps,pres)=split(&signed);
        verify_signatures(&capsule.public_key,&cps,&capsule.signatures,&pres,&capsule.presence_signatures).unwrap();
        let mut bad=capsule.signatures.clone();bad[3][12]^=1;
        assert!(verify_signatures(&capsule.public_key,&cps,&bad,&pres,&capsule.presence_signatures).is_err());
    }
    #[test] fn pauses_and_finish_close_parts_early_and_the_seal_goes_to_the_final_step() {
        let r=record_with(700,40,"",true);let (p,capsule,fixed)=private(&r);
        let session=Session::new(&p,true,&fixed,Format::V3).unwrap();let (chunks,..)=session.run().unwrap();
        // Every part, including the one closed at Finish, was closed and exported before the seal.
        assert_eq!(chunks.len(),r.background.len());
        assert!(chunks.iter().any(|c|c.ops.1-c.ops.0<Format::V3.chunk_ops()));
        assert_eq!(chunks.last().unwrap().ops.1,p.replay.words.len());
        assert_eq!(session.plan.tail.1-session.plan.tail.0,2); // seal presence and final checkpoint
        let mut s=session.genesis();
        for (chunk,earlier) in chunks.iter().zip(&r.background) {let (input,next)=session.chunk_input(&s,chunk,None).unwrap();assert_eq!(&input,earlier);s=next;}
        let (input,statement)=session.final_input(&s,None).unwrap();
        assert!(input.get("signatures").is_none() && input.get("device").is_none() && input["expected"].get("device").is_none());
        assert_eq!(statement,capsule.statement);assert_eq!(statement.text_capacity,1024);
        assert_eq!(input["events"].as_array().unwrap().iter().filter(|e|e["kind"]!="0").count(),2);
        // A changed plan cannot overlap, skip or overfill parts.
        let mut bad=fixed.clone();bad[1].ops.0+=1;assert!(Session::new(&p,true,&bad,Format::V3).is_err());
        let mut bad=fixed.clone();bad.remove(0);assert!(Session::new(&p,true,&bad,Format::V3).is_err());
    }
    #[test] fn a_page_that_outgrows_its_tier_is_proved_again_at_the_next_one() {
        let key=SigningKey::random(&mut OsRng);
        let mut c=LiveAssuranceCapture::with_profile("",key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),1000,LONG_PROFILE).unwrap();
        approve(&mut c,&key);let mut text=String::new();let mut t=100u64;let mut tiers=vec![];
        let origin=Origin {present:true,pid:0,state:1,keyboard:40,repeated:false};
        for i in 0..1100usize {
            c.sample("down",(i%40) as u16,0,t,origin.clone()).unwrap();c.edit(text.encode_utf16().count(),0,"a","typing",t+1).unwrap();text.push('a');
            c.sample("up",(i%40) as u16,0,t+60,origin.clone()).unwrap();t+=160;
            if i%100==99 {c.long_cut().unwrap();tiers.push(c.long_chunk(0).unwrap()["tier"].as_u64().unwrap());}
        }
        // The first part's input is made again at 4096 once the text passes 1,024 characters.
        assert_eq!(tiers.first(),Some(&1024));assert_eq!(tiers.last(),Some(&4096));
        // Deleting back below 1,024 keeps the tier: the session once held more.
        for _ in 0..200 {let units=text.encode_utf16().count();c.edit(units-1,1,"","typing",t).unwrap();text.pop();t+=50;}
        c.long_cut().unwrap();assert_eq!(c.long_chunk(0).unwrap()["tier"],4096);
        assert_eq!(peak(&c.snapshot_words()).unwrap(),1100);
    }
    #[test] fn text_tiers_follow_the_sealed_length() {
        assert_eq!(tier(&"a".repeat(1024)).unwrap(),1024);assert_eq!(tier(&"a".repeat(1025)).unwrap(),4096);
        assert_eq!(tier(&"😀".repeat(4097)).unwrap(),10000);assert!(tier(&"a".repeat(10001)).is_err());
        assert_ne!(text_commitment("a",0,1024).unwrap(),text_commitment("a",0,4096).unwrap());
    }
    #[test] fn dense_checkpoints_split_chunks_by_event_slots() {
        let r=record(300,1,"start ");let (p,capsule,fixed)=private(&r);
        let (chunks,..)=Session::new(&p,true,&fixed,Format::V3).unwrap().run().unwrap();let ops=Format::V3.chunk_ops();
        assert!(chunks.iter().all(|c|c.events.1-c.events.0<=SLOTS && c.ops.1-c.ops.0<=ops));
        assert!(chunks.iter().any(|c|c.ops.1-c.ops.0<ops && c.events.1-c.events.0==SLOTS));
        assert!(!capsule.statement.rules[0]); // a starting draft is never relabeled as typed
        assert_eq!(chunks.len(),r.background.len());
    }
    #[test] fn changed_history_events_or_text_cannot_reproduce_the_signed_chain() {
        let r=record(400,50,"");let (p,capsule,fixed)=private(&r);
        let original=Session::new(&p,true,&fixed,Format::V3).unwrap().run().unwrap().1;
        let changes:[fn(&mut Private);6]=[
            |p|p.replay.words[40]^=1<<16,
            |p|p.origins[3].pid^=1,
            |p|p.presence[0].answered+=1,
            |p|p.replay.checkpoints[2].unix+=1,
            |p|{let i=p.checkpoint_presence.iter().rposition(|c|*c==0).unwrap();p.checkpoint_presence[i]=1;},
            |p|{p.presence.remove(0);for c in &mut p.checkpoint_presence {*c=c.saturating_sub(1);}},
        ];
        for (index,change) in changes.into_iter().enumerate() {
            let mut q=p.clone();change(&mut q);assert!(q!=p);
            if let Ok((_,signed,..))=Session::new(&q,true,&fixed,Format::V3).and_then(|s|s.run()) {assert_ne!(signed,original,"mutation {index} reproduced the chain");}
        }
        assert_eq!(capsule.checkpoint_roots.len(),p.replay.checkpoints.len());
    }
    #[test] fn input_during_presence_and_unsealed_sessions_are_rejected() {
        let r=record(120,30,"");let (p,_,fixed)=private(&r);
        let mut early=p.clone();early.presence[0].answered=u64::MAX/2;
        assert!(Session::new(&early,true,&fixed,Format::V3).and_then(|s|s.run()).is_err());
        let mut unsealed=p.clone();unsealed.replay.checkpoints.pop();unsealed.checkpoint_presence.pop();
        assert!(Session::new(&unsealed,true,&fixed,Format::V3).is_err());
        assert!(finalize(&State::genesis([f(1),f(2)],[f(3),f(4)],1024),f(0),[f(1),f(2)],[f(3),f(4)],None,1024).is_err());
    }
}
