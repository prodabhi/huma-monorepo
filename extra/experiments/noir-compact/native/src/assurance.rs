//! V4 experiment: the existing replay plus authenticated origin/presence and
//! the shared experimental writing policy. All P-256 checks remain mandatory.
use crate::{commit,ops,protocol};
use ark_bn254::Fr;
use huma_replay_core::{human, Edit, Sample, Witness};
use p256::ecdsa::{signature::{Signer,Verifier},Signature,SigningKey,VerifyingKey};
use rand_core::{OsRng,RngCore};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};

pub const KIND:&str="huma-compact-assurance-experiment-v4";
pub const CP_DOMAIN:&[u8]=b"HUMA_COMPACT_ASSURANCE_CHECKPOINT_V4\0";
pub const PRESENCE_DOMAIN:&[u8]=b"HUMA_COMPACT_ASSURANCE_PRESENCE_V4\0";
const ORIGIN_SEED:u64=0x48554d410401;
const ORIGIN_BLOCK:u64=0x48554d410402;
const ORIGIN_PREFIX:u64=0x48554d410403;
const PRESENCE_SEED:u64=0x48554d410404;
const ISSUE:u64=0x48554d410405;
const RESPONSE:u64=0x48554d410406;
const PRESENCE_PREFIX:u64=0x48554d410407;
const CHECKPOINT:u64=0x48554d410408;
const CAPTURE:u64=0x48554d410409;
fn need(ok:bool)->Result<(),String> {if ok {Ok(())}else{Err("Invalid V4 assurance session".into())}}
#[derive(Clone,Debug,Default,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {pub present:bool,pub pid:u32,pub state:u32,pub keyboard:u32,pub repeated:bool}
impl Origin {
    pub fn from_sample(sample:&Sample)->Result<Self,String> {
        if let Some(o)=&sample.origin {
            Ok(Self {present:true,pid:i32::try_from(o.source_unix_process_id).map_err(|_|"PID exceeds V4 profile")? as u32,
                state:i32::try_from(o.source_state_id).map_err(|_|"Source state exceeds V4 profile")? as u32,
                keyboard:u32::try_from(o.keyboard_type).map_err(|_|"Keyboard type exceeds V4 profile")?,repeated:o.is_repeat})
        } else {Ok(Self::default())}
    }
    pub fn packed(&self)->Result<Fr,String> {
        need(self.present || (self.pid==0 && self.state==0 && self.keyboard==0 && !self.repeated))?;
        Ok(Fr::from(self.pid as u128 + ((self.state as u128)<<32) + ((self.keyboard as u128)<<64)
            + ((self.repeated as u128)<<96) + ((self.present as u128)<<97)))
    }
    fn sample_origin(&self)->Option<human::Origin> {
        self.present.then_some(human::Origin {source_unix_process_id:(self.pid as i32) as i64,
            source_state_id:(self.state as i32) as i64,keyboard_type:self.keyboard as i64,is_repeat:self.repeated})
    }
}
#[derive(Clone,Debug,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {pub offset:usize,pub nonce:[String;2],pub reason:u8,pub issued:u64,pub answered:u64,pub outcome:u8}
#[derive(Clone,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Private {
    pub replay:protocol::PrivateWitness,pub origins:Vec<Origin>,pub presence:Vec<Presence>,pub checkpoint_presence:Vec<usize>,
}
#[derive(Clone,Debug,PartialEq,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub replay:protocol::Journal,
    pub origin_root:String,pub presence_root:String,pub bound_root:String,
    pub origin_present:u32,pub origin_hid:u32,pub presence_count:u32,pub approved:u32,pub on_time:u32,pub missed:u32,
    pub median_response:u64,pub longest_gap:u64,pub rules:[bool;9],pub policy_satisfied:bool,
    pub checkpoint_roots:Vec<String>,pub presence_roots:Vec<String>,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {pub kind:String,pub journal:Journal,pub public_key:Vec<u8>,pub signatures:Vec<Vec<u8>>,pub presence_signatures:Vec<Vec<u8>>}

pub(crate) struct OriginTranscript {heads:Vec<Fr>,values:Vec<Fr>}
impl OriginTranscript {
    pub(crate) fn new(nonce:[Fr;2],salt:[Fr;2],origins:&[Origin])->Result<Self,String> {
        let values=origins.iter().map(Origin::packed).collect::<Result<Vec<_>,_>>()?;
        let mut heads=vec![commit::hash(&[Fr::from(ORIGIN_SEED),nonce[0],nonce[1],salt[0],salt[1]])];
        for chunk in values.chunks_exact(6) {let p=Self::pack(chunk);heads.push(commit::hash(&[Fr::from(ORIGIN_BLOCK),*heads.last().unwrap(),p[0],p[1],p[2]]));}
        Ok(Self {heads,values})
    }
    /// Appends origins to an append-only transcript, hashing only completed blocks.
    pub(crate) fn extend(&mut self,origins:&[Origin])->Result<(),String> {
        for o in &origins[self.values.len()..] {
            self.values.push(o.packed()?);
            if self.values.len()%6==0 {
                let p=Self::pack(&self.values[self.values.len()-6..]);
                self.heads.push(commit::hash(&[Fr::from(ORIGIN_BLOCK),*self.heads.last().unwrap(),p[0],p[1],p[2]]));
            }
        }
        Ok(())
    }
    fn pack(values:&[Fr])->[Fr;3] {
        let mut p=[Fr::from(0u64);3];let scale=Fr::from(1u128<<98);
        for (i,value) in values.iter().enumerate() {p[i/2]+=*value*if i%2==0 {Fr::from(1u64)}else{scale};}p
    }
    pub(crate) fn prefix(&self,count:usize)->Fr {
        let start=count/6*6;let p=Self::pack(&self.values[start..count]);
        commit::hash(&[Fr::from(ORIGIN_PREFIX),self.heads[count/6],Fr::from(count as u64),p[0],p[1],p[2]])
    }
}
fn parsed_halves(raw:&[String;2])->Result<[Fr;2],String> {
    let result=[commit::parse(&raw[0])?,commit::parse(&raw[1])?];
    for f in &result {need(commit::bytes(*f)[..16].iter().all(|x|*x==0))?;}Ok(result)
}
fn empty_edit(source:String)->Edit {Edit {sequence:0,elapsed_milliseconds:0,source,location:0,removed_length:0,
    inserted_text:String::new(),previous_head:String::new(),text_hash:String::new(),head:String::new()}}
pub fn statement(w:&Private,capacity:usize)->Result<Journal,String> {
    need(w.replay.words.len()<=65536 && w.origins.len()<=65536 && w.presence.len()<=32)?;
    let base=protocol::statement(&w.replay,capacity)?;
    let replay=ops::replay(&w.replay.words,capacity)?;
    let nonce=parsed_halves(&w.replay.nonce)?;let salt=parsed_halves(&w.replay.salt)?;
    let transcript=commit::Transcript::new(nonce,salt,&w.replay.words);
    let origin=OriginTranscript::new(nonce,salt,&w.origins)?;
    need(w.origins.len()==base.samples as usize && w.checkpoint_presence.len()==w.replay.checkpoints.len())?;
    let mut samples=vec![];let mut edits=vec![];let mut source=String::new();
    for (i,word) in w.replay.words.iter().enumerate() {
        let code=(word>>56) as u8;let arg=word&((1u64<<56)-1);
        if code==ops::BEGIN {source=if (arg>>32)&255==1 {"typing"}else{"other"}.into();}
        if code==ops::END {edits.push(empty_edit(source.clone()));}
        if code==ops::DOWN || code==ops::UP {
            let key=arg as u16;need(key<256)?;
            samples.push(Sample {kind:if code==ops::DOWN {"down"}else{"up"}.into(),key_code:key,modifiers:0,
                elapsed_milliseconds:replay.prefixes[i+1].elapsed,origin:w.origins[samples.len()].sample_origin()});
        }
    }
    let behavior=human::writing_policy(if base.initial_bytes==0 {""}else{"baseline"},&edits,&samples,base.elapsed).map_err(str::to_string)?;
    let r=behavior.rules;let rules=[r.blank_baseline,r.typing_edits_only,r.minimum_duration,r.minimum_keys,r.paired_keys,
        r.dwell_bounds,r.interval_bounds,r.pause_present,r.rate_bound];
    let mut heads=vec![commit::hash(&[Fr::from(PRESENCE_SEED),nonce[0],nonce[1],salt[0],salt[1]])];
    let (mut approved,mut on_time,mut last_approval,mut longest,mut prior_offset,mut prior_time)=(0u32,0u32,0u64,0u64,0usize,0u64);
    let mut nonces=std::collections::BTreeSet::new();let mut roots=vec![];let mut latencies=vec![];
    for (i,p) in w.presence.iter().enumerate() {
        need(p.offset>=prior_offset && p.offset<=w.replay.words.len() && p.issued>=prior_time && p.answered>=p.issued
            && matches!(p.reason,1|2) && matches!(p.outcome,1..=4) && nonces.insert(p.nonce.clone()))?;
        let n=parsed_halves(&p.nonce)?;need(n.iter().any(|x|*x!=Fr::from(0u64)))?;
        let prefix=&replay.prefixes[p.offset];need(prefix.phase==1 && p.issued>=prefix.elapsed)?;
        let next=w.replay.words.iter().enumerate().skip(p.offset).find(|(_,word)| matches!((**word>>56) as u8,ops::DOWN|ops::UP|ops::BEGIN));
        need(next.map_or(base.elapsed,|(at,_)|replay.prefixes[at+1].elapsed)>=p.answered)?;
        let issue=commit::hash(&[Fr::from(ISSUE),nonce[0],nonce[1],Fr::from(i as u64),*heads.last().unwrap(),
            transcript.prefix(&w.replay.words,p.offset),origin.prefix(prefix.samples as usize),Fr::from(prefix.edits as u64),
            Fr::from(prefix.samples as u64),n[0],n[1],Fr::from(p.reason),Fr::from(p.issued)]);
        let response=commit::hash(&[Fr::from(RESPONSE),issue,Fr::from(p.answered),Fr::from(p.outcome)]);
        heads.push(commit::hash(&[Fr::from(PRESENCE_PREFIX),*heads.last().unwrap(),issue,response]));
        if p.outcome==1 {
            approved+=1;let latency=p.answered-p.issued;if latency<=10000 {on_time+=1;}
            latencies.push(latency);longest=longest.max(p.answered-last_approval);last_approval=p.answered;roots.push(response.to_string());
        }
        prior_offset=p.offset;prior_time=p.answered;
    }
    let last=w.presence.last().ok_or("V4 requires a seal presence response")?;
    need(last.reason==2 && last.outcome==1 && last.answered-last.issued<=10000 && last.offset==w.replay.words.len() && base.elapsed>=last.answered)?;
    longest=longest.max(base.elapsed-last_approval);latencies.sort_unstable();
    let mut checkpoint_roots=vec![];
    for (i,cp) in w.replay.checkpoints.iter().enumerate() {
        let count=w.checkpoint_presence[i];need(count<=w.presence.len() && (i!=0 || count==0)
            && (i+1!=w.replay.checkpoints.len() || count==w.presence.len()))?;
        for (index,p) in w.presence.iter().enumerate() {
            need(if index<count {p.offset<=cp.offset && p.answered<=cp.elapsed}
                else {cp.offset<=p.offset && cp.elapsed<=p.issued})?;
        }
        let prefix=&replay.prefixes[cp.offset];
        checkpoint_roots.push(commit::hash(&[Fr::from(CHECKPOINT),commit::parse(&base.checkpoint_roots[i])?,
            origin.prefix(prefix.samples as usize),heads[count],Fr::from(count as u64)]).to_string());
    }
    let origin_root=origin.prefix(w.origins.len());let presence_root=*heads.last().unwrap();
    let bound=commit::hash(&[Fr::from(CAPTURE),commit::parse(&base.capture_root)?,origin_root,presence_root]);
    Ok(Journal {origin_root:origin_root.to_string(),presence_root:presence_root.to_string(),bound_root:bound.to_string(),
        origin_present:w.origins.iter().filter(|o|o.present).count() as u32,origin_hid:w.origins.iter().filter(|o|o.present && o.state==1).count() as u32,
        presence_count:w.presence.len() as u32,approved,on_time,missed:w.presence.len() as u32-on_time,
        median_response:latencies[latencies.len()/2],longest_gap:longest,rules,policy_satisfied:behavior.satisfied,
        checkpoint_roots,presence_roots:roots,replay:base})
}
pub fn message(domain:&[u8],root:&str)->Result<Vec<u8>,String> {let mut out=domain.to_vec();out.extend_from_slice(&commit::bytes(commit::parse(root)?));Ok(out)}
pub fn verify(c:&Capsule)->Result<String,String> {
    need(c.kind==KIND && c.public_key.len()==65 && c.public_key[0]==4 && c.signatures.len()>=2 && c.signatures.len()<=1024
        && c.signatures.len()==c.journal.checkpoint_roots.len() && c.presence_signatures.len()==c.journal.approved as usize
        && c.presence_signatures.len()==c.journal.presence_roots.len() && !c.presence_signatures.is_empty())?;
    let key=VerifyingKey::from_sec1_bytes(&c.public_key).map_err(|_|"Invalid V4 key")?;
    for (domain,roots,signatures) in [(CP_DOMAIN,&c.journal.checkpoint_roots,&c.signatures),(PRESENCE_DOMAIN,&c.journal.presence_roots,&c.presence_signatures)] {
        for (root,der) in roots.iter().zip(signatures) {
            need(der.len()<=72)?;let sig=Signature::from_der(der).map_err(|_|"Invalid V4 DER")?;
            key.verify(&message(domain,root)?,&sig).map_err(|_|"Invalid V4 signature")?;
        }
    }
    Ok(hex::encode(Sha256::digest(&c.public_key)))
}

/// Public test-fixture conversion only: signs a NEW transcript with a NEW software key.
pub fn synthetic_fixture(w:&Witness,capacity:usize)->Result<(Private,Capsule),String> {
    huma_replay_core::replay(w).map_err(str::to_string)?;
    let mut builder=ops::Builder::new(&w.session.initial_text,capacity,65536)?;
    let mut origins=vec![];let mut presence=vec![];let mut offsets=vec![builder.words.len()];let mut counts=vec![0];
    let events=w.session.presence_events.as_deref().unwrap_or(&[]);let mut issue=None;
    for capture in w.session.capture_records.as_deref().ok_or("Missing capture")? {
        match capture.kind.as_str() {
            "edit"=>{let e=&w.session.events[capture.index];builder.edit(e.location,e.removed_length,&e.inserted_text,&e.source,e.elapsed_milliseconds)?;},
            "key"=>{let e=&w.session.input_samples.as_ref().ok_or("Missing samples")?[capture.index];
                builder.sample(&e.kind,e.key_code,e.modifiers,e.elapsed_milliseconds)?;origins.push(Origin::from_sample(e)?);},
            "presence"=>{let e=&events[capture.index];if e.kind=="challenge" {issue=Some(e);}else {
                let issued=issue.take().ok_or("Missing issue")?;
                let mut nonce=[0u8;32];OsRng.fill_bytes(&mut nonce);
                presence.push(Presence {offset:builder.words.len(),nonce:commit::halves(&nonce).map(|x|x.to_string()),
                    reason:if issued.reason=="seal" {2}else{1},issued:issued.elapsed_milliseconds,answered:e.elapsed_milliseconds,
                    outcome:match e.outcome.as_str() {"approved"=>1,"cancelled"=>2,"timedOut"=>3,_=>4}});
            }},_=>return Err("Unknown capture".into()),
        }
        offsets.push(builder.words.len());counts.push(presence.len());
    }
    let mut nonce=[0u8;32];let mut salt=[0u8;32];OsRng.fill_bytes(&mut nonce);OsRng.fill_bytes(&mut salt);
    let cps=w.session.signed_checkpoints.as_ref().ok_or("Missing checkpoints")?;
    let private=Private {replay:protocol::PrivateWitness {nonce:commit::halves(&nonce).map(|x|x.to_string()),salt:commit::halves(&salt).map(|x|x.to_string()),
        words:builder.words,checkpoints:cps.iter().map(|c|{let t=c.reported_time.as_ref().ok_or("Missing signed time")?;
            Ok(protocol::Checkpoint {offset:offsets[c.capture_count],unix:t.unix_milliseconds,elapsed:t.elapsed_milliseconds})}).collect::<Result<Vec<_>,String>>()?},
        origins,presence,checkpoint_presence:cps.iter().map(|c|counts[c.capture_count]).collect()};
    let capsule=synthetic_capsule(&private,capacity)?;Ok((private,capsule))
}
fn synthetic_capsule(private:&Private,capacity:usize)->Result<Capsule,String> {
    let journal=statement(private,capacity)?;let key=SigningKey::random(&mut OsRng);
    let sign=|roots:&[String],domain:&[u8]|roots.iter().map(|r|{let sig:Signature=key.sign(&message(domain,r).unwrap());sig.to_der().as_bytes().to_vec()}).collect();
    let capsule=Capsule {kind:KIND.into(),signatures:sign(&journal.checkpoint_roots,CP_DOMAIN),presence_signatures:sign(&journal.presence_roots,PRESENCE_DOMAIN),
        journal,public_key:key.verifying_key().to_encoded_point(false).as_bytes().to_vec()};verify(&capsule)?;Ok(capsule)
}

/// Named generated test cases, including regular synthetic input that deliberately
/// passes the illustrative policy. These are not human-training data.
pub fn synthetic_case(name:&str)->Result<(Private,Capsule,String),String> {
    let mut builder=ops::Builder::new(if name=="u64max" {"x"}else{""},256,1536)?;
    let (mut origins,mut checkpoints)=(vec![],vec![protocol::Checkpoint {offset:builder.words.len(),unix:1792627200000,elapsed:0}]);
    let mut last_count=0;let mut last_time=0;
    if name=="u64max" {
        builder.sample("down",255,0,u64::MAX)?;origins.push(Origin {present:true,state:1,..Origin::default()});last_time=u64::MAX;
    } else {
        need(["typed250","rollover","repeat","unpaired","rate","dwell","missing-origin","late","timeout","paste-small","paste-large"].contains(&name))?;
        let count=if name=="typed250" {250}else{40};
        let spacing=if name=="rate" {20}else if ["rollover","repeat","typed250"].contains(&name) {80}else{550};
        let hold=if name=="rollover" || name=="repeat" {110}else if name=="dwell" {5}else{65};
        let mut actions=vec![];
        for i in 0..count {
            let t=100+i*spacing+if i>=30 {700}else{0};let key=(i%8) as u16;
            actions.push((t,0u8,key,false));actions.push((t+1,1u8,key,false));
            if name=="repeat" && i==0 {actions.push((t+30,0u8,key,true));}
            if name!="unpaired" || i<count-5 {actions.push((t+hold,2u8,key,false));}
        }
        actions.sort();let mut letters=0;
        for (time,kind,key,repeated) in actions {
            if kind==1 {
                let text=builder.text();let letter=char::from(b'a'+(letters%26) as u8).to_string();letters+=1;
                let pasted=letters==1 && ["paste-small","paste-large"].contains(&name);
                let inserted=if pasted && name=="paste-large" {"x".repeat(128)} else {letter};
                builder.edit(text.encode_utf16().count(),0,&inserted,if pasted {"paste"}else{"typing"},time)?;
            } else {
                builder.sample(if kind==0 {"down"}else{"up"},key,0,time)?;
                origins.push(if name=="missing-origin" {Origin::default()}else{Origin {present:true,state:1,repeated,..Origin::default()}});
            }
            if builder.captures()-last_count>=256 || time-last_time>=10000 {
                checkpoints.push(protocol::Checkpoint {offset:builder.words.len(),unix:1792627200000+time,elapsed:time});
                last_count=builder.captures();last_time=time;
            }
        }
        last_time=builder.elapsed();
    }
    let mut nonce=[0u8;32];let mut salt=[0u8;32];OsRng.fill_bytes(&mut nonce);OsRng.fill_bytes(&mut salt);
    let mut presence=vec![];
    if name!="u64max" {
        let mut n=[0u8;32];OsRng.fill_bytes(&mut n);let issued=(last_time+200).max(22500);
        presence.push(Presence {offset:builder.words.len(),nonce:commit::halves(&n).map(|x|x.to_string()),reason:1,issued,
            answered:issued+if name=="timeout" || name=="late" {10001}else{400},outcome:if name=="timeout" {3}else{1}});
    }
    let mut n=[0u8;32];OsRng.fill_bytes(&mut n);
    let issued=if name=="u64max" {u64::MAX}else{(presence.last().unwrap().answered+100).max(34000)};
    let answered=if name=="u64max" {u64::MAX}else{issued+400};
    presence.push(Presence {offset:builder.words.len(),nonce:commit::halves(&n).map(|x|x.to_string()),reason:2,issued,answered,outcome:1});
    let mut checkpoint_presence=vec![0;checkpoints.len()];checkpoint_presence.push(presence.len());
    checkpoints.push(protocol::Checkpoint {offset:builder.words.len(),unix:1792627200000+if name=="u64max" {1}else{answered},elapsed:answered});
    let text=builder.text();let private=Private {replay:protocol::PrivateWitness {nonce:commit::halves(&nonce).map(|x|x.to_string()),
        salt:commit::halves(&salt).map(|x|x.to_string()),words:builder.words,checkpoints},origins,presence,checkpoint_presence};
    let capsule=synthetic_capsule(&private,256)?;Ok((private,capsule,text))
}

#[cfg(test)] mod tests {
    use super::*;
    fn fixture(name:&str)->Witness {
        serde_json::from_slice(&std::fs::read(format!("{}/../../../../backend/zkvm/common/tests/fixtures/{name}.json",env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
    }
    #[test] fn one_pasted_character_fails_the_typing_rule_even_with_valid_signatures() {
        for name in ["paste-small","paste-large"] {
            let (_,capsule,_)=synthetic_case(name).unwrap();verify(&capsule).unwrap();
            assert_eq!(capsule.journal.replay.paste,1);assert_eq!(capsule.journal.replay.typing,39);
            assert!(!capsule.journal.policy_satisfied);
            for (index,passed) in capsule.journal.rules.iter().enumerate() {assert_eq!(*passed,index!=1);}
        }
    }
    #[test] fn signed_origins_presence_and_shared_policy_bind_one_replay() {
        for (name,pass,missed) in [("presence-typed",true,0),("presence-paste-missed",false,1)] {
            let (private,capsule)=synthetic_fixture(&fixture(name),256).unwrap();
            assert_eq!(statement(&private,256).unwrap(),capsule.journal);
            assert_eq!(capsule.journal.policy_satisfied,pass);assert_eq!(capsule.journal.missed,missed);
            assert_eq!(capsule.journal.origin_present,80);verify(&capsule).unwrap();
            let mut origin=private.clone();origin.origins[0].pid^=1;
            let changed=statement(&origin,256).unwrap();
            assert_eq!(changed.replay,capsule.journal.replay);assert_ne!(changed.origin_root,capsule.journal.origin_root);
            let mut altered=capsule.clone();altered.journal=changed;assert!(verify(&altered).is_err());
            for n in 0..capsule.signatures.len() {
                let mut altered=capsule.clone();altered.signatures[n][15]^=1;assert!(verify(&altered).is_err());
            }
            for n in 0..capsule.presence_signatures.len() {
                let mut altered=capsule.clone();altered.presence_signatures[n][15]^=1;assert!(verify(&altered).is_err());
            }
        }
    }
    #[test] fn malformed_or_uncovered_presence_and_source_metadata_reject() {
        let (p,_)=synthetic_fixture(&fixture("presence-typed"),256).unwrap();
        let mut changed=p.clone();changed.origins[0].present=false;assert!(statement(&changed,256).is_err());
        let mut changed=p.clone();changed.presence[1].nonce=changed.presence[0].nonce.clone();assert!(statement(&changed,256).is_err());
        let mut changed=p.clone();changed.presence[1].answered=changed.presence[1].issued+10001;assert!(statement(&changed,256).is_err());
        let mut changed=p.clone();changed.checkpoint_presence[1]=0;assert!(statement(&changed,256).is_err());
        let mut changed=p.clone();changed.presence[0].offset=1;assert!(statement(&changed,256).is_err());
        let mut changed=p.clone();changed.origins.pop();assert!(statement(&changed,256).is_err());
        let mut missing=p.clone();missing.origins.fill(Origin::default());
        let report=statement(&missing,256).unwrap();assert_eq!(report.origin_present,0);assert!(report.policy_satisfied);
        let mut changed=p.clone();changed.replay.words[1]=(changed.replay.words[1]&!65535)|65535;assert!(statement(&changed,256).is_err());
    }
    #[test] fn named_case_matrix_covers_behavior_branches_and_exact_u64() {
        for (name,pass) in [("typed250",true),("rollover",true),("repeat",true),("unpaired",false),
            ("rate",false),("dwell",false),("missing-origin",true),("late",true),("timeout",true),("u64max",false)] {
            let (p,c,text)=synthetic_case(name).unwrap();verify(&c).unwrap();
            assert_eq!(statement(&p,256).unwrap(),c.journal);assert_eq!(c.journal.policy_satisfied,pass,"{name}");
            assert_eq!(c.journal.replay.text_hash,<[u8;32]>::from(Sha256::digest(text.trim_end_matches([' ','\t']).as_bytes())));
            if name=="typed250" {assert_eq!(p.origins.len(),500);assert_eq!(p.replay.words.len(),1251);assert!(p.replay.checkpoints.len()<=8);}
            if name=="missing-origin" {assert_eq!(c.journal.origin_present,0);}
            if name=="late" || name=="timeout" {assert_eq!(c.journal.missed,1);}
            if name=="u64max" {assert_eq!(c.journal.replay.elapsed,u64::MAX);}
        }
    }
}
