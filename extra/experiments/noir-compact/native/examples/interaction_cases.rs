//! Synthetic carried replay/behavior/origin reference. No owner keys or app use.
#[allow(dead_code)] #[path="continuation_cases.rs"] mod replay;
use ark_bn254::Fr;
use huma_compact_experiment::{assurance::{self,Origin},commit,ops};
use huma_replay_core::{human,Edit,Sample};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest,Sha256};

#[derive(Clone,Serialize)]
struct Behavior {
    held:Vec<String>,rate_ring:[u64;20],downs:u32,pairs:u32,good_dwells:u32,
    good_intervals:u32,anomalies:u32,previous_down:u64,pause:bool,rate_ok:bool,
}
impl Behavior {
    fn new()->Self {Self {held:vec!["0".into();256],rate_ring:[0;20],downs:0,pairs:0,
        good_dwells:0,good_intervals:0,anomalies:0,previous_down:0,pause:false,rate_ok:true}}
    fn step(&mut self,code:u8,key:usize,t:u64,o:&Origin)->Result<(),String> {
        if !matches!(code,ops::DOWN|ops::UP) {return Ok(());}
        if key>=256 {return Err("Key exceeds policy range".into());}
        let old=self.held[key].parse::<u128>().unwrap();
        if code==ops::DOWN {
            if o.repeated {self.anomalies+=u32::from(old==0);return Ok(());}
            self.anomalies+=u32::from(old!=0);
            if self.downs>0 {let interval=t.checked_sub(self.previous_down).ok_or("Time moved backwards")?;
                self.good_intervals+=u32::from((5..=30000).contains(&interval));self.pause|=interval>=500;}
            let ring=self.downs as usize%20;
            if self.downs>=20 {self.rate_ok &= t.checked_sub(self.rate_ring[ring]).ok_or("Bad rate history")?>=1000;}
            self.rate_ring[ring]=t;self.previous_down=t;self.downs+=1;self.held[key]=(t as u128+1).to_string();
        } else if old!=0 {
            let dwell=t.checked_sub((old-1) as u64).ok_or("Bad held history")?;
            self.pairs+=1;self.good_dwells+=u32::from((10..=2000).contains(&dwell));self.held[key]="0".into();
        } else {self.anomalies+=1;}
        Ok(())
    }
    fn rules(&self,s:&replay::State)->[bool;9] {
        [s.initial_bytes==0,s.edits>0&&s.typing==s.edits,s.elapsed>=20000,self.downs>=30,
         self.anomalies==0&&self.pairs*100>=self.downs*90,self.pairs>0&&self.good_dwells*100>=self.pairs*90,
         self.downs>1&&self.good_intervals*100+90>=self.downs*90,self.pause,self.downs>0&&self.rate_ok]
    }
}
fn origin_pack(values:&[Fr])->[Fr;3] {
    let mut p=[Fr::from(0u64);3];for (i,v) in values.iter().enumerate() {
        p[i/2]+=*v*if i%2==0 {Fr::from(1u64)}else{Fr::from(1u128<<98)};
    }p
}
struct FullOrigins {values:Vec<Fr>,heads:Vec<Fr>}
impl FullOrigins {
    fn new(origins:&[Origin],nonce:[Fr;2],salt:[Fr;2])->Result<Self,String> {
        let values=origins.iter().map(Origin::packed).collect::<Result<Vec<_>,_>>()?;
        let mut heads=vec![commit::hash(&[Fr::from(0x48554d410401u64),nonce[0],nonce[1],salt[0],salt[1]])];
        for group in values.chunks_exact(6) {let p=origin_pack(group);
            heads.push(commit::hash(&[Fr::from(0x48554d410402u64),*heads.last().unwrap(),p[0],p[1],p[2]]));}
        Ok(Self {values,heads})
    }
    fn prefix(&self,count:usize)->Fr {let p=origin_pack(&self.values[count/6*6..count]);
        commit::hash(&[Fr::from(0x48554d410403u64),self.heads[count/6],Fr::from(count as u64),p[0],p[1],p[2]])}
}
#[derive(Clone,Serialize)]
struct Interaction {behavior:Behavior,origin_head:String,origin_tail:[String;6],origin_present:u32,origin_hid:u32}
impl Interaction {
    fn new(nonce:[Fr;2],salt:[Fr;2])->Self {Self {behavior:Behavior::new(),
        origin_head:commit::hash(&[Fr::from(0x48554d410401u64),nonce[0],nonce[1],salt[0],salt[1]]).to_string(),
        origin_tail:std::array::from_fn(|_|"0".into()),origin_present:0,origin_hid:0}}
    fn sample(&mut self,code:u8,key:usize,t:u64,o:&Origin,count:u32)->Result<(),String> {
        self.behavior.step(code,key,t,o)?;
        self.origin_present+=u32::from(o.present);self.origin_hid+=u32::from(o.present&&o.state==1);
        self.origin_tail[count as usize%6]=o.packed()?.to_string();
        if (count+1)%6==0 {
            let p=origin_pack(&self.origin_tail.iter().map(|n|commit::parse(n).unwrap()).collect::<Vec<_>>());
            self.origin_head=commit::hash(&[Fr::from(0x48554d410402u64),commit::parse(&self.origin_head)?,p[0],p[1],p[2]]).to_string();
            self.origin_tail=std::array::from_fn(|_|"0".into());
        }Ok(())
    }
    fn prefix(&self,count:u32)->Fr {
        let p=origin_pack(&self.origin_tail.iter().map(|n|commit::parse(n).unwrap()).collect::<Vec<_>>());
        commit::hash(&[Fr::from(0x48554d410403u64),commit::parse(&self.origin_head).unwrap(),Fr::from(count),p[0],p[1],p[2]])
    }
    fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        let b=&self.behavior;
        let mut fields=vec![Fr::from(0x48554d410603u64),nonce[0],nonce[1],salt[0],salt[1],commit::parse(&self.origin_head).unwrap()];
        fields.extend(self.origin_tail.iter().map(|n|commit::parse(n).unwrap()));
        fields.extend([self.origin_present,self.origin_hid,b.downs,b.pairs,b.good_dwells,b.good_intervals,b.anomalies].map(Fr::from));
        fields.extend([Fr::from(b.previous_down),Fr::from(u8::from(b.pause)),Fr::from(u8::from(b.rate_ok))]);assert_eq!(fields.len(),22);
        for pair in b.held.chunks(2) {
            fields.push(commit::parse(&pair[0]).unwrap()+commit::parse(&pair[1]).unwrap()*Fr::from(1u128<<65));
        }
        for group in b.rate_ring.chunks(3) {
            let (mut value,mut scale)=(Fr::from(0u64),Fr::from(1u64));
            for t in group {value+=Fr::from(*t)*scale;scale*=Fr::from(1u128<<64);}fields.push(value);
        }
        assert_eq!(fields.len(),157);commit::hash(&fields)
    }
}
#[derive(Clone,Serialize)]
struct State {#[serde(flatten)] replay:replay::State,interaction:Interaction}
impl State {
    fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        commit::hash(&[Fr::from(0x48554d410602u64),self.replay.root(nonce,salt),self.interaction.root(nonce,salt)])
    }
    fn append(&mut self,words:&[u64],origins:&[Origin])->Result<(),String> {
        let mut next=self.clone();let mut index=0;
        for word in words {let code=(word>>56) as u8;let before=next.replay.samples;next.replay.step(*word)?;
            if matches!(code,ops::DOWN|ops::UP) {
                let origin=origins.get(index).ok_or("Missing origin")?;
                next.interaction.sample(code,(*word&65535) as usize,next.replay.elapsed,origin,before)?;index+=1;
            }}
        if index!=origins.len() {return Err("Unused origin".into());}*self=next;Ok(())
    }
}
fn fixture(name:&str)->Result<(Vec<u64>,Vec<Origin>,usize,usize),String> {
    if name.starts_with("master-") {
        let text=match name {
            "master-trailing"=>"A 🍁e\u{301}\u{a0} \t","master-gap"=>"x😀z \t",
            "master-nfc"=>"é","master-nfd"=>"e\u{301}","master-newline"=>"a \n",
            "master-crlf"=>"a\r\n","master-nbsp"=>"a\u{a0}","master-nul"=>"a\0",
            "master-bom"=>"\u{feff}a","master-maxscalar"=>"\u{10ffff}",
            "master-empty"=>"","master-spaces"=>" \t",_=>return Err("Unknown master fixture".into()),
        };
        let mut b=ops::Builder::new(text,64,65536)?;
        if name=="master-gap" {b.edit(1,2,"é","typing",10)?;}
        return Ok((b.words,vec![],64,12));
    }
    if ["revision","typing10000","emoji10000","baseline10000"].contains(&name) {
        let (words,capacity,chunk)=replay::fixture(name)?;let mut index=0;
        let origins=words.iter().filter(|w|matches!((**w>>56) as u8,ops::DOWN|ops::UP)).map(|_| {
            let at=index;index+=1;
            if at%17==0 {Origin::default()}else{Origin {present:true,pid:if at%3==0 {u32::MAX}else{0},
                state:if at%11==0 {u32::MAX}else{1},keyboard:40,repeated:false}}
        }).collect();return Ok((words,origins,capacity,chunk));
    }
    // New disposable software fixtures only; their signing keys/signatures are not reused.
    let (private,capsule,_)=assurance::synthetic_case(name)?;
    let mut words=private.replay.words;let raw=ops::replay(&words,256)?;
    let delta=capsule.journal.replay.elapsed-raw.prefixes.last().unwrap().elapsed;
    if delta>0 {words.push(ops::word(ops::ADVANCE,delta));}
    Ok((words,private.origins,256,12))
}
fn empty_edit(source:u8)->Edit {Edit {sequence:0,elapsed_milliseconds:0,source:if source==1 {"typing"}else{"other"}.into(),
    location:0,removed_length:0,inserted_text:String::new(),previous_head:String::new(),text_hash:String::new(),head:String::new()}}
fn origin_sample(o:&Origin)->Option<human::Origin> {o.present.then_some(human::Origin {
    source_unix_process_id:(o.pid as i32) as i64,source_state_id:(o.state as i32) as i64,
    keyboard_type:o.keyboard as i64,is_repeat:o.repeated})}
fn policy(r:human::Rules)->[bool;9] {[r.blank_baseline,r.typing_edits_only,r.minimum_duration,r.minimum_keys,
    r.paired_keys,r.dwell_bounds,r.interval_bounds,r.pause_present,r.rate_bound]}
fn boundary(before:&State,after:&State,nonce:[Fr;2],salt:[Fr;2],final_step:bool)->serde_json::Value {
    let r=&after.replay;let rules=after.interaction.behavior.rules(r);
    json!({"nonce":["1","2"],"start_root":before.root(nonce,salt).to_string(),"end_root":after.root(nonce,salt).to_string(),
        "start_offset":before.replay.offset,"end_offset":r.offset,"capture_root":r.prefix().to_string(),"final_step":final_step,
        "origin_root":after.interaction.prefix(r.samples).to_string(),"rules":if final_step {rules}else{[false;9]},
        "policy_satisfied":final_step&&rules.iter().all(|r|*r),"origin_present":after.interaction.origin_present,"origin_hid":after.interaction.origin_hid})
}
fn input(index:usize,before:&State,part:&[u64],origins:&[Origin],chunk:usize,expected:serde_json::Value)->serde_json::Value {
    let mut supplied=vec![];let mut at=0;let mut ops=vec![];
    for word in part {let code=(word>>56) as u8;
        supplied.push(if matches!(code,ops::DOWN|ops::UP) {let o=origins[at].clone();at+=1;o}else{Origin::default()});
        ops.push(json!({"code":code,"arg":word&((1u64<<56)-1)}));}
    supplied.resize(chunk,Origin::default());ops.resize(chunk,json!({"code":0,"arg":0}));
    json!({"index":index,"salt":["3","4"],"state":before,"ops":ops,"origins":supplied,"op_count":part.len(),"expected":expected})
}
fn text_commitment(text:&str,capacity:usize,scope:u8)->Fr {
    let scalars=text.chars().map(|c|c as u32).collect::<Vec<_>>();assert!(scalars.len()<=capacity);
    let mut fields=vec![Fr::from(0x48554d410604u64),Fr::from(capacity as u64),Fr::from(scope),
        Fr::from(scalars.len() as u64),Fr::from(text.len() as u64)];
    for block in 0..capacity.div_ceil(12) {
        let (mut packed,mut scale)=(Fr::from(0u64),Fr::from(1u64));
        for i in 0..12 {packed+=Fr::from(*scalars.get(block*12+i).unwrap_or(&0))*scale;scale*=Fr::from(1u64<<21);}
        fields.push(packed);
    }commit::hash(&fields)
}
fn main()->Result<(),String> {
    let name=std::env::args().nth(1).ok_or("Expected fixture")?;
    let mode=std::env::args().nth(2);if mode.as_deref().is_some_and(|m|m!="--terminal") {return Err("Unknown reference option".into());}
    let (words,origins,capacity,chunk)=fixture(&name)?;
    let nonce=[Fr::from(1u64),Fr::from(2u64)];let salt=[Fr::from(3u64),Fr::from(4u64)];
    let reference=ops::replay(&words,capacity)?;let transcript=commit::Transcript::new(nonce,salt,&words);
    let origin_transcript=FullOrigins::new(&origins,nonce,salt)?;
    let mut state=State {replay:replay::State::new(capacity,nonce,salt),interaction:Interaction::new(nonce,salt)};
    let total=words.len().div_ceil(chunk);let mut boundaries=vec![];let mut selected=vec![];let mut hostile=vec![];let mut samples=vec![];let mut edits=vec![];
    let mut source=0;let mut residues=std::collections::BTreeSet::new();let mut held_across=0;
    for (i,part) in words.chunks(chunk).enumerate() {
        let before=state.clone();let start=before.replay.samples as usize;
        let count=part.iter().filter(|w|matches!((**w>>56) as u8,ops::DOWN|ops::UP)).count();
        state.append(part,&origins[start..start+count])?;
        for (j,word) in part.iter().enumerate() {
            let code=(word>>56) as u8;let arg=word&((1u64<<56)-1);let offset=before.replay.offset as usize+j;
            if code==ops::BEGIN {source=((arg>>32)&255) as u8;}
            if code==ops::END {edits.push(empty_edit(source));}
            if matches!(code,ops::DOWN|ops::UP) {let o=&origins[samples.len()];samples.push(Sample {
                kind:if code==ops::DOWN {"down"}else{"up"}.into(),key_code:arg as u16,modifiers:0,
                elapsed_milliseconds:reference.prefixes[offset+1].elapsed,origin:origin_sample(o)});}
        }
        let r=&state.replay;let p=&reference.prefixes[r.offset as usize];
        assert_eq!((r.phase,r.elapsed,r.edits,r.samples,r.typing,r.paste,r.initial_bytes),
            (p.phase,p.elapsed,p.edits,p.samples,p.typing,p.paste,p.initial_bytes));
        assert_eq!(r.prefix(),transcript.prefix(&words,r.offset as usize));
        assert_eq!(state.interaction.prefix(r.samples),origin_transcript.prefix(r.samples as usize));
        let report=human::writing_policy(if r.initial_bytes==0 {""}else{"baseline"},&edits,&samples,r.elapsed).map_err(str::to_string)?;
        let rules=state.interaction.behavior.rules(r);assert_eq!(rules,policy(report.rules));
        residues.insert(r.samples%6);held_across+=usize::from(state.interaction.behavior.held.iter().any(|t|t!="0")&&i+1<total);
        let final_step=i+1==total;
        let expected=boundary(&before,&state,nonce,salt,final_step);
        if ["revision","rollover"].contains(&name.as_str()) || [0,total/2,total-1].contains(&i) {
            selected.push(input(i,&before,part,&origins[start..start+count],chunk,expected.clone()));
        }
        if i==0 {for label in ["ForgedGenesisHeldKey","ForgedGenesisPause","ForgedGenesisOriginHead"] {
            let mut bad=before.clone();
            match label {
                "ForgedGenesisHeldKey"=>bad.interaction.behavior.held[255]="1".into(),
                "ForgedGenesisPause"=>bad.interaction.behavior.pause=true,
                _=>bad.interaction.origin_head="1".into(),
            }
            let supplied=bad.clone();bad.append(part,&origins[start..start+count])?;
            let mut value=input(i,&supplied,part,&origins[start..start+count],chunk,boundary(&supplied,&bad,nonce,salt,final_step));
            value.as_object_mut().unwrap().remove("index");value.as_object_mut().unwrap().insert("name".into(),json!(label));hostile.push(value);
        }}
        boundaries.push(expected);
    }
    assert_eq!(state.replay.text(),reference.text);
    assert_eq!(state.interaction.origin_present,origins.iter().filter(|o|o.present).count() as u32);
    assert_eq!(state.interaction.origin_hid,origins.iter().filter(|o|o.present&&o.state==1).count() as u32);
    for pair in boundaries.windows(2) {assert_eq!(pair[0]["end_root"],pair[1]["start_root"]);assert_eq!(pair[0]["end_offset"],pair[1]["start_offset"]);}
    let final_rules=state.interaction.behavior.rules(&state.replay);
    if mode.is_some() {
        let text=state.replay.text();let canonical=huma_compact_experiment::protocol::canonical(&text);
        let expected=json!({"nonce":["1","2"],"state_root":state.root(nonce,salt).to_string(),
            "capture_root":state.replay.prefix().to_string(),"origin_root":state.interaction.prefix(state.replay.samples).to_string(),
            "op_count":state.replay.offset,"raw_scalars":text.chars().count(),"canonical_scalars":canonical.chars().count(),
            "raw_bytes":text.len(),"canonical_bytes":canonical.len(),
            "raw_commitment":text_commitment(&text,capacity,0).to_string(),"canonical_commitment":text_commitment(canonical,capacity,1).to_string(),
            "rules":final_rules,"policy_satisfied":final_rules.iter().all(|r|*r),
            "origin_present":state.interaction.origin_present,"origin_hid":state.interaction.origin_hid});
        println!("{}",json!({"case":name,"capacity":capacity,"chunkOperations":chunk,
            "inputs":{"salt":["3","4"],"state":state,"expected":expected},"text":text,
            "rawSha256":hex::encode(Sha256::digest(text.as_bytes())),"canonicalSha256":hex::encode(Sha256::digest(canonical.as_bytes())),
            "lastBoundary":boundaries.last(),"expectedAccepted":!canonical.is_empty(),"softwareFixturesOnly":true,
            "ownerIdentityUsed":false,"signaturesVerified":false,"completeHumaSessionProof":false}));return Ok(());
    }
    println!("{}",json!({"case":name,"capacity":capacity,"chunkOperations":chunk,"scalarPack":12,"totalOperations":words.len(),
        "chunks":total,"selected":selected,"hostile":hostile,"boundaries":boundaries,"originResidues":residues,"boundariesWithHeldKeys":held_across,
        "allNativeBoundaryPoliciesMatchSharedPolicy":true,"allCapturePrefixesMatchExistingProtocol":true,
        "allOriginPrefixesMatchExistingProtocol":true,"allNativeBoundaryCountersMatchReplay":true,"finalTextMatchesReplay":true,
        "finalRules":final_rules,"policySatisfied":final_rules.iter().all(|r|*r),"softwareFixturesOnly":true,
        "ownerIdentityUsed":false,"signaturesVerified":false,"completeHumaSessionProof":false,"proofGenerated":false}));
    Ok(())
}
