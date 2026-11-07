//! Replay-continuation reference only. No keys, signatures or owner data.
use huma_compact_experiment::{commit,ops};
use ark_bn254::Fr;
use serde::{Deserialize,Serialize};
use serde_json::json;

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
pub(crate) struct State {
    pub buffer:Vec<u32>,pub left:u32,pub right:u32,pub cursor:u32,pub total:u32,pub target:u32,pub remaining:u32,
    pub phase:u8,pub elapsed:u64,pub edits:u32,pub samples:u32,pub typing:u32,pub paste:u32,pub source:u8,
    pub initial_bytes:u32,pub baseline_end:u32,pub offset:u32,pub head:String,pub tail:[u64;12],
}
fn need(ok:bool)->Result<(),String>{if ok {Ok(())}else{Err("Invalid continuation".into())}}
fn pack(words:&[u64])->[Fr;3] {
    let mut result=[Fr::from(0u64);3];
    for (i,w) in words.iter().enumerate(){
        let mut scale=Fr::from(1u64);for _ in 0..i%4 {scale*=Fr::from(1u64<<62);}
        result[i/4]+=Fr::from(*w)*scale;
    }result
}
impl State {
    pub(crate) fn new(capacity:usize,nonce:[Fr;2],salt:[Fr;2])->Self {
        Self {buffer:vec![0;capacity],left:0,right:capacity as u32,cursor:0,total:0,target:0,remaining:0,
            phase:0,elapsed:0,edits:0,samples:0,typing:0,paste:0,source:0,initial_bytes:0,baseline_end:0,offset:0,
            head:commit::hash(&[Fr::from(0x48554d410301u64),nonce[0],nonce[1],salt[0],salt[1]]).to_string(),tail:[0;12]}
    }
    pub(crate) fn root(&self,nonce:[Fr;2],salt:[Fr;2])->Fr {
        let mut values=vec![Fr::from(0x48554d410601u64),nonce[0],nonce[1],salt[0],salt[1],Fr::from(self.buffer.len() as u64)];
        values.extend([self.left as u64,self.right as u64,self.cursor as u64,self.total as u64,self.target as u64,
            self.remaining as u64,self.phase as u64,self.elapsed,self.edits as u64,self.samples as u64,self.typing as u64,
            self.paste as u64,self.source as u64,self.initial_bytes as u64,self.baseline_end as u64,self.offset as u64].map(Fr::from));
        values.push(commit::parse(&self.head).unwrap());values.extend(self.tail.map(Fr::from));assert_eq!(values.len(),35);
        for group in self.buffer.chunks(12) {
            let (mut packed,mut scale)=(Fr::from(0u64),Fr::from(1u64));
            for value in group {assert!(*value<1<<21);packed+=Fr::from(*value)*scale;scale*=Fr::from(1u64<<21);}
            values.push(packed);
        }
        commit::hash(&values)
    }
    pub(crate) fn prefix(&self)->Fr {
        let p=pack(&self.tail);
        commit::hash(&[Fr::from(0x48554d410303u64),commit::parse(&self.head).unwrap(),Fr::from(self.offset),p[0],p[1],p[2]])
    }
    pub(crate) fn text(&self)->String {
        self.buffer[..self.left as usize].iter().chain(self.buffer[self.right as usize..].iter())
            .map(|n|char::from_u32(*n).unwrap()).collect()
    }
    pub(crate) fn append(&mut self,words:&[u64])->Result<(),String> {
        let mut candidate=self.clone();for word in words {candidate.step(*word)?;}*self=candidate;Ok(())
    }
    pub(crate) fn step(&mut self,word:u64)->Result<(),String> {
        need(word<1u64<<62 && self.offset<65536)?;
        let code=(word>>56) as u8;let arg=word&((1u64<<56)-1);let capacity=self.buffer.len() as u32;
        let scalar=||u32::try_from(arg).ok().and_then(char::from_u32).ok_or("Invalid scalar".to_string());
        match code {
            ops::BASELINE=>{need(self.phase==0&&self.left<self.right)?;let c=scalar()?;
                self.buffer[self.left as usize]=c as u32;self.left+=1;self.cursor+=c.len_utf16() as u32;
                self.total+=c.len_utf16() as u32;self.initial_bytes+=c.len_utf8() as u32;},
            ops::BASELINE_END=>{need(self.phase==0&&arg==0)?;self.phase=1;self.baseline_end=self.offset+1;},
            ops::DOWN|ops::UP=>{need(self.phase==1)?;self.elapsed=self.elapsed.checked_add(arg>>16).ok_or("Elapsed overflow")?;self.samples+=1;},
            ops::BEGIN=>{need(self.phase==1)?;self.target=(arg&65535) as u32;self.remaining=((arg>>16)&65535) as u32;
                self.source=((arg>>32)&255) as u8;
                need(self.target<=self.total && self.remaining<=self.total-self.target && matches!(self.source,1..=6|255))?;
                self.elapsed=self.elapsed.checked_add(arg>>40).ok_or("Elapsed overflow")?;self.phase=2;},
            ops::LEFT=>{need(arg==0&&self.phase==2&&self.cursor>self.target&&self.left>0)?;
                self.left-=1;self.right-=1;self.buffer[self.right as usize]=self.buffer[self.left as usize];
                self.cursor-=char::from_u32(self.buffer[self.right as usize]).unwrap().len_utf16() as u32;},
            ops::RIGHT=>{need(arg==0&&self.phase==2&&self.cursor<self.target&&self.right<capacity)?;
                self.buffer[self.left as usize]=self.buffer[self.right as usize];
                self.cursor+=char::from_u32(self.buffer[self.left as usize]).unwrap().len_utf16() as u32;self.left+=1;self.right+=1;},
            ops::DELETE=>{need(arg==0&&matches!(self.phase,2|3)&&self.cursor==self.target&&self.right<capacity)?;
                let width=char::from_u32(self.buffer[self.right as usize]).unwrap().len_utf16() as u32;
                need(self.remaining>=width)?;self.remaining-=width;self.total-=width;self.right+=1;self.phase=3;},
            ops::INSERT=>{need(matches!(self.phase,2..=4)&&self.remaining==0&&(self.phase==4||self.cursor==self.target)&&self.left<self.right)?;
                let c=scalar()?;self.buffer[self.left as usize]=c as u32;self.left+=1;
                self.cursor+=c.len_utf16() as u32;self.total+=c.len_utf16() as u32;self.phase=4;},
            ops::END=>{need(arg==0&&matches!(self.phase,2..=4)&&self.remaining==0&&(self.phase==4||self.cursor==self.target))?;
                self.phase=1;self.edits+=1;self.typing+=u32::from(self.source==1);self.paste+=u32::from(self.source==2);},
            ops::ADVANCE=>{need(self.phase==1&&arg>0)?;self.elapsed=self.elapsed.checked_add(arg).ok_or("Elapsed overflow")?;},
            ops::FLAGS_LOW|ops::FLAGS_HIGH=>need(self.phase==1&&arg<=u32::MAX as u64)?,
            _=>return Err("Invalid opcode".into()),
        }
        self.tail[self.offset as usize%12]=word;self.offset+=1;
        if self.offset%12==0 {
            let p=pack(&self.tail);self.head=commit::hash(&[Fr::from(0x48554d410302u64),commit::parse(&self.head)?,p[0],p[1],p[2]]).to_string();self.tail=[0;12];
        }
        Ok(())
    }
}
#[derive(Clone,Serialize)]
struct Boundary {nonce:[String;2],start_root:String,end_root:String,start_offset:u32,end_offset:u32,capture_root:String,final_step:bool}
fn links(boundaries:&[Boundary])->bool {
    !boundaries.is_empty() && boundaries[0].start_offset==0 && boundaries.iter().enumerate().all(|(i,b)|
        b.end_offset>b.start_offset && b.final_step==(i+1==boundaries.len()) && (i==0 || {
            let p=&boundaries[i-1];p.end_offset==b.start_offset && p.end_root==b.start_root && p.nonce==b.nonce
        }))
}
// Operations per 10k-capacity chunk. 120 reproduces the earlier experiments; 528 and 1440
// fill the prover's 2^19 / 2^20 padding (measured 520,299 / 1,043,863 gates).
// Non-final chunks must stay aligned to the 12-word capture packing.
fn large_chunk()->Result<usize,String> {
    let chunk=match std::env::var("HUMA_CHUNK_OPS") {Ok(v)=>v.parse::<usize>().map_err(|_|"Invalid HUMA_CHUNK_OPS")?,Err(_)=>120};
    if chunk==0||chunk%12!=0||chunk>2400 {return Err("HUMA_CHUNK_OPS must be a multiple of 12 up to 2400".into());}
    Ok(chunk)
}
pub(crate) fn fixture(name:&str)->Result<(Vec<u64>,usize,usize),String> {
    let capacity=if name=="revision" {64}else{10000};let chunk=if name=="revision" {12}else{large_chunk()?};
    let baseline=if name=="revision" {"🍁x".into()}else if name=="baseline10000" {"😀".repeat(10000)}else{String::new()};
    let mut b=ops::Builder::new(&baseline,capacity,65536)?;
    if name=="revision" {
        b.sample("down",1,0,10)?;b.edit(0,3,"ab😀z","typing",11)?;b.sample("up",1,0,80)?;
        b.edit(2,2,"é","typing",100)?;b.edit(3,0,"\u{301}","typing",200)?;
        b.edit(5,0,"q","paste",300)?;b.sample("down",2,1u64<<50,310)?;b.sample("up",2,0,380)?;
    } else if name!="baseline10000" {
        need(["typing10000","emoji10000"].contains(&name))?;
        for i in 0..10000 {
            let at=100+i as u64*160;let flags=if i==5000 {1u64<<50}else{0};
            b.sample("down",(i%128) as u16,flags,at)?;
            b.edit(if name=="emoji10000" {i*2}else{i},0,if name=="emoji10000" {"😀"}else{"a"},"typing",at+1)?;
            b.sample("up",(i%128) as u16,flags,at+65)?;
        }
    }
    Ok((b.words,capacity,chunk))
}
fn main()->Result<(),String> {
    let name=std::env::args().nth(1).ok_or("Expected case")?;
    let (words,capacity,chunk)=fixture(&name)?;
    let nonce=[Fr::from(1u64),Fr::from(2u64)];let salt=[Fr::from(3u64),Fr::from(4u64)];
    let reference=ops::replay(&words,capacity)?;let transcript=commit::Transcript::new(nonce,salt,&words);
    let mut state=State::new(capacity,nonce,salt);let mut boundaries=vec![];let mut selected=vec![];let mut hostile=vec![];
    let total=words.len().div_ceil(chunk);
    for (i,part) in words.chunks(chunk).enumerate() {
        let before=state.clone();let start_root=before.root(nonce,salt);state.append(part)?;
        let expected=Boundary {nonce:["1".into(),"2".into()],start_root:start_root.to_string(),end_root:state.root(nonce,salt).to_string(),
            start_offset:before.offset,end_offset:state.offset,capture_root:state.prefix().to_string(),final_step:i+1==total};
        let p=&reference.prefixes[state.offset as usize];
        assert_eq!((state.phase,state.elapsed,state.edits,state.samples,state.typing,state.paste,state.initial_bytes),
            (p.phase,p.elapsed,p.edits,p.samples,p.typing,p.paste,p.initial_bytes));
        assert_eq!(state.prefix(),transcript.prefix(&words,state.offset as usize));
        if name=="revision" || [0,total/2,total-1].contains(&i) {
            let mut ops=part.iter().map(|word|json!({"code":word>>56,"arg":word&((1u64<<56)-1)})).collect::<Vec<_>>();
            ops.resize(chunk,json!({"code":0,"arg":0}));
            selected.push(json!({"index":i,"salt":["3","4"],"state":before,"ops":ops,"op_count":part.len(),"expected":expected}));
        }
        if i==0 {
            for label in ["ForgedGenesisTime","DirtyGenesisBuffer"] {
                let mut bad=before.clone();
                if label=="ForgedGenesisTime" {bad.elapsed=1;}else{bad.buffer[capacity/2]=97;}
                let bad_start=bad.root(nonce,salt);let supplied=bad.clone();bad.append(part)?;
                let mut claimed=expected.clone();claimed.start_root=bad_start.to_string();claimed.end_root=bad.root(nonce,salt).to_string();
                let mut ops=part.iter().map(|word|json!({"code":word>>56,"arg":word&((1u64<<56)-1)})).collect::<Vec<_>>();
                ops.resize(chunk,json!({"code":0,"arg":0}));
                hostile.push(json!({"name":label,"salt":["3","4"],"state":supplied,"ops":ops,"op_count":part.len(),"expected":claimed}));
            }
        }
        boundaries.push(expected);
    }
    assert!(links(&boundaries));assert_eq!(state.text(),reference.text);assert_eq!(state.baseline_end as usize,reference.baseline_end);
    let mut dropped=boundaries.clone();if dropped.len()>2 {dropped.remove(1);assert!(!links(&dropped));}
    let mut reordered=boundaries.clone();if reordered.len()>2 {reordered.swap(1,2);assert!(!links(&reordered));}
    let before=state.clone();assert!(state.append(&[ops::word(ops::ADVANCE,1),ops::word(ops::INSERT,0xd800)]).is_err());assert_eq!(state,before);
    println!("{}",json!({"case":name,"capacity":capacity,"chunkOperations":chunk,"totalOperations":words.len(),
        "chunks":total,"scalarPack":12,"selected":selected,"hostile":hostile,"allNativeBoundariesMatchIndependentReplay":true,
        "capturePrefixesMatchExistingProtocol":true,"droppedAndReorderedChunksRejected":true,
        "invalidAppendRollsBack":true,"finalScalars":reference.text.chars().count(),"finalBytes":reference.text.len(),
        "boundaries":boundaries,"completeHumaSessionProof":false,"signaturesVerified":false,"proofGenerated":false}));
    Ok(())
}
