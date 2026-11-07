//! Deliberately forged statements for circuit testing, never a proof producer.
use huma_compact_experiment::{commit,ops,protocol::{self,Checkpoint,Journal,PrivateWitness}};
use ark_bn254::Fr;
use serde::Serialize;
use sha2::{Digest,Sha256};

#[derive(Serialize)]
struct Case { name: &'static str, private: PrivateWitness, expected: Journal, accepted: bool }
fn make(name: &'static str,words: Vec<u64>,text: &[u8],initial: u32,
        elapsed: u64,edits: u32,samples: u32,typing: u32,accepted: bool) -> Case {
    let first=words.iter().position(|w|(*w>>56) as u8==ops::BASELINE_END).unwrap()+1;
    let nonce=["1".to_string(),"2".to_string()];let salt=["3".to_string(),"4".to_string()];
    let transcript=commit::Transcript::new([Fr::from(1u64),Fr::from(2u64)],[Fr::from(3u64),Fr::from(4u64)],&words);
    let private=PrivateWitness {nonce:nonce.clone(),salt,checkpoints:vec![
        Checkpoint {offset:first,unix:0,elapsed:0},Checkpoint {offset:words.len(),unix:1,elapsed}],words};
    let digest:[u8;32]=Sha256::digest(text).into();let halves=commit::halves(&digest);
    let mut previous=Fr::from(0u64);let mut roots=Vec::new();
    for (i,c) in private.checkpoints.iter().enumerate() {
        let last=i==1;let e=if last {edits}else{0};let s=if last {samples}else{0};
        previous=commit::hash(&[Fr::from(commit::CHECKPOINT),transcript.prefix(&private.words,c.offset),
            Fr::from(i as u64),Fr::from((e+s) as u64),Fr::from(e as u64),Fr::from(s as u64),
            Fr::from(c.unix),Fr::from(c.elapsed),Fr::from(last as u64),previous,
            if last {halves[0]}else{Fr::from(0u64)},if last {halves[1]}else{Fr::from(0u64)}]);
        roots.push(previous.to_string());
    }
    let expected=Journal {session_nonce:nonce,capture_root:transcript.prefix(&private.words,private.words.len()).to_string(),
        text_hash:digest,byte_length:text.len() as u32,raw_byte_length:text.len() as u32,initial_bytes:initial,
        edits,samples,captures:edits+samples,typing,paste:0,op_count:private.words.len() as u32,
        start_unix:0,end_unix:1,elapsed,clock_back:false,checkpoint_roots:roots};
    let matches=protocol::statement(&private,64).map(|j|j==expected).unwrap_or(false);
    assert_eq!(matches,accepted,"Independent native reference disagrees for {name}");
    Case {name,private,expected,accepted}
}
fn main() {
    use ops::*;
    let simple=vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0),word(DOWN,80<<16|1),word(UP,1<<16|1)];
    let mut overflow=vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0)];
    overflow.extend(std::iter::repeat_n(word(ADVANCE,(1u64<<56)-1),257));
    let wrapped=(257u128*((1u128<<56)-1)) as u64;
    let cases=vec![
        make("ValidUnicodeRevision",vec![word(BASELINE,0x1f600),word(BASELINE,b'b' as u64),word(BASELINE_END,0),
            word(BEGIN,(2<<16)|(1<<32)),word(LEFT,0),word(LEFT,0),word(DELETE,0),word(INSERT,0xe9),word(END,0),
            word(BEGIN,2|(1<<32)),word(RIGHT,0),word(INSERT,0x10ffff),word(END,0)],"éb\u{10ffff}".as_bytes(),5,0,2,0,2,true),
        make("ValidLargeAdvance",vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0),word(ADVANCE,(1u64<<56)-1)],
            b"b",1,(1u64<<56)-1,0,0,0,true),
        make("MoveAwayAndBack",vec![word(BASELINE,b'a' as u64),word(BASELINE,b'b' as u64),word(BASELINE_END,0),
            word(BEGIN,2|(1<<32)),word(LEFT,0),word(RIGHT,0),word(END,0)],b"ab",2,0,1,0,1,false),
        make("InsertWithoutBegin",vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0),word(INSERT,b'c' as u64),word(END,0)],
            b"bc",1,0,1,0,0,false),
        make("EndBeforeDeletion",vec![word(BASELINE,b'a' as u64),word(BASELINE,b'b' as u64),word(BASELINE_END,0),
            word(BEGIN,1|(1<<16)|(1<<32)),word(LEFT,0),word(END,0)],b"ab",2,0,1,0,1,false),
        make("BeginPastEnd",vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0),word(BEGIN,2|(1<<32)),word(END,0)],
            b"b",1,0,1,0,1,false),
        make("ValidSemantic",simple.clone(),b"b",1,81,0,2,0,true),
        make("ElapsedOverflow",overflow,b"b",1,wrapped,0,0,0,false),
        make("MidEditSample",vec![word(BASELINE,b'b' as u64),word(BASELINE_END,0),
             word(BEGIN,1|(1<<32)),word(DOWN,80<<16|1),word(END,0)],b"b",1,80,1,1,1,false),
        make("SplitSurrogate",vec![word(BASELINE,0x1f600),word(BASELINE_END,0),
             word(BEGIN,1|(1<<32)),word(LEFT,0),word(END,0)],"😀".as_bytes(),4,0,1,0,1,false),
        make("InvalidUnicode",vec![word(BASELINE,0xd800),word(BASELINE_END,0)],&[0xed,0xa0,0x80],3,0,0,0,0,false),
        make("ForgedFinalText",simple,b"c",1,81,0,2,0,false),
    ];
    println!("{}",serde_json::to_string_pretty(&cases).unwrap());
}
