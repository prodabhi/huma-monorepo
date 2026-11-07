//! Positive live-capture boundaries, signed as each checkpoint occurs.
use huma_compact_experiment::capture::{LiveCapture,SCALARS,CHECKPOINTS};
use p256::ecdsa::{signature::Signer,Signature,SigningKey};
use rand_core::OsRng;
use serde_json::{json,Value};
fn start(text: &str)->(LiveCapture,SigningKey) {
    let key=SigningKey::random(&mut OsRng);
    let mut capture=LiveCapture::new(text,key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),10).unwrap();
    approve(&mut capture,&key);(capture,key)
}
fn approve(capture: &mut LiveCapture,key: &SigningKey) {
    let sig:Signature=key.sign(&capture.pending_message().unwrap());capture.accept(sig.to_der().as_bytes().to_vec()).unwrap();
}
fn finish(name: &str,mut capture: LiveCapture,key: &SigningKey,text: &str,elapsed: u64)->Value {
    capture.prepare(9,elapsed,true,text).unwrap();approve(&mut capture,key);
    json!({"name":name,"snapshot":capture.snapshot().unwrap()})
}
fn main() {
    let (mut unicode,key)=start("a😀z");
    unicode.sample("down",65535,0x8000000100000002,(1u64<<40)+2).unwrap();
    unicode.edit(1,2,"e\u{301}","composition",(1u64<<40)+70000).unwrap();
    unicode.edit(0,1,"é","paste",(1u64<<40)+70001).unwrap();
    unicode.edit(4,0,"! \t","typing",(1u64<<40)+70002).unwrap();
    unicode.sample("up",65535,0,(1u64<<40)+70003).unwrap();
    let unicode=finish("LiveUnicodeFlagsCursor",unicode,&key,"ée\u{301}z! \t",(1u64<<40)+70003);
    let (mut time,key)=start("a");time.sample("down",1,0,u64::MAX).unwrap();
    let time=finish("LiveU64Maximum",time,&key,"a",u64::MAX);
    let initial="😀".repeat(SCALARS);let (mut maximum,key)=start(&initial);
    for i in 0..CHECKPOINTS-2 {
        maximum.sample("down",1,0,i as u64).unwrap();maximum.prepare(20+i as u64,i as u64,false,&initial).unwrap();approve(&mut maximum,&key);
    }
    let maximum=finish("Live256Scalars1024Bytes8Checkpoints",maximum,&key,&initial,10);
    let (mut operations,key)=start("a");for _ in 0..1534 {operations.sample("down",1,0,0).unwrap();}
    let operations=finish("Live1536Operations",operations,&key,"a",0);
    println!("{}",json!([unicode,time,maximum,operations]));
}
