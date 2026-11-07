//! New disposable software-key boundary fixtures. Never uses an enrolled key.
use huma_compact_experiment::{assurance::{self,Origin,Presence,Private},ops,protocol};
use serde_json::json;
use p256::ecdsa::{signature::Signer,Signature,SigningKey};
use rand_core::OsRng;
fn fixture(name:&str,capacity:usize)->Result<serde_json::Value,String> {
    let mut builder=ops::Builder::new("",256,1536)?;let mut origins=vec![];
    for i in 0..40 {
        let at=100+i*550+if i>=30 {700}else{0};
        for (kind,at) in [("down",at),("up",at+65)] {
            builder.sample(kind,(i%8) as u16,0,at)?;
            origins.push(Origin {present:true,state:1,..Origin::default()});
        }
    }
    let count=capacity+usize::from(name.starts_with("Overflow"));
    let text=if name=="FullAscii" {"a".repeat(count)}else{"😀".repeat(count)};
    let at=builder.elapsed()+100;
    builder.edit(0,0,&text,"typing",at)?;
    if name=="DeleteAllUnicode" {builder.edit(0,count*2,"x","typing",at+100)?;}
    if name=="OverflowAfterDeletion" {builder.edit(2,(count-1)*2,"","typing",at+100)?;}
    let text=builder.text();
    let private=Private {replay:protocol::PrivateWitness {nonce:["1".into(),"2".into()],salt:["3".into(),"4".into()],
        checkpoints:vec![protocol::Checkpoint {offset:1,unix:1792627200000,elapsed:0},
            protocol::Checkpoint {offset:builder.words.len(),unix:1792627235000,elapsed:35000}],words:builder.words},
        origins,presence:vec![Presence {offset:builder.capture_offsets.last().copied().unwrap(),nonce:["11".into(),"12".into()],
            reason:2,issued:34000,answered:34400,outcome:1}],checkpoint_presence:vec![0,1]};
    let journal=assurance::statement(&private,256)?;
    let key=SigningKey::random(&mut OsRng);
    let sign=|roots:&[String],domain:&[u8]|roots.iter().map(|root|{
        let signature:Signature=key.sign(&assurance::message(domain,root).unwrap());signature.to_der().as_bytes().to_vec()
    }).collect();
    let capsule=assurance::Capsule {kind:assurance::KIND.into(),signatures:sign(&journal.checkpoint_roots,assurance::CP_DOMAIN),
        presence_signatures:sign(&journal.presence_roots,assurance::PRESENCE_DOMAIN),journal,
        public_key:key.verifying_key().to_encoded_point(false).as_bytes().to_vec()};
    assurance::verify(&capsule)?;
    let accepted=assurance::statement(&private,capacity).is_ok();
    assert_eq!(accepted,!name.starts_with("Overflow"));
    assert!(capsule.journal.policy_satisfied);
    Ok(json!({"name":name,"private":private,"capsule":capsule,"text":text,"accepted":accepted,
        "softwareKeysOnly":true,"proofGenerated":false}))
}
fn main()->Result<(),String> {
    let capacity=std::env::args().nth(1).ok_or("Expected capacity")?.parse::<usize>().map_err(|_|"Invalid capacity")?;
    if ![64,128].contains(&capacity) {return Err("Unsupported test capacity".into());}
    let result=["FullAscii","FullUnicode","DeleteAllUnicode","OverflowScalars","OverflowAfterDeletion"]
        .into_iter().map(|name|fixture(name,capacity)).collect::<Result<Vec<_>,_>>()?;
    println!("{}",serde_json::to_string(&result).unwrap());Ok(())
}
