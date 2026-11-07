//! Synthetic software-key long sessions for circuit checks. Never an owner key or app data.
use huma_compact_experiment::{assurance::Origin,assurance_capture::{LiveAssuranceCapture,LONG_PROFILE},long};
use p256::ecdsa::{signature::Signer,Signature,SigningKey};
use rand_core::OsRng;
use serde_json::json;

fn approve(c:&mut LiveAssuranceCapture,key:&SigningKey) {
    let signature:Signature=key.sign(&c.pending_message().unwrap());c.accept(signature.to_der().as_bytes().to_vec()).unwrap();
}
fn main()->Result<(),String> {
    let args:Vec<String>=std::env::args().collect();
    let chars:usize=args.get(1).ok_or("chars")?.parse().map_err(|_|"chars")?;
    let every:usize=args.get(2).ok_or("every")?.parse().map_err(|_|"every")?;
    let initial=args.get(3).cloned().unwrap_or_default();
    let cuts=args.get(4).is_some_and(|a|a=="--cuts");
    let key=SigningKey::random(&mut OsRng);
    let mut c=LiveAssuranceCapture::with_profile(&initial,key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),1_700_000_000_000,LONG_PROFILE)?;
    approve(&mut c,&key);let mut text=initial.clone();let mut t=100u64;let mut nonce=1u8;let mut background=vec![];let mut tier=serde_json::Value::Null;
    for i in 0..chars {
        let origin=Origin {present:true,pid:0,state:1,keyboard:40,repeated:false};let code=(i%40) as u16;
        c.sample("down",code,0,t,origin.clone())?;
        let units=text.encode_utf16().count();
        if i%97==96 {let last=text.chars().last().map_or(1,char::len_utf16);c.edit(units-last,last,"","typing",t+1)?;text.pop();}
        else {let s=if i%50==7 {"é"}else if i%333==5 {"😀"}else{"a"};c.edit(units,0,s,"typing",t+1)?;text.push_str(s);}
        c.sample("up",code,0,t+60,origin)?;t+=if i%40==39 {700}else{160};
        if i%every==every-1 {c.prepare(1_700_000_000_000+t,t,false,&text)?;approve(&mut c,&key);}
        if i%600==300 {c.issue([nonce;32],1,t)?;nonce+=1;c.respond(if i%1200==300 {2}else{1},t+900)?;
            if c.pending_message().is_ok() {approve(&mut c,&key);}t+=1000;}
        // As the app does: close the open part at a pause once it holds 450 of its 600 operations.
        if cuts && i%150==149 && c.info()["openOperations"].as_u64().unwrap_or(0)>=450 {c.long_cut()?;}
        // Parts proved while writing: again from the first when the text outgrows its tier.
        while c.long_chunks().len()>background.len() {
            let part=c.long_chunk(background.len())?;
            if part["tier"]!=tier {tier=part["tier"].clone();background.clear();continue;}
            background.push(part["input"].clone());
        }
    }
    if cuts {c.long_cut()?;}
    c.issue([200;32],2,t)?;c.respond(1,t+500)?;approve(&mut c,&key);
    c.prepare(1_700_000_005_000+t,t+600,true,&text)?;approve(&mut c,&key);
    while c.long_chunks().len()>background.len() {
        let part=c.long_chunk(background.len())?;
        if part["tier"]!=tier {tier=part["tier"].clone();background.clear();continue;}
        background.push(part["input"].clone());
    }
    let snapshot=c.snapshot()?;
    let private:huma_compact_experiment::assurance::Private=serde_json::from_value(snapshot["private"].clone()).map_err(|e|e.to_string())?;
    let plan:Vec<long::Chunk>=serde_json::from_value(snapshot["plan"].clone()).map_err(|e|e.to_string())?;
    let capsule:long::Capsule=serde_json::from_value(snapshot["capsule"].clone()).map_err(|e|e.to_string())?;
    let session=long::Session::new(&private,true,&plan,long::Format::V3)?;let (_,signed,state,_)=session.run()?;
    let events:String=signed.iter().map(|(k,_)|if *k==1 {'1'}else{'2'}).collect();
    let (final_input,_)=session.final_input(&state,None)?;
    println!("{}",json!({"chars":chars,"every":every,"text":text,"tier":session.capacity,"chunks":background,"final":final_input,"capsule":snapshot["capsule"],
        "events":events,"softwareKeyOnly":true}));
    Ok(())
}
