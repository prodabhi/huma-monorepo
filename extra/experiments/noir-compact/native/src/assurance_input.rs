//! Complete new-session input binding. Recomputes the capture projection without
//! creating a key, replacing a nonce, dropping records or issuing new signatures.
use crate::{assurance::{self,Origin,Presence,Private,Journal,Capsule},assurance_capture::{checkpoint_limit,PROFILE,EXTENDED_PROFILE,SAMPLES,PRESENCE},capture::{SCALARS,OPERATIONS},commit,ops,protocol};
use huma_replay_core::Witness;
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};

#[derive(Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub profile:String,pub sealed:bool,pub private:Private,pub capsule:Capsule,pub text:String,pub experimental:bool,
}
#[derive(Clone,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {pub witness:Witness,pub snapshot:Snapshot}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {pub ok:bool,pub result:Snapshot}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppInput {pub witness:Witness,pub snapshot:SnapshotEnvelope}
fn need(ok:bool)->Result<(),String> {if ok {Ok(())}else{Err("Live V4 input differs from its complete signed session".into())}}

pub fn validate(w:&Witness,snapshot:&Snapshot)->Result<Journal,String> {
    let checkpoints=checkpoint_limit(&snapshot.profile).ok_or("Unsupported assurance capture profile")?;
    need(snapshot.sealed && snapshot.experimental && snapshot.text.as_bytes()==w.text.as_bytes())?;
    let s=&w.session;
    let cps=s.signed_checkpoints.as_deref().ok_or("Missing live checkpoints")?;
    let records=s.capture_records.as_deref().ok_or("Missing live capture order")?;
    let samples=s.input_samples.as_deref().unwrap_or(&[]);
    let events=s.presence_events.as_deref().unwrap_or(&[]);
    need(s.presence_protocol.as_deref()==Some("local-presence-v1") && (2..=checkpoints).contains(&cps.len())
        && samples.len()<=SAMPLES && events.len()<=PRESENCE*2 && s.events.len()<=OPERATIONS
        && records.len()<=OPERATIONS+PRESENCE*2 && w.text.len()<=1024
        && snapshot.private.replay.words.len()<=OPERATIONS && snapshot.private.origins.len()<=SAMPLES
        && snapshot.private.presence.len()<=PRESENCE && snapshot.private.replay.checkpoints.len()<=checkpoints
        && snapshot.capsule.signatures.len()<=checkpoints && snapshot.capsule.presence_signatures.len()<=PRESENCE)?;
    let legacy=huma_replay_core::replay(w).map_err(str::to_string)?;
    let expected=rebuild(w,&snapshot.private.replay.nonce,&snapshot.private.replay.salt,SCALARS,OPERATIONS)?;
    need(expected==snapshot.private)?;
    let journal=assurance::statement(&expected,SCALARS)?;
    need(journal==snapshot.capsule.journal)?;
    let key=assurance::verify(&snapshot.capsule)?;
    need(legacy.capture_key_hash.as_deref()==Some(key.as_str()))?;
    Ok(journal)
}

pub fn inputs(w:&Witness,snapshot:&Snapshot)->Result<Value,String> {
    let journal=validate(w,snapshot)?;
    let limits=crate::profile_fit::limits_for_profile(&snapshot.profile).ok_or("Unsupported assurance capture profile")?;
    padded_inputs(snapshot,journal,limits)
}
fn padded_inputs(snapshot:&Snapshot,journal:Journal,limits:crate::profile_fit::Limits)->Result<Value,String> {
    let private=&snapshot.private;let r=&private.replay;let capacity=limits.cps;
    need(r.words.len()<=limits.ops && r.checkpoints.len()<=capacity && private.origins.len()<=limits.samples
        && private.presence.len()<=limits.pres && snapshot.text.len()<=limits.bytes)?;
    need(assurance::statement(private,limits.scalars)?==journal)?;
    let mut checkpoints=r.checkpoints.iter().zip(&private.checkpoint_presence).map(|(c,count)|json!({"offset":c.offset,"unix":c.unix,"elapsed":c.elapsed,"presence":count})).collect::<Vec<_>>();
    let count=checkpoints.len();
    checkpoints.resize(capacity,json!({"offset":0,"unix":0,"elapsed":0,"presence":0}));
    let replay=ops::replay(&r.words,limits.scalars)?;
    let mut timings=r.words.iter().enumerate().filter_map(|(i,word)|{
        let code=(word>>56) as u8;
        matches!(code,ops::DOWN|ops::UP).then(||json!({"offset":i,"elapsed":replay.prefixes[i+1].elapsed,"key":word&65535,"up":code==ops::UP}))
    }).collect::<Vec<_>>();
    need(timings.len()<=limits.samples)?;timings.resize(limits.samples,json!({"offset":0,"elapsed":0,"key":0,"up":false}));
    let mut operations=r.words.iter().map(|word|json!({"code":word>>56,"arg":word&((1u64<<56)-1)})).collect::<Vec<_>>();
    operations.resize(limits.ops,json!({"code":0,"arg":0}));
    let mut origins=private.origins.iter().map(|o|serde_json::to_value(o).unwrap()).collect::<Vec<_>>();
    origins.resize(limits.samples,json!({"present":false,"pid":0,"state":0,"keyboard":0,"repeated":false}));
    let mut presence=private.presence.iter().map(|p|serde_json::to_value(p).unwrap()).collect::<Vec<_>>();
    presence.resize(limits.pres,json!({"offset":0,"nonce":["0","0"],"reason":0,"issued":0,"answered":0,"outcome":0}));
    let mut expected=serde_json::to_value(journal).unwrap();
    expected["replay"]["checkpoint_count"]=json!(count);
    expected["replay"]["checkpoint_roots"].as_array_mut().unwrap().resize(capacity,json!("0"));
    expected["checkpoint_roots"].as_array_mut().unwrap().resize(capacity,json!("0"));
    expected["presence_roots"].as_array_mut().unwrap().resize(limits.pres,json!("0"));
    Ok(json!({"nonce":r.nonce,"salt":r.salt,"ops":operations,"op_count":r.words.len(),"checkpoints":checkpoints,
        "timings":timings,"origins":origins,"presence":presence,"expected":expected}))
}

/// Lossless bridge to the bundled ACVM runtime. Private u64 values must never
/// pass through a JavaScript Number, including values near u64::MAX.
fn exact_numbers(value:Value)->Value {
    match value {
        Value::Number(n)=>Value::String(n.to_string()),
        Value::Array(items)=>Value::Array(items.into_iter().map(exact_numbers).collect()),
        Value::Object(items)=>Value::Object(items.into_iter().map(|(k,v)|(k,exact_numbers(v))).collect()),
        v=>v,
    }
}
fn flatten_public(value:&Value,abi:&Value,out:&mut Vec<u8>)->Result<(),String> {
    match abi["kind"].as_str() {
        Some("struct")=>for field in abi["fields"].as_array().ok_or("Invalid bundled ABI")? {
            let name=field["name"].as_str().ok_or("Invalid bundled field")?;
            flatten_public(value.get(name).ok_or("Missing public field")?,&field["type"],out)?;
        },
        Some("array")=>{
            let items=value.as_array().ok_or("Invalid public array")?;
            need(Some(items.len() as u64)==abi["length"].as_u64())?;
            for item in items {flatten_public(item,&abi["type"],out)?;}
        },
        Some("field")|Some("integer")|Some("boolean")=>{
            let decimal=match value {
                Value::Bool(b)=>if *b {"1".into()} else {"0".into()},
                Value::String(s)=>s.clone(),Value::Number(n)=>n.to_string(),
                _=>return Err("Invalid public scalar".into()),
            };
            out.extend_from_slice(&commit::bytes(commit::parse(&decimal)?));
        },
        _=>return Err("Unsupported bundled ABI".into()),
    }
    Ok(())
}
pub fn worker_input(w:&Witness,snapshot:&Snapshot)->Result<Value,String> {
    let values=inputs(w,snapshot)?;
    prepared_input(snapshot,values,checkpoint_limit(&snapshot.profile).ok_or("Unsupported capture profile")?)
}
pub fn sized_worker_input(w:&Witness,snapshot:&Snapshot,requested:Option<&str>)->Result<Value,String> {
    let journal=validate(w,snapshot)?;
    let profile=match requested {Some(profile)=>profile,None=>crate::profile_fit::smallest_validated(snapshot,&journal)?};
    let limits=crate::profile_fit::limits_for_profile(profile).ok_or("Unsupported proof profile")?;
    let values=padded_inputs(snapshot,journal,limits)?;
    let mut prepared=prepared_input(snapshot,values,limits.cps)?;
    prepared["provingProfile"]=json!(profile);Ok(prepared)
}
fn prepared_input(snapshot:&Snapshot,values:Value,capacity:usize)->Result<Value,String> {
    let (abi,length)=match capacity {
        8=>(include_str!("../../browser/assets/assurance-abi.json"),3008),
        32=>(include_str!("../../browser/assets/assurance-cp32-abi.json"),4544),
        _=>return Err("Unsupported public checkpoint capacity".into()),
    };
    let abi:Value=serde_json::from_str(abi).map_err(|_|"Invalid bundled ABI")?;
    let mut public=vec![];flatten_public(&values["expected"],&abi,&mut public)?;need(public.len()==length)?;
    let c=&snapshot.capsule;
    let mut journal=serde_json::to_value(&c.journal).map_err(|_|"Invalid journal")?;
    for field in ["start_unix","end_unix","elapsed"] {journal["replay"][field]=Value::String(journal["replay"][field].to_string());}
    for field in ["median_response","longest_gap"] {journal[field]=Value::String(journal[field].to_string());}
    Ok(json!({"captureProfile":snapshot.profile,"inputs":exact_numbers(values),"publicInputsHex":hex::encode(public),"journal":journal,
        "text":snapshot.text,"publicKeyHex":hex::encode(&c.public_key),
        "signaturesHex":c.signatures.iter().map(hex::encode).collect::<Vec<_>>(),
        "presenceSignaturesHex":c.presence_signatures.iter().map(hex::encode).collect::<Vec<_>>()}))
}

/// Recompute the compact projection of a complete signed Swift session: every edit,
/// key sample, presence event and checkpoint, in capture order. Nothing is dropped.
pub fn rebuild(w:&Witness,nonce:&[String;2],salt:&[String;2],scalars:usize,operations:usize)->Result<Private,String> {
    let s=&w.session;
    let cps=s.signed_checkpoints.as_deref().ok_or("Missing live checkpoints")?;
    let records=s.capture_records.as_deref().ok_or("Missing live capture order")?;
    let samples=s.input_samples.as_deref().unwrap_or(&[]);
    let events=s.presence_events.as_deref().unwrap_or(&[]);
    let mut builder=ops::Builder::new(&s.initial_text,scalars,operations)?;
    let mut origins=vec![];let mut presence=vec![];let mut offsets=vec![builder.words.len()];let mut counts=vec![0];
    let mut pending_at=vec![false];let mut issue=None;
    for capture in records {
        match capture.kind.as_str() {
            "edit"=>{
                need(issue.is_none())?;let e=s.events.get(capture.index).ok_or("Missing live edit")?;
                // The recorder counts these labels as typing (crate::web::proved_source); the log keeps the label.
                builder.edit(e.location,e.removed_length,&e.inserted_text,crate::web::proved_source(&e.source),e.elapsed_milliseconds)?;
            },
            "key"=>{
                need(issue.is_none())?;let e=samples.get(capture.index).ok_or("Missing live sample")?;
                need(e.key_code<256)?;
                builder.sample(&e.kind,e.key_code,e.modifiers,e.elapsed_milliseconds)?;origins.push(Origin::from_sample(e)?);
            },
            "presence"=>{
                let e=events.get(capture.index).ok_or("Missing live presence event")?;
                if e.kind=="challenge" {need(issue.is_none())?;issue=Some(e);}
                else {
                    let issued=issue.take().ok_or("Missing live presence issue")?;
                    let nonce:[u8;32]=hex::decode(&issued.nonce).map_err(|_|"Invalid live nonce")?.try_into().map_err(|_|"Invalid live nonce length")?;
                    presence.push(Presence {offset:builder.words.len(),nonce:commit::halves(&nonce).map(|n|n.to_string()),
                        reason:match issued.reason.as_str(){"interval"=>1,"seal"=>2,_=>return Err("Invalid live presence reason".into())},
                        issued:issued.elapsed_milliseconds,answered:e.elapsed_milliseconds,
                        outcome:match e.outcome.as_str(){"approved"=>1,"cancelled"=>2,"timedOut"=>3,"interrupted"=>4,_=>return Err("Invalid live presence outcome".into())}});
                }
            },
            _=>return Err("Unsupported live capture kind".into()),
        }
        offsets.push(builder.words.len());counts.push(presence.len());pending_at.push(issue.is_some());
    }
    need(issue.is_none() && builder.text().as_bytes()==w.text.as_bytes())?;
    let mut checkpoints=vec![];let mut checkpoint_presence=vec![];
    for c in cps {
        let time=c.reported_time.as_ref().ok_or("Live V4 needs signed time fields")?;
        need(c.version==2 && !*pending_at.get(c.capture_count).ok_or("Invalid live checkpoint boundary")?)?;
        checkpoints.push(protocol::Checkpoint {offset:*offsets.get(c.capture_count).ok_or("Invalid live checkpoint offset")?,
            unix:time.unix_milliseconds,elapsed:time.elapsed_milliseconds});
        checkpoint_presence.push(counts[c.capture_count]);
    }
    Ok(Private {replay:protocol::PrivateWitness {nonce:nonce.clone(),salt:salt.clone(),words:builder.words,checkpoints},origins,presence,checkpoint_presence})
}

#[cfg(test)] mod tests {
    use super::*;
    use crate::capture::CHECKPOINTS;
    use p256::ecdsa::{signature::Signer,Signature,SigningKey};
    use rand_core::OsRng;
    fn fixture()->Input {serde_json::from_str(include_str!("../tests/fixtures/live-assurance.json")).unwrap()}
    #[test] fn adaptive_inputs_remove_only_padding_and_preserve_all_original_evidence() {
        let mut original=fixture();
        assert_eq!(sized_worker_input(&original.witness,&original.snapshot,None).unwrap()["provingProfile"],crate::profile_fit::PROFILE_64);
        original.snapshot.profile=EXTENDED_PROFILE.into();
        for (requested,profile,operations,samples,checkpoints,bytes) in [
            (None,crate::profile_fit::PROFILE_64,372,132,8,3008),
            (Some(crate::profile_fit::PROFILE_128),crate::profile_fit::PROFILE_128,756,260,32,4544),
            (Some(EXTENDED_PROFILE),EXTENDED_PROFILE,1536,516,32,4544),
        ] {
            let prepared=sized_worker_input(&original.witness,&original.snapshot,requested).unwrap();
            assert_eq!(prepared["provingProfile"],profile);
            assert_eq!(prepared["inputs"]["ops"].as_array().unwrap().len(),operations);
            assert_eq!(prepared["inputs"]["origins"].as_array().unwrap().len(),samples);
            assert_eq!(prepared["inputs"]["checkpoints"].as_array().unwrap().len(),checkpoints);
            assert_eq!(hex::decode(prepared["publicInputsHex"].as_str().unwrap()).unwrap().len(),bytes);
            assert_eq!(prepared["signaturesHex"].as_array().unwrap().len(),original.snapshot.capsule.signatures.len());
            assert_eq!(prepared["presenceSignaturesHex"].as_array().unwrap().len(),original.snapshot.capsule.presence_signatures.len());
            assert_eq!(prepared["inputs"]["op_count"],original.snapshot.private.replay.words.len().to_string());
            let unsigned=&prepared["inputs"]["ops"].as_array().unwrap()[original.snapshot.private.replay.words.len()..];
            assert!(unsigned.iter().all(|op|op["code"]=="0" && op["arg"]=="0"));
        }
        assert!(sized_worker_input(&original.witness,&original.snapshot,Some("unknown-profile")).is_err());
        original.snapshot.capsule.signatures[0][10]^=1;
        assert!(sized_worker_input(&original.witness,&original.snapshot,None).is_err());
    }
    #[test] fn extended_abi_preserves_the_original_signed_journal() {
        let mut value=fixture();value.snapshot.profile=EXTENDED_PROFILE.into();
        let prepared=worker_input(&value.witness,&value.snapshot).unwrap();
        assert_eq!(prepared["captureProfile"],EXTENDED_PROFILE);
        assert_eq!(prepared["inputs"]["checkpoints"].as_array().unwrap().len(),32);
        assert_eq!(hex::decode(prepared["publicInputsHex"].as_str().unwrap()).unwrap().len(),4544);
        assert_eq!(validate(&value.witness,&value.snapshot).unwrap(),value.snapshot.capsule.journal);
        value.snapshot.profile="assurance256-unknown".into();assert!(validate(&value.witness,&value.snapshot).is_err());
    }
    #[test] fn runtime_bridge_keeps_u64_exact_and_freezes_public_field_order() {
        let request=fixture();let value=worker_input(&request.witness,&request.snapshot).unwrap();
        assert_eq!(value["inputs"]["op_count"],request.snapshot.private.replay.words.len().to_string());
        assert!(value["inputs"]["origins"][0]["present"].is_boolean());
        let public=hex::decode(value["publicInputsHex"].as_str().unwrap()).unwrap();assert_eq!(public.len(),3008);
        assert_eq!(&public[..32],&commit::bytes(commit::parse(&request.snapshot.private.replay.nonce[0]).unwrap()));
        let max=exact_numbers(json!({"u64":u64::MAX,"bool":true}));
        assert_eq!(max["u64"],"18446744073709551615");assert_eq!(max["bool"],true);
        assert!(value["journal"]["replay"]["elapsed"].is_string());
    }
    #[test] fn captured_swift_history_matches_complete_private_input_and_fixed_abi() {
        let request=fixture();let j=validate(&request.witness,&request.snapshot).unwrap();
        assert!(j.policy_satisfied);assert_eq!(j.origin_present,80);assert_eq!(j.on_time,2);
        let input=inputs(&request.witness,&request.snapshot).unwrap();
        for (name,count) in [("ops",OPERATIONS),("timings",SAMPLES),("origins",SAMPLES),("presence",PRESENCE),("checkpoints",CHECKPOINTS)] {
            assert_eq!(input[name].as_array().unwrap().len(),count);
        }
        assert_eq!(input["expected"]["replay"]["checkpoint_count"],4);
        assert_eq!(input["expected"]["checkpoint_roots"][4],"0");
        assert_eq!(input["expected"]["presence_roots"][2],"0");
        assert_eq!(input["ops"][201]["code"],0);
        assert_eq!(input["presence"][0]["nonce"],serde_json::to_value(&request.snapshot.private.presence[0].nonce).unwrap());
    }
    #[test] fn mutated_private_capture_presence_boundaries_and_signatures_cannot_rebind() {
        let original=fixture();
        let changes:[fn(&mut Input);10]=[
            |v|v.snapshot.private.replay.words[1]^=1,
            |v|v.snapshot.private.origins[0].pid^=1,
            |v|v.snapshot.private.presence[0].nonce[0]="1".into(),
            |v|v.snapshot.private.checkpoint_presence[1]^=1,
            |v|v.snapshot.private.replay.checkpoints[1].offset+=1,
            |v|v.snapshot.capsule.signatures[0][10]^=1,
            |v|v.snapshot.capsule.presence_signatures[0][10]^=1,
            |v|v.snapshot.capsule.journal.policy_satisfied=false,
            |v|v.witness.session.id.push('x'),
            |v|v.snapshot.text.push(' '),
        ];
        for (index,change) in changes.into_iter().enumerate() {
            let mut changed=original.clone();change(&mut changed);
            assert!(validate(&changed.witness,&changed.snapshot).is_err(),"Mutation {index} was accepted");
        }
    }
    #[test] fn valid_capsule_from_another_key_cannot_replace_the_legacy_capture_key() {
        let mut request=fixture();let key=SigningKey::random(&mut OsRng);let c=&mut request.snapshot.capsule;
        c.public_key=key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        for (roots,signatures,domain) in [(&c.journal.checkpoint_roots,&mut c.signatures,assurance::CP_DOMAIN),
            (&c.journal.presence_roots,&mut c.presence_signatures,assurance::PRESENCE_DOMAIN)] {
            *signatures=roots.iter().map(|root|{let sig:Signature=key.sign(&assurance::message(domain,root).unwrap());sig.to_der().as_bytes().to_vec()}).collect();
        }
        assert!(assurance::verify(c).is_ok());
        assert!(validate(&request.witness,&request.snapshot).is_err());
    }
    #[test] fn unsealed_or_oversized_live_snapshots_are_rejected_without_truncation() {
        let original=fixture();
        let mut unsealed=original.clone();unsealed.snapshot.sealed=false;assert!(inputs(&unsealed.witness,&unsealed.snapshot).is_err());
        let mut large=original.clone();large.snapshot.private.replay.words.resize(OPERATIONS+1,0);assert!(inputs(&large.witness,&large.snapshot).is_err());
        let mut legacy=original;legacy.witness.session.presence_protocol=None;assert!(inputs(&legacy.witness,&legacy.snapshot).is_err());
    }
}
