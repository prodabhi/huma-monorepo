//! Choose a circuit only after validating the complete original signed capture.
use crate::{assurance,assurance_input,ops};
use huma_replay_core::Witness;
use serde::Serialize;
use serde_json::{json,Value};

#[derive(Clone,Copy,Serialize)]
#[serde(rename_all="UPPERCASE")]
pub struct Limits {
    pub ops:usize,pub scalars:usize,pub bytes:usize,
    pub samples:usize,pub cps:usize,pub pres:usize,
}
const CANDIDATES:[(&str,Limits);2]=[
    ("short64",Limits {ops:372,scalars:64,bytes:256,samples:132,cps:8,pres:8}),
    ("short128",Limits {ops:756,scalars:128,bytes:512,samples:260,cps:32,pres:8}),
];
pub const PROFILE_64:&str="assurance64-v1";
pub const PROFILE_128:&str="assurance128-cp32-v1";
pub fn limits_for_profile(profile:&str)->Option<Limits> {
    match profile {
        PROFILE_64=>Some(CANDIDATES[0].1),PROFILE_128=>Some(CANDIDATES[1].1),
        "assurance256-v1"|"assurance256-v2"|"assurance256-cp32-v1"=>Some(Limits {
            ops:crate::capture::OPERATIONS,scalars:crate::capture::SCALARS,bytes:1024,
            samples:crate::assurance_capture::SAMPLES,pres:crate::assurance_capture::PRESENCE,
            cps:if profile==crate::assurance_capture::EXTENDED_PROFILE {32}else{8}}),
        _=>None,
    }
}
#[derive(Serialize)]
struct Fit {name:&'static str,limits:Limits,eligible:bool,reasons:Vec<&'static str>}
fn fit(name:&'static str,limits:Limits,private:&assurance::Private,reference:&ops::Replayed)->Fit {
    let mut reasons=vec![];
    for (exceeds,reason) in [
        (private.replay.words.len()>limits.ops,"operations"),
        (private.origins.len()>limits.samples,"key-events"),
        (private.replay.checkpoints.len()>limits.cps,"checkpoints"),
        (private.presence.len()>limits.pres,"presence"),
        (reference.text.len()>limits.bytes,"encoded-text"),
    ] {if exceeds {reasons.push(reason);}}
    match ops::replay(&private.replay.words,limits.scalars) {
        Err(_)=>reasons.push("intermediate-text"),
        Ok(replayed)=>if replayed.text!=reference.text || replayed.prefixes!=reference.prefixes
            || replayed.baseline_end!=reference.baseline_end {reasons.push("replay-differs");},
    }
    Fit {name,limits,eligible:reasons.is_empty(),reasons}
}
/// The caller must have authenticated the original input first. No checkpoint,
/// event, signature or intermediate revision is removed to fit a bucket.
pub(crate) fn smallest_validated(snapshot:&assurance_input::Snapshot,original:&assurance::Journal)->Result<&'static str,String> {
    let reference=ops::replay(&snapshot.private.replay.words,crate::capture::SCALARS)?;
    for (index,(name,limits)) in CANDIDATES.into_iter().enumerate() {
        if fit(name,limits,&snapshot.private,&reference).eligible {
            if assurance::statement(&snapshot.private,limits.scalars)?!=*original {
                return Err("Smaller circuit would change the signed statement".into());
            }
            return Ok(if index==0 {PROFILE_64}else{PROFILE_128});
        }
    }
    Ok(crate::assurance_capture::EXTENDED_PROFILE)
}
pub fn evaluate(witness:&Witness,snapshot:&assurance_input::Snapshot)->Result<Value,String> {
    let original=assurance_input::validate(witness,snapshot)?;
    let reference=ops::replay(&snapshot.private.replay.words,crate::capture::SCALARS)?;
    let mut candidates=vec![];
    for (name,limits) in CANDIDATES {
        let candidate=fit(name,limits,&snapshot.private,&reference);
        if candidate.eligible && assurance::statement(&snapshot.private,limits.scalars)?!=original {
            return Err("Smaller circuit would change the signed statement".into());
        }
        candidates.push(candidate);
    }
    Ok(json!({"kind":"huma-proof-sizing-candidates-v1","completeInputValidated":true,
        "registeredForProving":true,"proofGenerated":false,"candidates":candidates}))
}

#[cfg(test)] mod tests {
    use super::*;
    fn fixture()->assurance_input::Input {
        serde_json::from_str(include_str!("../tests/fixtures/live-assurance.json")).unwrap()
    }
    #[test] fn original_signed_capture_fits_without_changing_any_journal_field() {
        let original=fixture();let result=evaluate(&original.witness,&original.snapshot).unwrap();
        for candidate in result["candidates"].as_array().unwrap() {assert_eq!(candidate["eligible"],true);}
        let mut changed=original;changed.snapshot.private.replay.words[1]^=1;
        assert!(evaluate(&changed.witness,&changed.snapshot).is_err());
    }
    #[test] fn selection_checks_peak_text_even_when_final_text_is_one_character() {
        let mut private=fixture().snapshot.private;
        let mut builder=ops::Builder::new("",256,1536).unwrap();
        builder.edit(0,0,&"x".repeat(80),"typing",1).unwrap();
        builder.edit(1,79,"","typing",2).unwrap();
        private.replay.words=builder.words;
        let reference=ops::replay(&private.replay.words,256).unwrap();assert_eq!(reference.text,"x");
        let small=fit(CANDIDATES[0].0,CANDIDATES[0].1,&private,&reference);
        assert!(!small.eligible);assert_eq!(small.reasons,vec!["intermediate-text"]);
        assert!(fit(CANDIDATES[1].0,CANDIDATES[1].1,&private,&reference).eligible);
    }
    #[test] fn count_limits_never_discard_records_and_unicode_uses_scalar_capacity() {
        let mut private=fixture().snapshot.private;
        let mut builder=ops::Builder::new("",256,1536).unwrap();
        builder.edit(0,0,&"😀".repeat(64),"typing",1).unwrap();
        builder.edit(0,128,"","typing",2).unwrap();
        private.replay.words=builder.words;
        let reference=ops::replay(&private.replay.words,256).unwrap();
        assert!(fit(CANDIDATES[0].0,CANDIDATES[0].1,&private,&reference).eligible);
        private.origins.resize(133,assurance::Origin::default());
        assert_eq!(fit(CANDIDATES[0].0,CANDIDATES[0].1,&private,&reference).reasons,vec!["key-events"]);
        private.presence.resize(9,private.presence[0].clone());
        assert!(fit(CANDIDATES[1].0,CANDIDATES[1].1,&private,&reference).reasons.contains(&"presence"));
    }
    #[test] fn too_many_checkpoints_choose_a_larger_bucket_instead_of_pruning_signatures() {
        let mut private=fixture().snapshot.private;
        let reference=ops::replay(&private.replay.words,256).unwrap();
        private.replay.checkpoints.resize(9,private.replay.checkpoints[0].clone());
        assert_eq!(fit(CANDIDATES[0].0,CANDIDATES[0].1,&private,&reference).reasons,vec!["checkpoints"]);
        assert!(fit(CANDIDATES[1].0,CANDIDATES[1].1,&private,&reference).eligible);
    }
}
