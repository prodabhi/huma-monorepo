use huma_compact_experiment::protocol::{self,Capsule};
use std::io::{Read,Write};
fn run()->Result<(),String> {
    let args:Vec<_>=std::env::args().collect();
    let command=args.get(1).ok_or("Use fixture or signatures")?;
    let mut input=String::new();std::io::stdin().take(64*1024*1024+1).read_to_string(&mut input).map_err(|e|e.to_string())?;
    if input.len()>64*1024*1024 {return Err("Input exceeds experiment bound".into());}
    let result=match command.as_str() {
        "assurance-input"=>{
            let request:huma_compact_experiment::assurance_input::Input=serde_json::from_str(&input).map_err(|_|"Invalid live V4 input")?;
            huma_compact_experiment::assurance_input::inputs(&request.witness,&request.snapshot)?
        },
        "assurance-worker-input"=>{
            let request:huma_compact_experiment::assurance_input::AppInput=serde_json::from_str(&input).map_err(|_|"Invalid app V4 input")?;
            if !request.snapshot.ok {return Err("Unsuccessful capture snapshot".into());}
            huma_compact_experiment::assurance_input::worker_input(&request.witness,&request.snapshot.result)?
        },
        "assurance-sized-worker-input"=>{
            let request:huma_compact_experiment::assurance_input::AppInput=serde_json::from_str(&input).map_err(|_|"Invalid sized app input")?;
            if !request.snapshot.ok {return Err("Unsuccessful capture snapshot".into());}
            huma_compact_experiment::assurance_input::sized_worker_input(&request.witness,&request.snapshot.result,args.get(2).map(String::as_str))?
        },
        "long-worker-input"|"long-worker-statement"=>{
            let request:huma_compact_experiment::long::AppInput=serde_json::from_str(&input).map_err(|_|"Invalid long-session input")?;
            if !request.snapshot.ok {return Err("Unsuccessful capture snapshot".into());}
            huma_compact_experiment::long::worker_input(&request.witness,&request.snapshot.result,command=="long-worker-statement")?
        },
        "profile-fit"=>{
            let request:huma_compact_experiment::assurance_input::AppInput=serde_json::from_str(&input).map_err(|_|"Invalid app sizing input")?;
            if !request.snapshot.ok {return Err("Unsuccessful capture snapshot".into());}
            huma_compact_experiment::profile_fit::evaluate(&request.witness,&request.snapshot.result)?
        },
        "assurance-publictext-input"=>{
            let request:huma_compact_experiment::assurance_input::AppInput=serde_json::from_str(&input).map_err(|_|"Invalid app V5 input")?;
            if !request.snapshot.ok {return Err("Unsuccessful capture snapshot".into());}
            huma_compact_experiment::public_text::worker_input(&request.witness,&request.snapshot.result)?
        },
        "publictext-commitment"=>{
            let text:String=serde_json::from_str(&input).map_err(|_|"Invalid text")?;
            serde_json::json!({"commitment":huma_compact_experiment::public_text::commitment(&text)?})
        },
        "assurance-case"=>{
            let (private,capsule,text)=huma_compact_experiment::assurance::synthetic_case(args.get(2).ok_or("Missing case")?)?;
            serde_json::json!({"private":private,"capsule":capsule,"text":text})
        },
        "assurance-fixture"=>{
            let witness=serde_json::from_str(&input).map_err(|e|e.to_string())?;
            let (private,capsule)=huma_compact_experiment::assurance::synthetic_fixture(&witness,256)?;
            serde_json::json!({"private":private,"capsule":capsule})
        },
        "assurance-signatures"=>{
            let capsule=serde_json::from_str(&input).map_err(|e|e.to_string())?;
            let fingerprint=huma_compact_experiment::assurance::verify(&capsule)?;
            serde_json::json!({"signaturesValid":true,"keyHash":fingerprint,"experimental":true})
        },
        "fixture"=>{
            let witness=serde_json::from_str(&input).map_err(|e|e.to_string())?;
            let capacity=args.get(2).ok_or("Missing scalar capacity")?.parse::<usize>().map_err(|e|e.to_string())?;
            if capacity>65535 {return Err("Capacity exceeds experiment bound".into());}
            let (private,capsule)=protocol::synthetic_fixture(&witness,capacity)?;
            serde_json::json!({"private":private,"capsule":capsule})
        },
        "signatures"=>{
            let capsule:Capsule=serde_json::from_str(&input).map_err(|e|e.to_string())?;
            let fingerprint=protocol::verify_signatures(&capsule,None,None)?;
            serde_json::json!({"signaturesValid":true,"keyHash":fingerprint,"experimental":true,"attestationVerified":false,"trustedTime":false})
        },
        "compile"=>{
            let witness=serde_json::from_str(&input).map_err(|e|e.to_string())?;
            let compiled=huma_compact_experiment::ops::compile(&witness)?;
            serde_json::json!({"words":compiled.words,"captureOffsets":compiled.capture_offsets})
        },
        _=>return Err("Unknown command".into()),
    };
    std::io::stdout().write_all(serde_json::to_string(&result).unwrap().as_bytes()).map_err(|e|e.to_string())
}
fn main(){if let Err(e)=run(){eprintln!("Compact experiment: {e}");std::process::exit(1);}}
