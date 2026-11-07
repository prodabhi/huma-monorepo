//! C ABI for a trusted in-process caller. Each handle has one serial owner.
//! No files, device credentials, biometric APIs, private signing keys or network access.
use crate::capture::{LiveCapture,PROFILE};
use crate::{assurance::Origin,assurance_capture::{LiveAssuranceCapture,PROFILE as ASSURANCE_PROFILE,EXTENDED_PROFILE,LONG_PROFILE}};
use serde::Deserialize;
use serde_json::{json,Value};
use std::{ffi::{c_char,CString},panic::{catch_unwind,AssertUnwindSafe},slice};

const MAX_REQUEST: usize=128*1024;
enum Capture {Replay(LiveCapture),Assurance(LiveAssuranceCapture)}
impl Capture {fn info(&self)->Value {match self {Self::Replay(c)=>c.info(),Self::Assurance(c)=>c.info()}}}
pub struct Handle {capture: Capture,poisoned: bool}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {profile:String,initial_text:String,public_key:Vec<u8>,unix:u64}
#[derive(Deserialize)]
#[serde(tag="command",rename_all="snake_case",deny_unknown_fields)]
enum Request {
    Edit {location:u32,removed:u32,inserted:String,source:String,elapsed:u64},
    Sample {kind:String,key:u16,modifiers:u64,elapsed:u64},
    SampleOrigin {kind:String,key:u16,modifiers:u64,elapsed:u64,origin:Origin},
    PresenceIssue {nonce:[u8;32],reason:u8,elapsed:u64},
    PresenceResponse {outcome:u8,elapsed:u64},
    Checkpoint {unix:u64,elapsed:u64,is_final:bool,text:String},
    Accept {signature:Vec<u8>},Info {},Snapshot {},
    LongChunk {index:usize},LongCut {},
}
fn response(result: Result<Value,String>)->*mut c_char {
    let value=match result {Ok(result)=>json!({"ok":true,"result":result}),Err(error)=>json!({"ok":false,"error":error})};
    CString::new(serde_json::to_vec(&value).unwrap()).unwrap().into_raw()
}
unsafe fn input<'a>(data:*const u8,len:usize)->Result<&'a [u8],String> {
    if data.is_null() || len==0 || len>MAX_REQUEST {return Err("Invalid capture request length".into());}
    Ok(slice::from_raw_parts(data,len))
}
fn execute(capture: &mut Capture,request: Request)->Result<Value,String> {
    match capture {
      Capture::Replay(capture)=>match request {
        Request::Edit {location,removed,inserted,source,elapsed}=>capture.edit(location as usize,removed as usize,&inserted,&source,elapsed)?,
        Request::Sample {kind,key,modifiers,elapsed}=>capture.sample(&kind,key,modifiers,elapsed)?,
        Request::Checkpoint {unix,elapsed,is_final,text}=>{capture.prepare(unix,elapsed,is_final,&text)?;},
        Request::Accept {signature}=>capture.accept(signature)?,
        Request::Info {}=>{},Request::Snapshot {}=>return capture.snapshot(),
        _=>return Err("V3 capture cannot omit or reinterpret V4 origin/presence".into()),
      },
      Capture::Assurance(capture)=>match request {
        Request::Edit {location,removed,inserted,source,elapsed}=>capture.edit(location as usize,removed as usize,&inserted,&source,elapsed)?,
        Request::Sample {kind,key,modifiers,elapsed}=>capture.sample(&kind,key,modifiers,elapsed,Origin::default())?,
        Request::SampleOrigin {kind,key,modifiers,elapsed,origin}=>capture.sample(&kind,key,modifiers,elapsed,origin)?,
        Request::PresenceIssue {nonce,reason,elapsed}=>capture.issue(nonce,reason,elapsed)?,
        Request::PresenceResponse {outcome,elapsed}=>capture.respond(outcome,elapsed)?,
        Request::Checkpoint {unix,elapsed,is_final,text}=>capture.prepare(unix,elapsed,is_final,&text)?,
        Request::Accept {signature}=>capture.accept(signature)?,
        Request::Info {}=>{},Request::Snapshot {}=>return capture.snapshot(),
        // Private chunk input as an exact JSON string; the caller passes it to the local prover unchanged.
        Request::LongCut {}=>capture.long_cut()?,
        Request::LongChunk {index}=>{let mut value=capture.long_chunk(index)?;value["input"]=json!(value["input"].to_string());return Ok(value);},
      },
    };
    Ok(capture.info())
}

/// `data` must reference `len` valid bytes; `reply` must be writable. Free returned
/// replies with huma_compact_response_free and the handle with huma_compact_destroy.
#[no_mangle]
pub unsafe extern "C" fn huma_compact_create(data:*const u8,len:usize,reply:*mut *mut c_char)->*mut Handle {
    if reply.is_null() {return std::ptr::null_mut();}
    let result=catch_unwind(AssertUnwindSafe(||->Result<Capture,String>{
        let config:Config=serde_json::from_slice(input(data,len)?).map_err(|_|"Invalid capture configuration")?;
        match config.profile.as_str() {
            PROFILE=>LiveCapture::new(&config.initial_text,config.public_key,config.unix).map(Capture::Replay),
            ASSURANCE_PROFILE|EXTENDED_PROFILE|LONG_PROFILE=>LiveAssuranceCapture::with_profile(&config.initial_text,config.public_key,config.unix,&config.profile).map(Capture::Assurance),
            _=>Err("Unsupported compact capture profile".into()),
        }
    }));
    match result {
        Ok(Ok(capture))=>{*reply=response(Ok(capture.info()));Box::into_raw(Box::new(Handle {capture,poisoned:false}))},
        Ok(Err(error))=>{*reply=response(Err(error));std::ptr::null_mut()},
        Err(_)=>{*reply=response(Err("Capture initialization stopped".into()));std::ptr::null_mut()},
    }
}

/// A live handle may only be called serially and must not already be destroyed.
#[no_mangle]
pub unsafe extern "C" fn huma_compact_call(handle:*mut Handle,data:*const u8,len:usize)->*mut c_char {
    let result=catch_unwind(AssertUnwindSafe(||->Result<Value,String>{
        let state=handle.as_mut().ok_or("Missing compact capture handle")?;
        if state.poisoned {return Err("Compact capture stopped after an internal failure".into());}
        let request:Request=serde_json::from_slice(input(data,len)?).map_err(|_|"Invalid capture command")?;
        execute(&mut state.capture,request)
    }));
    if result.is_err() {if let Some(state)=handle.as_mut(){state.poisoned=true;}}
    response(result.unwrap_or_else(|_|Err("Compact capture stopped".into())))
}
#[no_mangle]
pub unsafe extern "C" fn huma_compact_destroy(handle:*mut Handle) {if !handle.is_null(){drop(Box::from_raw(handle));}}
#[no_mangle]
pub unsafe extern "C" fn huma_compact_response_free(reply:*mut c_char) {if !reply.is_null(){drop(CString::from_raw(reply));}}

#[cfg(test)] mod tests {
    use super::*;
    use std::ffi::CStr;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    unsafe fn decoded(reply:*mut c_char)->Value {
        let value=serde_json::from_slice(CStr::from_ptr(reply).to_bytes()).unwrap();huma_compact_response_free(reply);value
    }
    #[test] fn c_abi_rejects_bad_requests_without_unwinding_or_changing_state() {unsafe {
        let key=SigningKey::random(&mut OsRng);
        let config=serde_json::to_vec(&json!({"profile":PROFILE,"initial_text":"a","public_key":key.verifying_key().to_encoded_point(false).as_bytes(),"unix":0})).unwrap();
        let mut reply=std::ptr::null_mut();let handle=huma_compact_create(config.as_ptr(),config.len(),&mut reply);
        assert!(!handle.is_null());let before=decoded(reply)["result"].clone();
        for bytes in [b"{\"command\":\"unknown\"}".as_slice(),b"{\"command\":\"info\",\"privateKey\":1}",
            b"{\"command\":\"snapshot\",\"privateKey\":1}",b"{\"command\":\"info\",\"command\":\"snapshot\"}",b"\xff"] {
            assert_eq!(decoded(huma_compact_call(handle,bytes.as_ptr(),bytes.len()))["ok"],false);
        }
        assert_eq!(decoded(huma_compact_call(handle,std::ptr::null(),0))["ok"],false);
        assert_eq!(decoded(huma_compact_call(handle,b"x".as_ptr(),MAX_REQUEST+1))["ok"],false);
        let command=b"{\"command\":\"info\"}";
        assert_eq!(decoded(huma_compact_call(handle,command.as_ptr(),command.len()))["result"],before);
        (*handle).poisoned=true;
        assert_eq!(decoded(huma_compact_call(handle,command.as_ptr(),command.len()))["ok"],false);
        huma_compact_destroy(handle);huma_compact_destroy(std::ptr::null_mut());huma_compact_response_free(std::ptr::null_mut());
        assert_eq!(decoded(huma_compact_call(std::ptr::null_mut(),command.as_ptr(),command.len()))["ok"],false);
    }}
}
