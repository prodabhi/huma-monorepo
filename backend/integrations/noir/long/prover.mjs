// assurance-long-v2 tooling. Programs, all from prover.nr:
//   start      the first part of a session (genesis), a chain proof on its own
//   fold       every later part: proves its step and verifies the previous chain proof
//   final<N>   the seal for each text tier: verifies the last chain proof, so one proof covers the session.
//              final1024 also proves the last part's step (empty when that part is already proved), so
//              Finish on pages up to 1,024 characters is a single proof; the larger tiers would not fit 2^21 gates.
// Every part and the final step check the capture key's P-256 signatures in-circuit.
//   build                       compile all programs, write their keys and pin the chain keys into later programs
//   check <case.json> [--mutations]   witnesses only (software-key fixtures)
//   chain <case.json>           prove the whole session, then assemble and verify the public proof
import { readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'../../../..');
const target=path.join(root,'build/research/noir-long2');
const nargo=path.join(root,'build/research/noir-tools/noir/nargo');
const bb=path.join(root,'build/research/noir-tools/bb/bb');
const crs=path.join(root,'build/research/noir-crs');
const out=s=>process.stdout.write(s+'\n');
export const TIERS=[1024,4096,10000];
export const NAMES=['start','fold',...TIERS.map(t=>'final'+t)];
const chainArgs=`nonce:[Field;2],salt:[Field;2],state:State,ops:[Op;OPS],origins:[Origin;OPS],op_count:u32,
        events:[Event;SLOTS],text:[Field;2],device:Device,signatures:[[u8;64];SLOTS],expected:Boundary`;
const chainCall='prover::chunk(nonce,salt,state,ops,origins,op_count,events,text,device,signatures,expected);';
const verifyPrev='bb::verify_honk_proof(prev_key,prev_proof,[prev.end_root,prev.chain_key,prev.device],key);';
const entries={
  start:()=>`fn main(${chainArgs},link:pub Link) {
    ${chainCall}
    assert(expected.genesis&(link.end_root==expected.end_root)&(link.device==prover::device_root(device.x,device.y)));
}`,
  fold:keys=>`global START_KEY:Field=${keys.start};
fn main(${chainArgs},prev_key:[Field;115],prev_proof:[Field;458],prev:Link,link:pub Link) {
    ${chainCall}
    let key=commit::hash(prev_key);
    // The previous proof is the start program or this one; the final step pins this program's key.
    assert(!expected.genesis&((key==START_KEY)|(key==link.chain_key))&(prev.chain_key==link.chain_key)&(prev.device==link.device));
    assert((prev.end_root==expected.start_root)&(link.end_root==expected.end_root)&(link.device==prover::device_root(device.x,device.y)));
    ${verifyPrev}
}`,
  // Pages up to 1,024 characters: the last part's step and the seal in one program.
  final1024:keys=>`global START_KEY:Field=${keys.start};
global FOLD_KEY:Field=${keys.fold};
fn main(${chainArgs},tail:[Event;SLOTS],tail_signatures:[[u8;64];TAIL],
        prev_key:[Field;115],prev_proof:[Field;458],prev:Link,expected_final:pub Final,owner:pub Field) {
    // The wallet this proof is for (0 off-chain). Only a prover holding the session can choose it,
    // so an on-chain record can't be claimed by whoever copies the proof.
    owner.assert_max_bit_size::<160>();
    let after=prover::step(nonce,salt,state,ops,origins,op_count,events,text,device,signatures,expected);
    prover::finalize(nonce,salt,after,tail,text,device,tail_signatures,expected_final);
    let key=commit::hash(prev_key);
    assert(!expected.genesis&((key==START_KEY)|(key==FOLD_KEY))&(prev.chain_key==FOLD_KEY)&(prev.end_root==expected.start_root)&(prev.device==expected_final.device));
    ${verifyPrev}
}`,
  final:keys=>`global START_KEY:Field=${keys.start};
global FOLD_KEY:Field=${keys.fold};
fn main(nonce:[Field;2],salt:[Field;2],state:State,events:[Event;SLOTS],text:[Field;2],device:Device,signatures:[[u8;64];TAIL],
        prev_key:[Field;115],prev_proof:[Field;458],prev:Link,expected:pub Final,owner:pub Field) {
    // The wallet this proof is for (0 off-chain). Only a prover holding the session can choose it,
    // so an on-chain record can't be claimed by whoever copies the proof.
    owner.assert_max_bit_size::<160>();
    prover::finalize(nonce,salt,state,events,text,device,signatures,expected);
    let key=commit::hash(prev_key);
    assert(((key==START_KEY)|(key==FOLD_KEY))&(prev.chain_key==FOLD_KEY)&(prev.end_root==expected.state_root)&(prev.device==expected.device));
    ${verifyPrev}
}`,
};
export const programPath=name=>path.join(target,name,`target/huma_long_${name}.json`);
export const keyPath=name=>path.join(target,name,'target/vk');
const env={...process.env,RAYON_NUM_THREADS:'2',HARDWARE_CONCURRENCY:'2'};
const run=(args,options={})=>execFileSync('/usr/bin/nice',['-n','10',bb,...args],{env,stdio:['ignore','ignore','pipe'],...options});
const fieldsOf=buf=>{const o=[];for(let i=0;i<buf.length;i+=32)o.push('0x'+buf.subarray(i,i+32).toString('hex'));return o;};
export async function keyHash(vk){
  const {hash}=await import('../../../../extra/experiments/noir-compact/browser/final-text.mjs');
  const {poseidon2Permute}=await import('./reader.mjs');
  return '0x'+(await hash(fieldsOf(vk).map(BigInt),poseidon2Permute)).toString(16).padStart(64,'0');
}

async function build(){
  const keys={};
  for(const name of NAMES){
    const dir=path.join(target,name);await rm(dir,{recursive:true,force:true});await mkdir(path.join(dir,'src'),{recursive:true});
    await writeFile(path.join(dir,'Nargo.toml'),`[package]\nname="huma_long_${name}"\ntype="bin"\nauthors=[]\n[dependencies]\n`);
    const source=await readFile(path.join(here,'prover.nr'),'utf8'),tier=name.startsWith('final')?name.slice(5):'10000';
    if(!source.includes('pub global TEXT:u32=10000;'))throw Error('TEXT tier declaration changed');
    await writeFile(path.join(dir,'src/prover.nr'),source.replace('pub global TEXT:u32=10000;',`pub global TEXT:u32=${tier};`));
    for(const m of ['commit.nr','assurance.nr'])await copyFile(path.join(root,'extra/experiments/noir-compact/src',m),path.join(dir,'src',m));
    await copyFile(path.join(here,'bb.nr'),path.join(dir,'src/bb.nr'));
    const entry=(entries[name]??entries.final)(keys);
    if(name==='final1024'&&!(await readFile(path.join(here,'prover.nr'),'utf8')).includes('pub fn step('))throw Error('prover.nr lacks step()');
    await writeFile(path.join(dir,'src/main.nr'),'mod commit;\nmod assurance;\nmod prover;\nmod bb;\nuse assurance::Origin;\n'+
      'use prover::{Boundary,Device,Event,Final,Link,Op,State,OPS,SLOTS,TAIL};\n'+entry+'\n');
    execFileSync(nargo,['compile','--silence-warnings'],{cwd:dir,stdio:'inherit'});
    run(['write_vk','-b',programPath(name),'-t','noir-recursive','-c',crs,'-o',path.dirname(keyPath(name))]);
    if(name==='start'||name==='fold')keys[name]=await keyHash(await readFile(keyPath(name)));
    // The final steps also get the EVM key that their Solidity verifiers are generated from.
    if(name.startsWith('final'))run(['write_vk','-b',programPath(name),'-t','evm','-c',crs,'-o',path.join(dir,'target/evm-vk')]);
    const gates=JSON.parse(execFileSync(bb,['gates','-b',programPath(name)],{stdio:['ignore','pipe','ignore']})).functions[0].circuit_size;
    out(`built ${name}: ${gates} gates (2^${Math.ceil(Math.log2(gates))})`);
  }
  await writeFile(path.join(target,'keys.json'),JSON.stringify(keys,null,1)+'\n');
}

const noir=async name=>{
  const {Noir}=await import(path.join(root,'extra/experiments/noir-replay/runtime/node_modules/@noir-lang/noir_js/lib/index.mjs'));
  for(const method of ['debug','error','info','log','warn'])console[method]=()=>{};
  return new Noir(JSON.parse(await readFile(programPath(name),'utf8')));
};
const noForeign=async()=>{throw Error('foreign calls disabled');};
/** The input of part `index` (start or fold) or of the final step, given the previous chain proof. */
export function stepInput(input,keys,prev){
  const step={...input,link:{...input.link,chain_key:keys.fold}};
  if(!prev)return step;
  return {...step,prev_key:fieldsOf(prev.key),prev_proof:fieldsOf(prev.proof),prev:{end_root:BigInt('0x'+prev.inputs.subarray(0,32).toString('hex')).toString(),
    chain_key:keys.fold,device:BigInt('0x'+prev.inputs.subarray(64,96).toString('hex')).toString()}};
}
export function finalInput(input,keys,prev,owner='0'){
  const {link:_,...rest}=stepInput({...input,link:{}},keys,prev);return {...rest,owner};
}
/** A step that changes nothing, from the chain's end state: the merged final step when every part is proved. */
export function emptyStep(final){
  const zero={code:'0',arg:'0'},origin={present:false,pid:'0',state:'0',keyboard:'0',repeated:false};
  const event={kind:'0',offset:'0',unix:'0',elapsed:'0',last:false,nonce:['0','0'],reason:'0',issued:'0',answered:'0',outcome:'0'};
  const unsigned=Array.from({length:64},(_,i)=>i===31||i===63?'1':'0');
  return {nonce:final.nonce,salt:final.salt,state:final.state,ops:Array(528).fill(zero),origins:Array(528).fill(origin),op_count:'0',
    events:Array(8).fill(event),text:final.text,device:final.device,signatures:Array(8).fill(unsigned),
    expected:{start_root:final.expected.state_root,end_root:final.expected.state_root,genesis:false}};
}
/** Input of the merged final1024 program: the last part's step (or an empty one) and the seal, over `prev`. */
export function mergedInput(step,final,keys,prev,owner='0'){
  const {link:_,...rest}=step;
  return {...rest,text:final.text,tail:final.events,tail_signatures:final.signatures,expected_final:final.expected,owner,
    ...Object.fromEntries(Object.entries(finalInput(final,keys,prev,owner)).filter(([k])=>k.startsWith('prev')))};
}

async function check(file,flags){
  const keys=JSON.parse(await readFile(path.join(target,'keys.json'),'utf8'));
  const fixture=JSON.parse(await readFile(file,'utf8'));
  const programs={start:await noir('start'),fold:await noir('fold'),final:await noir('final'+fixture.final.expected.text_capacity)};
  // Witness checks don't verify inner proofs (the prover does); they need the real previous key and boundary.
  const fake=async (i)=>({key:await readFile(keyPath(i===0?'start':'fold')),proof:Buffer.alloc(14656),
    inputs:Buffer.from([fixture.chunks[i].expected.end_root,keys.fold,fixture.chunks[i].link.device].map(v=>BigInt(v).toString(16).padStart(64,'0')).join(''),'hex')});
  const inputs=await Promise.all(fixture.chunks.map(async (c,i)=>i===0?stepInput(c,keys):stepInput(c,keys,await fake(i-1))));
  const n=fixture.chunks.length,merged=Number(fixture.final.expected.text_capacity)===1024;
  const final=merged?mergedInput(fixture.chunks[n-1],fixture.final,keys,await fake(n-2)):finalInput(fixture.final,keys,await fake(n-1));
  const allProved=merged?mergedInput(emptyStep(fixture.final),fixture.final,keys,await fake(n-1)):null;
  // noir_js may rewrite nested input objects, and inputs share them with the fixture.
  const accepts=async (program,input)=>{try{await program.execute(structuredClone(input),noForeign);return true;}catch{return false;}};
  const results=[];
  for(const [i,input] of inputs.entries())results.push({case:'part'+i,expected:true,accepted:await accepts(i?programs.fold:programs.start,input)});
  results.push({case:'final',expected:true,accepted:await accepts(programs.final,final)});
  if(allProved)results.push({case:'final (every part already proved)',expected:true,accepted:await accepts(programs.final,allProved)});
  if(flags.includes('--mutations')){
    const bump=v=>String(BigInt(v)+1n),flipSig=v=>{const s=[...v];s[40]=String((Number(s[40])+1)%256);return s;};
    const signedSlot=input=>input.events.findIndex(e=>e.kind==='1');
    const cases={
      ForgedCheckpointSignature:[0,v=>{const j=signedSlot(v);v.signatures[j]=flipSig(v.signatures[j]);}],
      OtherDevice:[1,v=>{v.device.x[5]=String((Number(v.device.x[5])+1)%256);}],
      ForgedLinkDevice:[0,v=>{v.link.device=bump(v.link.device);}],
      ForgedLinkEnd:[1,v=>{v.link.end_root=bump(v.link.end_root);}],
      BrokenChain:[1,v=>{v.prev.end_root=bump(v.prev.end_root);}],
      // Part 2 folds a fold proof: its key must then equal the chain key it claims.
      OtherFoldKey:[2,v=>{v.prev.chain_key=bump(v.prev.chain_key);v.link.chain_key=bump(v.link.chain_key);}],
      GenesisFolded:[1,v=>{v.expected.genesis=true;}],
      ChangedOperation:[0,v=>{v.ops[5].arg=bump(v.ops[5].arg);}],
      FinalForgedDevice:['final',v=>{(v.expected_final??v.expected).device=bump((v.expected_final??v.expected).device);}],
      FinalBrokenChain:['final',v=>{v.prev.end_root=bump(v.prev.end_root);}],
      FinalForeignChainKey:['final',v=>{v.prev.chain_key=bump(v.prev.chain_key);}],
      FinalForgedSealSignature:['final',v=>{const ev=v.tail??v.events,sig=v.tail_signatures??v.signatures;const j=ev.findLastIndex(e=>e.kind==='1');sig[j]=flipSig(sig[j]);}],
      FinalForgedDigest:['final',v=>{(v.expected_final??v.expected).event_digest=bump((v.expected_final??v.expected).event_digest);}],
      FinalForgedRawCommitment:['final',v=>{(v.expected_final??v.expected).raw_commitment=bump((v.expected_final??v.expected).raw_commitment);}],
      FinalSkippedLastPart:['final',v=>{if(v.expected_final){const e=emptyStep({...v,expected:v.expected_final,events:v.tail,signatures:v.tail_signatures});Object.assign(v,{...e,expected:e.expected});}else v.prev.end_root=bump(v.prev.end_root);}],
      FinalForgedLastPartOperation:['final',v=>{if(v.ops)v.ops[3].arg=bump(v.ops[3].arg);else v.prev.end_root=bump(v.prev.end_root);}],
    };
    for(const [name,[which,change]] of Object.entries(cases)){
      const input=structuredClone(which==='final'?final:inputs[which]);change(input);
      results.push({case:'Reject'+name,expected:false,accepted:await accepts(which==='final'?programs.final:which?programs.fold:programs.start,input)});
    }
  }
  const failed=results.filter(r=>r.expected!==r.accepted);
  out(JSON.stringify({file:path.basename(file),checks:results.length,failed}));
  process.exitCode=failed.length?1:0;
}

/** Proves every part in order, then the final step; returns the final proof and per-step timings. */
export async function proveChain(fixture,dir,{flavor='noir-recursive',reuse=false}={}){
  const keys=JSON.parse(await readFile(path.join(target,'keys.json'),'utf8'));
  await mkdir(dir,{recursive:true});
  const programs={start:await noir('start'),fold:await noir('fold'),final:await noir('final'+fixture.final.expected.text_capacity)};
  const timings=[];let prev=null;
  const step=async (label,name,program,input,type='noir-recursive')=>{
    const o0=path.join(dir,label);
    if(reuse&&label!=='final')try{return {key:await readFile(keyPath(name)),proof:await readFile(path.join(o0,'proof')),inputs:await readFile(path.join(o0,'public_inputs'))};}catch{}
    const t=performance.now();const {witness}=await program.execute(input,noForeign);
    const w=path.join(dir,label+'.gz'),o=path.join(dir,label);await writeFile(w,witness);
    run(['prove','-b',programPath(name),'-w',w,'-k',type==='noir-recursive'?keyPath(name):path.join(target,name,'target/evm-vk/vk'),'-t',type,'-c',crs,'-o',o]);
    timings.push({label,ms:Math.round(performance.now()-t)});
    return {key:await readFile(keyPath(name)),proof:await readFile(path.join(o,'proof')),inputs:await readFile(path.join(o,'public_inputs'))};
  };
  const name='final'+fixture.final.expected.text_capacity,merged=name==='final1024',parts=fixture.chunks.length;
  // final1024 proves the last part itself unless the session has a single part (then it takes an empty step).
  const proved=merged&&parts>1?parts-1:parts;
  for(const [i,c] of fixture.chunks.slice(0,proved).entries())prev=await step('part'+i,i?'fold':'start',i?programs.fold:programs.start,stepInput(c,keys,prev));
  const input=merged?mergedInput(proved<parts?fixture.chunks[parts-1]:emptyStep(fixture.final),fixture.final,keys,prev):finalInput(fixture.final,keys,prev);
  const final=await step('final',name,programs.final,input,flavor);
  return {final,timings,name};
}

async function chain(file){
  const fixture=JSON.parse(await readFile(file,'utf8'));const base=path.basename(file,'.json');
  const dir=path.join(target,'proofs',base);const started=performance.now();
  const {final,timings,name}=await proveChain(fixture,dir);
  const t=performance.now();
  run(['verify','-p',path.join(dir,'final/proof'),'-i',path.join(dir,'final/public_inputs'),'-k',keyPath(name),'-t','noir-recursive','-c',crs]);
  out(JSON.stringify({parts:fixture.chunks.length,proveAllMs:Math.round(t-started),verifyMs:Math.round(performance.now()-t),
    finalInputBytes:final.inputs.length,proofBytes:final.proof.length,timings}));
}

/** The final step again, as an EVM (Keccak transcript, zero-knowledge) proof, from the last part proved by `chain`. */
export async function evmFinal(fixture,dir,owner='0'){
  const keys=JSON.parse(await readFile(path.join(target,'keys.json'),'utf8'));
  const name='final'+fixture.final.expected.text_capacity,n=fixture.chunks.length,merged=name==='final1024';
  // Reuses `chain`'s parts; final1024 proves the last part's step again unless it was the only part.
  const last=merged&&n>1?n-2:n-1;
  const prev={key:await readFile(keyPath(last?'fold':'start')),proof:await readFile(path.join(dir,'part'+last,'proof')),
    inputs:await readFile(path.join(dir,'part'+last,'public_inputs'))};
  const evmKey=path.join(target,name,'target/evm-vk');
  try{await readFile(path.join(evmKey,'vk'));}catch{run(['write_vk','-b',programPath(name),'-t','evm','-c',crs,'-o',evmKey]);}
  const input=merged?mergedInput(n>1?fixture.chunks[n-1]:emptyStep(fixture.final),fixture.final,keys,prev,owner):finalInput(fixture.final,keys,prev,owner);
  const t=performance.now();const {witness}=await (await noir(name)).execute(input,noForeign);
  await writeFile(path.join(dir,'final-evm.gz'),witness);
  run(['prove','-b',programPath(name),'-w',path.join(dir,'final-evm.gz'),'-k',path.join(evmKey,'vk'),'-t','evm','-c',crs,'-o',path.join(dir,'final-evm')]);
  run(['verify','-p',path.join(dir,'final-evm/proof'),'-i',path.join(dir,'final-evm/public_inputs'),'-k',path.join(evmKey,'vk'),'-t','evm','-c',crs]);
  return {ms:Math.round(performance.now()-t),proof:await readFile(path.join(dir,'final-evm/proof')),inputs:await readFile(path.join(dir,'final-evm/public_inputs'))};
}

// bundle <case.json>: the v2 public proof from `chain`'s parts (reused), checked by the reader, then altered copies.
async function bundle(file){
  const fixture=JSON.parse(await readFile(file,'utf8'));const dir=path.join(target,'proofs',path.basename(file,'.json'));
  const {final}=await proveChain(fixture,dir,{reuse:true});
  const c=fixture.capsule,hexOf=a=>Buffer.from(a).toString('hex');
  const {assembleLong2,verifyLongNode}=await import('./reader.mjs');
  const source=assembleLong2({publicKeyHex:hexOf(c.public_key),events:fixture.events,checkpointRoots:c.checkpoint_roots,presenceRoots:c.presence_roots,
    text:fixture.text},{proof:final.proof.toString('base64'),publicInputs:final.inputs.toString('base64')});
  await writeFile(path.join(target,path.basename(file,'.json')+'-proof.json'),source);
  const t=performance.now();const report=await verifyLongNode(source,{text:fixture.text});
  out(JSON.stringify({bundleBytes:source.length,readerMs:Math.round(performance.now()-t),verified:report.verified,policy:report.journal.policy_satisfied,
    signatures:report.signaturesVerified,presence:report.presenceSignaturesVerified,owner:report.journal.owner}));
  const flip=b=>{const raw=Buffer.from(b,'base64');raw[raw.length>>1]^=1;return raw.toString('base64');};
  const cases={
    ChangedFinalProof:p=>{p.final=flip(p.final);},
    ChangedFinalInputs:p=>{p.finalInputs=flip(p.finalInputs);},
    OtherKey:p=>{const k=Buffer.from(p.publicKey,'base64');k[40]^=1;p.publicKey=k.toString('base64');},
    ChangedRoot:p=>{p.checkpointRoots[1]=String(BigInt(p.checkpointRoots[1])+1n);},
    ReorderedEvents:p=>{const i=p.events.indexOf('2');p.events=p.events.slice(0,i-1)+'21'+p.events.slice(i+1);},
    ChangedEmbeddedText:p=>{p.text=p.text.replace('a','b');},
    ExtraField:p=>{p.chunks=[];},
    V1Kind:p=>{p.kind='huma-long-assurance-public-proof-v1';},
  };
  const results=[];
  for(const [name,change] of Object.entries(cases)){
    const p=JSON.parse(source);change(p);let ok;try{ok=(await verifyLongNode(JSON.stringify(p),{text:fixture.text})).verified===true;}catch{ok=false;}
    results.push({case:'Reject'+name,accepted:ok});
  }
  for(const [name,other] of [['TrailingSpaceAccepted',fixture.text+' \t'],['ChangedText',fixture.text.slice(0,-1)]]){
    let ok;try{ok=(await verifyLongNode(source,{text:other})).verified===true;}catch{ok=false;}
    results.push({case:name,accepted:ok});
  }
  const failed=results.filter(r=>r.accepted!==(r.case==='TrailingSpaceAccepted'));
  out(JSON.stringify({checks:results.length,failed}));process.exitCode=failed.length?1:0;
}

const [command,...rest]=process.argv.slice(2);
if(command==='build')await build();
else if(command==='check')await check(rest[0],rest.slice(1));
else if(command==='chain')await chain(rest[0]);
else if(command==='bundle')await bundle(rest[0]);
else if(command==='evm'){const f=JSON.parse(await readFile(rest[0],'utf8'));const r=await evmFinal(f,path.join(target,'proofs',path.basename(rest[0],'.json')),rest[1]);
  out(JSON.stringify({evmProveMs:r.ms,proofBytes:r.proof.length,inputBytes:r.inputs.length}));}
else if(command!==undefined){process.stderr.write('Use: build | check <case.json> [--mutations] | chain <case.json>\n');process.exitCode=2;}
