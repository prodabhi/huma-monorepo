// Bundled local prover. All paths are reader-owned; the request supplies only
// the original signed session and an optional public proof. No key or signing API.
import { readFile, writeFile, lstat, readdir, mkdir, symlink, readlink, unlink } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createAssuranceVerifier } from './reader/assurance-core.mjs';
import { profileForProof } from './reader/assurance-profile.mjs';
import { createEvidenceVerifier } from './evidence/core.mjs';
import { KINDS as LONG_KINDS, KIND2 as LONG_KIND2, KIND3 as LONG_KIND3, KIND3P as LONG_KIND3P, KEYS as LONG_KEYS, KEYS2 as LONG_KEYS2, KEYS3 as LONG_KEYS3, assembleLong3, createLongVerifier, decodeFinal } from './reader/long.mjs';

globalThis.crypto ??= webcrypto;
process.umask(0o077);
// Keep anything a library logs (it could quote private values) out of both stdout and stderr. Our protocol uses
// direct writes.
for(const method of ['debug','error','info','log','warn'])console[method]=()=>{};
const root=path.dirname(fileURLToPath(import.meta.url));
const profiles={
  'assurance64-v1':{version:5,abi:'assurance-abi.json',publicBytes:3008,abiHash:'729cc9a345f5b8a37549cddbe3ef848edb7bfc8d051867c016928ddabbf3fdc5',
    bytecode:'c282b242a8ba73bf03b889ec4e512287f9a746ec4fdf5bd47555cd12666f04ec',
    vk:'bf1319ff4d1bc49029fa4875a9c5f529a5d17ec85bae5547ace311bbbbc3d3df',program:'program64.json',key:'assurance64.vk',profile:'assurance64-v1'},
  'assurance128-cp32-v1':{version:5,abi:'assurance-cp32-abi.json',publicBytes:4544,abiHash:'39aa83ef3ddeb5cb43c4f424d39f9ae349cc031241e5650da3678b3f96b9d075',
    bytecode:'6cb951178bc0530e85d7826e3720a641d2580015577b515aa950b960e0e3bb61',
    vk:'f8360140d689befc8f23b1794d5f0a9fe373a415804bd8881acdc4886af7f19c',program:'program128.json',key:'assurance128-cp32.vk',profile:'assurance128-cp32-v1'},
  'assurance256-v1':{version:4,abi:'assurance-abi.json',publicBytes:3008,abiHash:'729cc9a345f5b8a37549cddbe3ef848edb7bfc8d051867c016928ddabbf3fdc5',bytecode:'15d6b3c7d5db15310f56452b0d5808444daf166c6a610daffdd7ddf682c8b1c5',
    vk:'1cab7a6b3ce5947916ad8bc09616c801de66f896eecc6677dbaf43284696a496',program:'program.json',key:'assurance256.vk',profile:'assurance256-v1'},
  'assurance256-v2':{version:5,abi:'assurance-abi.json',publicBytes:3008,abiHash:'729cc9a345f5b8a37549cddbe3ef848edb7bfc8d051867c016928ddabbf3fdc5',bytecode:'64c7bee1b03e1538c1f86784afe1bc108df3cf603ea8628bf0e436bd197ca1c3',
    vk:'9faf09ad7af8b403cd8ea02cd1f896c96971f19bc03182660cc2008c8218f714',program:'program-v5.json',key:'assurance256-v2.vk',profile:'assurance256-v2'},
  'assurance256-cp32-v1':{version:5,abi:'assurance-cp32-abi.json',publicBytes:4544,abiHash:'39aa83ef3ddeb5cb43c4f424d39f9ae349cc031241e5650da3678b3f96b9d075',
    bytecode:'d2816750fd1278beb70c16743e4851561f9d5b30c57770f1a707a4d16ef2d2bc',
    vk:'5b3a98abe325feca9d5187668fc3e97ab0486b0a0f1e5cb2f904de1c67621b11',program:'program-cp32.json',key:'assurance256-cp32.vk',profile:'assurance256-cp32-v1'},
};
const sha=b=>createHash('sha256').update(b).digest('hex');
// bb locks its setup folder and unpacks the bundled compressed points into it on first use, so the folder
// can't be inside the signed (read-only) app. It lives in the user's cache and is filled once per Mac.
let crsDir;
// The step in progress, reported on failure (never text or inputs) so a failure on someone's Mac can be diagnosed.
let stage='start';
// Release builds leave the 64 MB of points out of the installer; the app downloads them once into crsDir
// (HumaCore ProvingSetup) and this checks them against the same fixed fingerprint before bb may use them.
const CRS_SHA256='3e1ac09652ee9df779a4955fb8f7050620c7b1ee7f18566581bd00326b06be37';
async function linkSetup(){
  stage='setup';
  crsDir=path.join(process.env.HOME??'/nonexistent','Library/Caches/dev.swayam.huma/crs');
  await mkdir(crsDir,{recursive:true,mode:0o700});
  const name='bn254_g1_compressed.dat',target=path.join(root,'crs',name),link=path.join(crsDir,name);
  if(await lstat(target).then(()=>true,()=>false)){
    // Development builds carry the points: re-point the link when the app moved (e.g. from the disk image to Applications).
    if(await readlink(link).catch(()=>null)!==target){await unlink(link).catch(()=>{});await symlink(target,link);}
    return;
  }
  const held=await lstat(link).catch(()=>null);
  if(!held?.isFile()||sha(await readFile(link))!==CRS_SHA256)throw Error('setup missing');
}
const b64=b=>Buffer.from(b).toString('base64');
function decode(s,max) {
  if(typeof s!=='string'||s.length>Math.ceil(max/3)*4)throw Error('input');
  const raw=Buffer.from(s,'base64');if(raw.length>max||b64(raw)!==s)throw Error('input');return raw;
}
// Two threads on a writer's Mac; the server prover passes its own count (the app clears this variable).
const threads=/^[1-9][0-9]{0,2}$/.test(process.env.HUMA_PROVER_THREADS??'')?process.env.HUMA_PROVER_THREADS:'2';
function child(executable,args,input=Buffer.alloc(0),limit=2*1024*1024,threadCount=threads) {
  // Long sessions emit one private chunk input per ~30 characters.
  return new Promise((resolve,reject)=>{
    const p=spawn(executable,args,{env:{...process.env,RAYON_NUM_THREADS:String(threadCount),HARDWARE_CONCURRENCY:String(threadCount)},
      stdio:['pipe','pipe','ignore']}); // No private assertions or tool diagnostics in logs.
    const chunks=[];let count=0,failed=false;
    p.stdout.on('data',chunk=>{count+=chunk.length;if(count>limit){failed=true;p.kill('SIGKILL');}else chunks.push(chunk);});
    const tool=path.basename(executable);
    p.once('error',()=>reject(Error(tool+' did not start')));
    p.once('close',(code,signal)=>code===0&&!failed?resolve(Buffer.concat(chunks)):reject(Error(tool+(failed?' output too large':' exit '+(signal??code)))));
    p.stdin.on('error',()=>{});p.stdin.end(input);
  });
}
// Long drafts (assurance-long-v3): every part is proved on its own while the writer types, and the final step
// states the sealed session; no proof verifies another. One part and one final program per text tier, all
// staged from integrations/noir/long3. Pages proved before v3 (v1, v2) are only verified.
const long3={
  chunk1024:{bytecode:'7fb97a2452c2d421f3728f891ce981e3da41f4b7f1ced019acf4c0549c0a4300',vk:'8d8a3bae78664b1b3883b94a1e361d56ee573b7102acc5c18bfd6e721490396b'},
  final1024:{bytecode:'0ef8d2d4be19b51eb1727484703837e59d229cea631177b5b4b100cd8a1f3a44',vk:'c9ce374434fdda60af5c436336410bacc83bdadfaef034ac33432d82a1b3cc28'},
  chunk4096:{bytecode:'a1508af5bebc2f671a49aed30e85866c8de7748c7849cb3247d32c822cf807be',vk:'a73280bcdb84a952e6ca84bc7bcf264dcaea0ee480b3dde00933d7d123782894'},
  final4096:{bytecode:'6a50011e511032c23d70186cb437b70c353fd79aabb89d264dae1635e7764abc',vk:'75414e8be776c623d3eca1177fa1ba2af5f094cd6605427826e0af8c1e5ee95f'},
  chunk10000:{bytecode:'afc3a541737fdc7a0e2c13ef20ec689fce67ced65d3feb9c05be2935d5c08ca4',vk:'fd0f825f50bfc0312b617bc02141c73a2691df7f444eee5ddd78b219cd3d0ba0'},
  final10000:{bytecode:'21da3a3c460175280b96937a3c9e6851725dceee711a90af1d511ac9be7aeb78',vk:'842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8'}};
const TIERS=[1024,4096,10000];
function isLong(proof){try{return typeof proof==='string'&&LONG_KINDS.includes(JSON.parse(proof).kind);}catch{return false;}}
const programFile=name=>path.join(root,'long3-'+name+'.json'),keyFile=name=>path.join(root,'reader/assets/long3-'+name+'.vk');
async function program3(name){
  const pin=long3[name];if(!pin)throw Error('tier');
  const program=JSON.parse(await readFile(programFile(name),'utf8'));
  if(sha(program.bytecode)!==pin.bytecode||sha(await readFile(keyFile(name)))!==pin.vk)throw Error('program pin');
  return program;
}
/** Writes the witness for `program`'s `input` to the new file `out`: Noir's own solver run natively (witness,
 *  from integrations/noir/witness). Same bytes as noir_js; a 600-operation part takes about 1 s, where noir_js on
 *  JavaScriptCore took 44 s. */
const solve=(program,input,out)=>child(path.join(root,'witness'),[program,out],Buffer.from(JSON.stringify(input)),0);
const fieldHex=v=>BigInt(v).toString(16).padStart(64,'0');
/** Public inputs of a part proof: the state it starts at, the one it ends at, and whether it starts the session. */
const boundaryInputs=input=>b64(Buffer.from(fieldHex(input.expected.start_root)+fieldHex(input.expected.end_root)+fieldHex(input.expected.genesis?1:0),'hex'));
/** The witness for `input` now; returns the job that proves it on `count` threads and checks the proof natively
 *  before returning it. */
async function prove3(name,input,work,label){
  stage='prove '+name;
  await program3(name);
  const dir=path.join(work,label);
  await solve(programFile(name),input,dir+'.gz');
  return async(count=threads)=>{
    await child(path.join(root,'bb'),['prove','-b',programFile(name),'-w',dir+'.gz','-o',dir,'-k',keyFile(name),'-t','noir-recursive','-c',crsDir],undefined,undefined,count);
    await child(path.join(root,'bb'),['verify','-p',path.join(dir,'proof'),'-i',path.join(dir,'public_inputs'),'-k',keyFile(name),'-t','noir-recursive','-c',crsDir]);
    return {proof:b64(await readFile(path.join(dir,'proof'))),publicInputs:b64(await readFile(path.join(dir,'public_inputs')))};
  };
}
/** The tier a part's input is for: the size of the text buffer it carries. */
function inputTier(input){const n=input?.state?.buffer?.length;if(!TIERS.includes(n))throw Error('tier');return n;}
function sameStatement(decoded,statement){
  const {owner:_,...rest}=decoded;
  return Object.keys(rest).length===Object.keys(statement).length&&
    Object.entries(rest).every(([k,v])=>String(v)===String(statement[k]));
}
const keyNames=[['long-',LONG_KEYS],['long2-',LONG_KEYS2],['long3-',LONG_KEYS3]];
// Native verification of each exact (proof, inputs, key) triple, cached for the envelope's second pass.
function nativeVerifier(work){
  const seen=new Map();let count=0;
  return async(proof,inputs,key)=>{
    const id=sha(Buffer.concat([Buffer.from(proof),Buffer.from(inputs),Buffer.from(key)]));
    if(seen.has(id))return seen.get(id);
    const digest=sha(Buffer.from(key));
    const named=keyNames.map(([prefix,pins])=>[prefix,Object.keys(pins).find(n=>pins[n]===digest)]).find(([,n])=>n);
    if(!named)return false;
    const p=path.join(work,'verify-'+count),i=path.join(work,'verify-inputs-'+count++);
    await writeFile(p,proof,{flag:'wx',mode:0o600});await writeFile(i,inputs,{flag:'wx',mode:0o600});
    const pinned=path.join(root,'reader/assets',named[0]+named[1]+'.vk');
    let ok=true;try{await child(path.join(root,'bb'),['verify','-p',p,'-i',i,'-k',pinned,'-t','noir-recursive','-c',crsDir]);}catch{ok=false;}
    seen.set(id,ok);return ok;
  };
}
async function longKeys(){
  const read=(prefix,names,pins)=>Promise.all(names.map(async n=>{const k=await readFile(path.join(root,'reader/assets',prefix+n+'.vk'));if(sha(k)!==pins[n])throw Error('key pin');return [n,k];}));
  return {keys:Object.fromEntries(await read('long-',Object.keys(LONG_KEYS),LONG_KEYS)),keys2:Object.fromEntries(await read('long2-',Object.keys(LONG_KEYS2),LONG_KEYS2)),
    keys3:Object.fromEntries(await read('long3-',Object.keys(LONG_KEYS3),LONG_KEYS3))};
}
async function longSession(request,timings,validationStarted){
  const work=request.workDirectory,st=await lstat(work);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)||(await readdir(work)).length)throw Error('private workspace');
  await linkSetup();
  const started=performance.now();
  if(request.command==='chunk'){
    // One closed part, proved on its own while the writer keeps typing, at the tier its input carries.
    if(request.proof!==undefined||request.chunkProofs!==undefined||request.previous!==undefined)throw Error('request');
    const input=JSON.parse(decode(request.input,4*1024*1024)),tier=inputTier(input);
    const proved=await (await prove3('chunk'+tier,input,work,'chunk'))();
    if(proved.publicInputs!==boundaryInputs(input))throw Error('different part boundary');
    await emit({ok:true,proof:proved.proof,publicInputs:proved.publicInputs,tier,elapsedMs:performance.now()-started});return;
  }
  const decoded=decode(request.input,48*1024*1024);
  const summary=JSON.parse(await child(path.join(root,'capture-input'),[request.command==='verify'?'long-worker-statement':'long-worker-input'],decoded,512*1024*1024));
  timings.validationMs=performance.now()-validationStarted;
  let source;
  if(request.command==='prove-long'){
    // Only sessions recorded for v3 (their nonce binds the capture key) are proved; older ones keep their proofs.
    if(summary.format!=='v3'||!TIERS.includes(summary.tier))throw Error('older recording');
    const cached=request.chunkProofs??[],count=summary.chunks.length,tier=summary.tier;
    if(!Array.isArray(cached)||cached.length>count)throw Error('chunk proofs');
    // A part proved while writing is reused when it proves this exact boundary (so also this tier).
    const parts=summary.chunks.map((input,i)=>{const c=cached[i];
      return c&&typeof c==='object'&&c.index===i&&typeof c.proof==='string'&&c.publicInputs===boundaryInputs(input)?{proof:c.proof,publicInputs:c.publicInputs}:null;});
    // Parts saved under an older part key would fail the final step on every retry, so each must verify now.
    if(parts.some(Boolean))await program3('chunk'+tier);
    for(let i=0;i<count;i++)if(parts[i]){
      const p=path.join(work,'reuse-'+i),inputs=p+'-inputs';
      await writeFile(p,Buffer.from(parts[i].proof,'base64'),{flag:'wx',mode:0o600});await writeFile(inputs,Buffer.from(parts[i].publicInputs,'base64'),{flag:'wx',mode:0o600});
      try{await child(path.join(root,'bb'),['verify','-p',p,'-i',inputs,'-k',keyFile('chunk'+tier),'-t','noir-recursive','-c',crsDir]);}catch{parts[i]=null;}
    }
    const proveStarted=performance.now();timings.reusedChunks=parts.filter(Boolean).length;
    // Witnesses one after another here; proofs in two lanes that share the threads, so missing parts and the
    // final step prove side by side. With every part already proved, the final step gets all of them.
    const missing=parts.filter(p=>!p).length,lanes=[Promise.resolve(),Promise.resolve()].slice(0,missing?2:1);
    const each=Math.max(1,Math.floor(Number(threads)/lanes.length));let turn=0;const proving=[];
    const queue=job=>{const lane=turn++%lanes.length,done=lanes[lane].then(()=>job(each));lanes[lane]=done.catch(()=>{});done.catch(()=>{});proving.push(done);return done;};
    for(let i=0;i<count;i++)if(!parts[i]){
      const done=queue(await prove3('chunk'+tier,summary.chunks[i],work,'part-'+i));
      const checked=done.then(p=>{if(p.publicInputs!==boundaryInputs(summary.chunks[i]))throw Error('different part boundary');parts[i]=p;});
      checked.catch(()=>{});proving.push(checked); // awaited below; a failure there ends the proof
    }
    const final=queue(await prove3('final'+tier,summary.final,work,'final'));
    await Promise.all(proving);
    const sealed=await final,statement=decodeFinal(Buffer.from(sealed.publicInputs,'base64'));
    if(!sameStatement(statement,summary.statement)||statement.text_capacity!==tier)throw Error('different final statement');
    timings.proveMs=performance.now()-proveStarted;timings.chunks=count;
    source=assembleLong3(summary,parts,sealed);
  } else {
    if(request.chunkProofs!==undefined)throw Error('request');
    source=request.proof;const p=JSON.parse(source);
    // The imported proof must carry this draft's exact signed session, read in the format it was proved in.
    const key=b64(Buffer.from(summary.publicKeyHex,'hex'));
    const v2=p.kind===LONG_KIND2,v3=p.kind===LONG_KIND3||p.kind===LONG_KIND3P,inputs=decode(p.finalInputs,v2?1472:1408);
    if((summary.format==='v3')!==v3)throw Error('different signed session');
    if(p.publicKey!==key||p.events!==summary.events||JSON.stringify(p.checkpointRoots)!==JSON.stringify(summary.checkpointRoots)||
      JSON.stringify(p.presenceRoots)!==JSON.stringify(summary.presenceRoots)||
      (!v2&&(JSON.stringify(p.signatures)!==JSON.stringify(summary.signaturesHex.map(h=>b64(Buffer.from(h,'hex'))))||
        JSON.stringify(p.presenceSignatures)!==JSON.stringify(summary.presenceSignaturesHex.map(h=>b64(Buffer.from(h,'hex'))))))||
      typeof p.finalInputs!=='string'||!sameStatement(decodeFinal(inputs),v2||v3?summary.statement:(({device:_,...rest})=>rest)(summary.statement)))throw Error('different signed session');
  }
  const verifyStarted=performance.now();
  const {keys,keys2,keys3}=await longKeys();
  const verifyLong=createLongVerifier({keys,keys2,keys3,verifyZk:nativeVerifier(work)});
  const engine=createEvidenceVerifier({verifyLong});
  const wrapped=await engine.envelope(source,{requireSignedCapture:true,expectedKey:sha(Buffer.from(summary.publicKeyHex,'hex'))},summary.text);
  if(!wrapped.report.verified)throw Error('verification');
  timings.verifyMs=performance.now()-verifyStarted;
  const kind=JSON.parse(source).kind;
  await emit({ok:true,proof:source,envelope:wrapped.envelope,report:wrapped.report,
    elapsedMs:performance.now()-started,timings,backend:kind===LONG_KIND3||kind===LONG_KIND3P?'noir-long-v3':kind===LONG_KIND2?'noir-long-v2':'noir-long-v1'});
}
// Large replies must reach the pipe before the process exits.
const emit=value=>new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(value),e=>e?reject(e):resolve()));
try {
  const validationStarted=performance.now();const timings={};
  let raw;
  const parts=[];let size=0;
  for await(const chunk of process.stdin){size+=chunk.length;if(size>64*1024*1024)throw Error('size');parts.push(chunk);}
  raw=Buffer.concat(parts);
  const request=JSON.parse(raw);
  if(!request||!['prove','verify','chunk','prove-long'].includes(request.command)||
    Object.keys(request).some(k=>!['command','input','proof','workDirectory','chunkProofs','previous'].includes(k)))throw Error('request');
  if(request.previous!==undefined)throw Error('request');
  stage=request.command;
  if(['chunk','prove-long'].includes(request.command)||(request.command==='verify'&&isLong(request.proof))){
    await longSession(request,timings,validationStarted);process.exit(0);
  }
  let selected,imported;
  if(request.command==='verify'){
    if(typeof request.proof!=='string'||Buffer.byteLength(request.proof)>65536)throw Error('proof');
    imported=JSON.parse(request.proof);
    selected=profileForProof(request.proof).profile;
  }
  const work=request.workDirectory,st=await lstat(work);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)|| (await readdir(work)).length)throw Error('private workspace');
  await linkSetup();
  const prepared=JSON.parse(await child(path.join(root,'capture-input'),['assurance-sized-worker-input',...(selected?[selected]:[])],decode(request.input,4*1024*1024)));
  if(request.command==='prove')selected=prepared.provingProfile;
  if(prepared.provingProfile!==selected)throw Error('different proof profile');
  const pin=Object.hasOwn(profiles,selected)?profiles[selected]:undefined;if(!pin)throw Error('unsupported proof');
  const version=pin.version;
  const program=JSON.parse(await readFile(path.join(root,pin.program),'utf8'));
  const [vk,abi]=await Promise.all([pin.key,pin.abi].map(name=>readFile(path.join(root,'reader/assets',name))));
  if(sha(program.bytecode)!==pin.bytecode||sha(vk)!==pin.vk||sha(abi)!==pin.abiHash)throw Error('program pin');
  timings.validationMs=performance.now()-validationStarted;
  const expectedInputs=Buffer.from(prepared.publicInputsHex,'hex');
  const key=Buffer.from(prepared.publicKeyHex,'hex');
  const template={kind:'huma-compact-assurance-public-proof-v'+version,profile:pin.profile,publicKey:b64(key),
    signatures:prepared.signaturesHex.map(s=>b64(Buffer.from(s,'hex'))),
    presenceSignatures:prepared.presenceSignaturesHex.map(s=>b64(Buffer.from(s,'hex'))),text:prepared.text};
  const started=performance.now();let publicProof;
  const bb=path.join(root,'bb'),common=['-k',path.join(root,'reader/assets',pin.key),'-t','noir-recursive','-c',crsDir];
  if(request.command==='prove') {
    if(request.proof!==undefined)throw Error('unexpected proof');
    const witnessStarted=performance.now();
    await solve(path.join(root,pin.program),prepared.inputs,path.join(work,'witness.gz'));
    timings.witnessMs=performance.now()-witnessStarted;
    const proveStarted=performance.now();
    await child(bb,['prove','-b',path.join(root,pin.program),'-w',path.join(work,'witness.gz'),'-o',path.join(work,'proof'),...common]);
    timings.proveMs=performance.now()-proveStarted;
    publicProof={...template,proof:b64(await readFile(path.join(work,'proof/proof'))),publicInputs:b64(await readFile(path.join(work,'proof/public_inputs')))};
  } else {
    publicProof=imported;
  }
  const verifyStarted=performance.now();
  if(publicProof.publicInputs!==b64(expectedInputs)||publicProof.publicKey!==template.publicKey||
      JSON.stringify(publicProof.signatures)!==JSON.stringify(template.signatures)||
      JSON.stringify(publicProof.presenceSignatures)!==JSON.stringify(template.presenceSignatures))throw Error('different signed session');
  const proof=decode(publicProof.proof,14656),inputs=decode(publicProof.publicInputs,pin.publicBytes);
  if(proof.length!==14656||inputs.length!==pin.publicBytes)throw Error('proof size');
  await writeFile(path.join(work,'proof.bin'),proof,{flag:'wx',mode:0o600});
  await writeFile(path.join(work,'inputs.bin'),inputs,{flag:'wx',mode:0o600});
  await child(bb,['verify','-p',path.join(work,'proof.bin'),'-i',path.join(work,'inputs.bin'),...common]);
  const source=JSON.stringify(publicProof);
  const verifyAssurance=await createAssuranceVerifier({verificationKey:new Uint8Array(vk),journalABI:new Uint8Array(abi),version,profile:pin.profile,
    // Native verification above is cached only for these exact immutable bytes.
    verifyZk:async(p,i,k)=>Buffer.from(p).equals(proof)&&Buffer.from(i).equals(inputs)&&Buffer.from(k).equals(vk)});
  const engine=createEvidenceVerifier({verifyAssurance});
  const wrapped=await engine.envelope(source,{requireSignedCapture:true,expectedKey:sha(key)},prepared.text);
  if(!wrapped.report.verified)throw Error('verification');
  timings.verifyMs=performance.now()-verifyStarted;
  process.stdout.write(JSON.stringify({ok:true,proof:source,envelope:wrapped.envelope,report:wrapped.report,
    elapsedMs:performance.now()-started,timings,backend:'noir-assurance-v'+version}));
} catch(error) {
  // Only messages this worker wrote itself; library errors (e.g. JSON parsing) can quote inputs, so just their type.
  const code=/^[A-Z][A-Z0-9_]{1,24}$/.test(error?.code??'')?' '+error.code:'';
  const detail=(error?.name==='Error'&&/^[a-z][a-z0-9 .:_-]{0,60}$/i.test(error.message)?error.message:String(error?.name??'unknown').slice(0,30))+code;
  process.stdout.write(JSON.stringify({ok:false,failure:(stage+': '+detail).slice(0,100)}));
  process.stderr.write('The local Noir proof did not validate. Your signed recording is unchanged.\n');
  process.exitCode=1;
}
