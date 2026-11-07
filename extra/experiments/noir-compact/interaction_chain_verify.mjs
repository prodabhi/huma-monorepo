// Offline export/verification and adversarial checks of a portable component.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat} from 'node:fs/promises';
import {createHash,webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {CHAIN_KIND,ChainError,verifyInteractionChain} from './browser/interaction-chain.mjs';
import {createWasmVerifier} from './browser/wasm.mjs';
import {checkAsset} from './browser/profile.mjs';
import {verify as verifyEvidence} from '../../../frontend/verify-core/node.mjs';

globalThis.crypto??=webcrypto;
for(const name of ['debug','error','info','log','warn'])console[name]=()=>{};
const root=fileURLToPath(new URL('../../../',import.meta.url));
const work=path.join(root,'build/research/noir-interaction/rollover-full-v3');
const reportPath=path.join(work,'portable-chain-results.json');
try{await stat(reportPath);throw new Error('Existing report is immutable');}catch(e){if(e.code!=='ENOENT')throw e;}
const key=new Uint8Array(await readFile(path.join(work,'target/setup/vk')));
const keyHash=createHash('sha256').update(key).digest('hex');
assert.equal(keyHash,'e4417cf3287a69d79ec01fe858bdecc4dd0d8f9f0c1ee5edaab7f00e020329a8');
const native=JSON.parse(await readFile(path.join(work,'proof-results.json'),'utf8'));
assert.equal(native.allReplayChunksProved,true);assert.equal(native.cases.length,17);
async function bundleFor(name,profile){
  const directory=path.join(root,'build/research/noir-interaction',name);
  const report=JSON.parse(await readFile(path.join(directory,'proof-results.json'),'utf8'));
  const chunks=[];
  for(const row of report.cases){
    const p=path.join(directory,'target','proof-Chunk'+row.index);
    chunks.push({proof:(await readFile(path.join(p,'proof'))).toString('base64'),
      publicInputs:(await readFile(path.join(p,'public_inputs'))).toString('base64')});
  }
  return {kind:CHAIN_KIND,profile,chunks};
}
const bundle=await bundleFor('rollover-full-v3','interaction256-ops12-v1');
const serialized=JSON.stringify(bundle);
const exported=path.join(work,'public-component-chain.json');
await writeFile(exported,serialized+'\n',{flag:'wx',mode:0o600});
const reopened=await readFile(exported,'utf8');assert.deepEqual(JSON.parse(reopened),bundle);
const wasm=fileURLToPath(new URL('./browser/assets/barretenberg-threads.wasm',import.meta.url));
await checkAsset('barretenberg-threads.wasm',new Uint8Array(await readFile(wasm)));
const setupStarted=performance.now();
const backend=await createWasmVerifier(new Uint8Array(await readFile(new URL('./browser/assets/g2.dat',import.meta.url))),wasm);
const setupMs=performance.now()-setupStarted;
const probes=[];let valid,verifyMs,sdkRejected=false;
function alterInput(value,row,field,change){
  const raw=Buffer.from(value.chunks[row].publicInputs,'base64');
  const before=BigInt('0x'+raw.subarray(field*32,field*32+32).toString('hex'));
  Buffer.from(change(before).toString(16).padStart(64,'0'),'hex').copy(raw,field*32);
  value.chunks[row].publicInputs=raw.toString('base64');
}
try{
  const options={backend,loadKey:async()=>key};
  const started=performance.now();valid=await verifyInteractionChain(reopened,options);verifyMs=performance.now()-started;
  assert.equal(valid.componentVerified,true);assert.equal(valid.policySatisfied,true);
  assert.equal(valid.chunks,17);assert.equal(valid.finalTextVerified,false);
  async function reject(name,value,expectedCode,override={}){
    let code;
    try{await verifyInteractionChain(typeof value==='string'?value:JSON.stringify(value),{...options,...override});}
    catch(e){if(!(e instanceof ChainError))throw e;code=e.code;}
    assert.equal(code,expectedCode,name);probes.push({name,rejected:true,code});
  }
  const changed=(fn)=>{const value=structuredClone(bundle);fn(value);return value;};
  await reject('DroppedChunk',changed(v=>v.chunks.splice(1,1)),'Link');
  await reject('ReorderedChunks',changed(v=>[v.chunks[1],v.chunks[2]]=[v.chunks[2],v.chunks[1]]),'Link');
  await reject('PartialPrefix',changed(v=>v.chunks.pop()),'Link');
  await reject('CrossSession',changed(v=>alterInput(v,1,0,n=>n+1n)),'Link');
  await reject('ResetState',changed(v=>alterInput(v,1,2,n=>n+1n)),'Link');
  await reject('ChangedFinalOriginRoot',changed(v=>alterInput(v,16,8,n=>n+1n)),'ProofRejected');
  await reject('ForgedFinalPolicy',changed(v=>{for(let i=9;i<=18;i++)alterInput(v,16,i,()=>0n);}),'ProofRejected');
  await reject('ChangedProof',changed(v=>{
    const b=Buffer.from(v.chunks[8].proof,'base64');b[b.length/2]^=1;v.chunks[8].proof=b.toString('base64');
  }),'ProofRejected');
  await reject('UnknownProfile',changed(v=>v.profile='anything-the-proof-chooses'),'UntrustedProfile');
  const substituted=new Uint8Array(key);substituted[0]^=1;
  await reject('SubstitutedVerifierKey',bundle,'KeyRejected',{loadKey:async()=>substituted});
  await reject('NonCanonicalBase64',changed(v=>v.chunks[0].proof+='\n'),'Format');
  await reject('ExtraPrivateClaim',changed(v=>v.typedText='unproven text'),'Format');
  await reject('EmptyChain',changed(v=>v.chunks=[]),'Format');
  const sampled=await bundleFor('typing10000-v2','interaction10000-ops120-v1');
  await reject('Sampled10kChunksAreNotACompleteChain',sampled,'Link');
  sdkRejected=(await verifyEvidence(reopened,{})).verified===false;assert(sdkRejected);
}finally{await backend.destroy();}
const report={kind:'huma-portable-interaction-chain-acceptance-v1',softwareFixturesOnly:true,
  ownerIdentityUsed:false,appChanged:false,sdkProfileRegistered:false,completeHumaSessionProof:false,
  keyHash,chunks:17,exportedBytes:Buffer.byteLength(reopened),exportSha256:createHash('sha256').update(reopened).digest('hex'),
  wasmSetupMs:setupMs,allChunkVerificationMs:verifyMs,setupAndVerifyMs:setupMs+verifyMs,
  valid,negativeChecks:probes,sdkRejectedUnfinishedComponent:sdkRejected,
  completeTenThousandCharacterSessionVerified:false};
await writeFile(reportPath,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify(report)+'\n');
