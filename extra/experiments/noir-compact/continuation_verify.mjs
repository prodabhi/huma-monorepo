// Independent final pairing checks for the research component, not SDK admission.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash,webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createWasmVerifier} from './browser/wasm.mjs';
import {checkAsset} from './browser/profile.mjs';

globalThis.crypto??=webcrypto;
for(const name of ['debug','error','info','log','warn'])console[name]=()=>{};
const root=fileURLToPath(new URL('../../../',import.meta.url));
const name=process.argv[2],expectedKey=process.argv[3];
const mode=process.argv[4]??'replay',checkOnly=process.argv[5]==='--check-only';
assert.match(name??'',/^[a-zA-Z0-9-]+$/);assert(!name.includes('unsafe'));
assert.match(expectedKey??'',/^[0-9a-f]{64}$/);
assert(['replay','interaction'].includes(mode));assert(process.argv[5]===undefined||checkOnly);
const interaction=mode==='interaction';
const work=path.join(root,'build/research',interaction?'noir-interaction':'noir-continuation',name);
const native=JSON.parse(await readFile(path.join(work,'proof-results.json'),'utf8'));
const key=new Uint8Array(await readFile(path.join(work,'target/setup/vk')));
const sha=b=>createHash('sha256').update(b).digest('hex');
assert.equal(sha(key),expectedKey);assert.equal(native.keySha256,expectedKey);
const wasm=fileURLToPath(new URL('./browser/assets/barretenberg-threads.wasm',import.meta.url));
await checkAsset('barretenberg-threads.wasm',new Uint8Array(await readFile(wasm)));
const backend=await createWasmVerifier(new Uint8Array(await readFile(new URL('./browser/assets/g2.dat',import.meta.url))),wasm);
const cases=[];
try{
  for(const row of native.cases){
    const directory=path.join(work,'target','proof-Chunk'+row.index);
    const proof=new Uint8Array(await readFile(path.join(directory,'proof')));
    const inputs=new Uint8Array(await readFile(path.join(directory,'public_inputs')));
    assert.equal(proof.length,row.proofBytes);assert.equal(inputs.length,interaction?672:256);
    assert.equal(sha(proof),row.proofSha256);assert.equal(sha(inputs),row.publicInputsSha256);
    const b=row.boundary,values=[...b.nonce,b.start_root,b.end_root,b.start_offset,b.end_offset,b.capture_root,Number(b.final_step)];
    if(interaction)values.push(b.origin_root,...b.rules.map(Number),Number(b.policy_satisfied),b.origin_present,b.origin_hid);
    const expected=Buffer.from(values.map(n=>BigInt(n).toString(16).padStart(64,'0')).join(''),'hex');
    assert.deepEqual(Buffer.from(inputs),expected);
    const alteredInputs=async name=>new Uint8Array(await readFile(path.join(directory,name)));
    const variants=[
      ['Valid',proof,inputs,true],
      ['ChangedCapturePrefix',proof,await alteredInputs(interaction?'changed_capture_inputs':'changed_public_inputs'),false],
      ['ChangedProof',new Uint8Array(await readFile(path.join(directory,'changed_proof'))),inputs,false],
    ];
    if(interaction)variants.push(['ChangedOriginRoot',proof,await alteredInputs('changed_origin_inputs'),false],
      ['ChangedPolicy',proof,await alteredInputs('changed_policy_inputs'),false]);
    for(const [label,p,i,accepted] of variants){
      const verified=await backend.verify(p,i,key);assert.equal(verified,accepted,`${row.index}:${label}`);
      cases.push({index:row.index,name:label,verified,expectedVerified:accepted});
    }
  }
}finally{await backend.destroy();}
const report={kind:interaction?'huma-interaction-continuation-wasm-v1':'huma-continuation-component-wasm-v1',keySha256:expectedKey,
  softwareFixturesOnly:true,ownerIdentityUsed:false,completeHumaSessionProof:false,appChanged:false,cases};
if(checkOnly)assert.deepEqual(JSON.parse(await readFile(path.join(work,'wasm-results.json'),'utf8')),report);
else await writeFile(path.join(work,'wasm-results.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify(report)+'\n');
