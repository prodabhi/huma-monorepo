// Research-only WASM cross-check. These keys are not admitted by the public SDK.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash, webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createWasmVerifier } from './browser/wasm.mjs';
import { checkAsset } from './browser/profile.mjs';

globalThis.crypto ??= webcrypto;
for (const name of ['debug','error','info','log','warn']) console[name] = () => {};
const root=fileURLToPath(new URL('../../../',import.meta.url));
const pins={
  'short64-cp8-v2':{key:'bf1319ff4d1bc49029fa4875a9c5f529a5d17ec85bae5547ace311bbbbc3d3df',inputs:3008},
  'short128-cp32-v2':{key:'f8360140d689befc8f23b1794d5f0a9fe373a415804bd8881acdc4886af7f19c',inputs:4544},
};
const [directory,...names]=process.argv.slice(2),pin=Object.hasOwn(pins,directory)?pins[directory]:undefined;
assert(pin && names.length && names.every(name=>/^[a-zA-Z0-9-]+$/.test(name)));
const work=path.join(root,'build/research/noir-capacity',directory),sha=b=>createHash('sha256').update(b).digest('hex');
const key=new Uint8Array(await readFile(path.join(work,'target/setup/vk')));
assert.equal(key.length,3680);assert.equal(sha(key),pin.key);
const wasm=fileURLToPath(new URL('./browser/assets/barretenberg-threads.wasm',import.meta.url));
await checkAsset('barretenberg-threads.wasm',new Uint8Array(await readFile(wasm)));
const backend=await createWasmVerifier(new Uint8Array(await readFile(new URL('./browser/assets/g2.dat',import.meta.url))),wasm);
const results=[];
try {
  const rejects=async(proof,inputs)=>{
    try {assert.notEqual(await backend.verify(proof,inputs,key),true);}
    catch(error) {if(error?.code==='ERR_ASSERTION')throw error;}
  };
  for(const name of names) {
    const folder=path.join(work,'target','proof-'+name);
    const proof=new Uint8Array(await readFile(path.join(folder,'proof'))),inputs=new Uint8Array(await readFile(path.join(folder,'public_inputs')));
    assert.equal(proof.length,14656);assert.equal(inputs.length,pin.inputs);
    assert.equal(await backend.verify(proof,inputs,key),true);
    const badProof=proof.slice();badProof[badProof.length-1]^=1;await rejects(badProof,inputs);
    const badInputs=inputs.slice();badInputs[31]^=1;await rejects(proof,badInputs);
    results.push({name,validProofAccepted:true,changedProofRejected:true,changedPublicInputsRejected:true,
      proofSha256:sha(proof),publicInputsSha256:sha(inputs)});
  }
} finally {await backend.destroy();}
const report={kind:'huma-short-bucket-wasm-check-v1',sdkProfileRegistered:false,proofGenerated:false,
  softwareFixturesOnly:true,ownerIdentityUsed:false,programKeyHash:pin.key,cases:results};
await writeFile(path.join(work,'wasm-results.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify(report)+'\n');
