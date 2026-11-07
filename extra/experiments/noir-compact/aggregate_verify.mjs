// Research-only final pairing checks; no profile is added to the Huma SDK.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash,webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createWasmVerifier} from './browser/wasm.mjs';
import {checkAsset} from './browser/profile.mjs';
import {verify as verifyEvidence} from '../../../frontend/verify-core/node.mjs';

globalThis.crypto??=webcrypto;
for(const name of ['debug','error','info','log','warn'])console[name]=()=>{};
const root=fileURLToPath(new URL('../../../',import.meta.url));
const work=path.join(root,'build/research/noir-aggregation/recursive64-one-v1');
const key=new Uint8Array(await readFile(path.join(work,'target/setup/vk')));
const sha=b=>createHash('sha256').update(b).digest('hex');
assert.equal(sha(key),'967c30dd70e3a0bb822e621cdf5269d0b3c1f4986468eb2ab27523e20dde94d8');
const wasm=fileURLToPath(new URL('./browser/assets/barretenberg-threads.wasm',import.meta.url));
await checkAsset('barretenberg-threads.wasm',new Uint8Array(await readFile(wasm)));
const backend=await createWasmVerifier(new Uint8Array(await readFile(new URL('./browser/assets/g2.dat',import.meta.url))),wasm);
const cases=[];let profileSubstitutionRejected=false;
try{
  for(const [name,expected] of [['Valid',true],['BadInnerProof',false],['BadInnerPublicInput',false]]){
    const directory=path.join(work,'target','proof-'+name);
    const proof=new Uint8Array(await readFile(path.join(directory,'proof')));
    const inputs=new Uint8Array(await readFile(path.join(directory,'public_inputs')));
    assert.equal(proof.length,14656);assert.equal(inputs.length,3008);
    const verified=await backend.verify(proof,inputs,key);
    assert.equal(verified,expected,name);
    cases.push({name,verified,expectedVerified:expected,proofSha256:sha(proof),publicInputsSha256:sha(inputs)});
    if(name==='Valid'){
      const original=JSON.parse(await readFile(new URL('./browser/test/fixtures/Assurance64.json',import.meta.url),'utf8'));
      original.proof=Buffer.from(proof).toString('base64');
      original.publicInputs=Buffer.from(inputs).toString('base64');
      assert.equal((await verifyEvidence(JSON.stringify(original),{},original.text)).verified,false);
      profileSubstitutionRejected=true;
    }
  }
}finally{await backend.destroy();}
const report={kind:'huma-recursive-component-wasm-v1',softwareFixturesOnly:true,ownerIdentityUsed:false,
  completeHumaSessionProof:false,appChanged:false,profileSubstitutionRejected,cases};
await writeFile(path.join(work,'wasm-profile-results.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify(report)+'\n');
