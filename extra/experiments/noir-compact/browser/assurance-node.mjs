// Internal engine; public SDK owns the single cancellable verification worker.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createAssuranceVerifier } from './assurance-core.mjs';
import { checkAsset, profileForProof } from './assurance-profile.mjs';
import { checkAsset as checkCrypto } from './profile.mjs';
import { createWasmVerifier } from './wasm.mjs';
export async function verifyAssurancePublic(source,options) {
  const selected=profileForProof(source);
  const [verificationKey,journalABI,g2]=await Promise.all([selected.key,selected.abi,'g2.dat'].map(async name=>{
    const bytes=new Uint8Array(await readFile(new URL('./assets/'+name,import.meta.url)));
    return name==='g2.dat'?checkCrypto(name,bytes):checkAsset(name,bytes);
  }));
  const wasm=new URL('./assets/barretenberg-threads.wasm',import.meta.url);await checkCrypto('barretenberg-threads.wasm',new Uint8Array(await readFile(wasm)));
  const backend=await createWasmVerifier(g2,fileURLToPath(wasm));
  try{return await(await createAssuranceVerifier({verificationKey,journalABI,verifyZk:backend.verify,version:selected.version,profile:selected.profile}))(source,options);}
  finally{await backend.destroy();}
}
