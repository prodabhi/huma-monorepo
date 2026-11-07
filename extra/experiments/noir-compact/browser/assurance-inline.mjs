import { createAssuranceVerifier } from './assurance-core.mjs';
import { loadAsset, profileForProof } from './assurance-profile.mjs';
import { loadAsset as loadCrypto } from './profile.mjs';
import { createWasmVerifier } from './wasm.mjs';
export async function verifyAssuranceInline(source,options) {
  if(typeof WorkerGlobalScope==='undefined'||!(self instanceof WorkerGlobalScope))throw new Error('A dedicated verification worker is required.');
  const selected=profileForProof(source);
  const [verificationKey,journalABI,g2]=await Promise.all([loadAsset(selected.key),loadAsset(selected.abi),loadCrypto('g2.dat')]);
  const backend=await createWasmVerifier(g2);
  try{return await(await createAssuranceVerifier({verificationKey,journalABI,verifyZk:backend.verify,version:selected.version,profile:selected.profile}))(source,options);}
  finally{await backend.destroy();}
}
