import {ChainError,verifyInteractionChain} from './interaction-chain.mjs';
import {createWasmVerifier} from './wasm.mjs';
const results=[];let backend,failed=0,message='',timing;
const need=(ok,name)=>{if(!ok)throw new Error(name);};
try{
  const [bundle,key,g2,partial]=await Promise.all([
    fetch('/chain.json').then(r=>r.json()),fetch('/key').then(r=>r.arrayBuffer()).then(b=>new Uint8Array(b)),
    fetch('/assets/g2.dat').then(r=>r.arrayBuffer()).then(b=>new Uint8Array(b)),fetch('/partial.json').then(r=>r.json()),
  ]);
  const started=performance.now();backend=await createWasmVerifier(g2);const setupMs=performance.now()-started;
  const options={backend,loadKey:async()=>key};const verifyStarted=performance.now();
  const result=await verifyInteractionChain(JSON.stringify(bundle),options);
  const verifyMs=performance.now()-verifyStarted;timing={setupMs,verifyMs,setupAndVerifyMs:setupMs+verifyMs};
  need(result.componentVerified&&result.policySatisfied&&result.chunks===17,'full chain');
  results.push({name:'All17 proofs and links verify in Chrome',passed:true});
  need(!result.finalTextVerified&&!result.checkpointSignaturesVerified&&!result.hardwareAttestationVerified,'scope');
  results.push({name:'Component scope remains explicit',passed:true});
  const changed=fn=>{const value=structuredClone(bundle);fn(value);return value;};
  async function reject(name,value,expected,override={}){
    let code;try{await verifyInteractionChain(JSON.stringify(value),{...options,...override});}
    catch(e){if(!(e instanceof ChainError))throw e;code=e.code;}
    need(code===expected,name);results.push({name,passed:true,rejectedAs:code});
  }
  await reject('Dropped chunk rejected',changed(v=>v.chunks.splice(1,1)),'Link');
  await reject('Reordered chunks rejected',changed(v=>[v.chunks[1],v.chunks[2]]=[v.chunks[2],v.chunks[1]]),'Link');
  await reject('Changed proof rejected',changed(v=>{
    const bytes=Uint8Array.from(atob(v.chunks[8].proof),c=>c.charCodeAt(0));bytes[bytes.length/2]^=1;
    v.chunks[8].proof=btoa(String.fromCharCode(...bytes));
  }),'ProofRejected');
  await reject('Changed final origin root rejected',changed(v=>{
    const bytes=Uint8Array.from(atob(v.chunks[16].publicInputs),c=>c.charCodeAt(0));bytes[8*32+31]^=1;
    v.chunks[16].publicInputs=btoa(String.fromCharCode(...bytes));
  }),'ProofRejected');
  const wrongKey=new Uint8Array(key);wrongKey[0]^=1;
  await reject('Substituted verifier key rejected',bundle,'KeyRejected',{loadKey:async()=>wrongKey});
  await reject('Sampled10k proofs rejected as incomplete',partial,'Link');
}catch(e){failed=1;message=String(e?.message??e);}
finally{await backend?.destroy();}
const report={kind:'huma-interaction-chain-chrome-v1',passed:results.length,failed,message,results,timing,
  softwareFixturesOnly:true,ownerIdentityUsed:false,appChanged:false,completeHumaSessionProof:false,
  userAgent:navigator.userAgent,crossOriginIsolated:globalThis.crossOriginIsolated};
document.querySelector('pre').textContent=JSON.stringify(report,null,2);
await fetch('/report',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(report)});
