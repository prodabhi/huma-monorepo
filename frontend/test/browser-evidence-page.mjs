import { verify, envelope } from '/verify-core/browser.mjs';
const fatal=error=>fetch('/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passed:0,failed:1,results:[{name:'page execution',passed:false,error:String(error?.message??error)}]})});
addEventListener('error',event=>void fatal(event.error??event.message));
addEventListener('unhandledrejection',event=>void fatal(event.reason));
const results=[];
async function check(name, operation) {
  try { await operation(); results.push({name,passed:true}); }
  catch(error) { results.push({name,passed:false,error:String(error?.message??error)}); }
}
function assert(value) { if(!value) throw new Error('Unexpected verification result'); }
const proof=await (await fetch('/fixture/replay')).text(),text=JSON.parse(proof).text;
const compact=await (await fetch('/fixture/compact')).text(),compactText=JSON.parse(compact).text;
const native=await (await fetch('/fixture/native')).text();
await check('RISC Zero verified through common browser worker',async()=>assert((await verify(proof,{},text)).verified));
await check('native Mac envelope verifies with matching statement hash',async()=>{
  const a=await verify(native,{},text),b=await envelope(proof,{},text);
  assert(a.verified&&a.statementHash===b.report.statementHash);
});
await check('compact proof and every signature verify through common worker',async()=>assert((await verify(compact,{},compactText)).verified));
const compactEnvelope=(await envelope(compact,{},compactText)).envelope;
await check('compact envelope retains proof identity',async()=>{
  const a=await verify(compact,{},compactText),b=await verify(compactEnvelope,{},compactText);
  assert(b.verified&&a.proofReport.proofIdentity===b.proofReport.proofIdentity);
});
await check('Unicode fixture retains exact character policy',async()=>{
  const source=await (await fetch('/fixture/unicode')).text();assert((await verify(source,{},JSON.parse(source).text)).verified);
});
await check('only absolute-end ASCII space/tab ignored',async()=>assert((await verify(native,{},text+' \t')).verified));
await check('changed displayed text rejected',async()=>assert(!(await verify(native,{},text+'!')).verified));
await check('changed claimed capture rejected',async()=>{
  const changed=JSON.parse(native);changed.statement.captureHead='0'.repeat(64);
  assert(!(await verify(JSON.stringify(changed),{},text)).verified);
});
await check('invented policy result rejected',async()=>{
  const changed=JSON.parse(native);changed.statement.policyID='huma-writing-rules-v1';changed.statement.policySatisfied=true;
  assert(!(await verify(JSON.stringify(changed),{},text)).verified);
});
await check('fake manufacturer attachment rejected',async()=>{
  const changed=JSON.parse(native);changed.attachments.device='{}';assert(!(await verify(JSON.stringify(changed),{},text)).verified);
});
await check('retired account policy rejected',async()=>assert(!(await verify(native,{expectedFID:1},text)).verified));
await check('cancellation and single admission',async()=>{
  const controller=new AbortController(),pending=verify(native,{},text,{signal:controller.signal});
  let busy=false;try{await verify(native,{},text);}catch{busy=true;}assert(busy);
  controller.abort();let stopped=false;try{await pending;}catch(e){stopped=e.name==='AbortError';}assert(stopped);
  assert((await verify(native,{},text)).verified);
});
for (const kind of ['image','audio','video']) {
  await check('real '+kind+' proof verifies exact master in browser',async()=>{
    const source=await (await fetch('/fixture/'+kind)).text();
    const master=new Uint8Array(await (await fetch('/fixture/'+kind+'-master')).arrayBuffer());
    const result=await verify(source,{},master);
    assert(result.verified&&result.statement.contentKind===kind&&result.proofReport.masterCompared);
    assert(!result.proofReport.decodingProven&&!result.proofReport.scenePolicyChecked&&!result.proofReport.samplingFreshnessVerified);
  });
}
await check('media envelope rejects altered master and claimed policy',async()=>{
  const source=await (await fetch('/fixture/image')).text();
  const master=new Uint8Array(await (await fetch('/fixture/image-master')).arrayBuffer());
  const wrapped=await envelope(source,{},master);assert(wrapped.report.verified);
  const changed=master.slice();changed[0]^=1;assert(!(await verify(wrapped.envelope,{},changed)).verified);
  const altered=JSON.parse(wrapped.envelope);altered.statement.policyID='huma-scene-v1';altered.statement.policySatisfied=true;
  assert(!(await verify(JSON.stringify(altered),{},master)).verified);
});
await check('media browser rejects changed SNARK and unsupported freshness claim',async()=>{
  const source=await (await fetch('/fixture/audio')).text();
  const master=new Uint8Array(await (await fetch('/fixture/audio-master')).arrayBuffer());
  const altered=JSON.parse(source),bytes=Uint8Array.from(atob(altered.proof),c=>c.charCodeAt(0));bytes[500]^=1;
  altered.proof=btoa(String.fromCharCode(...bytes));
  assert(!(await verify(JSON.stringify(altered),{},master)).verified);
  assert(!(await verify(source,{expectedSamplingChallenge:'0'.repeat(64)},master)).verified);
});
await check('full Noir writing-policy proof verifies origin and presence in browser',async()=>{
  const source=await(await fetch('/fixture/assurance')).text(),text=JSON.parse(source).text;
  const report=await verify(source,{requirePolicy:'huma-writing-rules-v1'},text);
  assert(report.verified&&report.statement.policySatisfied&&report.proofReport.presenceSignaturesVerified===2);
  assert(report.proofReport.proofIdentity==='fb435120e6c8f04e38b226a4f94461bbfdf44ec372640692794e4a4d5654e67e');
});
await check('fresh Swift capture proof preserves all original signatures in browser',async()=>{
  const source=await(await fetch('/fixture/swift-assurance')).text(),text=JSON.parse(source).text;
  const report=await verify(source,{requirePolicy:'huma-writing-rules-v1'},text);
  assert(report.verified&&report.proofReport.signaturesVerified===7&&report.proofReport.presenceSignaturesVerified===2);
  assert(report.proofReport.proofIdentity==='c12a8574de25d1b53b71216e560d44d420b99598794d2c36fdd91d8fbd21a649');
});
await check('long draft: every chunk proof, signature and the text verify in browser',async()=>{
  const source=await(await fetch('/fixture/long')).text(),text=JSON.parse(source).text;
  const report=await verify(source,{requirePolicy:'huma-writing-rules-v1'},text);
  assert(report.verified&&report.proofReport.chunks===8&&report.proofReport.signaturesVerified===13&&report.proofReport.presenceSignaturesVerified===2);
  assert(report.statement.captureScheme==='poseidon2-capture-long-v1');
  const wrapped=await envelope(source,{},text);assert(wrapped.report.statementHash===report.statementHash);
  assert(!(await verify(source,{},text.slice(0,-1)+'!')).verified);
  const p=JSON.parse(source);[p.chunks[1],p.chunks[2]]=[p.chunks[2],p.chunks[1]];
  assert(!(await verify(JSON.stringify(p),{},text)).verified);
});
await check('optimized V5 verifies the original full signed statement in browser',async()=>{
  const source=await(await fetch('/fixture/assurance-v5')).text(),text=JSON.parse(source).text;
  const report=await verify(source,{requirePolicy:'huma-writing-rules-v1'},text);
  assert(report.verified&&report.proofReport.version===5&&report.proofReport.signaturesVerified===7&&report.proofReport.presenceSignaturesVerified===2);
  assert(report.proofReport.proofIdentity==='3fc834ba0c6cadf0c69b70435bf1275920c4d7c88fd1c5843ae92dcce5409b46');
});
for(const [fixture,profile,count] of [
  ['small64','assurance64-v1',4],['small64-unicode','assurance64-v1',2],
  ['small128-boundary','assurance128-cp32-v1',32],['small128-unicode','assurance128-cp32-v1',2],
])await check('small profile '+fixture+' verifies full evidence in browser',async()=>{
  const source=await(await fetch('/fixture/'+fixture)).text(),proof=JSON.parse(source);
  const report=await verify(source,{requireSignedCapture:true,requirePolicy:'huma-writing-rules-v1'},proof.text);
  assert(report.verified&&report.proofReport.profile===profile&&report.proofReport.signaturesVerified===count);
});
await check('small profile substitution and changed final signature rejected in browser',async()=>{
  const original=JSON.parse(await(await fetch('/fixture/small128-boundary')).text());
  assert(!(await verify(JSON.stringify({...original,profile:'assurance256-cp32-v1'}),{},original.text)).verified);
  const bytes=Uint8Array.from(atob(original.signatures[31]),c=>c.charCodeAt(0));bytes[10]^=1;
  original.signatures[31]=btoa(String.fromCharCode(...bytes));assert(!(await verify(JSON.stringify(original),{},original.text)).verified);
});
for(const [fixture,count] of [['cp32',24],['cp32-boundary',32]])await check('expanded profile verifies all '+count+' original checkpoints in browser',async()=>{
  const source=await(await fetch('/fixture/'+fixture)).text(),proof=JSON.parse(source);
  const report=await verify(source,{requireSignedCapture:true},proof.text);
  assert(report.verified&&report.proofReport.profile==='assurance256-cp32-v1'&&report.proofReport.signaturesVerified===count);
});
await check('expanded browser profile rejects a changed final checkpoint signature',async()=>{
  const proof=JSON.parse(await(await fetch('/fixture/cp32-boundary')).text());
  const bytes=Uint8Array.from(atob(proof.signatures[31]),c=>c.charCodeAt(0));bytes[10]^=1;
  proof.signatures[31]=btoa(String.fromCharCode(...bytes));
  assert(!(await verify(JSON.stringify(proof),{},proof.text)).verified);
});
await check('optional Noir history disclosure verifies proof without certifying raw history',async()=>{
  const source=await(await fetch('/fixture/swift-assurance')).text(),proof=JSON.parse(source);
  const revealed=JSON.stringify({kind:'huma-writing-disclosure-v1',proof:source,
    capturePublicKey:{format:'p256-x963-base64',value:proof.publicKey},session:{rawHistory:'browser-private-marker'}});
  const report=await verify(revealed,{},proof.text);
  assert(report.verified&&report.unverifiedDisclosures[0]==='session');
  assert(!(await envelope(revealed,{},proof.text)).envelope.includes('browser-private-marker'));
});
await check('browser distinguishes valid proof from satisfied writing policy',async()=>{
  const source=await(await fetch('/fixture/policy-failed')).text(),text=JSON.parse(source).text;
  const report=await verify(source,{},text);assert(report.verified&&report.statement.policySatisfied===false);
  assert(!(await verify(source,{requirePolicy:'huma-writing-rules-v1'},text)).verified);
});
await check('browser rejects changed V4 presence signature',async()=>{
  const source=JSON.parse(await(await fetch('/fixture/assurance')).text());
  const bytes=Uint8Array.from(atob(source.presenceSignatures[0]),c=>c.charCodeAt(0));bytes[10]^=1;
  source.presenceSignatures[0]=btoa(String.fromCharCode(...bytes));
  assert(!(await verify(JSON.stringify(source),{},source.text)).verified);
});

const frame=document.createElement('iframe');frame.src='/verify';document.body.append(frame);
await new Promise((resolve,reject)=>{frame.onload=resolve;setTimeout(()=>reject(new Error('Reader did not load')),10000);});
const reader=frame.contentDocument;
await check('proof reader has no account flow or retired service bundle',async()=>{
  assert(!reader.querySelector('#accountImport')&&!reader.querySelector('#checkAccount'));
  const response=await fetch('/account-verifier.js');assert(response.status===404);
});
async function waitState(expected, target = reader) {
  const end=performance.now()+15000;
  while(performance.now()<end) {
    const result=target.querySelector('#result');
    if(result.dataset.state===expected) return;
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  throw new Error('Reader status: '+target.querySelector('#result').textContent);
}
async function importProof(source) {
  reader.querySelector('#proofJSON').value=source;reader.querySelector('#loadJSON').click();
  reader.querySelector('#verify').click();await waitState('valid');
}
await check('existing reader accepts legacy RISC Zero via shared core',()=>importProof(proof));
await check('existing reader imports native evidence envelope',()=>importProof(native));
await check('existing reader imports compact evidence envelope',()=>importProof(compactEnvelope));
await check('existing reader imports full Noir writing policy with its results',async()=>{
  const source=await(await fetch('/fixture/assurance')).text();await importProof(source);
  assert(reader.querySelector('#report').textContent.includes('huma-writing-rules-v1'));
});
await check('reader imports optimized V5 and renders its policy and presence results',async()=>{
  const source=await(await fetch('/fixture/assurance-v5')).text();await importProof(source);
  assert(reader.querySelector('#report').textContent.includes('huma-writing-rules-v1'));
});
await check('reader imports the expanded profile and renders all 32 checkpoint signatures',async()=>{
  const source=await(await fetch('/fixture/cp32-boundary')).text();await importProof(source);
  assert(reader.querySelector('#report').textContent.includes('32 P-256 signatures'));
});
await check('reader imports the optional native Noir history-disclosure file',async()=>{
  const source=await(await fetch('/fixture/swift-assurance')).text();
  await importProof(JSON.stringify({kind:'huma-writing-disclosure-v1',proof:source,session:{fixture:true}}));
  assert(reader.querySelector('#report').textContent.includes('huma-writing-rules-v1'));
});
await check('reader invalidates altered text then accepts final whitespace',async()=>{
  await importProof(compactEnvelope);
  const field=reader.querySelector('#text');field.value=compactText+'!';field.dispatchEvent(new Event('input',{bubbles:true}));
  reader.querySelector('#verify').click();await waitState('invalid');
  field.value=compactText+' \t';field.dispatchEvent(new Event('input',{bubbles:true}));
  reader.querySelector('#verify').click();await waitState('valid');
});
await check('native envelope registry link opens and verifies automatically',async()=>{
  const uploaded=await fetch('/api/proofs',{method:'POST',headers:{'Content-Type':'application/json'},body:native});
  assert(uploaded.status===201);const {id}=await uploaded.json();
  const linked=document.createElement('iframe');linked.src='/verify/'+id;
  const loaded=new Promise(resolve=>{linked.onload=resolve;});document.body.append(linked);await loaded;
  await waitState('valid',linked.contentDocument);
});
await check('full Noir writing-policy registry link verifies automatically',async()=>{
  const source=await(await fetch('/fixture/assurance')).text();
  const uploaded=await fetch('/api/proofs',{method:'POST',headers:{'Content-Type':'application/json'},body:source});
  assert(uploaded.status===201);const {id}=await uploaded.json();
  const linked=document.createElement('iframe');linked.src='/verify/'+id;
  const loaded=new Promise(resolve=>{linked.onload=resolve;});document.body.append(linked);await loaded;
  await waitState('valid',linked.contentDocument);
  assert(linked.contentDocument.querySelector('#report').textContent.includes('huma-writing-rules-v1'));
});
async function publishOriginal(proof, master, mediaType) {
  const bytes = typeof master === 'string' ? new TextEncoder().encode(master) : master;
  const prepared = await fetch('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof,
      master: { mediaType, base64: btoa(String.fromCharCode(...bytes)) } }) });
  assert(prepared.status === 201); const pending = await prepared.json();
  const published = await fetch('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
    headers: { Authorization: 'Bearer browser-fixture-owner', 'X-Huma-Ticket': pending.ticket } });
  assert(published.ok); return (await published.json()).path;
}
for(const [fixture,version] of [['assurance',4],['assurance-v5',5],['cp32','5 expanded']])await check('shared exact text master and V'+version+' proof download and verify in reader',async()=>{
  const source=await(await fetch('/fixture/'+fixture)).text(),text=JSON.parse(source).text+' \t';
  const path=await publishOriginal(source,text,'text/plain;charset=utf-8');
  const linked=document.createElement('iframe'); linked.src=path;
  const loaded=new Promise(resolve=>{linked.onload=resolve;});document.body.append(linked);await loaded;
  await waitState('valid',linked.contentDocument);
  assert(linked.contentDocument.querySelector('#text').value===text);
  assert(linked.contentDocument.querySelectorAll('a[download]').length===2);
  assert(linked.contentDocument.querySelector('#report').textContent.includes('huma-writing-rules-v1'));
});
await check('shared audio master and membership proof verify exact downloaded bytes in reader',async()=>{
  const source=await(await fetch('/fixture/audio')).text();
  const master=new Uint8Array(await(await fetch('/fixture/audio-master')).arrayBuffer());
  const path=await publishOriginal(source,master,'audio/flac');
  const linked=document.createElement('iframe'); linked.src=path;
  const loaded=new Promise(resolve=>{linked.onload=resolve;});document.body.append(linked);await loaded;
  await waitState('valid',linked.contentDocument);
  assert(linked.contentDocument.querySelector('#report').textContent.includes('sensor capture and decoding are not proved'));
  assert(linked.contentDocument.querySelectorAll('a[download]').length===2);
});
const report={passed:results.filter(r=>r.passed).length,failed:results.filter(r=>!r.passed).length,
  crossOriginIsolated,softwareFixturesOnly:true,results};
document.querySelector('pre').textContent=JSON.stringify(report,null,2);
await fetch('/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(report)});
