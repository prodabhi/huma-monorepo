import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verify, envelope } from '../verify-core/node.mjs';
const load = name => readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/'+name+'.json',import.meta.url),'utf8');
test('small V5 profiles verify full Unicode buffers and all original checkpoint signatures',async()=>{
  for(const [name,profile,count,bytes] of [
    ['Assurance64','assurance64-v1',4,3008],['Assurance64Unicode','assurance64-v1',2,3008],
    ['Assurance128Boundary','assurance128-cp32-v1',32,4544],['Assurance128Unicode','assurance128-cp32-v1',2,4544],
  ]) {
    const source=await load(name),proof=JSON.parse(source);
    assert.equal(Buffer.from(proof.publicInputs,'base64').length,bytes);
    const report=await verify(source,{requireSignedCapture:true,requirePolicy:'huma-writing-rules-v1'},proof.text);
    assert.equal(report.verified,true);assert.equal(report.proofReport.profile,profile);
    assert.equal(report.proofReport.signaturesVerified,count);
    assert.equal((await verify((await envelope(source,{},proof.text)).envelope,{},proof.text)).verified,true);
    assert.equal((await verify(source,{},proof.text+'!')).verified,false);
  }
});
test('small profiles reject relabeling, tampering and missing original signatures',async()=>{
  for(const name of ['Assurance64','Assurance128Boundary']) {
    const original=JSON.parse(await load(name));
    for(const profile of ['assurance64-v1','assurance128-cp32-v1','assurance256-v2','assurance256-cp32-v1']) {
      if(profile!==original.profile)assert.equal((await verify(JSON.stringify({...original,profile}),{},original.text)).verified,false);
    }
    for(const field of ['proof','publicInputs']) {
      const changed=structuredClone(original),bytes=Buffer.from(changed[field],'base64');bytes[95]^=1;
      changed[field]=bytes.toString('base64');assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false);
    }
    const missing=structuredClone(original);missing.signatures.pop();
    assert.equal((await verify(JSON.stringify(missing),{},original.text)).verified,false);
  }
});
test('expanded V5 retains 24 and all 32 original checkpoints with exact public input size',async()=>{
  for(const [name,count] of [['AssuranceCP32',24],['AssuranceCP32Boundary',32]]) {
    const source=await load(name),proof=JSON.parse(source);
    assert.equal(Buffer.from(proof.publicInputs,'base64').length,4544);
    const report=await verify(source,{requireSignedCapture:true},proof.text+' \t');
    assert.equal(report.verified,true);assert.equal(report.proofReport.profile,'assurance256-cp32-v1');
    assert.equal(report.proofReport.version,5);assert.equal(report.proofReport.signaturesVerified,count);
    assert.equal(report.proofReport.presenceSignaturesVerified,2);
    assert.equal((await verify((await envelope(source,{},proof.text)).envelope,{},proof.text)).verified,true);
  }
});
test('expanded V5 requires every signature and rejects capacity-profile substitution',async()=>{
  const original=JSON.parse(await load('AssuranceCP32Boundary'));
  for(let index=0;index<32;index++) {
    const changed=structuredClone(original),signature=Buffer.from(changed.signatures[index],'base64');signature[10]^=1;
    changed.signatures[index]=signature.toString('base64');assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false,'signature '+index);
  }
  for(const profile of ['assurance256-v1','assurance256-v2','unknown-profile']) {
    assert.equal((await verify(JSON.stringify({...original,profile}),{},original.text)).verified,false);
  }
  const missing=structuredClone(original);missing.signatures.pop();
  assert.equal((await verify(JSON.stringify(missing),{},missing.text)).verified,false);
  const old=JSON.parse(await load('AssuranceV5'));old.profile='assurance256-cp32-v1';
  assert.equal((await verify(JSON.stringify(old),{},old.text)).verified,false);
});
test('optimized V5 preserves the full V4 statement and original signatures with its own program identity',async()=>{
  const source=await load('AssuranceV5'),text=JSON.parse(source).text;
  const report=await verify(source,{requirePolicy:'huma-writing-rules-v1'},text);
  const old=await verify(await load('SwiftLiveV4'),{},text);
  assert.equal(report.verified,true);assert.deepEqual(report.statement,old.statement);
  assert.equal(report.proofReport.version,5);assert.equal(report.proofReport.signaturesVerified,7);
  assert.equal(report.proofReport.presenceSignaturesVerified,2);
  assert.equal(report.proofReport.proofIdentity,'3fc834ba0c6cadf0c69b70435bf1275920c4d7c88fd1c5843ae92dcce5409b46');
  assert.notEqual(report.proofReport.proofIdentity,old.proofReport.proofIdentity);
  assert.equal((await verify((await envelope(source,{},text)).envelope,{},text)).verified,true);
});
test('V4 and V5 cannot substitute a verifier key or change signed data',async()=>{
  for(const [name,kind,profile] of [['AssuranceV5','huma-compact-assurance-public-proof-v4','assurance256-v1'],['SwiftLiveV4','huma-compact-assurance-public-proof-v5','assurance256-v2']]){
    const original=JSON.parse(await load(name)),changed={...original,kind,profile};
    assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false);
  }
  const original=JSON.parse(await load('AssuranceV5'));
  for(const [field,index] of [['proof',500],['publicInputs',95],['signatures',0],['presenceSignatures',1]]){
    const changed=structuredClone(original);
    const raw=Buffer.from(Array.isArray(changed[field])?changed[field][index]:changed[field],'base64');
    raw[Array.isArray(changed[field])?10:index]^=1;
    if(Array.isArray(changed[field]))changed[field][index]=raw.toString('base64');else changed[field]=raw.toString('base64');
    assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false);
  }
  assert.equal((await verify(JSON.stringify(original),{},original.text+'!')).verified,false);
});
test('optional Noir disclosure verifies only its proof and publication strips raw history',async()=>{
  const source=await load('SwiftLiveV4'),proof=JSON.parse(source);
  const disclosure=JSON.stringify({kind:'huma-writing-disclosure-v1',proof:source,
    capturePublicKey:{format:'p256-x963-base64',value:proof.publicKey},session:{rawHistory:'private-fixture-marker'}});
  const report=await verify(disclosure,{},proof.text);
  assert.equal(report.verified,true);assert.deepEqual(report.unverifiedDisclosures,['session']);
  const output=await envelope(disclosure,{},proof.text);
  assert.equal(output.envelope.includes('private-fixture-marker'),false);
  assert.equal((await verify(output.envelope,{},proof.text)).verified,true);
  const changed=JSON.parse(disclosure);changed.capturePublicKey.value='different-key';
  await assert.rejects(()=>verify(JSON.stringify(changed),{},proof.text));
  const changedText=await verify(disclosure,{},proof.text+'!');assert.equal(changedText.verified,false);
});
test('fresh Swift capture keeps its original seven checkpoints and two presence signatures',async()=>{
  const source=await load('SwiftLiveV4'),text=JSON.parse(source).text;
  const report=await verify(source,{requireSignedCapture:true,requirePolicy:'huma-writing-rules-v1'},text);
  assert.equal(report.verified,true);assert.equal(report.statement.policySatisfied,true);
  assert.equal(report.proofReport.signaturesVerified,7);assert.equal(report.proofReport.presenceSignaturesVerified,2);
  assert.equal(report.proofReport.proofIdentity,'c12a8574de25d1b53b71216e560d44d420b99598794d2c36fdd91d8fbd21a649');
  const wrapped=await envelope(source,{},text);
  assert.equal((await verify(wrapped.envelope,{},text)).verified,true);
  const exported=JSON.parse(wrapped.envelope);
  assert.deepEqual(Object.keys(JSON.parse(exported.proof)).sort(),Object.keys(JSON.parse(source)).sort());
});
test('full Noir writing policy, origin and every presence signature verify',async()=>{
  const source=await load('Assurance250'),text=JSON.parse(source).text;
  const report=await verify(source,{requireSignedCapture:true,requirePolicy:'huma-writing-rules-v1'},text);
  assert.equal(report.verified,true);assert.equal(report.statement.policySatisfied,true);
  assert.equal(report.statement.captureScheme,'poseidon2-capture-v4');
  assert.equal(report.proofReport.journal.replay.samples,500);
  assert.equal(report.proofReport.signaturesVerified,4);assert.equal(report.proofReport.presenceSignaturesVerified,2);
  assert.equal(report.proofReport.proofIdentity,'fb435120e6c8f04e38b226a4f94461bbfdf44ec372640692794e4a4d5654e67e');
  const wrapped=await envelope(source,{requirePolicy:'huma-writing-rules-v1'},text);
  assert.equal(wrapped.report.statementHash,report.statementHash);
  assert.equal((await verify(wrapped.envelope,{},text+' \t')).verified,true);
  assert.equal((await verify(source,{requireDevice:true},text)).verified,false);
});
test('valid proof of failed policy is different from policy acceptance',async()=>{
  const source=await load('AssuranceRate'),text=JSON.parse(source).text;
  const report=await verify(source,{},text);
  assert.equal(report.verified,true);assert.equal(report.statement.policySatisfied,false);
  assert.equal(report.facts.find(f=>f.id==='behavior').value.satisfied,false);
  assert.equal((await verify(source,{requirePolicy:'huma-writing-rules-v1'},text)).verified,false);
});
test('every V4 checkpoint and approved presence signature is mandatory',async()=>{
  const source=await load('Assurance250'),original=JSON.parse(source);
  for(const field of ['signatures','presenceSignatures'])for(let index=0;index<original[field].length;index++){
    const changed=JSON.parse(source),signature=Buffer.from(changed[field][index],'base64');signature[10]^=1;
    changed[field][index]=signature.toString('base64');assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false,field+index);
  }
  const missing=JSON.parse(source);missing.presenceSignatures.pop();
  assert.equal((await verify(JSON.stringify(missing),{},original.text)).verified,false);
});
test('changed V4 SNARK, authenticated facts, text, key and policy claims fail',async()=>{
  const source=await load('Assurance250'),original=JSON.parse(source);
  for(const [field,offset] of [['proof',500],['publicInputs',95]]){
    const changed=JSON.parse(source),bytes=Buffer.from(changed[field],'base64');bytes[offset]^=1;changed[field]=bytes.toString('base64');
    assert.equal((await verify(JSON.stringify(changed),{},original.text)).verified,false);
  }
  assert.equal((await verify(source,{},original.text+'!')).verified,false);
  assert.equal((await verify(source,{expectedKey:'0'.repeat(64)},original.text)).verified,false);
  const wrapped=JSON.parse((await envelope(source,{},original.text)).envelope);
  wrapped.statement.policySatisfied=false;assert.equal((await verify(JSON.stringify(wrapped),{},original.text)).verified,false);
});
