import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verify, envelope } from '../verify-core/node.mjs';
import { validateStatement, statementBytes, statementHash, parseEnvelope, contentBytes } from '../verify-core/contract.mjs';
const replay = await readFile(new URL('../../backend/zkvm/verifier/tests/fixtures/timed-receipt.json', import.meta.url), 'utf8');
const compact = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Bucket250.json', import.meta.url), 'utf8');
const vectors = JSON.parse(await readFile(new URL('../verify-core/fixtures/statements.json', import.meta.url))).vectors;
const rawText = JSON.parse(replay).text;

test('Swift/JS statement vectors freeze payload bytes, null slots, Unicode commitment and u64 maximum', async () => {
  for (const vector of vectors) {
    assert.equal(new TextDecoder().decode(statementBytes(vector.statement)), vector.payload, vector.name);
    assert.equal(await statementHash(vector.statement), vector.sha256, vector.name);
  }
  for (const change of [{version:2},{contentKind:'document'},{contentPolicy:'remove-all-spaces'},
    {contentHash:'0'.repeat(64)+'\n'},{byteLength:'01'},{byteLength:'18446744073709551616'},
    {byteLength:'1\n'},{captureScheme:'producer-supplied'},{captureHead:'0'},{checkpointBinding:null},
    {captureKeyHash:null},{policyID:'arbitrary\n'},{policySatisfied:null},{policyID:null},{trustedHuman:true}]) {
    assert.throws(() => validateStatement({...vectors[1].statement,...change}));
  }
  for (const text of ['\ud800','\udc00','x\ud800z']) assert.throws(() => contentBytes(text));
  assert.equal(new TextDecoder().decode(contentBytes(' x\n \t')), ' x\n');
  for (const text of ['x \n','x\t\r\n',' x\u00a0','e\u0301']) assert.equal(new TextDecoder().decode(contentBytes(text)),text);
});

test('real RISC Zero and compact proofs retain identity through a portable envelope', async () => {
  const otherCompact=await Promise.all(['Bucket50','BucketUnicode'].map(name=>readFile(new URL(`../../extra/experiments/noir-compact/browser/test/fixtures/${name}.json`,import.meta.url),'utf8')));
  for (const source of [replay, compact,...otherCompact]) {
    const text = JSON.parse(source).text;
    const base = await verify(source, {requireSignedCapture:true}, text);
    assert.equal(base.verified, true, JSON.stringify(base.failures));
    const wrapped = await envelope(source, {requireSignedCapture:true}, text);
    const read = await verify(wrapped.envelope, {}, text+' \t');
    assert.equal(read.verified, true, JSON.stringify(read.failures));
    assert.deepEqual(read.statement, base.statement);
    assert.equal(read.statementHash, base.statementHash);
    assert.equal(read.proofReport.proofIdentity, base.proofReport.proofIdentity);
    assert.deepEqual(read.missing, ['behavior','device','witness','external-time']);
    assert.equal(read.facts.some(f => f.id==='signed-capture'), true);
    assert.equal(read.facts.some(f => f.id==='device'), false);
  }
});

test('displayed content, claimed statement and policy substitutions fail with real proofs', async () => {
  const wrapped = await envelope(replay, {}, rawText);
  const original = JSON.parse(wrapped.envelope);
  for (const change of [
    s=>{s.contentHash='0'.repeat(64)},s=>{s.byteLength='1'},s=>{s.sessionBinding='0'.repeat(64)},
    s=>{s.captureHead='0'.repeat(64)},s=>{s.captureKeyHash='0'.repeat(64)},s=>{s.checkpointBinding='0'.repeat(64)},
    s=>{s.captureScheme='sha256-capture-v3'},s=>{s.policyID='huma-writing-rules-v1';s.policySatisfied=true},
  ]) {
    const changed=structuredClone(original); change(changed.statement);
    const report=await verify(JSON.stringify(changed),{},rawText);
    assert.equal(report.verified,false); assert.equal(report.failures[0].evidence,'statement');
  }
  for (const text of [rawText+'!',rawText.replace(' ','  '),'\ud800']) assert.equal((await verify(wrapped.envelope,{},text)).verified,false);
  assert.equal((await verify(wrapped.envelope,{})).verified,false);
  const changed=structuredClone(original), proof=JSON.parse(changed.proof); proof.text+='!'; changed.proof=JSON.stringify(proof);
  assert.equal((await verify(JSON.stringify(changed),{},rawText)).verified,false);
  assert.equal((await verify(wrapped.envelope,{expectedKey:'0'.repeat(64)},rawText)).verified,false);
  for (const policy of [{expectedFID:1},{requireAccount:true},{requireDevice:true},{requirePolicy:'huma-writing-rules-v1'}]) {
    const report=await verify(wrapped.envelope,policy,rawText);
    assert.equal(report.verified,false); assert.equal(report.failures.length,1);
  }
});

test('untrusted or retired attachments and future fields cannot upgrade the result', async () => {
  const wrapped=JSON.parse((await envelope(replay,{},rawText)).envelope);
  for (const attachments of [{device:'{}'},{account:'{}'},{witness:'{}'},{device:JSON.stringify({verified:true})}]) {
    const report=await verify(JSON.stringify({...wrapped,attachments}),{},rawText);
    assert.equal(report.verified,false);
    assert.equal(report.facts.some(f=>f.id==='device'||f.id==='account'),false);
  }
  const changed={...wrapped,policy:{satisfied:true}};
  assert.equal((await verify(JSON.stringify(changed),{},rawText)).verified,false);
  assert.equal((await verify(JSON.stringify({...wrapped,kind:'huma-evidence-envelope-v2'}),{},rawText)).verified,false);
  assert.throws(()=>parseEnvelope(JSON.stringify({...wrapped,attachments:{device:'x'}})));
  const polluted=JSON.parse(replay); polluted.session={private:'PRIVATE-MARKER'}; polluted.privateHistory='PRIVATE-MARKER';
  const output=await envelope(JSON.stringify(polluted),{},rawText);
  assert.equal(output.envelope.includes('PRIVATE-MARKER'),false);
});

test('Node SDK cancellation and admission preserve subsequent real verification', async () => {
  const stopped=new AbortController(); stopped.abort();
  await assert.rejects(verify(replay,{},rawText,{signal:stopped.signal}),{name:'AbortError'});
  const controller=new AbortController();
  const pending=verify(replay,{},rawText,{signal:controller.signal});
  await assert.rejects(verify(replay,{},rawText),/already running/);
  controller.abort(); await assert.rejects(pending,{name:'AbortError'});
  assert.equal((await verify(replay,{},rawText)).verified,true);
});

test('a page whose every check-in the passkey approved keeps its statement and reports the passkey through the envelope', async () => {
  const { generateKeyPairSync, sign, createHash } = await import('node:crypto');
  const { KEYS, KEYS2, KEYS3, createLongVerifier, deviceRoot, passkeyBinding, passkeyChallenge, poseidon2Permute } = await import('../../backend/integrations/noir/long/reader.mjs');
  const { hash } = await import('../../extra/experiments/noir-compact/browser/final-text.mjs');
  const { createEvidenceVerifier } = await import('../verify-core/core.mjs');
  const source = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8');
  const text = JSON.parse(source).text, sha = b => createHash('sha256').update(b).digest(), field = n => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex');
  const pair = () => { const k = generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { key: k.privateKey, raw: k.publicKey.export({ format: 'der', type: 'spki' }).subarray(-65) }; };
  const der = (key, bytes) => sign('sha256', bytes, { key, dsaEncoding: 'der' }).toString('base64');
  const passkey = pair(), stranger = pair();
  const withPasskey = async (page, writer) => { const p = JSON.parse(page); p.kind = 'huma-long-assurance-public-proof-v3-passkey';
    p.passkey = { publicKey: passkey.raw.toString('base64'), assertions: await Promise.all(p.presenceRoots.map(async root => {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(await passkeyChallenge(root)).toString('base64url'), origin: 'https://huma.social', crossOrigin: false }));
      const authenticatorData = Buffer.concat([sha('huma.social'), Buffer.from([0x05, 0, 0, 0, 0])]);
      return { authenticatorData: authenticatorData.toString('base64'), clientDataJSON: clientDataJSON.toString('base64'),
        signature: der(passkey.key, Buffer.concat([authenticatorData, sha(clientDataJSON)])), binding: der(writer, await passkeyBinding(root, passkey.raw)) };
    })) }; return JSON.stringify(p); };
  // Shipped reader, every proof: the real page verifies plain; a passkey bound by anyone but its writer fails the whole page.
  assert.equal((await verify(source, {}, text)).verified, true);
  assert.equal((await verify(await withPasskey(source, stranger.key), {}, text)).verified, false);
  // The fixture's writing key isn't available, so the passing page is the same page re-keyed, read by the real long reader with a
  // ZK verifier that accepts (the proofs no longer match the new key; everything else is checked).
  const f = JSON.parse(source), writer = pair(), inputs = Buffer.from(f.finalInputs, 'base64');
  f.publicKey = writer.raw.toString('base64');
  f.signatures = f.checkpointRoots.map(r => der(writer.key, Buffer.concat([Buffer.from('HUMA_LONG_ASSURANCE_CHECKPOINT_V1\0'), field(r)])));
  f.presenceSignatures = f.presenceRoots.map(r => der(writer.key, Buffer.concat([Buffer.from('HUMA_LONG_ASSURANCE_PRESENCE_V1\0'), field(r)])));
  field(await hash([0x48554d410802n, await deviceRoot(writer.raw), BigInt('0x' + inputs.subarray(0, 32).toString('hex'))], poseidon2Permute) % (1n << 128n)).copy(inputs, 32);
  f.finalInputs = inputs.toString('base64');
  const asset = n => readFile(new URL('../../extra/experiments/noir-compact/browser/assets/' + n + '.vk', import.meta.url)).then(b => new Uint8Array(b));
  const load = async (prefix, names) => Object.fromEntries(await Promise.all(Object.keys(names).map(async n => [n, await asset(prefix + n)])));
  const verifyLong = createLongVerifier({ keys: await load('long-', KEYS), keys2: await load('long2-', KEYS2), keys3: await load('long3-', KEYS3), verifyZk: async () => true });
  const engine = createEvidenceVerifier({ verifyLong });
  const rekeyed = JSON.stringify(f), page = await withPasskey(rekeyed, writer.key);
  const plain = await engine.envelope(rekeyed, { requireSignedCapture: true }, text), wrapped = await engine.envelope(page, { requireSignedCapture: true }, text);
  assert.equal(wrapped.report.verified, true, JSON.stringify(wrapped.report.failures));
  assert.equal(wrapped.report.proofReport.passkeyVerified, true);
  assert.deepEqual(wrapped.report.statement, plain.report.statement);
  assert.equal(wrapped.report.facts.find(x => x.id === 'replay').method, 'noir-part-chain');
  assert.deepEqual(wrapped.report.facts.find(x => x.id === 'presence-passkey'), { id: 'presence-passkey', method: 'webauthn-p256-outside-zk', value: { count: 1, keyHash: sha(passkey.raw).toString('hex') } });
  assert.ok(!plain.report.proofReport.passkeyVerified); assert.equal(plain.report.facts.some(x => x.id === 'presence-passkey'), false);
  const read = await engine.verify(wrapped.envelope, {}, text);
  assert.equal(read.verified, true); assert.equal(read.proofReport.passkeyVerified, true);
  // A passkey assertion or binding that isn't this page's fails the whole page.
  for (const name of ['signature', 'binding']) {
    const p = JSON.parse(page), sig = Buffer.from(p.passkey.assertions[0][name], 'base64'); sig[sig.length - 3] ^= 1; p.passkey.assertions[0][name] = sig.toString('base64');
    assert.equal((await engine.verify(JSON.stringify(p), {}, text)).verified, false);
  }
  assert.equal((await engine.verify(await withPasskey(rekeyed, stranger.key), {}, text)).verified, false);
});
