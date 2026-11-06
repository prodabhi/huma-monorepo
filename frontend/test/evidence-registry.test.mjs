import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRegistry } from '../registry.mjs';
import { envelope, verify } from '../verify-core/node.mjs';

test('portable RISC Zero and compact envelopes survive public transport without private metadata', {timeout:30000}, async t => {
  const store=await mkdtemp(path.join(tmpdir(),'huma-evidence-registry-'));
  const server=await createRegistry({store, allowLegacyUploads: true});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(store,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${server.address().port}`;
  const upload=source=>fetch(base+'/api/proofs',{method:'POST',headers:{'Content-Type':'application/json'},body:source});
  for(const file of ['../../backend/zkvm/verifier/tests/fixtures/timed-receipt.json','../../extra/experiments/noir-compact/browser/test/fixtures/Bucket250.json']) {
    const proof=await readFile(new URL(file,import.meta.url),'utf8'),text=JSON.parse(proof).text;
    const wrapped=await envelope(proof,{},text);
    const response=await upload(wrapped.envelope);
    assert.equal(response.status,201,await response.clone().text());
    const {id}=await response.json(),stored=await (await fetch(base+'/api/proofs/'+id)).text();
    assert.equal(createHash('sha256').update(stored).digest('hex'),id);
    assert.equal((await verify(stored,{},text)).statementHash,wrapped.report.statementHash);
    assert.equal((await fetch(base+'/verify/'+id)).status,200);
    const altered=JSON.parse(wrapped.envelope);altered.statement.contentHash='0'.repeat(64);
    assert.equal((await upload(JSON.stringify(altered))).status,422);
    const fakeAttachment=JSON.parse(wrapped.envelope);fakeAttachment.attachments.device='{}';
    assert.equal((await upload(JSON.stringify(fakeAttachment))).status,422);
    if (file.includes('timed-receipt')) {
      const polluted=JSON.parse(wrapped.envelope),inner=JSON.parse(polluted.proof);
      inner.privateHistory='PRIVATE-HISTORY-MARKER';inner.bundle.receipt.privateHistory='PRIVATE-HISTORY-MARKER';
      polluted.proof=JSON.stringify(inner);
      const cleaned=await upload(JSON.stringify(polluted));assert.equal(cleaned.status,201);
      const record=await (await fetch(base+'/api/proofs/'+(await cleaned.json()).id)).text();
      assert.equal(record.includes('PRIVATE-HISTORY-MARKER'),false);
    }
  }
  for (const route of ['/verify-core/browser.mjs','/verify-core/worker.mjs','/verify-core/core.mjs','/verify-core/contract.mjs','/compact/compact-inline.js']) assert.equal((await fetch(base+route)).status,200);
  for (const route of ['/verify-core/node-engine.mjs','/verify-core/node-worker.mjs','/verify-core/fixtures/statements.json']) assert.equal((await fetch(base+route)).status,404);
});
