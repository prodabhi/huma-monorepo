import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { envelope } from '../verify-core/node.mjs';
const run = promisify(execFile), root = fileURLToPath(new URL('../../', import.meta.url));
const check = (...args) => run(process.execPath, ['backend/zkvm/scripts/verify-file.mjs', ...args], { cwd: root, timeout: 25000, maxBuffer: 128 * 1024 });
test('saved package and exact text verify through the independent CLI', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-package-cli-'));
  try {
    const proof = await readFile(new URL('../../backend/zkvm/verifier/tests/fixtures/timed-receipt.json', import.meta.url), 'utf8');
    const text = JSON.parse(proof).text, wrapped = await envelope(proof, {}, text);
    const file = path.join(directory, 'proof.json'), content = path.join(directory, 'text.txt');
    await writeFile(file, wrapped.envelope); await writeFile(content, text);
    assert.equal(JSON.parse((await check(file)).stdout).verified, true);
    assert.equal(JSON.parse((await check(file, '--text', content)).stdout).statementHash, wrapped.report.statementHash);
    await writeFile(content, text + '!'); await assert.rejects(check(file, '--text', content));
    await assert.rejects(check(file, '--account-evidence', file));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('CLI verifies real writing-policy and media proof exports', async () => {
  const writing = JSON.parse((await check('extra/experiments/noir-compact/browser/test/fixtures/Assurance250.json')).stdout);
  assert.equal(writing.statement.policySatisfied, true);
  const media = JSON.parse((await check('extra/experiments/noir-media/reader/test/fixtures/image.json', '--media', 'extra/experiments/noir-media/reader/test/fixtures/image.png')).stdout);
  assert.equal(media.verified, true); assert.equal(media.proofReport.scenePolicyChecked, false);
});
test('CLI verifies the native Noir disclosure file and rejects a substituted outer key', async () => {
  const directory=await mkdtemp(path.join(tmpdir(),'huma-noir-cli-'));
  try {
    const proof=await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/SwiftLiveV4.json',import.meta.url),'utf8');
    const value={kind:'huma-writing-disclosure-v1',proof,capturePublicKey:{format:'p256-x963-base64',value:JSON.parse(proof).publicKey},session:{fixture:true}};
    const file=path.join(directory,'disclosed.json');await writeFile(file,JSON.stringify(value));
    assert.equal(JSON.parse((await check(file)).stdout).verified,true);
    value.capturePublicKey.value='wrong';await writeFile(file,JSON.stringify(value));await assert.rejects(check(file));
  } finally {await rm(directory,{recursive:true,force:true});}
});
