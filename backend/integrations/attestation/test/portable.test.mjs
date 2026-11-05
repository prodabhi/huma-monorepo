import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initSync, verify_replay } from '../../../../frontend/dist/replay/huma_replay_browser.js';
import { readerPolicy, verifyReplayDeviceBinding, verifyPortableDeviceEvidence } from '../portable.mjs';
import { verifyArchivedAttestation } from '../apple.mjs';

initSync({ module: await readFile(new URL('../../../../frontend/dist/replay/huma_replay_browser_bg.wasm', import.meta.url)) });
const source = await readFile(new URL('../../../zkvm/verifier/tests/fixtures/timed-receipt.json', import.meta.url), 'utf8');
const report = JSON.parse(verify_replay(source, undefined, undefined));
const witness = JSON.parse(await readFile(new URL('../../../zkvm/common/tests/fixtures/swift-timed.json', import.meta.url)));
const oldApple = JSON.parse(await readFile(new URL('./fixtures/upstream-development.json', import.meta.url)));
const policy = readerPolicy({ appID: 'ABCDE12345.dev.swayam.huma', environment: 'development', versions: ['1'] });
const binding = { version: 2, sessionID: witness.session.id, captureHead: report.journal.captureHead,
    editHead: report.journal.editHead, textHash: report.journal.rawTextHash, proofHash: report.proofIdentity,
    checkpointHash: report.journal.checkpointHash, captureKeyHash: report.journal.captureKeyHash };

test('portable binding matches a genuine replay report; every cross-proof/key/session substitution rejects', async () => {
    assert.deepEqual(await verifyReplayDeviceBinding(binding, report), binding);
    for (const field of Object.keys(binding).filter(field => !['version', 'sessionID'].includes(field))) {
        await assert.rejects(verifyReplayDeviceBinding({ ...binding, [field]: '0'.repeat(64) }, report));
    }
    await assert.rejects(verifyReplayDeviceBinding({ ...binding, sessionID: '11111111-1111-1111-1111-111111111111' }, report));
    await assert.rejects(verifyReplayDeviceBinding({ ...binding, version: 1 }, report));
    await assert.rejects(verifyReplayDeviceBinding(binding, { ...report, verified: false }));
    await assert.rejects(verifyReplayDeviceBinding({ ...binding, privateMetadata: true }, report));
});

test('reader chooses the expected app policy; evidence cannot choose its own authority', async () => {
    for (const appID of ['ABCDE12345Xdev.swayam.huma', 'self-declared', '']) assert.throws(() => readerPolicy({ appID, environment: 'development', versions: ['1'] }));
    assert.throws(() => readerPolicy({ appID: policy.appID, environment: 'development', versions: ['1,2'] }));
    assert.deepEqual(readerPolicy({ appID: policy.appID, environment: 'production', versions: ['1'] }).categories, [2, 4, 6]);
    await assert.rejects(verifyPortableDeviceEvidence({ version: 1, appID: 'OTHER12345.some.app', environment: 'development' }, report, policy), /reader app policy/);
});

test('historical Apple certificates are not rejected merely for age, but an iOS enrollment never qualifies as Mac', async () => {
    const args = { attestation: Buffer.from(oldApple.attestation, 'base64'), payload: Buffer.from(oldApple.challenge, 'base64'),
        keyID: oldApple.keyId, policy: { ...policy, appID: 'V8H6LQ9448.io.uebelacker.AppAttestExample' } };
    await assert.rejects(verifyArchivedAttestation(args), /extension/); // Chain date check passed; required signed Mac ACL is absent.
    await assert.rejects(verifyArchivedAttestation({ ...args, now: new Date('2020-01-01') }), /historical enrollment date/);
    await assert.rejects(verifyArchivedAttestation({ ...args, attestation: Buffer.from('software assertion') }));
});
