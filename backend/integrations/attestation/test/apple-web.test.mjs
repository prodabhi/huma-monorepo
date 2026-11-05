import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, sign, createHash, X509Certificate } from 'node:crypto';
import cbor from 'cbor';
import { appleWebVerifier, base64, decodeCBOR, digest } from '../apple-web.mjs';
import { portableVerifier, readerPolicy } from '../portable-core.mjs';
import { initSync, verify_replay } from '../../../../frontend/dist/replay/huma_replay_browser.js';

const root = path => readFileSync(new URL('../certificates/' + path, import.meta.url));
const apple = appleWebVerifier(new X509Certificate(root('Apple_App_Attestation_Root_CA.pem')).raw, root('AppleRootCA-G3.cer'));
const fixture = JSON.parse(readFileSync(new URL('./fixtures/upstream-development.json', import.meta.url)));
const decoded = cbor.decodeFirstSync(Buffer.from(fixture.attestation, 'base64'));
const date = new Date('2024-02-04T20:27:06.193Z');
const hash = bytes => createHash('sha256').update(bytes).digest();
const policy = readerPolicy({ appID: 'ABCDE12345.dev.swayam.huma', environment: 'development', versions: ['1'] });

test('WebCrypto verifies real historical Apple certificates and receipt; substitutions reject', async () => {
    const leaf = await apple.verifyAppleChain(decoded.attStmt.x5c, date);
    const publicKey = new Uint8Array(leaf.subjectPublicKeyInfo.toSchema().toBER(false));
    const args = { appID: 'V8H6LQ9448.io.uebelacker.AppAttestExample', publicKey,
        clientHash: hash(Buffer.from(fixture.challenge, 'base64')), now: date };
    await apple.verifyReceipt(decoded.attStmt.receipt, args);
    await assert.rejects(apple.verifyReceipt(decoded.attStmt.receipt, { ...args, appID: policy.appID }));
    await assert.rejects(apple.verifyReceipt(decoded.attStmt.receipt, { ...args, clientHash: new Uint8Array(32) }));
    await assert.rejects(apple.verifyReceipt(decoded.attStmt.receipt, { ...args, now: new Date(date.getTime() + 301000) }));
    const changed = Buffer.from(decoded.attStmt.receipt); changed[changed.length - 20] ^= 1;
    await assert.rejects(apple.verifyReceipt(changed, args));
    await assert.rejects(apple.verifyAppleChain([...decoded.attStmt.x5c].reverse(), date));
    await assert.rejects(apple.verifyAppleChain(decoded.attStmt.x5c, new Date('2050-01-01')));
    await assert.rejects(apple.verifyArchivedAttestation({ attestation: Buffer.from(fixture.attestation, 'base64'),
        payload: Buffer.from(fixture.challenge, 'base64'), keyID: fixture.keyId, policy }), /extension/);
});

test('WebCrypto validates P256 assertion, app policy and unsigned counter without a Node crypto shim', async () => {
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const payload = Buffer.from('reader-independent challenge');
    function assertion(counter, changes = {}) {
        const count = Buffer.alloc(4); count.writeUInt32BE(counter);
        const properties = cbor.encode({ apple_validation_category_01: 3, apple_bundle_version_01: '1', ...changes });
        const auth = Buffer.concat([hash(Buffer.from(policy.appID)), Buffer.from([0x80]), count, properties]);
        const nonce = hash(Buffer.concat([auth, hash(payload)]));
        return cbor.encode({ authenticatorData: auth, signature: sign('sha256', nonce, key.privateKey) });
    }
    const args = { assertion: assertion(2147483649), payload, publicKey: key.publicKey.export({ format: 'der', type: 'spki' }), signCount: 0, policy };
    assert.equal((await apple.verifyAssertion(args)).signCount, 2147483649);
    await assert.rejects(apple.verifyAssertion({ ...args, payload: Buffer.from('substituted') }));
    await assert.rejects(apple.verifyAssertion({ ...args, signCount: 2147483649 }));
    await assert.rejects(apple.verifyAssertion({ ...args, assertion: assertion(1, { apple_validation_category_01: 10 }) }));
    await assert.rejects(apple.verifyAssertion({ ...args, assertion: assertion(1, { apple_bundle_version_01: '2' }) }));
    await assert.rejects(apple.verifyAssertion({ ...args, assertion: Buffer.concat([args.assertion, Buffer.from([0])]) }));
});

test('browser CBOR rejects duplicates, excessive nesting, indefinite maps and trailing bytes', () => {
    for (const encoded of ['a2616101616102', 'bfff', 'a000', '81'.repeat(12) + '00']) {
        assert.throws(() => decodeCBOR(Buffer.from(encoded, 'hex')));
    }
    const encoded = cbor.encode(new Map([[-1, 1], [-2, Buffer.from([2])]]));
    assert.equal(decodeCBOR(encoded).get(-1), 1);
    assert.equal(decodeCBOR(Buffer.concat([encoded, Buffer.from([0])]), true).length, encoded.length);
    const largest = Buffer.alloc(65536, 255);
    assert.deepEqual(Buffer.from(base64(largest.toString('base64'))), largest);
    assert.throws(() => base64(Buffer.alloc(65537).toString('base64')));
    for (const invalid of ['', 'AA', 'AB==', 'AA===']) assert.throws(() => base64(invalid));
});

test('shared browser binding uses the real pinned replay report and requires reader-owned app policy', async () => {
    initSync({ module: readFileSync(new URL('../../../../frontend/dist/replay/huma_replay_browser_bg.wasm', import.meta.url)) });
    const record = readFileSync(new URL('../../../zkvm/verifier/tests/fixtures/timed-receipt.json', import.meta.url), 'utf8');
    const report = JSON.parse(verify_replay(record, undefined, undefined));
    const witness = JSON.parse(readFileSync(new URL('../../../zkvm/common/tests/fixtures/swift-timed.json', import.meta.url)));
    const binding = { version: 2, sessionID: witness.session.id, captureHead: report.journal.captureHead, editHead: report.journal.editHead,
        textHash: report.journal.rawTextHash, proofHash: report.proofIdentity, checkpointHash: report.journal.checkpointHash, captureKeyHash: report.journal.captureKeyHash };
    const browser = portableVerifier({ base64, digest, ...apple });
    assert.deepEqual(await browser.verifyReplayDeviceBinding(binding, report), binding);
    await assert.rejects(browser.verifyReplayDeviceBinding({ ...binding, proofHash: '0'.repeat(64) }, report));
    await assert.rejects(browser.verifyPortableDeviceEvidence({ appID: 'OTHER12345.some.app', environment: 'development', version: 1 }, report, policy));
});
