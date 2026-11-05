import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import cbor from 'cbor';
import { verifyAppleChain, verifyAttestation, verifyReceipt, verifyAssertion, digest } from '../apple.mjs';
import { EvidenceStore } from '../store.mjs';
import { EvidenceService, policyFromEnvironment, bindingFields, validateBinding } from '../service.mjs';
import { makeServer } from '../server.mjs';

const policy = { appID: 'ABCDE12345.dev.swayam.huma', environment: 'development', versions: ['1'], categories: [3] };
const fixture = JSON.parse(readFileSync(new URL('./fixtures/upstream-development.json', import.meta.url)));
const fixtureDate = new Date('2024-02-04T20:27:06.193Z');
const real = cbor.decodeFirstSync(Buffer.from(fixture.attestation, 'base64'));
const binding = Object.fromEntries(bindingFields.map(field => [field, field === 'sessionID' ? '12345678-1234-1234-1234-123456789abc' : 'a'.repeat(64)]));
const testKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = testKey.publicKey.export({ format: 'jwk' });
const keyID = digest(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')])).toString('base64');
function assertion(clientData, counter, override = {}) {
    const count = Buffer.alloc(4); count.writeUInt32BE(counter);
    const properties = { apple_validation_category_01: 3, apple_bundle_version_01: '1', ...override };
    const auth = Buffer.concat([digest(Buffer.from(policy.appID)), Buffer.from([0x80]), count, cbor.encode(properties)]);
    const nonce = digest(Buffer.concat([auth, digest(Buffer.from(clientData, 'base64'))]));
    return cbor.encode({ authenticatorData: auth, signature: sign('sha256', nonce, testKey.privateKey) }).toString('base64');
}
function context() {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'huma-evidence-'));
    const store = new EvidenceStore(directory);
    const service = new EvidenceService(store, policy);
    // A generated software test key exercises assertions only. Production has no
    // route/configuration to seed a key; enrollment must pass Apple's real roots.
    store.state.keys[keyID] = { publicKey: testKey.publicKey.export({ type: 'spki', format: 'pem' }), environment: 'development', signCount: 0 };
    store.save();
    return { directory, store, service, close() { store.close(); rmSync(directory, { recursive: true, force: true }); } };
}

test('configuration requires explicit Apple identity, environment and release versions', () => {
    assert.throws(() => policyFromEnvironment({}));
    assert.deepEqual(policyFromEnvironment({ HUMA_APP_ID_PREFIX: 'ABCDE12345', HUMA_SIGNING_IDENTIFIER: 'dev.swayam.huma', HUMA_ATTEST_ENVIRONMENT: 'production', HUMA_BUNDLE_VERSIONS: '1,2' }).categories, [2, 4, 6]);
});
test('real Apple chain and CMS receipt validate historically; stale, wrong key/app/nonce fail', async () => {
    const leaf = verifyAppleChain(real.attStmt.x5c, fixtureDate);
    const args = { appID: 'V8H6LQ9448.io.uebelacker.AppAttestExample', publicKey: leaf.publicKey.export({ type: 'spki', format: 'pem' }), clientHash: digest(Buffer.from(fixture.challenge, 'base64')), now: fixtureDate };
    await verifyReceipt(real.attStmt.receipt, args);
    await assert.rejects(verifyReceipt(real.attStmt.receipt, { ...args, appID: policy.appID }));
    await assert.rejects(verifyReceipt(real.attStmt.receipt, { ...args, clientHash: Buffer.alloc(32) }));
    await assert.rejects(verifyReceipt(real.attStmt.receipt, { ...args, publicKey: testKey.publicKey }));
    await assert.rejects(verifyReceipt(real.attStmt.receipt, { ...args, now: new Date(fixtureDate.getTime() + 301000) }));
    assert.throws(() => verifyAppleChain([real.attStmt.x5c[1], real.attStmt.x5c[0]], fixtureDate));
    assert.throws(() => verifyAppleChain(real.attStmt.x5c, new Date('2050-01-01')));
    const changed = Buffer.from(real.attStmt.receipt); changed[changed.length - 20] ^= 1;
    await assert.rejects(verifyReceipt(changed, args));
    await assert.rejects(verifyAttestation({ attestation: Buffer.from(fixture.attestation, 'base64'), payload: Buffer.from(fixture.challenge, 'base64'), keyID: fixture.keyId, policy, now: fixtureDate }), /extension/); // No Mac ACL; never admit this iOS fixture.
});
test('historical Apple assertion confirms signature hashing; missing Mac properties still reject', () => {
    // Public upstream verifyAssertion.test.js fixture, covered by fixtures/LICENSE.
    const raw = Buffer.from('omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB', 'base64');
    const publicKey = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n-----END PUBLIC KEY-----\n';
    const payload = Buffer.from('{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}');
    const decoded = cbor.decodeFirstSync(raw);
    assert.ok(verify('sha256', digest(Buffer.concat([decoded.authenticatorData, digest(payload)])), publicKey, decoded.signature));
    assert.throws(() => verifyAssertion({ assertion: raw, payload, publicKey, signCount: 0,
        policy: { ...policy, appID: 'V8H6LQ9448.io.uebelacker.AppAttestExample' } }), /Mac app properties missing/);
});
test('assertion signature binds payload, app properties and monotonic unsigned counter', () => {
    const data = Buffer.from('one server nonce and exact binding').toString('base64');
    const raw = Buffer.from(assertion(data, 2147483649), 'base64');
    const args = { assertion: raw, payload: Buffer.from(data, 'base64'), publicKey: testKey.publicKey, signCount: 0, policy };
    assert.equal(verifyAssertion(args).signCount, 2147483649);
    assert.throws(() => verifyAssertion({ ...args, payload: Buffer.from('changed') }));
    assert.throws(() => verifyAssertion({ ...args, signCount: 2147483649 }));
    assert.throws(() => verifyAssertion({ ...args, policy: { ...policy, appID: 'OTHER12345.dev.swayam.huma' } }));
    assert.throws(() => verifyAssertion({ ...args, assertion: Buffer.from(assertion(data, 1, { apple_validation_category_01: 10 }), 'base64') }));
    assert.throws(() => verifyAssertion({ ...args, assertion: Buffer.from(assertion(data, 1, { apple_bundle_version_01: '999' }), 'base64') }));
    assert.throws(() => verifyAssertion({ ...args, assertion: Buffer.concat([raw, Buffer.from([0])]) }));
});
test('single-use challenge, exact binding, idempotent result, persistent counter and expiry', async () => {
    const c = context();
    try {
        const challenge = await c.service.challenge({ purpose: 'assert', keyID, binding });
        const changed = { ...binding, textHash: 'b'.repeat(64) };
        const other = await c.service.challenge({ purpose: 'assert', keyID, binding: changed });
        const request = { challengeID: challenge.id, keyID, assertion: assertion(challenge.clientData, 1) };
        const accepted = await c.service.accept(request, 'assert');
        assert.deepEqual(accepted.binding, binding);
        assert.equal(accepted.signCount, 1);
        assert.deepEqual(await c.service.accept(request, 'assert'), accepted);
        await assert.rejects(c.service.accept({ ...request, challengeID: other.id }, 'assert')); // Different binding/nonce.
        await assert.rejects(c.service.accept({ challengeID: other.id, keyID, assertion: assertion(other.clientData, 2) }, 'assert')); // Failed attempt burned it.
        c.store.close();
        c.store = new EvidenceStore(c.directory); c.service = new EvidenceService(c.store, policy);
        const fresh = await c.service.challenge({ purpose: 'assert', keyID, binding });
        await assert.rejects(c.service.accept({ keyID, challengeID: fresh.id, assertion: assertion(fresh.clientData, 1) }, 'assert')); // Counter survived restart.
        const expired = await c.service.challenge({ purpose: 'assert', keyID, binding });
        c.store.state.challenges[expired.id].expiresAt = Date.now() - 1; c.store.save();
        await assert.rejects(c.service.accept({ keyID, challengeID: expired.id, assertion: assertion(expired.clientData, 2) }, 'assert'));
        const concurrent = await Promise.all([c.service.challenge({ purpose: 'assert', keyID, binding }), c.service.challenge({ purpose: 'assert', keyID, binding })]);
        const outcomes = await Promise.allSettled(concurrent.map(ch => c.service.accept({ keyID, challengeID: ch.id, assertion: assertion(ch.clientData, 2) }, 'assert')));
        assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1);
        assert.equal(c.store.state.keys[keyID].signCount, 2);
        assert.throws(() => new EvidenceStore(c.directory), /EEXIST/);
    } finally { c.close(); }
});
test('portable replay binding has its own signed domain and rejects version downgrade', async () => {
    const c = context();
    try {
        assert.deepEqual(c.service.info().bindingVersions, [1, 2]);
        const portable = { version: 2, ...binding };
        assert.deepEqual(validateBinding(portable), portable);
        for (const value of [0, 1, 3, '2', null]) assert.throws(() => validateBinding({ ...binding, version: value }));
        const v1 = await c.service.challenge({ purpose: 'assert', keyID, binding });
        const v2 = await c.service.challenge({ purpose: 'assert', keyID, binding: portable });
        const fields = JSON.parse(Buffer.from(v2.clientData, 'base64'));
        assert.equal(fields[0], 'huma-app-attest-assert-v2');
        const forged = Buffer.from(JSON.stringify(['huma-app-attest-assert-v1', ...fields.slice(1)])).toString('base64');
        await assert.rejects(c.service.accept({ challengeID: v2.id, keyID, assertion: assertion(forged, 1) }, 'assert'));
        const fresh = await c.service.challenge({ purpose: 'assert', keyID, binding: portable });
        const accepted = await c.service.accept({ challengeID: fresh.id, keyID, assertion: assertion(fresh.clientData, 1) }, 'assert');
        assert.deepEqual(accepted.binding, portable);
        await assert.rejects(c.service.accept({ challengeID: v1.id, keyID, assertion: assertion(fresh.clientData, 2) }, 'assert'));
    } finally { c.close(); }
});
test('HTTP round trip accepts a bound assertion and rejects browser-origin and untrusted enrollment', async () => {
    const c = context(), server = makeServer(c.service);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (route, value, headers = {}) => fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(value) });
    try {
        assert.equal((await fetch(base + '/v1/info')).status, 200);
        assert.equal((await post('/v1/challenges', {}, { Origin: 'https://example.com' })).status, 403);
        const challenge = await (await post('/v1/challenges', { purpose: 'assert', keyID, binding })).json();
        const accepted = await post('/v1/assert', { challengeID: challenge.id, keyID, assertion: assertion(challenge.clientData, 1) });
        assert.equal(accepted.status, 200); assert.deepEqual((await accepted.json()).binding, binding);
        const unknownKey = Buffer.alloc(32, 7).toString('base64');
        const enrollment = await (await post('/v1/challenges', { purpose: 'enroll', keyID: unknownKey })).json();
        assert.equal((await post('/v1/enroll', { keyID: unknownKey, challengeID: enrollment.id, attestation: Buffer.from('not Apple').toString('base64') })).status, 422);
        assert.equal(c.store.state.keys[unknownKey], undefined);
        assert.equal(c.store.state.challenges[enrollment.id], undefined);
    } finally { await new Promise(resolve => server.close(resolve)); c.close(); }
});

test('a failed durable write prevents subsequent in-memory acceptance', async () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'huma-evidence-write-'));
    const store = new EvidenceStore(directory);
    try {
        mkdirSync(path.join(directory, 'state.json')); // Force atomic rename to fail.
        assert.throws(() => store.save());
        await assert.rejects(store.exclusive(() => 'must not run'), /failed write/);
    } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('persisted evidence cannot be reused across app identities or environments', () => {
    const c = context();
    try {
        assert.throws(() => new EvidenceService(c.store, { ...policy, environment: 'production' }), /separate evidence stores/);
        assert.throws(() => new EvidenceService(c.store, { ...policy, appID: 'OTHER12345.dev.swayam.huma' }), /separate evidence stores/);
        assert.equal(c.store.state.identity, `${policy.appID}|development`);
    } finally { c.close(); }
});
