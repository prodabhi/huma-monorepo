import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify, X509Certificate, webcrypto } from 'node:crypto';
import cbor from 'cbor';
import * as asn1 from 'asn1js';
import * as pki from 'pkijs';

pki.setEngine('node', webcrypto, new pki.CryptoEngine({ name: 'node', crypto: webcrypto }));
const root = new X509Certificate(readFileSync(new URL('./certificates/Apple_App_Attestation_Root_CA.pem', import.meta.url)));
const receiptRoot = readFileSync(new URL('./certificates/AppleRootCA-G3.cer', import.meta.url));
const macACL = Buffer.from('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB', 'base64');
export const digest = bytes => createHash('sha256').update(bytes).digest();
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const options = { preventDuplicateKeys: true, max_depth: 10 };
const decode = bytes => cbor.decodeFirstSync(bytes, options);
const equal = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const item = (map, key) => map instanceof Map ? map.get(key) : map?.[key];

export function parseASN(bytes) {
    bytes = Buffer.from(bytes);
    const parsed = asn1.fromBER(bytes);
    requireThat(parsed.offset === bytes.length && !parsed.result.error, 'Invalid ASN.1.');
    return parsed.result;
}
function cert(bytes) { return new pki.Certificate({ schema: parseASN(bytes) }); }
function extensionBytes(certificate, oid) {
    const matches = certificate.extensions?.filter(e => e.extnID === oid) ?? [];
    requireThat(matches.length === 1, 'Required certificate extension missing.');
    const outer = parseASN(matches[0].extnValue.valueBlock.valueHexView);
    const tagged = outer.valueBlock.value;
    requireThat(outer instanceof asn1.Sequence && tagged.length === 1 && tagged[0].idBlock.tagClass === 3 && tagged[0].valueBlock.value.length === 1, 'Invalid extension.');
    const value = tagged[0].valueBlock.value[0];
    requireThat(value instanceof asn1.OctetString, 'Invalid extension value.');
    return Buffer.from(value.valueBlock.valueHexView);
}
function checkDate(certificate, now) {
    requireThat(Date.parse(certificate.validFrom) <= now.getTime() && Date.parse(certificate.validTo) >= now.getTime(), 'Certificate expired or not yet valid.');
}
export function verifyAppleChain(x5c, now = new Date()) {
    requireThat(Array.isArray(x5c) && x5c.length === 2 && x5c.every(Buffer.isBuffer), 'Invalid certificate chain.');
    const [leaf, intermediate] = x5c.map(bytes => new X509Certificate(bytes));
    requireThat(!leaf.ca && intermediate.ca && root.ca && leaf.checkIssued(intermediate) && intermediate.checkIssued(root) &&
        leaf.verify(intermediate.publicKey) && intermediate.verify(root.publicKey) && root.verify(root.publicKey), 'Untrusted Apple certificate chain.');
    for (const certificate of [leaf, intermediate, root]) checkDate(certificate, now);
    requireThat(leaf.publicKey.asymmetricKeyType === 'ec' && leaf.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1', 'Expected P-256 key.');
    return leaf;
}

// Read signed extensions even on systems that omit the ED flag. Require one
// complete CBOR dictionary; no unsigned client metadata substitutes for it.
export function authenticatorData(bytes, policy, attestation = false) {
    requireThat(Buffer.isBuffer(bytes) && bytes.length >= (attestation ? 55 : 37), 'Invalid authenticator data.');
    requireThat(equal(bytes.subarray(0, 32), digest(Buffer.from(policy.appID))), 'App ID mismatch.');
    const flags = bytes[32];
    if (attestation) requireThat(Boolean(flags & 0x40), 'Credential data missing.');
    // Apple assertions use the simplified layout even when AT remains set.
    // Parse the layout by object type, not that legacy flag.
    const counter = bytes.readUInt32BE(33);
    let offset = 37, credential, aaguid, cose;
    if (attestation) {
        aaguid = bytes.subarray(37, 53);
        requireThat(bytes.readUInt16BE(53) === 32 && bytes.length > 87, 'Invalid credential length.');
        credential = bytes.subarray(55, 87);
        const decoded = cbor.decodeFirstSync(bytes.subarray(87), { ...options, extendedResults: true });
        cose = decoded.value; offset = 87 + decoded.bytes.length;
    }
    requireThat(bytes.length > offset, 'Mac app properties missing.');
    const properties = decode(bytes.subarray(offset));
    const category = item(properties, 'apple_validation_category_01');
    const version = item(properties, 'apple_bundle_version_01');
    requireThat(policy.categories.includes(category), 'App distribution category not allowed.');
    requireThat(typeof version === 'string' && policy.versions.includes(version), 'App version not allowed.');
    return { counter, credential, aaguid, cose, category, version };
}

function receiptContents(bytes) {
    const info = new pki.ContentInfo({ schema: parseASN(bytes) });
    requireThat(info.contentType === '1.2.840.113549.1.7.2', 'Expected signed receipt.');
    const signed = new pki.SignedData({ schema: info.content });
    requireThat(signed.signerInfos.length === 1 && signed.encapContentInfo.eContentType === '1.2.840.113549.1.7.1' && signed.encapContentInfo.eContent, 'Invalid receipt.');
    const payload = parseASN(signed.encapContentInfo.eContent.getValue());
    requireThat(payload instanceof asn1.Set, 'Invalid receipt payload.');
    const fields = new Map();
    for (const entry of payload.valueBlock.value) {
        const values = entry.valueBlock.value;
        requireThat(entry instanceof asn1.Sequence && values.length === 3 && values[0] instanceof asn1.Integer && values[1] instanceof asn1.Integer && values[2] instanceof asn1.OctetString, 'Invalid receipt field.');
        const type = values[0].valueBlock.valueDec;
        requireThat(!fields.has(type), 'Duplicate receipt field.');
        fields.set(type, Buffer.from(values[2].getValue()));
    }
    return { signed, fields };
}

export async function verifyReceipt(bytes, { appID, publicKey, clientHash, now = new Date() }) {
    const { signed, fields } = receiptContents(bytes);
    const checked = await signed.verify({ signer: 0, checkChain: true, trustedCerts: [cert(receiptRoot)], checkDate: now, extendedMode: true });
    requireThat(checked.signatureVerified && checked.signerCertificateVerified && checked.certificatePath.some(c => Buffer.from(c.toSchema().toBER(false)).equals(receiptRoot)), 'Untrusted receipt.');
    const text = type => fields.get(type)?.toString('utf8');
    const created = Date.parse(text(12));
    requireThat(text(2) === appID && text(6) === 'ATTEST', 'Receipt identity mismatch.');
    requireThat(Number.isFinite(created) && created <= now.getTime() + 30000 && now.getTime() - created <= 300000, 'Receipt is not fresh.');
    requireThat(equal(new X509Certificate(fields.get(3)).publicKey.export({ format: 'der', type: 'spki' }), createPublicKey(publicKey).export({ format: 'der', type: 'spki' })), 'Receipt key mismatch.');
    requireThat(equal(fields.get(4), clientHash), 'Receipt challenge mismatch.');
}

// Historical enrollment verification is distinct from live admission. The date
// is not trusted until verifyAttestation verifies the SAME Apple-signed receipt.
// It does not establish a fresh session, current revocation status or typing time.
export async function verifyArchivedAttestation({ attestation, payload, keyID, policy, now = new Date() }) {
    const decoded = decode(attestation);
    requireThat(Buffer.isBuffer(decoded?.attStmt?.receipt), 'Missing enrollment receipt.');
    const { fields } = receiptContents(decoded.attStmt.receipt);
    const created = Date.parse(fields.get(12)?.toString('utf8'));
    requireThat(Number.isFinite(created) && created <= now.getTime() + 30000, 'Invalid historical enrollment date.');
    const verified = await verifyAttestation({ attestation, payload, keyID, policy, now: new Date(created) });
    return { ...verified, enrollmentCreatedAt: new Date(created).toISOString() };
}

export async function verifyAttestation({ attestation, payload, keyID, policy, now = new Date() }) {
    const decoded = decode(attestation);
    requireThat(decoded?.fmt === 'apple-appattest' && Buffer.isBuffer(decoded.authData) && Buffer.isBuffer(decoded.attStmt?.receipt), 'Invalid attestation object.');
    const leaf = verifyAppleChain(decoded.attStmt.x5c, now);
    const certificate = cert(leaf.raw);
    requireThat(equal(extensionBytes(certificate, '1.2.840.113635.100.8.6'), macACL), 'Mac security policy does not match SIP and Full Security.');
    requireThat(equal(extensionBytes(certificate, '1.2.840.113635.100.8.2'), digest(Buffer.concat([decoded.authData, digest(payload)]))), 'Attestation nonce mismatch.');
    const jwk = leaf.publicKey.export({ format: 'jwk' });
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    requireThat(digest(point).toString('base64') === keyID, 'Key ID mismatch.');
    const auth = authenticatorData(decoded.authData, policy, true);
    const expectedAAGUID = policy.environment === 'development' ? Buffer.from('appattestdevelop') : Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
    requireThat(auth.counter === 0 && equal(auth.aaguid, expectedAAGUID) && auth.credential.toString('base64') === keyID, 'Invalid attestation environment or credential.');
    requireThat(item(auth.cose, 1) === 2 && item(auth.cose, 3) === -7 && item(auth.cose, -1) === 1 && equal(item(auth.cose, -2), point.subarray(1, 33)) && equal(item(auth.cose, -3), point.subarray(33)), 'COSE key mismatch.');
    const publicKey = leaf.publicKey.export({ type: 'spki', format: 'pem' });
    await verifyReceipt(decoded.attStmt.receipt, { appID: policy.appID, publicKey, clientHash: digest(payload), now });
    return { publicKey, environment: policy.environment, receipt: decoded.attStmt.receipt.toString('base64'), category: auth.category, version: auth.version };
}

export function verifyAssertion({ assertion, payload, publicKey, signCount, policy }) {
    requireThat(Number.isSafeInteger(signCount) && signCount >= 0 && signCount <= 0xffffffff, 'Invalid stored counter.');
    const decoded = decode(assertion);
    requireThat(Buffer.isBuffer(decoded?.signature) && Buffer.isBuffer(decoded.authenticatorData), 'Invalid assertion.');
    const auth = authenticatorData(decoded.authenticatorData, policy);
    const nonce = digest(Buffer.concat([decoded.authenticatorData, digest(payload)]));
    requireThat(verify('sha256', nonce, publicKey, decoded.signature), 'Assertion signature mismatch.');
    requireThat(auth.counter > signCount, 'Assertion replay.');
    return { signCount: auth.counter, category: auth.category, version: auth.version };
}
