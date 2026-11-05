// Browser/Node WebCrypto backend. Roots are supplied by the trusted build entry,
// never by an evidence file or reader policy.
import * as asn1 from 'asn1js';
import * as pki from 'pkijs';
import { decodeFirst, Tokenizer } from 'cborg';

const demand = (value, message) => { if (!value) throw new Error(message); };
const bytes = value => value instanceof Uint8Array;
const equal = (a, b) => bytes(a) && bytes(b) && a.length === b.length && a.every((v, i) => v === b[i]);
const utf8 = value => new TextEncoder().encode(value);
const text = value => new TextDecoder('utf-8', { fatal: true }).decode(value);
const concat = (...values) => { const out = new Uint8Array(values.reduce((sum, v) => sum + v.length, 0)); let at = 0; for (const v of values) { out.set(v, at); at += v.length; } return out; };
const encoded = value => { let raw = ''; for (let offset = 0; offset < value.length; offset += 8192) raw += String.fromCharCode(...value.subarray(offset, offset + 8192)); return btoa(raw); };
export function base64(value, limit = 65536) {
    demand(typeof value === 'string' && value.length <= Math.ceil(limit / 3) * 4 && /^[A-Za-z0-9+/]*={0,2}$/.test(value), 'Invalid binary encoding.');
    const raw = Uint8Array.from(atob(value), c => c.charCodeAt(0));
    demand(raw.length > 0 && raw.length <= limit && encoded(raw) === value, 'Invalid binary encoding.');
    return raw;
}
export const digest = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', value));
export function decodeCBOR(value, first = false) {
    demand(bytes(value) && value.length > 0 && value.length <= 65536, 'Invalid CBOR size.');
    const options = { useMaps: true, rejectDuplicateMapKeys: true, allowIndefinite: false, allowBigInt: false, allowNaN: false, allowInfinity: false };
    const inner = new Tokenizer(value, options), remaining = [1]; let count = 0;
    const tokenizer = { pos: () => inner.pos(), done: () => inner.done(), next() {
        while (remaining.at(-1) === 0) remaining.pop();
        demand(remaining.length > 0 && remaining.length <= 10 && ++count <= 4096, 'CBOR nesting or item limit exceeded.');
        remaining[remaining.length - 1]--;
        const token = inner.next();
        if (token.type.major === 4 || token.type.major === 5) {
            demand(Number.isSafeInteger(token.value) && token.value <= 512, 'CBOR container exceeds limits.');
            remaining.push(token.value * (token.type.major === 5 ? 2 : 1));
        }
        return token;
    } };
    const [decoded, rest] = decodeFirst(value, { ...options, tokenizer });
    demand(first || rest.length === 0, 'Trailing CBOR data.');
    return first ? { value: decoded, length: value.length - rest.length } : decoded;
}
function parseASN(value) {
    demand(bytes(value) && value.length > 0 && value.length <= 65536, 'Invalid ASN.1 size.');
    const parsed = asn1.fromBER(value);
    demand(parsed.offset === value.length && !parsed.result.error, 'Invalid ASN.1.');
    return parsed.result;
}
const cert = value => new pki.Certificate({ schema: parseASN(value) });
const serial = value => new Uint8Array(value.toSchema().toBER(false));
function extension(certificate, oid) {
    const found = certificate.extensions?.filter(e => e.extnID === oid) ?? [];
    demand(found.length === 1, 'Required certificate extension missing.');
    const outer = parseASN(found[0].extnValue.valueBlock.valueHexView), tagged = outer.valueBlock.value;
    demand(outer instanceof asn1.Sequence && tagged.length === 1 && tagged[0].idBlock.tagClass === 3 && tagged[0].valueBlock.value.length === 1, 'Invalid extension.');
    const value = tagged[0].valueBlock.value[0];
    demand(value instanceof asn1.OctetString, 'Invalid extension value.');
    return new Uint8Array(value.valueBlock.valueHexView);
}
function receiptContents(value) {
    const info = new pki.ContentInfo({ schema: parseASN(value) });
    demand(info.contentType === '1.2.840.113549.1.7.2', 'Expected signed receipt.');
    const signed = new pki.SignedData({ schema: info.content });
    demand(signed.signerInfos.length === 1 && signed.encapContentInfo.eContentType === '1.2.840.113549.1.7.1' && signed.encapContentInfo.eContent, 'Invalid receipt.');
    const payload = parseASN(new Uint8Array(signed.encapContentInfo.eContent.getValue()));
    demand(payload instanceof asn1.Set, 'Invalid receipt payload.');
    const fields = new Map();
    for (const entry of payload.valueBlock.value) {
        const v = entry.valueBlock.value;
        demand(entry instanceof asn1.Sequence && v.length === 3 && v[0] instanceof asn1.Integer && v[1] instanceof asn1.Integer && v[2] instanceof asn1.OctetString, 'Invalid receipt field.');
        const type = v[0].valueBlock.valueDec;
        demand(!fields.has(type), 'Duplicate receipt field.'); fields.set(type, new Uint8Array(v[2].getValue()));
    }
    return { signed, fields };
}
export function appleWebVerifier(attestationRoot, receiptRoot) {
    const root = cert(attestationRoot), receiptCA = cert(receiptRoot);
    const engine = new pki.CryptoEngine({ name: 'huma-web', crypto });
    const macACL = base64('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB');
    const spki = certificate => new Uint8Array(certificate.subjectPublicKeyInfo.toSchema().toBER(false));
    async function verifyAppleChain(chain, now = new Date()) {
        demand(Array.isArray(chain) && chain.length === 2 && chain.every(bytes), 'Invalid certificate chain.');
        const [leaf, middle] = chain.map(cert);
        const isCA = c => c.extensions?.find(e => e.extnID === '2.5.29.19')?.parsedValue?.cA === true;
        demand(!isCA(leaf) && isCA(middle) && isCA(root) && leaf.issuer.isEqual(middle.subject) && middle.issuer.isEqual(root.subject) && root.issuer.isEqual(root.subject) &&
            await leaf.verify(middle, engine) && await middle.verify(root, engine) && await root.verify(root, engine), 'Untrusted Apple certificate chain.');
        for (const c of [leaf, middle, root]) demand(c.notBefore.value <= now && c.notAfter.value >= now, 'Certificate expired or not yet valid.');
        const info = leaf.subjectPublicKeyInfo;
        demand(info.algorithm.algorithmId === '1.2.840.10045.2.1' && info.algorithm.algorithmParams?.valueBlock?.toString() === '1.2.840.10045.3.1.7' && info.subjectPublicKey.valueBlock.unusedBits === 0, 'Expected P-256 key.');
        return leaf;
    }
    async function authenticatorData(raw, policy, attestation = false) {
        demand(bytes(raw) && raw.length >= (attestation ? 55 : 37), 'Invalid authenticator data.');
        demand(equal(raw.subarray(0, 32), await digest(utf8(policy.appID))), 'App ID mismatch.');
        if (attestation) demand(Boolean(raw[32] & 0x40), 'Credential data missing.');
        const counter = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint32(33);
        let offset = 37, credential, aaguid, cose;
        if (attestation) {
            aaguid = raw.subarray(37, 53);
            demand(new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint16(53) === 32 && raw.length > 87, 'Invalid credential length.');
            credential = raw.subarray(55, 87);
            const decoded = decodeCBOR(raw.subarray(87), true); cose = decoded.value; offset = 87 + decoded.length;
        }
        demand(raw.length > offset, 'Mac app properties missing.');
        const properties = decodeCBOR(raw.subarray(offset));
        const category = properties.get?.('apple_validation_category_01'), version = properties.get?.('apple_bundle_version_01');
        demand(policy.categories.includes(category), 'App distribution category not allowed.');
        demand(typeof version === 'string' && policy.versions.includes(version), 'App version not allowed.');
        return { counter, credential, aaguid, cose, category, version };
    }
    async function verifyReceipt(raw, { appID, publicKey, clientHash, now = new Date() }) {
        const { signed, fields } = receiptContents(raw);
        const checked = await signed.verify({ signer: 0, checkChain: true, trustedCerts: [receiptCA], checkDate: now, extendedMode: true }, engine);
        demand(checked.signatureVerified && checked.signerCertificateVerified && checked.certificatePath.some(c => equal(serial(c), receiptRoot)), 'Untrusted receipt.');
        const created = Date.parse(text(fields.get(12)));
        demand(text(fields.get(2)) === appID && text(fields.get(6)) === 'ATTEST', 'Receipt identity mismatch.');
        demand(Number.isFinite(created) && created <= now.getTime() + 30000 && now.getTime() - created <= 300000, 'Receipt is not fresh.');
        demand(equal(spki(cert(fields.get(3))), publicKey), 'Receipt key mismatch.');
        demand(equal(fields.get(4), clientHash), 'Receipt challenge mismatch.');
    }
    async function verifyArchivedAttestation({ attestation, payload, keyID, policy, now = new Date() }) {
        const decoded = decodeCBOR(attestation), statement = decoded.get?.('attStmt');
        const rawReceipt = statement?.get?.('receipt');
        demand(decoded.get?.('fmt') === 'apple-appattest' && bytes(decoded.get('authData')) && bytes(rawReceipt), 'Invalid attestation object.');
        const { fields } = receiptContents(rawReceipt), created = Date.parse(text(fields.get(12)));
        demand(Number.isFinite(created) && created <= now.getTime() + 30000, 'Invalid historical enrollment date.');
        const when = new Date(created), leaf = await verifyAppleChain(statement.get('x5c'), when), authData = decoded.get('authData');
        demand(equal(extension(leaf, '1.2.840.113635.100.8.6'), macACL), 'Mac security policy does not match SIP and Full Security.');
        demand(equal(extension(leaf, '1.2.840.113635.100.8.2'), await digest(concat(authData, await digest(payload)))), 'Attestation nonce mismatch.');
        const point = new Uint8Array(leaf.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        demand(point.length === 65 && point[0] === 4 && encoded(await digest(point)) === keyID, 'Key ID mismatch.');
        const auth = await authenticatorData(authData, policy, true);
        const aaguid = policy.environment === 'development' ? utf8('appattestdevelop') : concat(utf8('appattest'), new Uint8Array(7));
        demand(auth.counter === 0 && equal(auth.aaguid, aaguid) && encoded(auth.credential) === keyID, 'Invalid attestation environment or credential.');
        demand(auth.cose?.get?.(1) === 2 && auth.cose.get(3) === -7 && auth.cose.get(-1) === 1 && equal(auth.cose.get(-2), point.subarray(1, 33)) && equal(auth.cose.get(-3), point.subarray(33)), 'COSE key mismatch.');
        const publicKey = spki(leaf);
        await verifyReceipt(rawReceipt, { appID: policy.appID, publicKey, clientHash: await digest(payload), now: when });
        return { publicKey, enrollmentCreatedAt: when.toISOString() };
    }
    async function verifyAssertion({ assertion, payload, publicKey, signCount, policy }) {
        demand(Number.isSafeInteger(signCount) && signCount >= 0 && signCount <= 0xffffffff, 'Invalid stored counter.');
        const decoded = decodeCBOR(assertion), signature = decoded.get?.('signature'), authData = decoded.get?.('authenticatorData');
        demand(bytes(signature) && bytes(authData), 'Invalid assertion.');
        const auth = await authenticatorData(authData, policy);
        const nonce = await digest(concat(authData, await digest(payload)));
        const key = await crypto.subtle.importKey('spki', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        const rawSignature = pki.createECDSASignatureFromCMS(parseASN(signature), 32);
        demand(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSignature, nonce), 'Assertion signature mismatch.');
        demand(auth.counter > signCount, 'Assertion replay.');
        return { signCount: auth.counter, category: auth.category, version: auth.version };
    }
    return { verifyAppleChain, verifyReceipt, verifyArchivedAttestation, verifyAssertion, authenticatorData };
}
