import { ASSETS, PROFILE, KIND, MAX_EXPORT_BYTES, checkAsset, hex, sha256 } from './profile.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const encode = new TextEncoder();
const fail = message => { throw new Error(message); };
const join = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };
const integer = bytes => BigInt('0x' + hex(bytes));
const fieldBytes = value => Uint8Array.from(BigInt(value).toString(16).padStart(64, '0').match(/../g), x => parseInt(x, 16));

function base64(value, min, max) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3) || value.length % 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('Invalid public-proof encoding.');
  const raw = atob(value);
  if (raw.length < min || raw.length > max || btoa(raw) !== value) fail('Invalid public-proof length or encoding.');
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

export function canonicalTextBytes(text) {
  if (typeof text !== 'string' || text.length > 65536) fail('Reader text exceeds its limit.');
  // TextEncoder silently replaces lone surrogates. Reject rather than compare a different string.
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail('Text contains an invalid Unicode sequence.');
    } else if (c >= 0xdc00 && c <= 0xdfff) fail('Text contains an invalid Unicode sequence.');
  }
  let end = text.length;
  while (end > 0 && (text.charCodeAt(end - 1) === 32 || text.charCodeAt(end - 1) === 9)) end--;
  const bytes = encode.encode(text.slice(0, end));
  if (bytes.length > 65536) fail('Reader text exceeds its limit.');
  return bytes;
}

// WebCrypto uses IEEE P1363 r||s; the capture protocol preserves canonical DER.
export function derToP1363(der) {
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) fail('Invalid checkpoint DER signature.');
  let offset = 2; const values = [];
  for (let i = 0; i < 2; i++) {
    if (der[offset++] !== 2) fail('Invalid checkpoint DER integer.');
    const size = der[offset++], end = offset + size;
    if (size < 1 || size > 33 || end > der.length || der[offset] & 0x80 ||
        (size > 1 && der[offset] === 0 && !(der[offset + 1] & 0x80))) fail('Noncanonical checkpoint DER integer.');
    const n = integer(der.subarray(offset, end));
    if (n <= 0n || n >= P256_ORDER) fail('Checkpoint signature scalar is out of range.');
    values.push(fieldBytes(n)); offset = end;
  }
  if (offset !== der.length) fail('Trailing checkpoint signature bytes.');
  return join(...values);
}

export function decodeJournal(raw, abi) {
  if (!(raw instanceof Uint8Array) || raw.length !== 1824) fail('Unexpected public-input length.');
  let offset = 0;
  function decode(type) {
    if (type.kind === 'array') return Array.from({ length: type.length }, () => decode(type.type));
    if (type.kind === 'struct') return Object.fromEntries(type.fields.map(f => [f.name, decode(f.type)]));
    if (offset + 32 > raw.length) fail('Truncated public inputs.');
    const n = integer(raw.subarray(offset, offset + 32)); offset += 32;
    if (n >= FIELD) fail('Noncanonical public field.');
    if (type.kind === 'field') return n.toString();
    if (type.kind === 'boolean') { if (n > 1n) fail('Noncanonical public boolean.'); return n === 1n; }
    if (type.kind !== 'integer' || type.sign !== 'unsigned' || n >= 1n << BigInt(type.width)) fail('Invalid public integer.');
    // Preserve every u64 exactly across JSON and browser boundaries, even above 2^53.
    return type.width > 32 ? n.toString() : Number(n);
  }
  const journal = decode(abi);
  if (offset !== raw.length) fail('Unexpected extra public inputs.');
  const count = journal.checkpoint_count;
  if (count < 2 || count > 8 || journal.checkpoint_roots.length !== 8 || journal.checkpoint_roots.slice(count).some(r => r !== '0')) fail('Invalid checkpoint count or padding.');
  delete journal.checkpoint_count;
  journal.checkpoint_roots = journal.checkpoint_roots.slice(0, count);
  if (journal.session_nonce.some(n => BigInt(n) >= 1n << 128n) || journal.op_count < 1 || journal.op_count > 1536 ||
      journal.byte_length < 1 || journal.raw_byte_length > 1024 || journal.byte_length > journal.raw_byte_length || journal.initial_bytes > 1024 ||
      journal.captures !== journal.edits + journal.samples || journal.captures > 1536 || journal.typing + journal.paste > journal.edits ||
      BigInt(journal.start_unix) > 253402300799999n || BigInt(journal.end_unix) > 253402300799999n) fail('Public journal exceeds this profile.');
  return journal;
}

function parse(source, abi) {
  if (typeof source !== 'string' || source.length > MAX_EXPORT_BYTES || encode.encode(source).length > MAX_EXPORT_BYTES) fail('Public proof exceeds 512 KiB.');
  let file; try { file = JSON.parse(source); } catch { fail('Public proof is not valid JSON.'); }
  if (!file || Array.isArray(file) || typeof file !== 'object') fail('Invalid public proof.');
  const allowed = ['kind', 'profile', 'proof', 'publicInputs', 'publicKey', 'signatures', 'text'];
  if (Object.keys(file).some(k => !allowed.includes(k)) || file.kind !== KIND || file.profile !== PROFILE) fail('Unsupported public-proof format or profile.');
  const proof = base64(file.proof, 14656, 14656), inputs = base64(file.publicInputs, 1824, 1824), key = base64(file.publicKey, 65, 65);
  if (key[0] !== 4) fail('Expected an uncompressed P-256 public key.');
  const journal = decodeJournal(inputs, abi);
  if (!Array.isArray(file.signatures) || file.signatures.length !== journal.checkpoint_roots.length) fail('Every checkpoint needs its signature.');
  const signatures = file.signatures.map(s => derToP1363(base64(s, 8, 72)));
  const text = Object.hasOwn(file, 'text') ? canonicalTextBytes(file.text) : undefined;
  return { proof, inputs, key, journal, signatures, text };
}

// Internal composition point: shipped entry points always provide the pinned WASM backend.
export async function createCompactVerifier({ verificationKey, journalABI, verifyZk }) {
  verificationKey = verificationKey.slice(); journalABI = journalABI.slice();
  await checkAsset('cast256.vk', verificationKey);
  await checkAsset('journal-abi.json', journalABI);
  if (typeof verifyZk !== 'function') fail('A proof verifier is required.');
  const abi = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(journalABI));
  return async function verify(source, options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(k => !['text', 'expectedKey'].includes(k))) fail('Unsupported reader option.');
    const { proof, inputs, key, journal, signatures, text } = parse(source, abi);
    const keyHash = hex(await sha256(key));
    if (Object.hasOwn(options, 'expectedKey') && (typeof options.expectedKey !== 'string' || !/^[a-f0-9]{64}$/.test(options.expectedKey) || options.expectedKey !== keyHash)) fail('Unexpected capture key.');
    const texts = [];
    if (text !== undefined) texts.push(text);
    if (Object.hasOwn(options, 'text')) texts.push(canonicalTextBytes(options.text));
    for (const bytes of texts) if (bytes.length !== journal.byte_length || hex(await sha256(bytes)) !== hex(journal.text_hash)) fail('Reader text differs from the proven text.');
    let publicKey;
    try { publicKey = await crypto.subtle.importKey('raw', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']); }
    catch { fail('Invalid P-256 capture key.'); }
    for (let i = 0; i < signatures.length; i++) {
      const message = join(encode.encode('HUMA_COMPACT_EXPERIMENT_CHECKPOINT_V3\0'), fieldBytes(journal.checkpoint_roots[i]));
      if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signatures[i], message)) fail('Checkpoint signature rejected.');
    }
    if (await verifyZk(proof, inputs, verificationKey) !== true) fail('ZK proof rejected.');
    const vkHash = Uint8Array.from(ASSETS['cast256.vk'].sha256.match(/../g), x => parseInt(x, 16));
    const identity = hex(await sha256(join(encode.encode('HUMA_COMPACT_EXPERIMENT_ID_V3\0'), vkHash, inputs, key)));
    return {
      verified: true, experimental: true, profile: PROFILE, proofIdentity: identity,
      programKeyHash: ASSETS['cast256.vk'].sha256, keyHash, journal,
      checkpointCapacity: 8, signaturesVerified: signatures.length,
      disclosedPublicKey: true, textCompared: texts.length > 0,
      attestationVerified: false, trustedTime: false, humanAuthorshipProven: false,
    };
  };
}
