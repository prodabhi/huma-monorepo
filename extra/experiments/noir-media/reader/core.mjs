import { derToP1363 } from '../../noir-compact/browser/core.mjs';
import { KIND, PROFILE, MAX_EXPORT_BYTES, MAX_MASTER_BYTES, VK_PIN, checkKey, hex, sha256 } from './profile.mjs';
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const encoder = new TextEncoder();
const join = (...parts) => {
  const bytes = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0)); let offset = 0;
  for (const p of parts) { bytes.set(p, offset); offset += p.length; } return bytes;
};
const fail = () => { throw new Error('Media evidence rejected.'); };
function base64(value, min, max = min) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3) || value.length % 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail();
  const raw = atob(value);
  if (raw.length < min || raw.length > max || btoa(raw) !== value) fail();
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
// Fixed ABI for the pinned circuit. u64s remain exact decimal strings.
export function decodeJournal(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 8416) fail();
  let offset = 0;
  function uint(width) {
    const n = BigInt('0x' + hex(bytes.subarray(offset, offset + 32))); offset += 32;
    if (n >= FIELD || n >= 1n << BigInt(width)) fail();
    return width > 32 ? n.toString() : Number(n);
  }
  const digest = () => Array.from({ length: 32 }, () => uint(8));
  const j = { kind: uint(8), profile: uint(8), nonce: digest(), capture_head: digest(), encoded_hash: digest(),
    decoded_root: digest(), edit_root: digest(), layout_hash: digest(), encoded_length: uint(64),
    decoded_length: uint(64), leaf_count: uint(32), sealed_root: digest(), challenge: digest(),
    sampled_indices: [uint(32), uint(32)] };
  if (offset !== bytes.length || ![1, 2, 3].includes(j.kind) || j.profile !== j.kind || j.leaf_count < 1 || j.leaf_count > 256 ||
      BigInt(j.encoded_length) < 1n || BigInt(j.encoded_length) > 536870912n ||
      BigInt(j.decoded_length) < BigInt(j.leaf_count) || BigInt(j.decoded_length) > BigInt(j.leaf_count) * 3072n ||
      j.sampled_indices.some(n => n >= j.leaf_count)) fail();
  return j;
}
function parse(source) {
  if (typeof source !== 'string' || source.length > MAX_EXPORT_BYTES || encoder.encode(source).length > MAX_EXPORT_BYTES) fail();
  const file = JSON.parse(source), fields = ['kind', 'profile', 'proof', 'publicInputs', 'publicKey', 'signature'];
  if (!file || Array.isArray(file) || typeof file !== 'object' || Object.keys(file).length !== fields.length ||
      fields.some(k => !Object.hasOwn(file, k)) || file.kind !== KIND || file.profile !== PROFILE) fail();
  const proof = base64(file.proof, 14656), inputs = base64(file.publicInputs, 8416), key = base64(file.publicKey, 65);
  if (key[0] !== 4) fail();
  return { proof, inputs, key, signature: derToP1363(base64(file.signature, 8, 72)), journal: decodeJournal(inputs) };
}
// Internal composition point. Public SDKs supply the pinned bounded WASM verifier.
export async function createMediaVerifier({ verificationKey, verifyZk }) {
  verificationKey = await checkKey(verificationKey.slice());
  if (typeof verifyZk !== 'function') fail();
  return async function verify(source, options = {}) {
    if (!options || Array.isArray(options) || typeof options !== 'object' ||
        Object.keys(options).some(k => !['master', 'expectedKey', 'expectedChallenge'].includes(k))) fail();
    const master = options.master;
    if (!(master instanceof Uint8Array) || master.length < 1 || master.length > MAX_MASTER_BYTES) fail();
    const { proof, inputs, key, signature, journal } = parse(source);
    const keyHash = hex(await sha256(key));
    for (const [name, expected] of [['expectedKey', keyHash], ['expectedChallenge', hex(journal.challenge)]]) {
      if (Object.hasOwn(options, name) && (typeof options[name] !== 'string' || !/^[a-f0-9]{64}$/.test(options[name]) || options[name].length !== 64 || options[name] !== expected)) fail();
    }
    if (String(master.length) !== journal.encoded_length || hex(await sha256(master)) !== hex(journal.encoded_hash)) fail();
    const publicKey = await crypto.subtle.importKey('raw', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature,
      join(encoder.encode('HUMA_MEDIA_SEAL_SIGNATURE_V1\0'), Uint8Array.from(journal.sealed_root)))) fail();
    if (await verifyZk(proof, inputs, verificationKey) !== true) fail();
    const identity = hex(await sha256(join(encoder.encode('HUMA_MEDIA_MEMBERSHIP_ID_V1\0'),
      Uint8Array.from(VK_PIN.sha256.match(/../g), x => parseInt(x, 16)), inputs, key)));
    return { verified: true, experimental: true, profile: PROFILE, proofIdentity: identity, programKeyHash: VK_PIN.sha256,
      keyHash, journal, signaturesVerified: 1, masterCompared: true, sampledOpenings: 2,
      uniqueSampledLeaves: new Set(journal.sampled_indices).size, samplingMethod: 'with-replacement', totalLeaves: journal.leaf_count,
      decodingProven: false, scenePolicyChecked: false, captureChainChecked: false, attestationVerified: false,
      trustedTime: false, samplingFreshnessVerified: false, expectedChallengeMatched: Object.hasOwn(options, 'expectedChallenge') };
  };
}
