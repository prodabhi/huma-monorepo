// Data/encoding contract only. These helpers do not verify a proof or a signature.
export const ENVELOPE_KIND = 'huma-evidence-envelope-v1';
export const TEXT_POLICY = 'trailing-ascii-space-tab-v1';
export const WRITING_DISCLOSURE_KIND = 'huma-writing-disclosure-v1';
export const LONG_KIND = 'huma-long-assurance-public-proof-v1';
export const LONG_KIND2 = 'huma-long-assurance-public-proof-v2';
export const LONG_KIND3 = 'huma-long-assurance-public-proof-v3';
export const LONG_KIND3P = 'huma-long-assurance-public-proof-v3-passkey';
export const LONG_KINDS = [LONG_KIND, LONG_KIND2, LONG_KIND3, LONG_KIND3P];
export const PROOF_KINDS = ['huma-compact-public-proof-v1', 'huma-compact-assurance-public-proof-v4', 'huma-compact-assurance-public-proof-v5', ...LONG_KINDS, 'huma-media-public-proof-v1'];
export const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;
export const STATEMENT_FIELDS = ['version', 'contentKind', 'contentPolicy', 'contentHash', 'byteLength',
  'sessionBinding', 'captureScheme', 'captureHead', 'checkpointBinding', 'captureKeyHash', 'policyID', 'policySatisfied'];
const encoder = new TextEncoder();
export const fullMatch = (pattern, value) => typeof value === 'string' && value.match(pattern)?.[0] === value;
const hex64 = value => fullMatch(/^[a-f0-9]{64}$/, value);
export function exactKeys(value, required, optional = []) {
  if (!value || Array.isArray(value) || typeof value !== 'object' ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new Error('Unsupported evidence fields.');
}
export function boundedJSON(source, limit = MAX_DOCUMENT_BYTES) {
  if (typeof source !== 'string' || source.length > limit || encoder.encode(source).length > limit) throw new Error('Evidence exceeds its size limit.');
  return JSON.parse(source);
}
export function objectJSON(source, limit = MAX_DOCUMENT_BYTES) {
  const value = boundedJSON(source, limit);
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('Evidence must be a JSON object.');
  return value;
}
// Optional private disclosure is a transport wrapper. Only the nested proof is
// cryptographically verified here; an attached raw history is never certified.
export function writingDisclosure(source) {
  const outer=boundedJSON(source);
  if(outer?.kind!==WRITING_DISCLOSURE_KIND)return null;
  exactKeys(outer,['kind','proof'],['capturePublicKey','session']);
  const proof=objectJSON(outer.proof);
  if(!['huma-compact-assurance-public-proof-v4','huma-compact-assurance-public-proof-v5',...LONG_KINDS].includes(proof.kind))throw new Error('Unsupported disclosed proof.');
  if(!LONG_KINDS.includes(proof.kind)&&outer.proof.length>65536)throw new Error('Unsupported disclosed proof.');
  if(outer.capturePublicKey!==undefined){
    exactKeys(outer.capturePublicKey,['format','value']);
    if(outer.capturePublicKey.format!=='p256-x963-base64'||outer.capturePublicKey.value!==proof.publicKey)throw new Error('Disclosed key differs from proof.');
  }
  if(outer.session!==undefined&&(!outer.session||Array.isArray(outer.session)||typeof outer.session!=='object'))throw new Error('Invalid disclosed history.');
  return {proof:outer.proof,unverifiedDisclosures:outer.session===undefined?[]:['session']};
}
export function validateStatement(value) {
  exactKeys(value, STATEMENT_FIELDS);
  const kinds = ['text', 'image', 'audio', 'video'];
  const schemes = ['sha256-capture-v2', 'sha256-capture-v3', 'poseidon2-capture-v3', 'poseidon2-capture-v4', 'poseidon2-capture-long-v1', 'sha256-media-v1'];
  if (value.version !== 1 || !kinds.includes(value.contentKind) ||
      value.contentPolicy !== (value.contentKind === 'text' ? TEXT_POLICY : 'exact-bytes-v1') ||
      ![value.contentHash, value.sessionBinding, value.captureHead].every(hex64) ||
      !schemes.includes(value.captureScheme) || typeof value.byteLength !== 'string' ||
      !fullMatch(/^(?:0|[1-9][0-9]{0,19})$/, value.byteLength) || BigInt(value.byteLength) > 18446744073709551615n ||
      ![value.checkpointBinding, value.captureKeyHash].every(v => v === null || hex64(v)) ||
      ((value.checkpointBinding === null) !== (value.captureKeyHash === null)) ||
      !(value.policyID === null ? value.policySatisfied === null :
        fullMatch(/^[a-z0-9][a-z0-9.-]{0,95}$/, value.policyID) && typeof value.policySatisfied === 'boolean')) {
    throw new Error('Invalid evidence statement.');
  }
  return Object.fromEntries(STATEMENT_FIELDS.map(key => [key, value[key]]));
}
export function statementBytes(value) {
  const s = validateStatement(value);
  // Every value is restricted to ASCII; no platform-dependent Unicode or numeric
  // JSON canonicalization is involved. Nulls have distinct empty-string slots.
  return encoder.encode(JSON.stringify(['huma-evidence-statement-v1', '1', s.contentKind, s.contentPolicy,
    s.contentHash, s.byteLength, s.sessionBinding, s.captureScheme, s.captureHead,
    s.checkpointBinding ?? '', s.captureKeyHash ?? '', s.policyID ?? '',
    s.policySatisfied === null ? '' : String(s.policySatisfied)]));
}
export async function statementHash(value) {
  return hex(await crypto.subtle.digest('SHA-256', statementBytes(value)));
}
export function hex(bytes) { return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join(''); }
/** Base64 text as bytes. */
export const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
export function contentBytes(text) {
  if (typeof text !== 'string' || text.length > 65536) throw new Error('Invalid reader text.');
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Invalid Unicode.');
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('Invalid Unicode.');
  }
  let end = text.length;
  while (end > 0 && (text.charCodeAt(end - 1) === 32 || text.charCodeAt(end - 1) === 9)) end--;
  const bytes = encoder.encode(text.slice(0, end));
  if (bytes.length > 65536) throw new Error('Reader text exceeds its limit.');
  return bytes;
}
export function parseEnvelope(source) {
  return validateEnvelope(boundedJSON(source));
}
export function validateEnvelope(value) {
  exactKeys(value, ['kind', 'statement', 'proof', 'attachments']);
  if (value.kind !== ENVELOPE_KIND) throw new Error('Unsupported evidence envelope.');
  validateStatement(value.statement);
  objectJSON(value.proof);
  exactKeys(value.attachments, [], ['device']);
  for (const [key, attachment] of Object.entries(value.attachments)) {
    objectJSON(attachment, 256 * 1024);
  }
  return value;
}
export function encodeEnvelope(statement, proof, attachments = {}) {
  const source = JSON.stringify({ kind: ENVELOPE_KIND, statement: validateStatement(statement), proof, attachments });
  parseEnvelope(source);
  return source;
}
export function verificationDeadline(source) {
  const disclosure=writingDisclosure(source);
  const input = boundedJSON(disclosure?.proof??source);
  const proof = input?.kind === ENVELOPE_KIND ? boundedJSON(input.proof) : input;
  // Long sessions verify one proof per chunk; allow ~0.5 s each in a browser. The clock also
  // covers loading the ~3 MB proof engine, which can take most of a minute on a slow link.
  if (LONG_KINDS.includes(proof?.kind)) return 120000 + 500 * Math.min(Array.isArray(proof.chunks) ? proof.chunks.length : 0, 2048);
  return PROOF_KINDS.includes(proof?.kind) ? 20000 : 45000;
}
