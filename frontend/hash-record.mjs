// The signed hash record of a shared page: what Huma anchors publicly (arkiv-store.mjs, anchor) in place of the page.
// It holds hashes only, never the text or the proof, plus the writer's signature from publishing (publicationMessage,
// which commits to the statement and the text hash). `id` is the hash of the page's manifest, which names the proof's
// hash, so a reader holding the manifest can tie all three together; whoever holds the text and the proof checks them
// against the hashes here and re-verifies the proof themselves.
import { createHash } from 'node:crypto';
import { verifyMessage, getAddress } from 'viem';
import { publicationMessage } from './publication-contract.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const isHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const attestationKey = id => 'attestations/' + id;
export const ATTESTATION_KEY = /^attestations\/[a-f0-9]{64}$/;

/** The record for a published page: `manifestSource` is the manifest's exact JSON (its hash is the page's id), `signed`
 *  what publishing kept of the writer's signature ({ wallet, message, signature } or, from a Mac, { wallet, message,
 *  device: { publicKey, signature } }), `at` when it was shared (ms). null when the page wasn't signed. */
export function hashRecord(manifestSource, signed, at) {
  if (!signed) return null;
  const manifest = JSON.parse(manifestSource);
  return { version: 1, id: sha256(manifestSource), textHash: manifest.master.hash, proofHash: manifest.proof.hash,
    wallet: signed.wallet, message: signed.message, ...(signed.device ? { device: { publicKey: signed.device.publicKey, signature: signed.device.signature } } : { signature: signed.signature }), at };
}

/** Checks a record against the page's manifest JSON and returns { ok, signature, problems }. `signature` is 'wallet' when
 *  the wallet's signature was verified here, 'device' for a Mac's P-256 key (checked by publications.mjs when it was shared,
 *  not again here) or 'none'. A record whose hashes or message don't match the manifest is never ok. */
export async function checkHashRecord(record, manifestSource) {
  const problems = [];
  if (!record || record.version !== 1) return { ok: false, signature: 'none', problems: ['Unknown record version.'] };
  if (!isHash(record.id) || sha256(manifestSource) !== record.id) problems.push('The record is for a different manifest.');
  let manifest = null;
  try { manifest = JSON.parse(manifestSource); } catch { problems.push('The manifest is not valid.'); }
  if (manifest) {
    if (record.textHash !== manifest.master?.hash) problems.push('The text hash does not match the manifest.');
    if (record.proofHash !== manifest.proof?.hash) problems.push('The proof hash does not match the manifest.');
    if (record.message !== publicationMessage(manifest)) problems.push('The signed message does not match the manifest.');
  }
  let signature = 'none';
  if (record.device) signature = 'device';
  else if (typeof record.wallet === 'string' && typeof record.signature === 'string') {
    let valid = false;
    try { valid = await verifyMessage({ address: getAddress(record.wallet), message: record.message, signature: record.signature }); } catch {}
    if (valid) signature = 'wallet'; else problems.push('The wallet signature does not match.');
  } else problems.push('The record is not signed.');
  return { ok: problems.length === 0, signature, problems };
}

/** The bytes anchored for a record: stable JSON, so the same record always stores the same bytes. */
export const recordBytes = record => Buffer.from(JSON.stringify(record));
