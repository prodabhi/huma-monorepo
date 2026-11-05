import { engine } from './verify-core/node-engine.mjs';
import { randomBytes } from 'node:crypto';
import { ENVELOPE_KIND, LONG_KIND, boundedJSON, exactKeys, validateEnvelope, statementHash } from './verify-core/contract.mjs';
import { MASTER_LIMIT, PROOF_LIMIT, UPLOAD_LIMIT, REPLAY_LIMIT, digest, validateManifest, expectedMaster, replayRhythm } from './publication-contract.mjs';
import { verifyReplay } from './replay-core.mjs';

try {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length; if (size > UPLOAD_LIMIT) throw new Error(); chunks.push(chunk);
  }
  const upload = boundedJSON(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), UPLOAD_LIMIT);
  exactKeys(upload, Object.hasOwn(upload, 'replay') ? ['kind', 'master', 'proof', 'access', 'replay'] : ['kind', 'master', 'proof', 'access']);
  exactKeys(upload.master, ['base64', 'mediaType']);
  if (upload.kind !== 'huma-publication-upload-v1' || !['public', 'link'].includes(upload.access) ||
      typeof upload.master.base64 !== 'string' || typeof upload.proof !== 'string' || Buffer.byteLength(upload.proof) > PROOF_LIMIT) throw new Error();
  const master = Buffer.from(upload.master.base64, 'base64');
  if (!master.length || master.length > MASTER_LIMIT || master.toString('base64') !== upload.master.base64) throw new Error();
  const outer = boundedJSON(upload.proof, PROOF_LIMIT);
  const wrapped = outer.kind === ENVELOPE_KIND;
  if (wrapped) {
    validateEnvelope(outer);
    if (Object.keys(outer.attachments).length) throw new Error('Private/optional disclosures are not published.');
  }
  const contentKind = wrapped ? outer.statement.contentKind
    : outer.kind === 'huma-media-public-proof-v1' ? ['', 'image', 'audio', 'video'][outer.kindID] : 'text';
  // A raw media export's kind is encoded in public inputs. Its verifier checks
  // the exact master; the derived statement below determines the actual kind.
  const media = outer.kind === 'huma-media-public-proof-v1' || (wrapped && contentKind !== 'text');
  // A first-format long page doesn't tie its signing key to the recording (anyone can re-sign it), so it isn't shared.
  const page = wrapped ? boundedJSON(outer.proof, PROOF_LIMIT) : outer;
  if (page.kind === LONG_KIND) throw new Error();
  const content = media ? master : new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(master);
  const normalized = await engine.envelope(wrapped ? outer.proof : upload.proof, {}, content);
  if (wrapped && await statementHash(outer.statement) !== normalized.report.statementHash) throw new Error();
  const proof = Buffer.from(normalized.envelope);
  const manifest = validateManifest({ kind: 'huma-publication-v1', publicationNonce: randomBytes(32).toString('hex'), access: upload.access,
    master: { hash: await digest(master), byteLength: master.length, mediaType: upload.master.mediaType },
    proof: { hash: await digest(proof), byteLength: proof.length }, statement: normalized.report.statement,
    statementHash: normalized.report.statementHash });
  // This call also checks UTF-8 handling for the exact downloaded representation.
  expectedMaster(manifest, master);
  // A replay must rebuild this exact text and carry the Mac signature of the page proof's capture key.
  let replay, checked;
  if (Object.hasOwn(upload, 'replay')) {
    if (media || typeof upload.replay !== 'string' || Buffer.byteLength(upload.replay) > REPLAY_LIMIT) throw new Error();
    if (typeof page.publicKey !== 'string') throw new Error();
    checked = await verifyReplay(upload.replay, { publicKey: page.publicKey, text: content });
    replay = upload.replay;
  }
  // What the page's score is worked out from (humaScore, as a reader does in verify.mjs): a page proof's verified
  // journal, whether its writer's passkey approved its check-ins, and the composition of the replay just checked.
  const report = normalized.report.proofReport, j = report?.journal;
  const scoring = normalized.report.statement.captureScheme === 'poseidon2-capture-long-v1' && j ? { journal: { rules: j.rules, typing: j.typing,
    edits: j.edits, presence_count: j.presence_count, on_time: j.on_time, origin_present: j.origin_present,
    // A browser page's session nonce and claimed writing time, checked against when this server issued it (sessions.mjs).
    nonce: j.nonce, elapsed: j.elapsed, start_unix: j.start_unix, end_unix: j.end_unix }, passkey: report.passkeyVerified === true,
    composition: checked?.composition ?? null, rhythmAutomated: checked ? replayRhythm(checked.frames).automated : false } : null;
  process.stdout.write(JSON.stringify({ manifest, proof: normalized.envelope, ...(replay ? { replay } : {}), scoring }), () => process.exit(0));
} catch { process.exit(1); }
