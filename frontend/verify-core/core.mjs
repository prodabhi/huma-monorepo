import { ENVELOPE_KIND, LONG_KIND2, LONG_KIND3, LONG_KIND3P, LONG_KINDS, PROOF_KINDS, TEXT_POLICY, boundedJSON, exactKeys, validateStatement, statementBytes,
  statementHash, encodeEnvelope, contentBytes, fullMatch, objectJSON, validateEnvelope, hex, writingDisclosure } from './contract.mjs';

const sameStatement = (a, b) => hex(statementBytes(a)) === hex(statementBytes(b));
function validatePolicy(policy) {
  exactKeys(policy, [], ['expectedKey', 'device', 'requireSignedCapture', 'requireDevice', 'requirePolicy', 'expectedSamplingChallenge']);
  if ((policy.expectedKey !== undefined && !fullMatch(/^[a-f0-9]{64}$/, policy.expectedKey)) ||
      (policy.expectedSamplingChallenge !== undefined && !fullMatch(/^[a-f0-9]{64}$/, policy.expectedSamplingChallenge)) ||
      ['requireSignedCapture', 'requireDevice'].some(k => policy[k] !== undefined && typeof policy[k] !== 'boolean') ||
      (policy.requirePolicy !== undefined && !fullMatch(/^[a-z0-9][a-z0-9.-]{0,95}$/, policy.requirePolicy))) throw new Error('Invalid reader policy.');
  if (policy.device !== undefined) boundedJSON(JSON.stringify(policy.device), 16384);
}

function replayStatement(report) {
  const j = report.journal, behavior = j.assurance?.behavior;
  return validateStatement({ version: 1, contentKind: 'text', contentPolicy: TEXT_POLICY,
    contentHash: j.verifiedTextHash, byteLength: String(j.byteLength), sessionBinding: j.sessionIDHash,
    captureScheme: j.version === 3 ? 'sha256-capture-v3' : 'sha256-capture-v2', captureHead: j.captureHead,
    checkpointBinding: j.checkpointHash, captureKeyHash: j.captureKeyHash,
    policyID: behavior?.policyID ?? null, policySatisfied: behavior?.satisfied ?? null });
}
function fieldHex(value, width = 32) { return BigInt(value).toString(16).padStart(width * 2, '0'); }
async function compactStatement(report) {
  const v4 = report.version === 4 || report.version === 5, j = v4 ? report.journal.replay : report.journal;
  const prefix = new TextEncoder().encode(v4 ? 'huma-compact-session-binding-v4\0' : 'huma-compact-session-binding-v3\0');
  const nonce = Uint8Array.from((fieldHex(j.session_nonce[0], 16) + fieldHex(j.session_nonce[1], 16)).match(/../g), x => parseInt(x, 16));
  const bytes = new Uint8Array(prefix.length + nonce.length); bytes.set(prefix); bytes.set(nonce, prefix.length);
  return validateStatement({ version: 1, contentKind: 'text', contentPolicy: TEXT_POLICY,
    contentHash: hex(j.text_hash), byteLength: String(j.byte_length),
    sessionBinding: hex(await crypto.subtle.digest('SHA-256', bytes)), captureScheme: v4 ? 'poseidon2-capture-v4' : 'poseidon2-capture-v3',
    captureHead: fieldHex(v4 ? report.journal.bound_root : j.capture_root),
    checkpointBinding: fieldHex(v4 ? report.journal.checkpoint_roots.at(-1) : j.checkpoint_roots.at(-1)), captureKeyHash: report.keyHash,
    policyID: v4 ? 'huma-writing-rules-v1' : null, policySatisfied: v4 ? report.journal.policy_satisfied : null });
}
function longStatement(report) {
  const j = report.journal;
  return validateStatement({ version: 1, contentKind: 'text', contentPolicy: TEXT_POLICY,
    contentHash: report.contentHash, byteLength: String(j.canonical_bytes), sessionBinding: report.sessionBinding,
    captureScheme: 'poseidon2-capture-long-v1', captureHead: fieldHex(j.bound_root), checkpointBinding: report.checkpointBinding,
    captureKeyHash: report.keyHash, policyID: 'huma-writing-rules-v1', policySatisfied: j.policy_satisfied });
}
async function mediaStatement(report) {
  const j = report.journal, domain = new TextEncoder().encode('huma-media-session-binding-v1\0');
  const bytes = new Uint8Array(domain.length + 32); bytes.set(domain); bytes.set(j.nonce, domain.length);
  return validateStatement({ version: 1, contentKind: ['', 'image', 'audio', 'video'][j.kind], contentPolicy: 'exact-bytes-v1',
    contentHash: hex(j.encoded_hash), byteLength: j.encoded_length, sessionBinding: hex(await crypto.subtle.digest('SHA-256', bytes)),
    captureScheme: 'sha256-media-v1', captureHead: hex(j.capture_head), checkpointBinding: hex(j.sealed_root),
    captureKeyHash: report.keyHash, policyID: null, policySatisfied: null });
}

// Internal composition point. Shipped entry points supply fixed, pinned crypto
// adapters; producers can supply evidence, never a verifier or trust roots.
export function createEvidenceVerifier({ verifyReplay, verifyCompact, verifyAssurance, verifyLong, verifyMedia, verifyDevice, devicePolicy, publicReplay }) {
  async function verify(source, policy = {}, expectedContent, externalAttachments = {}) {
    const facts = [], missing = [], failures = [];
    const result = { verified: false, facts, missing, failures };
    const fact = (id, method, value) => facts.push({ id, method, value });
    let phase = 'input';
    try {
      validatePolicy(policy);
      const disclosed=writingDisclosure(source);
      if(disclosed){source=disclosed.proof;result.unverifiedDisclosures=disclosed.unverifiedDisclosures;}
      const parsed = boundedJSON(source);
      let proof = source, claimed;
      let attachments = {};
      if (parsed?.kind === ENVELOPE_KIND) {
        validateEnvelope(parsed);
        claimed = validateStatement(parsed.statement); proof = parsed.proof;
        attachments = parsed.attachments;
      }
      exactKeys(externalAttachments, [], ['device']);
      for (const [key, value] of Object.entries(externalAttachments)) {
        if (Object.hasOwn(attachments, key)) throw new Error('Duplicate evidence attachment.');
        objectJSON(value, 256 * 1024);
      }
      attachments = { ...attachments, ...externalAttachments };
      phase = 'proof';
      const input = boundedJSON(proof);
      const long = LONG_KINDS.includes(input?.kind);
      const assurance = long || ['huma-compact-assurance-public-proof-v4','huma-compact-assurance-public-proof-v5'].includes(input?.kind);
      const compact = assurance || input?.kind === 'huma-compact-public-proof-v1';
      const media = input?.kind === 'huma-media-public-proof-v1';
      if (!compact && !media && input?.kind !== undefined) throw new Error('Unsupported evidence format.');
      if (!compact && !media && input?.bundle?.system !== 'risc0-3.0.6') throw new Error('Unsupported proof.');
      // Readers supply the actual displayed text or exact encoded master bytes.
      // Embedded content never substitutes for the item being checked.
      let expectedBytes;
      if (media) {
        if (!(expectedContent instanceof Uint8Array) || expectedContent.length < 1 || expectedContent.length > 32 * 1024 * 1024) throw new Error('Expected master is required.');
        expectedBytes = expectedContent;
      } else {
        if (policy.expectedSamplingChallenge !== undefined) throw new Error('Sampling challenge requires media evidence.');
        expectedBytes = contentBytes(expectedContent);
      }
      const report = media ? await verifyMedia(proof, { master: expectedContent, ...(policy.expectedKey ? { expectedKey: policy.expectedKey } : {}),
        ...(policy.expectedSamplingChallenge ? { expectedChallenge: policy.expectedSamplingChallenge } : {}) })
        : compact ? await (long ? verifyLong : assurance ? verifyAssurance : verifyCompact)(proof, { text: expectedContent, ...(policy.expectedKey ? { expectedKey: policy.expectedKey } : {}) })
        : await verifyReplay(proof, expectedContent, policy.expectedKey);
      if (report?.verified !== true) throw new Error('Proof rejected.');
      phase = 'statement';
      result.statement = media ? await mediaStatement(report) : long ? longStatement(report) : compact ? await compactStatement(report) : replayStatement(report);
      const candidates = [expectedBytes];
      if (Object.hasOwn(input, 'text')) candidates.push(contentBytes(input.text));
      for (const bytes of candidates) {
        if (String(bytes.length) !== result.statement.byteLength || hex(await crypto.subtle.digest('SHA-256', bytes)) !== result.statement.contentHash) throw new Error('Content differs from proof.');
      }
      if (claimed && !sameStatement(claimed, result.statement)) throw new Error('Statement differs from proof.');
      result.statementHash = await statementHash(result.statement);
      result.proofReport = report;
      fact('content', media ? 'signed-master-hash' : 'zk-replay', { kind: result.statement.contentKind, policy: result.statement.contentPolicy, hash: result.statement.contentHash });
      if (media) {
        fact('sample-membership', 'noir-composite', { proofIdentity: report.proofIdentity, sampledOpenings: report.sampledOpenings,
          uniqueSampledLeaves: report.uniqueSampledLeaves, samplingMethod: report.samplingMethod, totalLeaves: report.totalLeaves, experimental: true });
        fact('signed-media-seal', 'p256-outside-zk', { keyHash: report.keyHash });
        missing.push('decoding', 'scene-policy', 'capture-chain', 'sampling-freshness');
      } else fact('replay', long ? (input.kind === LONG_KIND2 ? 'noir-folded-chain' : [LONG_KIND3, LONG_KIND3P].includes(input.kind) ? 'noir-part-chain' : 'noir-chunk-chain') : compact ? 'noir-composite' : 'risc0', { proofIdentity: report.proofIdentity, experimental: compact });
      const signed = media ? false : compact ? report.signaturesVerified > 0 : report.journal.signedCheckpointCount > 0;
      if (signed) fact('signed-capture', compact ? 'p256-outside-zk' : 'p256-inside-zk', { keyHash: result.statement.captureKeyHash });
      else missing.push('signed-capture');
      if (result.statement.policyID) fact('behavior', 'zk-policy', { policyID: result.statement.policyID, satisfied: result.statement.policySatisfied, experimental: true });
      else missing.push('behavior');
      if (assurance) {
        const j = report.journal;
        fact('input-origin', 'zk-reported-os-fields', { present: j.origin_present, hidState: j.origin_hid, samples: long ? j.samples : j.replay.samples });
        fact('presence', 'zk-and-p256', { count: j.presence_count, approved: j.approved, onTime: j.on_time, missed: j.missed,
          medianResponseMilliseconds: j.median_response, longestGapMilliseconds: j.longest_gap });
        // v3-passkey: the reader checked one passkey's WebAuthn assertion over each approved check-in's root.
        if (long && input.kind === LONG_KIND3P) {
          if (report.passkeyVerified !== true || !fullMatch(/^[a-f0-9]{64}$/, report.passkeyKeyHash)) throw new Error('Passkey check-ins rejected.');
          fact('presence-passkey', 'webauthn-p256-outside-zk', { count: j.approved, keyHash: report.passkeyKeyHash });
        }
      }
      // Experimental profiles have no device binding adapter yet; reject attachments.
      phase = 'attachments';
      if ((compact || media) && Object.keys(attachments).length) throw new Error('Attachments unsupported for this profile.');
      if (Object.hasOwn(attachments, 'device')) {
        if (!policy.device) throw new Error('Reader device policy required.');
        phase = 'device';
        report.deviceEvidence = await verifyDevice(boundedJSON(attachments.device, 256 * 1024), report, devicePolicy(policy.device));
        if (report.deviceEvidence?.verified !== true) throw new Error('Device evidence rejected.');
        report.checks.hardwareAttestation = 'apple-app-attest-historical-enrollment-and-bound-assertion';
        fact('device', 'apple-app-attest', report.deviceEvidence);
      } else missing.push('device');
      missing.push('witness', 'external-time');
      phase = 'requirements';
      for (const [required, id] of [[policy.requireSignedCapture, 'signed-capture'], [policy.requireDevice || policy.device !== undefined, 'device']]) {
        if (required && missing.includes(id)) failures.push({ code: 'required-evidence-missing', evidence: id });
      }
      if (policy.requirePolicy && (result.statement.policyID !== policy.requirePolicy || result.statement.policySatisfied !== true)) failures.push({ code: 'required-policy-not-satisfied', evidence: 'behavior' });
      result.verified = failures.length === 0;
    } catch {
      // Do not copy proof bytes, private history or producer strings into errors.
      failures.push({ code: 'evidence-rejected', evidence: phase });
    }
    return result;
  }
  async function envelope(source, policy, expectedContent, attachments = {}) {
    source=writingDisclosure(source)?.proof??source;
    const base = boundedJSON(source);
    if (base?.kind === ENVELOPE_KIND) throw new Error('Wrap a proof export, not another envelope.');
    if (base?.kind !== undefined && !PROOF_KINDS.includes(base.kind)) throw new Error('Unsupported proof export.');
    // Publication uses the typed public projection before considering optional
    // private disclosures. A polluted draft export never becomes public history.
    const proof = PROOF_KINDS.includes(base?.kind) ? source : await publicReplay(source);
    const preliminary = await verify(proof, {}, expectedContent);
    if (!preliminary.verified) throw new Error('Proof export did not verify.');
    const output = encodeEnvelope(preliminary.statement, proof, attachments);
    const report = await verify(output, policy, expectedContent);
    if (!report.verified) throw new Error('Evidence envelope did not verify.');
    return { envelope: output, report };
  }
  return { verify, envelope };
}
