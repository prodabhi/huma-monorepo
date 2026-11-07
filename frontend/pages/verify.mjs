import { verify as verifyEvidence, prepare as prepareVerifier } from '/verify-core/browser.mjs';
import { parseEnvelope, boundedJSON, writingDisclosure } from '/verify-core/contract.mjs';
import { checkDownloadedPublication, expectedMaster, unmetWritingRules, humaScore, replayRhythm, scoreLine, percentLabel, duration, writtenInBrowser, checkTier, passkeyRow, WRITING_RULES, MASTER_LIMIT, PROOF_LIMIT, HANDLE } from '/publication-contract.mjs';
const text = document.querySelector('#text');
const result = document.querySelector('#result');
const reportElement = document.querySelector('#report');
const expectedKey = document.querySelector('#expectedKey');
const verifyButton = document.querySelector('#verify');
const checkDevice = document.querySelector('#checkDevice');
const deviceJSON = document.querySelector('#deviceJSON');
const policyJSON = document.querySelector('#policyJSON');
const proofInput = document.querySelector('#proof');
const dropZone = document.querySelector('#dropZone');
let replayDocument;
let compactDocument;
let evidenceDocument;
let publicationManifest;
let publicationMaster;
let inputRevision = 0;
// The share menu's icons (shareMenu).
const ICONS = {
    share: '<path d="M8 10V2.5M5 5.5 8 2.5l3 3M3.5 8.5v4a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1v-4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
    link: '<path d="M6.5 9.5l3-3M7 4.5l1-1a2.8 2.8 0 0 1 4 4l-1 1M9 11.5l-1 1a2.8 2.8 0 0 1-4-4l1-1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    x: '<path d="M12.2 1.5h2.2L9.6 7l5.6 7.5h-4.4L7.4 10l-3.9 4.5H1.3l5.1-5.9L1 1.5h4.5l3.1 4.1z" fill="currentColor"/>',
    linkedin: '<path d="M2 3.5a1.5 1.5 0 1 1 3 0 1.5 1.5 0 0 1-3 0zM2.2 6h2.6v8H2.2zM6.5 6H9v1.1c.4-.7 1.3-1.3 2.6-1.3 2.4 0 2.9 1.6 2.9 3.6V14h-2.6v-4c0-1-.1-2.2-1.4-2.2s-1.6 1-1.6 2.1V14H6.5z" fill="currentColor"/>',
    whatsapp: '<path d="M8 1.8a6.2 6.2 0 0 0-5.3 9.4l-.9 3 3.1-.9A6.2 6.2 0 1 0 8 1.8z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M6 5.2c.2 1.9 1.6 3.8 3.9 4.8l.9-.9-1.2-.7-.6.5c-.8-.4-1.4-1-1.8-1.8l.5-.6-.7-1.2z" fill="currentColor"/>',
    telegram: '<path d="M14.6 2.1 1.6 7.2c-.6.2-.6 1.1.1 1.3l3.2 1 1.2 3.9c.2.5.8.7 1.2.3l1.8-1.7 3.3 2.4c.5.3 1.1.1 1.2-.5l2.1-10.9c.1-.6-.5-1.1-1.1-.9zM6.3 9.7l5.9-4.3-4.7 5.2-.3 2.3z" fill="currentColor"/>',
    mail: '<path d="M2 4h12v8.5H2zM2.5 4.5 8 9l5.5-4.5" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
    more: '<path d="M4 8h.01M8 8h.01M12 8h.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
    download: '<path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
};
const glyph = name => `<svg viewBox="0 0 16 16" aria-hidden="true">${ICONS[name]}</svg>`;
function showProof(title, detail) {
    dropZone.classList.toggle('loaded', title !== undefined);
    document.querySelector('#proofTitle').textContent = title ?? 'Drop a proof file or report';
    document.querySelector('#proofName').textContent = detail ?? 'or click to choose';
}
function clearReport(message) {
    inputRevision++; reportElement.hidden = true; reportElement.replaceChildren();
    result.dataset.state = ''; result.textContent = message;
}
function fact(list, title, value, code = false) {
    const row = document.createElement('div'); row.className = 'fact';
    const term = document.createElement('dt'); term.textContent = title;
    const detail = document.createElement('dd');
    const content = code ? document.createElement('code') : document.createElement('span');
    content.textContent = value; detail.append(content); row.append(term, detail); list.append(row);
}
function section(title) {
    const heading = document.createElement('h2'); heading.textContent = title;
    const list = document.createElement('dl'); reportElement.append(heading, list); return list;
}
function elapsed(value) {
    const milliseconds = BigInt(value); return `${milliseconds / 1000n}.${String(milliseconds % 1000n).padStart(3, '0')} seconds`;
}
function renderCompact(report) {
    reportElement.replaceChildren(); reportElement.hidden = false;
    const assurance = report.version === 4 || report.version === 5, journal = assurance ? report.journal.replay : report.journal;
    let list = section('Experimental compact session');
    fact(list, 'Profile', `${report.profile} · experimental`);
    fact(list, 'Proof identifier', report.proofIdentity, true);
    fact(list, 'Text', 'Matches · only final ASCII spaces and tabs ignored');
    fact(list, 'Edit replay', `${journal.edits} edits produce the committed text`);
    fact(list, 'Checkpoint signatures', `${report.signaturesVerified} P-256 signatures checked alongside the ZK proof`);
    fact(list, 'Signing-key fingerprint', report.keyHash, true);
    fact(list, 'Public key', 'Disclosed in this format');
    list = section('Recorded session details');
    fact(list, 'Initial text', journal.initial_bytes ? `${journal.initial_bytes} imported UTF-8 bytes` : 'Empty starting page');
    fact(list, 'Capture', `${journal.samples} key samples · ${journal.paste} edits labelled paste`);
    fact(list, 'Device-reported start', new Date(Number(journal.start_unix)).toISOString());
    fact(list, 'Device-reported end', new Date(Number(journal.end_unix)).toISOString());
    fact(list, 'Recorded elapsed time', elapsed(journal.elapsed));
    fact(list, 'Clock consistency', journal.clock_back ? 'Wall clock moved backwards' : 'No recorded backwards wall-clock change');
    if (assurance) {
        const j = report.journal;
        list = section('Writing evidence checked by the proof');
        fact(list, 'Writing policy', `huma-writing-rules-v1 · ${j.policy_satisfied ? 'all rules met' : 'some rules not met'} · experimental`);
        fact(list, 'Input provenance', `${j.origin_hid} samples report HID system state · ${j.origin_present} with origin metadata`);
        fact(list, 'Signed presence responses', `${j.on_time} of ${j.presence_count} answered within 10 seconds · ${j.missed} missed or late`);
        fact(list, 'Response signatures', `${report.presenceSignaturesVerified} P-256 signatures checked alongside the ZK proof`);
        fact(list, 'Longest recorded presence gap', elapsed(j.longest_gap));
        fact(list, 'Median approved response', elapsed(j.median_response));
        fact(list, 'Source interpretation', 'OS-reported fields; biometric gating needs trusted app/device evidence');
    }
    list = section('Evidence limits');
    fact(list, 'Trusted calendar time', 'Not established; these are signed device-reported readings');
    fact(list, 'Hardware evidence', 'Not supported for this experimental format yet');
    fact(list, 'Human authorship', 'Not established');
}
/** The folded long-page proof (one proof per page): what it shows, in plain words, then the details. */
// Page proofs readers check: v3 (made now, with or without the passkey check) and v2 (pages shared with 0.1).
const PAGE_PROOFS = ['huma-long-assurance-public-proof-v3-passkey', 'huma-long-assurance-public-proof-v3', 'huma-long-assurance-public-proof-v2'];
/** The page inside an evidence envelope when it's a page proof, else null. */
function pageProof(source) {
    try { const outer = JSON.parse(source), inner = typeof outer.proof === 'string' ? JSON.parse(outer.proof) : outer; return PAGE_PROOFS.includes(inner?.kind) ? inner : null; }
    catch { return null; }
}
/** True while a proof is shown as its page (a shared link, or a proof or report dropped here). */
let presenting = false;
let pageJournal, pageUnmet = [], pageBrowser = false, pagePasskey = false;
/** What the page's report says (downloadReport), gathered as the page is checked; null on the verification tool. */
let printable = null;
function renderLong(report) {
    reportElement.replaceChildren(); reportElement.hidden = false;
    const j = report.journal; pageJournal = j; pageBrowser = writtenInBrowser(j);
    // Every approved check-in also approved by the writer's passkey (checked by the reader, outside the proof).
    pagePasskey = pageBrowser && report.passkeyVerified === true;
    let list = section('What the proof shows');
    fact(list, 'Text', "Matches the proof's final text · only final spaces and tabs ignored");
    fact(list, 'Typing', `${j.samples} key presses · ${j.edits} edits · ${j.paste} pasted`);
    if (Number(j.initial_bytes)) fact(list, 'Imported text', `${j.initial_bytes} bytes were there before typing started`);
    fact(list, 'Presence checks', `${j.on_time} of ${j.presence_count} answered on time`);
    const unmet = WRITING_RULES.filter((_, i) => j.rules?.[i] === false);
    fact(list, 'Writing rules', j.policy_satisfied ? 'All met' : 'Not met: ' + (unmet.length ? unmet.join(', ') : 'see the proof'));
    fact(list, 'Time writing', elapsed(j.elapsed));
    const browser = writtenInBrowser(j);
    fact(list, 'Written in', checkTier(browser, pagePasskey).label);
    fact(list, 'Written (writer’s clock)', new Date(Number(j.start_unix)).toLocaleString());
    list = section('Details');
    fact(list, 'Proof identifier', report.proofIdentity, true);
    fact(list, 'Signing-key fingerprint', report.keyHash, true);
    fact(list, 'Signatures', `${report.signaturesVerified} checkpoint and ${report.presenceSignaturesVerified} presence signatures checked`);
    fact(list, 'Page size', `Up to ${j.text_capacity.toLocaleString()} characters`);
    fact(list, 'Longest gap between checks', elapsed(j.longest_gap));
    fact(list, 'Clock', j.clock_back ? 'The Mac clock moved backwards' : 'No backwards clock change');
}
function renderReplay(report) {
    reportElement.replaceChildren(); reportElement.hidden = false;
    const journal = report.journal, checks = report.checks;
    let list = section('Verified by the proof');
    fact(list, 'Proof identifier', report.proofIdentity, true);
    fact(list, 'Text', 'Matches · trailing ASCII spaces and tabs at the end ignored');
    fact(list, 'Edit replay', `${journal.editCount} edits produce the committed text`);
    fact(list, 'Checkpoint signatures', journal.signedCheckpointCount ? `${journal.signedCheckpointCount} valid P-256 signatures` : 'Unsigned capture');
    fact(list, 'Signing-key fingerprint', journal.captureKeyHash || 'No signed key', true);
    fact(list, 'Expected key', checks.expectedKey === true ? 'Matches the fingerprint you supplied' : 'No expected fingerprint supplied');
    fact(list, 'Revealed public key', checks.revealedKey === true ? 'Matches the proved signing key' : 'Not revealed');
    fact(list, 'Revealed history', checks.revealedHistory === true ? 'Independently replayed; matches the proof' : 'Kept private');
    list = section('Recorded session details');
    fact(list, 'Initial text', journal.initialByteLength ? `${journal.initialByteLength} imported UTF-8 bytes` : 'Empty starting page');
    fact(list, 'Capture', `${journal.boundInputSamples} key samples · ${journal.pasteEditCount} ${journal.pasteEditCount === 1 ? 'edit' : 'edits'} labelled paste`);
    if (report.reportedTime) {
        const time = report.reportedTime;
        fact(list, 'Device-reported start', new Date(Number(time.startUnixMilliseconds)).toISOString());
        fact(list, 'Device-reported end', new Date(Number(time.endUnixMilliseconds)).toISOString());
        fact(list, 'Recorded elapsed time', elapsed(time.elapsedMilliseconds));
        fact(list, 'Clock consistency', time.clockMovedBackwards ? 'Wall clock moved backwards' : 'No recorded backwards wall-clock change');
    } else fact(list, 'Time window', 'No signed time fields in this session');
    if (journal.assurance) {
        const { input, presence, behavior } = journal.assurance;
        list = section('Writing evidence');
        fact(list, 'Input provenance', `${input.hidStateReported} samples report HID system state · ${input.otherStateReported} other state · ${input.missingOrigin} without origin metadata`);
        fact(list, 'Source interpretation', 'OS-reported fields; physical input classification is under evaluation');
        if (presence) {
            fact(list, 'Signed presence responses', `${presence.onTime} of ${presence.challenges} answered within 10 seconds · ${presence.missed} missed or late`);
            fact(list, 'Longest recorded presence gap', elapsed(presence.longestGapMilliseconds));
            if (presence.medianResponseMilliseconds !== null) fact(list, 'Median approved response', elapsed(presence.medianResponseMilliseconds));
            fact(list, 'Challenge schedule', 'Generated locally; timing and randomness are not independently attested');
            fact(list, 'Biometric binding', 'Response signatures checked; biometric gating needs trusted app/device evidence');
        } else fact(list, 'Presence challenges', 'Absent');
        fact(list, 'Writing policy', `${behavior.policyID} · ${behavior.satisfied ? 'all rules met' : 'some rules not met'} · experimental`);
        fact(list, 'Policy checks', Object.entries(behavior.rules).map(([name, passed]) => `${name}: ${passed ? 'met' : 'not met'}`).join(' · '));
        fact(list, 'Scope', 'This does not prove that the person composed every word.');
    }
    list = section('Separate evidence');
    fact(list, 'Trusted calendar time', 'Not established; signatures bind app-reported readings');
    fact(list, 'Hardware attestation', report.deviceEvidence?.verified ? 'Apple enrollment and bound assertion checked' : 'Not checked by this receipt');
    fact(list, 'Human authorship', 'Not established');
    if (report.deviceEvidence?.verified) {
        const device = report.deviceEvidence;
        list = section('Apple device evidence');
        fact(list, 'App identity', device.appID, true);
        fact(list, 'Environment', device.environment);
        fact(list, 'Enrollment key', device.appAttestKeyID, true);
        fact(list, 'Apple enrollment time', device.appleReportedEnrollmentTime + ' · not the typing time');
        fact(list, 'Assertion counter', String(device.assertionCounter));
        fact(list, 'Mac security policy', 'SIP and Full Security checked at enrollment');
        fact(list, 'Capture-key association', 'Bound by the attested app to this replay statement');
        fact(list, 'Freshness and revocation', 'Fresh nonce, global counter reuse and current certificate revocation are not established offline');
    }


}
function checkReplay(raw) {
    return new Promise((resolve, reject) => {
        const worker = new Worker('/replay-worker.js', { type: 'module' });
        const close = () => { clearTimeout(timer); worker.terminate(); };
        const timer = setTimeout(() => { close(); reject(new Error('Replay verification reached its local time limit.')); }, 45000);
        worker.onerror = () => { close(); reject(new Error('The local replay verifier could not load.')); };
        worker.onmessage = ({ data }) => { close(); data.ok ? resolve(data.report) : reject(new Error(data.error)); };
        worker.postMessage({ document: replayDocument, text: raw, expectedKey: expectedKey.value.trim().toLowerCase(),
            ...(checkDevice.checked ? { deviceEvidence: deviceJSON.value, devicePolicy: policyJSON.value } : {}) });
    });
}
let bundle;
let originalText;
/** A writing replay that came inside a dropped report, checked once the page proof verifies. */
let localReplay = null, localFile = null;
let changed = false;
async function check() {
    const revision = inputRevision;
    result.textContent = 'Checking locally…'; result.dataset.state = ''; reportElement.hidden = true; verifyButton.disabled = true;
    try {
        const raw = changed ? text.value : originalText ?? text.value;
        if (evidenceDocument) {
            const policy = {}, attachments = {};
            // A first-format long proof doesn't tie its signing key to the recording, so anyone could re-sign it.
            const inner = (() => { try { const outer = JSON.parse(evidenceDocument); return typeof outer.proof === 'string' ? JSON.parse(outer.proof) : outer; } catch { return null; } })();
            if (inner?.kind === 'huma-long-assurance-public-proof-v1') throw new Error('This proof is in an older format that Huma no longer verifies.');
            // A page proof always needs its signed capture, and its writing rules always count, however it arrived.
            // A page shown as a page (shared, or dropped here) must be one; older formats prove less.
            const page = pageProof(evidenceDocument);
            if (!page && (presenting || publicationManifest?.statement.contentKind === 'text')) throw new Error('This page was shared in an older format that Huma no longer verifies.');
            if (page) policy.requireSignedCapture = true;
            const key = expectedKey.value.trim().toLowerCase();
            if (key) policy.expectedKey = key;
            if (checkDevice.checked) {
                policy.device = boundedJSON(policyJSON.value, 16384); policy.requireDevice = true;
                if (deviceJSON.value.trim()) attachments.device = deviceJSON.value;
            }
            const content = publicationManifest?.statement.contentKind !== 'text' && publicationMaster ? publicationMaster : raw;
            const report = await verifyEvidence(evidenceDocument, policy, content, { attachments });
            if (revision !== inputRevision) return;
            if (!report.verified) throw new Error('Evidence did not verify. Check the text and selected device policy.');
            if (publicationManifest && report.statementHash !== publicationManifest.statementHash) throw new Error('The proof and master manifest disagree.');
            if (publicationManifest?.statement.contentKind && publicationManifest.statement.contentKind !== 'text') {
                result.textContent = 'Master and proof verified locally. The downloaded bytes match their signed evidence.';
                result.dataset.state = 'valid'; reportElement.replaceChildren(); reportElement.hidden = false;
                const list = section('Verified master');
                fact(list, 'Content', publicationManifest.statement.contentKind);
                fact(list, 'Master SHA-256', publicationManifest.master.hash, true);
                fact(list, 'Proof statement', report.statementHash, true);
                fact(list, 'Evidence scope', 'Experimental signed master and sample membership; sensor capture and decoding are not proved.');
                return;
            }
            const scheme = report.statement.captureScheme;
            const render = () => scheme === 'poseidon2-capture-long-v1' ? renderLong(report.proofReport)
                : ['poseidon2-capture-v3', 'poseidon2-capture-v4'].includes(scheme) ? renderCompact(report.proofReport) : renderReplay(report.proofReport);
            // A page that misses a writing rule (some text pasted, say) still checks out; it just doesn't read as all typed.
            pageUnmet = page ? unmetWritingRules(page.finalInputs) : [];
            if (pageUnmet.length) {
                result.textContent = partialSummary(pageUnmet);
                result.dataset.state = 'partial'; render(); return true;
            }
            result.textContent = publicationManifest ? "Verified. This matches a signed Huma writing record, and it hasn't changed since."
                : 'Evidence verified. This text matches its recorded session.';
            result.dataset.state = 'valid'; render();
            return true;
        }
        if (compactDocument) {
            if (checkDevice.checked) throw new Error('The experimental compact format does not support device attachments yet.');
            const { verifyCompactProof } = await import('/compact/compact-verifier.js');
            const key = expectedKey.value.trim().toLowerCase();
            const report = await verifyCompactProof(compactDocument, { text: raw, ...(key ? { expectedKey: key } : {}) });
            if (revision !== inputRevision) return;
            result.textContent = 'Experimental proof verified. This text matches the signed compact session.';
            result.dataset.state = 'valid'; renderCompact(report); return;
        }
        if (bundle?.system !== 'risc0-3.0.6' || !replayDocument) throw new Error('Add a Huma proof file first.');
        const report = await checkReplay(raw);
        if (revision !== inputRevision) return;
        result.textContent = report.checks.checkpointSignatures ? 'Verified. This text matches its signed writing session.' : 'Edits replay correctly, but the session was not signed.';
        result.dataset.state = 'valid'; renderReplay(report);
    } catch (error) { if (revision === inputRevision) { result.textContent = error.message; result.dataset.state = 'invalid'; reportElement.hidden = true; } }
    finally { verifyButton.disabled = false; }
    return false;
}

verifyButton.addEventListener('click', check);
function loadSource(source) {
    compactDocument = undefined; evidenceDocument = undefined;
    publicationManifest = undefined; publicationMaster = undefined;
    text.readOnly = false;
    const record = JSON.parse(source);
    if (!record || typeof record !== 'object') throw new Error('Invalid proof file.');
    if (record.kind === 'huma-writing-disclosure-v1') {
        const disclosed = writingDisclosure(source), proof = boundedJSON(disclosed.proof);
        if (typeof proof.text !== 'string') throw new Error('Public text required.');
        originalText = proof.text; text.value = originalText; changed = false;
        evidenceDocument = source; replayDocument = undefined; bundle = undefined;
        clearReport('Writing proof loaded. Press Verify.'); return;
    }
    if (record.kind === 'huma-evidence-envelope-v1') {
        const envelope = parseEnvelope(source), proof = boundedJSON(envelope.proof);
        if (typeof proof.text !== 'string') throw new Error('This envelope has no public text.');
        originalText = proof.text; text.value = originalText; changed = false;
        evidenceDocument = source; replayDocument = undefined; bundle = undefined;
        clearReport('Evidence loaded. Press Verify.'); return;
    }
    if (['huma-compact-assurance-public-proof-v4','huma-compact-assurance-public-proof-v5'].includes(record.kind)) {
        // The pinned verifier owns supported profiles and their cryptographic
        // assets. Loading a file only checks its shape and resource limit.
        if (new TextEncoder().encode(source).length > 65536 || typeof record.profile !== 'string' || typeof record.text !== 'string') throw new Error('Unsupported writing-policy export.');
        originalText = record.text; text.value = originalText; changed = false;
        evidenceDocument = source; replayDocument = undefined; bundle = undefined;
        clearReport('Writing-policy proof loaded. Press Verify.'); return;
    }
    if (record.kind === 'huma-compact-public-proof-v1') {
        if (new TextEncoder().encode(source).length > 512 * 1024 || record.profile !== 'cast256-v1') throw new Error('Unsupported experimental profile or export size.');
        compactDocument = source; bundle = undefined; replayDocument = undefined;
        originalText = typeof record.text === 'string' ? record.text : undefined;
        if (originalText !== undefined) { text.value = originalText; changed = false; } else changed = true;
        clearReport('Experimental proof loaded. Press Verify.'); return;
    }
    bundle = record.bundle ?? record;
    if (bundle?.system !== 'risc0-3.0.6') throw new Error('Unsupported proof. Choose a Huma replay proof export.');
    originalText = typeof record.text === 'string' ? record.text : undefined;
    if (originalText !== undefined) { text.value = originalText; changed = false; } else changed = true;
    replayDocument = record.bundle ? source : JSON.stringify({ text: text.value, bundle });
    clearReport('Ready. Press Verify.');
}
async function loadFile(file) {
    bundle = undefined; replayDocument = undefined; compactDocument = undefined; evidenceDocument = undefined; showProof(); clearReport('Loading proof…');
    const selection = inputRevision;
    if (!file || file.size > 32 * 1024 * 1024) { clearReport('Choose a proof file smaller than 32 MB.'); return; }
    try {
        // A Huma report carries its page proof inside (report-pdf.mjs); a proof file is the proof itself.
        const pdf = /\.pdf$/i.test(file.name) || file.type === 'application/pdf';
        const found = pdf ? await reportFiles(file) : { proof: await file.text(), replay: null };
        if (selection !== inputRevision) return;
        loadSource(found.proof);
        localReplay = found.replay; localFile = new TextEncoder().encode(found.proof);
        showProof(compactDocument ? 'Experimental proof added' : 'Proof added', file.name);
        // A page proof opens as its page: checked at once, then shown the way a shared page is. Other formats stay here.
        if (evidenceDocument && pageProof(evidenceDocument)) await openLocal(file.name);
    } catch { if (selection === inputRevision) { bundle = undefined; replayDocument = undefined; compactDocument = undefined; evidenceDocument = undefined; clearReport('This file is not a Huma proof.'); } }
}
/** The page proof, and the writing replay if the writer attached it, inside a Huma report PDF. */
async function reportFiles(file) {
    const [PDFLib, { attached }] = await Promise.all([import('/vendor/pdf-lib/pdf-lib.mjs'), import('/report-pdf.mjs')]);
    const found = await attached(new Uint8Array(await file.arrayBuffer()), PDFLib);
    if (!found.proof) throw new Error('This PDF has no Huma proof inside.');
    return found;
}
proofInput.addEventListener('change', event => loadFile(event.target.files[0]));
for (const type of ['dragenter', 'dragover']) dropZone.addEventListener(type, event => { event.preventDefault(); dropZone.classList.add('over'); });
for (const type of ['dragleave', 'drop']) dropZone.addEventListener(type, () => dropZone.classList.remove('over'));
dropZone.addEventListener('drop', event => { event.preventDefault(); if (event.dataTransfer.files.length) loadFile(event.dataTransfer.files[0]); });
document.querySelector('#loadJSON').addEventListener('click', () => {
    bundle = undefined; replayDocument = undefined; compactDocument = undefined; evidenceDocument = undefined;
    try {
        const source = document.querySelector('#proofJSON').value;
        if (new TextEncoder().encode(source).length > 32 * 1024 * 1024) throw new Error('Proof export exceeds 32 MB.');
        loadSource(source);
        showProof(compactDocument ? 'Experimental proof added' : 'Proof added', 'Pasted JSON');
        document.querySelector('#proofJSON').value = '';
        document.querySelector('#jsonImport').open = false;
    } catch (error) { clearReport(error.message); }
});
text.addEventListener('input', () => { changed = true; clearReport('Text changed. Verify again.'); });
expectedKey.addEventListener('input', () => clearReport('Expected key changed. Verify again.'));
checkDevice.addEventListener('change', () => clearReport('Device-check selection changed. Verify again.'));
for (const field of [deviceJSON, policyJSON]) field.addEventListener('input', () => clearReport('Device evidence or reader policy changed. Verify again.'));
for (const [fileID, field, limit] of [['deviceFile', deviceJSON, 256 * 1024], ['policyFile', policyJSON, 16384]]) {
    document.querySelector('#' + fileID).addEventListener('change', async event => {
        field.value = ''; clearReport('Loading local evidence file…');
        const revision = inputRevision, file = event.target.files[0];
        if (!file || file.size > limit) { clearReport('Choose a JSON file within its stated size limit.'); return; }
        try {
            const source = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
            if (revision !== inputRevision) return;
            field.value = source; clearReport('Local file loaded. Select the corresponding evidence checks and verify.');
        } catch { if (revision === inputRevision) clearReport('Invalid UTF-8 JSON file.'); }
    });
}
const id = location.pathname.match(/^\/verify\/([a-f0-9]{64})$/)?.[1];
// A shared page opens by its full link (/original/<id>#<token>) or its short one (/p/<code>#<key>, id in huma-page).
const shortPath = location.pathname.match(/^\/p\/([A-Za-z0-9]{8,12})$/)?.[1];
const originalID = location.pathname.match(/^\/original\/([a-f0-9]{64})$/)?.[1]
    ?? (shortPath ? document.querySelector('meta[name=huma-page]')?.content.match(/^[a-f0-9]{64}$/)?.[0] : undefined);
if (originalID) {
    // Most of the wait is loading the checker, so it starts now, while the page and its proof download.
    prepareVerifier();
    // A shared link opens as a reader, not the verification tool: the text, one status line, downloads.
    // The server already sends it this way, with grey shapes where the text and buttons will go.
    document.body.classList.add('reader');
    document.querySelector('h1').textContent = 'Shared on Huma.';
    document.querySelector('.page-lead').textContent = 'Your browser checks this page itself.';
    // Two plain lines under the text: was it typed in Huma, and its score. Each says "Checking…" until it knows.
    const skeleton = document.querySelector('.skeleton');
    const typed = checkRow(document.querySelector('[data-check=typed]'));
    const score = checkRow(document.querySelector('[data-check=score]'));
    try {
        // A short link's key goes with its code, which is how the server finds the page it opens.
        const key = location.hash.slice(1), token = shortPath && key ? shortPath + '.' + key : key;
        if (key && !(shortPath ? /^[A-Za-z0-9]{16}$/ : /^[a-f0-9]{64}$/).test(key)) throw new Error('Invalid original link.');
        const headers = token ? { Authorization: 'Bearer ' + token } : {};
        async function download(part, limit) {
            const response = await fetch('/api/publications/' + originalID + part, { headers, redirect: 'error', signal: AbortSignal.timeout(30000) });
            if (response.status === 410) throw new Error('The writer removed this page.');
            if (!response.ok || Number(response.headers.get('content-length') ?? 0) > limit) throw new Error('Original unavailable or access was not granted.');
            const reader = response.body.getReader(), chunks = []; let length = 0;
            try {
                while (true) {
                    const { done, value } = await reader.read(); if (done) break;
                    length += value.length; if (length > limit) throw new Error('Published file exceeds its limit.'); chunks.push(value);
                }
            } finally { await reader.cancel(); }
            const bytes = new Uint8Array(length); let at = 0;
            for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; } return bytes;
        }
        const [manifestBytes, master, proof] = await Promise.all([download('', 8192), download('/master', MASTER_LIMIT), download('/proof', PROOF_LIMIT)]);
        const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
        const manifest = await checkDownloadedPublication(decoder.decode(manifestBytes), originalID, master, proof);
        const source = decoder.decode(proof), content = expectedMaster(manifest, master);
        if (manifest.statement.contentKind !== 'text') {
            bundle = undefined; replayDocument = undefined; compactDocument = undefined;
            originalText = undefined; changed = false; text.readOnly = true;
            text.value = 'This original is a ' + manifest.statement.contentKind + ' master. Its exact bytes are checked locally.';
            clearReport('Media master loaded.');
            evidenceDocument = source; publicationManifest = manifest; publicationMaster = master;
            showProof('Original and proof downloaded', 'File hashes checked; verifying evidence locally');
            typed.set('no', 'Media pages open in the Huma app.'); score.remove();
        } else {
        loadSource(source); originalText = content; text.value = content; changed = false;
        evidenceDocument = source; publicationManifest = manifest; publicationMaster = master;
        showProof('Original and proof downloaded', 'File hashes checked; verifying evidence locally');
        // Sharing uses the page's short link; only the page's own address and key, so nothing a link adds reaches the report.
        const pageLink = location.origin + location.pathname + location.hash;
        const shareLink = shortPath ? Promise.resolve(pageLink)
            : fetch('/api/publications/' + originalID + '/short', { method: 'POST', headers, redirect: 'error', signal: AbortSignal.timeout(15000) })
                .then(response => response.ok ? response.json() : null)
                .then(value => /^\/p\/[A-Za-z0-9]{8,12}(#[A-Za-z0-9]{16})?$/.test(value?.path) ? location.origin + value.path : pageLink, () => pageLink);
        await presentPage({ source, content, file: proof, share: shareLink, rows: { typed, score }, skeleton,
            replayText: async () => {
                const response = await fetch('/api/publications/' + originalID + '/replay', { headers, redirect: 'error', signal: AbortSignal.timeout(30000) });
                return response.ok ? response.text() : null;
            },
            writer: () => showWriterFromHost(headers) });
        }
    } catch (error) { typed.set('no', error.message); score.remove(); document.querySelector('.author')?.remove(); }
    finally { skeleton.remove(); document.querySelector('.actions.reader-only')?.remove(); }
}
/**
 * A page proof shown as its page: the text (pasted parts marked when there's a replay), whether it was typed, its
 * score, and its report, with the details below. For a shared link, and for a proof or report dropped on this page.
 */
async function presentPage({ source, content, file, share, rows, skeleton, replayText, writer }) {
    presenting = true;
    const article = document.querySelector('#article'); article.hidden = false; article.replaceChildren(); skeleton?.remove();
    const author = authorLabel();
    // Blank lines start a new paragraph; single line breaks stay as typed.
    for (const block of content.replace(/\r\n?/g, '\n').trim().split(/\n{2,}/)) {
        const paragraph = document.createElement('p'); paragraph.textContent = block; article.append(paragraph);
    }
    const links = document.createElement('div'); links.className = 'actions';
    if (share) links.append(shareMenu(share));
    // The report (to save as a PDF or print), with the proof inside, for anyone who wants to keep it or check it again.
    const report = reportButton();
    links.append(report.button);
    printable = { text: content, link: share ?? Promise.resolve(null), proof: source, file };
    const details = document.querySelector('.details'), more = document.createElement('button');
    more.className = 'button small secondary'; more.type = 'button'; more.textContent = 'All Details';
    more.setAttribute('aria-expanded', 'false');
    more.addEventListener('click', () => {
        details.open = !details.open; more.setAttribute('aria-expanded', String(details.open));
        more.textContent = details.open ? 'Hide Details' : 'All Details';
    });
    links.append(more);
    if (!share) {
        const again = document.createElement('button'); again.className = 'button small secondary'; again.type = 'button'; again.textContent = 'Check Another';
        again.addEventListener('click', () => location.reload());
        links.append(again);
    }
    document.querySelector('.actions.reader-only')?.replaceWith(links);
    const { typed, score } = rows;
    // The score only appears for a page that verified here, so it never sits next to a failed check.
    if (await check()) {
        const shown = showReplay(source, content, links, replayText);
        // The proof notes any paste (or imported text) while writing, even one deleted before Finish. When the replay,
        // checked against the proof, shows every character of the final text was typed, the page doesn't say otherwise.
        const replay = pageUnmet.some(rule => rule === WRITING_RULES[0] || rule === WRITING_RULES[1]) ? await shown : null;
        const c = replay?.composition;
        if (c?.total && !c.pasted && !c.before && !c.other) {
            pageUnmet = pageUnmet.filter(rule => rule !== WRITING_RULES[0] && rule !== WRITING_RULES[1]);
            if (!pageUnmet.length) { result.textContent = "Verified. This matches a signed Huma writing record, and it hasn't changed since."; result.dataset.state = 'valid'; }
            else result.textContent = partialSummary(pageUnmet);
        }
        if (!pageUnmet.length) {
            typed.set('ok', 'Typed in Huma. Unchanged since.');
            author.verified();
        } else {
            // "Typed in Huma" would overclaim when some of the text wasn't typed.
            if (notAllTyped(pageUnmet)) typed.row.querySelector('strong').textContent = 'Written in Huma';
            typed.set('partial', partialSummary(pageUnmet)); author.partial(notAllTyped(pageUnmet));
        }
        typed.explain(typingPoints(pageJournal));
        await Promise.all([writer?.(), shown.then(replay => showScore(score, pageJournal, replay))]);
        // Everything the report says is known now.
        report.ready();
    } else { typed.set('no', result.textContent); score.remove(); author.remove(); }
}
/** A proof or report dropped here, opened as its page. */
async function openLocal(name) {
    document.body.classList.add('reader', 'local');
    document.querySelector('h1').textContent = 'Checked in your browser.';
    document.querySelector('.page-lead').textContent = name;
    const rows = { typed: checkRow(document.querySelector('[data-check=typed]')), score: checkRow(document.querySelector('[data-check=score]')) };
    const skeleton = document.querySelector('.skeleton');
    try {
        await presentPage({ source: evidenceDocument, content: originalText ?? text.value, file: localFile, rows, skeleton,
            replayText: async () => localReplay });
    } catch (error) { rows.typed.set('no', error.message); rows.score.remove(); }
}
function checkRow(row) {
    const name = row.querySelector('strong'), line = row.querySelector('span'), title = name.textContent;
    return { line, row, remove: () => row.remove(),
             set(state, text) { row.dataset.state = state; line.textContent = text; },
             /** Takes the explanation off again, so it can be rebuilt. */
             clear() { row.querySelectorAll('.more, .explain').forEach(el => el.remove()); },
             /** A ⌃ button that opens a plain list of what was checked. */
             explain(points) {
                 if (!points.length) return;
                 const body = document.createElement('ul'); body.className = 'explain'; body.hidden = true;
                 body.id = 'explain-' + row.dataset.check;
                 for (const point of points) { const item = document.createElement('li'); item.append(point); body.append(item); }
                 const toggle = document.createElement('button'); toggle.className = 'more'; toggle.type = 'button';
                 toggle.setAttribute('aria-expanded', 'false'); toggle.setAttribute('aria-controls', body.id);
                 toggle.setAttribute('aria-label', 'What was checked: ' + title);
                 toggle.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
                 toggle.addEventListener('click', () => {
                     const open = toggle.getAttribute('aria-expanded') !== 'true';
                     toggle.setAttribute('aria-expanded', String(open)); body.hidden = !open;
                 });
                 name.after(toggle); row.append(body);
             } };
}
/** The label on the text card: "Checking…" from the moment the text shows, "Typed by a person" once it checks out. */
function authorLabel() {
    const label = document.createElement('div'); label.className = 'author is-checking';
    const mark = document.createElement('span'); mark.className = 'author-mark';
    const name = document.createElement('strong'); name.textContent = 'Checking…';
    label.append(mark, name);
    document.querySelector('#article').before(label);
    return { remove: () => label.remove(),
        /** Checked, but not all typed (some text pasted) or a typing check not met: said plainly, without the green tick. */
        partial(notTyped) {
            const done = document.createElement('span'); done.className = 'author-mark'; done.textContent = '–';
            mark.replaceWith(done); name.textContent = notTyped ? 'Written in Huma, not all typed' : 'Typed in Huma, not all checks met';
            label.classList.replace('is-checking', 'is-partial');
        },
        verified() {
        const done = document.createElement('span'); done.className = 'author-mark'; done.textContent = '✓';
        // Without the Mac's keyboard check it can't show a person typed it, so it says where it was typed instead.
        mark.replaceWith(done); name.textContent = pageBrowser ? 'Typed in Huma' : 'Typed by a person'; label.classList.remove('is-checking');
    } };
}
/** Share: copy the link, or send it with X, WhatsApp, Telegram, LinkedIn or email; "More Options…" opens the
 *  device's own share sheet. `link` resolves to the page's short link; the full one is used until it arrives. */
function shareMenu(link) {
    let url = location.href;
    const menu = document.createElement('details'); menu.className = 'share';
    const button = document.createElement('summary'); button.className = 'button small secondary';
    button.innerHTML = glyph('share'); button.append('Share');
    const list = document.createElement('div'); list.className = 'share-menu';
    // Closing the menu during the click can stop the browser from following the link, so it closes just after.
    const close = () => setTimeout(() => { menu.open = false; });
    const words = () => { const writer = document.querySelector('.author .writer b')?.textContent; return writer ? writer + ' typed this on Huma' : 'Typed by a person, on Huma'; };
    const item = (tag, name, label) => { const el = document.createElement(tag); el.innerHTML = glyph(name); el.append(label); list.append(el); return el; };
    const copy = item('button', 'link', 'Copy Link'); copy.type = 'button';
    copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(url); } catch { return; }
        copy.lastChild.textContent = 'Link Copied';
        setTimeout(() => { copy.lastChild.textContent = 'Copy Link'; menu.open = false; }, 1200);
    });
    const sites = [['x', 'Share on X', (u, t) => `https://x.com/intent/tweet?text=${t}&url=${u}`],
        ['whatsapp', 'Share on WhatsApp', (u, t) => `https://wa.me/?text=${t}%20${u}`],
        ['telegram', 'Share on Telegram', (u, t) => `https://t.me/share/url?url=${u}&text=${t}`],
        ['linkedin', 'Share on LinkedIn', u => `https://www.linkedin.com/sharing/share-offsite/?url=${u}`],
        ['mail', 'Share by Email', (u, t) => `mailto:?subject=${t}&body=${u}`]].map(([name, label, href]) => {
        const a = item('a', name, label); if (name !== 'mail') { a.target = '_blank'; a.rel = 'noopener'; }
        a.addEventListener('click', close);
        return [a, href];
    });
    // Every link is ready from the start, and is brought up to date when the short link or the writer's name arrives.
    const update = () => { const u = encodeURIComponent(url), t = encodeURIComponent(words()); for (const [a, href] of sites) a.href = href(u, t); };
    update();
    link.then(value => { url = value; update(); });
    menu.addEventListener('toggle', () => { if (menu.open) update(); });
    if (navigator.share) {
        const more = item('button', 'more', 'More Options…'); more.type = 'button';
        more.addEventListener('click', () => { navigator.share({ title: document.title, text: words(), url }).catch(() => {}); close(); });
    }
    document.addEventListener('click', event => { if (menu.open && !menu.contains(event.target)) menu.open = false; });
    menu.addEventListener('keydown', event => { if (event.key === 'Escape' && menu.open) { menu.open = false; button.focus(); } });
    menu.append(button, list);
    return menu;
}
/** The writer's face and name, as the host reports them (chosen in the app, not part of the proof): with a handle, a link to their page. */
function showWriter(profile, handle) {
    const label = document.querySelector('.author');
    if (!label || typeof profile?.name !== 'string' || !profile.name.trim() || [...profile.name].length > 40
        || typeof profile.avatar !== 'string' || !/^[A-Za-z0-9_-]{1,32}$/.test(profile.avatar)) return;
    const linked = typeof handle === 'string' && HANDLE.test(handle);
    const writer = document.createElement(linked ? 'a' : 'span'); writer.className = 'writer';
    if (linked) { writer.href = '/@' + handle; }
    const face = document.createElement('img'); face.className = 'face'; face.alt = ''; face.width = 28; face.height = 28;
    face.src = '/avatar/' + profile.avatar + '.svg';
    const name = document.createElement('b'); name.textContent = profile.name;
    writer.append(face, name);
    label.prepend(writer);
}
/** What "Typed in Huma" means for this page, one plain sentence each. */
function typingPoints(j) {
    if (!j) return [];
    const pasted = Number(j.paste), asked = Number(j.presence_count), answered = Math.min(Number(j.on_time), asked);
    const points = [`${Number(j.samples).toLocaleString()} key presses, typed over ${duration(j.elapsed)}.`,
        pasted ? `${pasted === 1 ? 'One edit was' : pasted.toLocaleString() + ' edits were'} pasted.` : 'Nothing was pasted.'];
    if (Number(j.initial_bytes)) points.push('Some text was there before typing started.');
    points.push(!asked ? (pageBrowser ? 'Confirmed at the finish.' : 'Confirmed with Touch ID at the start and finish.')
        : `${pageBrowser ? 'Check-ins' : 'Touch ID checks'}: ${answered} of ${asked} answered within 10 seconds.`);
    const unmet = WRITING_RULES.filter((_, i) => j.rules?.[i] === false);
    points.push(j.policy_satisfied ? 'All typing checks met.' : 'Not met: ' + unmet.join(', ') + '.');
    points.push('Signed on the writer’s device. Text unchanged.');
    points.push('Checked in your browser.');
    return points;
}
/** The writer's replay, if they shared one: checked here against the page proof's key and text, then a
 *  "typed" share by the name and a button to watch it. A replay that doesn't check out is never shown. */
async function showReplay(source, text, links, replayText) {
    let replay;
    try {
        const outer = JSON.parse(source), page = typeof outer.proof === 'string' ? JSON.parse(outer.proof) : outer;
        const [{ verifyReplay, REPLAY_LIMIT }, body] = await Promise.all([import('/replay-core.mjs'), replayText()]);
        if (typeof body !== 'string' || body.length > REPLAY_LIMIT) return;
        replay = await verifyReplay(body, { publicKey: page.publicKey, text });
    } catch { return; }
    const { openPlayer, mixLabel } = await import('/replay-player.js');
    markPasted(document.querySelector('#article'), text, replay.origin);
    const label = document.querySelector('.author');
    if (label && replay.composition.total) {
        // Pasted on the left, typed on the right, each named in its own colour. A browser can't tell one keyboard
        // from another, so its typing counts whole.
        const c = pageBrowser ? { ...replay.composition, typed: replay.composition.typed + (replay.composition.external ?? 0), external: 0 } : replay.composition;
        const mix = document.createElement('span'); mix.className = 'mix'; mix.setAttribute('aria-label', mixLabel(c));
        const share = value => percentLabel(value / c.total), named = (className, text) => Object.assign(document.createElement('span'), { className, textContent: text });
        const bar = document.createElement('span'); bar.className = 'mix-bar'; bar.setAttribute('aria-hidden', 'true');
        for (const name of ['pasted', 'before', 'other', 'external', 'typed']) if (c[name]) {
            const part = document.createElement('i'); part.className = name; part.style.flexGrow = c[name]; bar.append(part);
        }
        if (c.pasted) mix.append(named('mix-pasted', share(c.pasted) + ' pasted'));
        mix.append(bar, named('mix-typed', share(c.typed + (c.external ?? 0)) + ' typed'));
        label.append(mix);
        if (printable) printable.mix = mixLabel(c);
    }
    const watch = document.createElement('button'); watch.type = 'button'; watch.className = 'button small';
    watch.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 3.5v9l7.5-4.5z" fill="currentColor"/></svg>';
    watch.append('Watch It Being Written');
    const article = document.querySelector('#article');
    watch.addEventListener('click', () => {
        watch.disabled = true; article.scrollIntoView({ behavior: 'smooth', block: 'start' });
        openPlayer(article, replay, () => { watch.disabled = false; });
    });
    links.prepend(watch);
    return replay;
}
/** Highlights the pasted parts of the text (from the replay this browser checked), paragraph by paragraph as shown. */
function markPasted(article, text, origin) {
    if (typeof origin !== 'string' || origin.length !== text.length || !origin.includes('p') || /\r/.test(text)) return;
    // The same paragraphs as the plain text: trimmed, split at blank lines.
    const blocks = [], start = text.length - text.trimStart().length, end = text.trimEnd().length, body = text.slice(0, end), blank = /\n{2,}/g;
    for (let at = start; at < end;) {
        blank.lastIndex = at;
        const gap = blank.exec(body);
        blocks.push([at, gap ? gap.index : end]);
        at = gap ? gap.index + gap[0].length : end;
    }
    article.replaceChildren(...blocks.map(([from, to]) => {
        const paragraph = document.createElement('p');
        for (let i = from, run = from; i <= to; i++) {
            if (i < to && (origin[i] === 'p') === (origin[run] === 'p')) continue;
            const piece = text.slice(run, i);
            if (origin[run] === 'p') { const mark = document.createElement('mark'); mark.className = 'pasted'; mark.textContent = piece; paragraph.append(mark); }
            else paragraph.append(piece);
            run = i;
        }
        return paragraph;
    }));
    const legend = document.createElement('p'); legend.className = 'replay-legend pasted-legend';
    const swatch = document.createElement('span'); swatch.className = 'swatch'; legend.append(swatch, 'Pasted text');
    article.after(legend);
}
/** Download Report: one PDF with everything (report-pdf.mjs), ready once the checks finish. */
function reportButton() {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'button small secondary';
    button.innerHTML = glyph('download'); button.append('Download Report');
    button.disabled = true; button.title = 'Ready once the checks finish';
    const name = button.lastChild;
    button.addEventListener('click', async () => {
        button.disabled = true; name.textContent = 'Preparing…';
        try { await downloadReport(); name.textContent = 'Download Report'; }
        catch { name.textContent = 'Try Again'; }
        finally { button.disabled = false; }
    });
    return { button, ready() { button.disabled = !printable?.score; button.removeAttribute('title'); } };
}
/** Makes the page's report in this browser, from what it just checked, and saves it: the result, score and writing rules,
 *  the writing session and zero-knowledge proof with links to each, the text, and the proof file attached. */
async function downloadReport() {
    const p = printable, j = pageJournal;
    if (!p?.score || !j) throw new Error('Nothing to report yet.');
    // Its tools load only now: the PDF library (classic script), fonts, the mark and the QR code.
    const script = src => new Promise((resolve, reject) => {
        if (globalThis.fontkit) return resolve();
        const tag = Object.assign(document.createElement('script'), { src, onload: resolve, onerror: reject }); document.head.append(tag);
    });
    const bytes = async url => new Uint8Array(await (await fetch(url)).arrayBuffer());
    const [PDFLib, { makeReport, VERIFY_URL, REPLAY_FILE }, { default: encodeQR }, , serif, bold, mark, link] = await Promise.all([import('/vendor/pdf-lib/pdf-lib.mjs'),
        import('/report-pdf.mjs'), import('/vendor/qr/qr.mjs'), script('/vendor/pdf-lib/fontkit.js'), bytes('/fonts/tinos-report.ttf'), bytes('/fonts/tinos-bold-report.ttf'),
        fetch('/brand/huma-mark.svg').then(r => r.text()), p.link]);
    const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
    const sha = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? new TextEncoder().encode(value) : value))]
        .map(b => b.toString(16).padStart(2, '0')).join('');
    const outer = JSON.parse(p.proof), inner = typeof outer.proof === 'string' ? outer.proof : p.proof, page = JSON.parse(inner);
    const firstLine = p.text.trim().split('\n')[0].trim(), title = firstLine.length <= 140 ? firstLine : firstLine.slice(0, 140);
    const s = p.score, c = p.composition, edits = Number(j.edits) || 1;
    const paragraphs = [...document.querySelectorAll('#article > p')].map(paragraph => [...paragraph.childNodes]
        .map(node => ({ text: node.textContent, pasted: node.nodeName === 'MARK' && node.classList.contains('pasted') })));
    // The result in the words this page uses for it.
    // The result in a few words; the typing checks say the rest.
    const mixed = c?.pasted ? `${percentLabel((c.typed + c.external) / c.total)} typed, ${percentLabel(c.pasted / c.total)} pasted. Unchanged since.` : 'Unchanged since it was written.';
    const status = !pageUnmet.length ? { verified: true, headline: pageBrowser ? 'Typed in Huma' : 'Verified: typed in Huma', detail: mixed }
        : { verified: false, headline: notAllTyped(pageUnmet) ? 'Written in Huma, not all typed' : 'Typed in Huma, not all checks met', detail: mixed };
    const pdf = await makeReport({
        title, writer: document.querySelector('.author .writer b')?.textContent, status, rules: WRITING_RULES.map(rule => !pageUnmet.includes(rule)),
        ...(pageBrowser ? { where: 'browser' } : {}), tier: checkTier(pageBrowser, pagePasskey).label,
        started: new Date(Number(j.start_unix)), ended: new Date(Number(j.end_unix)), savedAt: new Date(), madeBy: 'Huma',
        score: { value: s.value, weights: s.weights, rows: [
            [pageBrowser ? 'Typed' : 'Typed by hand', s.handTyped === null ? (pageBrowser ? 'Replay not attached' : 'Replay not shared, so typing counts at 60%')
                : percentLabel(s.handTyped) + (s.external ? `, ${percentLabel(s.external)} on another keyboard` : ''), `${s.points.typed} / ${s.weights[0]}`],
            ['Typing checks', `${s.checksMet} of 7 met`, `${s.points.checks} / ${s.weights[1]}`],
            [pageBrowser ? 'Check-ins' : 'Touch ID', s.presenceCount ? `${s.presenceOnTime} of ${s.presenceCount} on time` : 'None needed', `${s.points.touch} / ${s.weights[2]}`]],
            terms: { typed: s.typedShare, checks: [s.checksMet, 7], touch: [s.presenceOnTime, s.presenceCount] } },
        session: [['Writing time', duration(j.elapsed)], ['Key presses', Number(j.samples).toLocaleString('en-US')],
            ...(c ? [] : [['Typing edits', percentLabel(Number(j.typing) / edits)]]), [c ? 'Pasted' : 'Pasted edits', percentLabel(c ? c.pasted / c.total : Number(j.paste) / edits)],
            ['Replay', c ? 'Checked' : 'Not shared'], ...(pagePasskey ? [passkeyRow(page)] : [])],
        proof: { fingerprint: await sha(inner), textHash: /^[a-f0-9]{64}$/.test(outer.statement?.contentHash) ? outer.statement.contentHash : await sha(p.text),
            signingKey: await sha(decode(page.publicKey)), parts: (page.chunks?.length ?? 0) + 1, size: Math.max(1, Math.round(p.file.length / 1024)) + ' KB' },
        // The code opens the shared page, where the proof is checked; a report without one has no code to scan.
        link: link ?? undefined, qr: link ? encodeQR(link, 'raw', { ecc: 'medium', border: 0 }) : undefined, paragraphs,
        mix: c?.total ? { typed: percentLabel((c.typed + c.external) / c.total), pasted: percentLabel(c.pasted / c.total), share: c.pasted / c.total } : undefined,
        attachment: { name: 'Huma-evidence.json', bytes: p.file },
        // The replay this browser checked travels on with the report, so the next reader sees the pasted parts too.
        ...(localReplay && c ? { replay: { name: REPLAY_FILE, bytes: new TextEncoder().encode(localReplay) } } : {}),
    }, { PDFLib, fontkit: globalThis.fontkit, fonts: { serif, bold }, mark: mark.match(/ d="([^"]+)"/)[1] });
    const clean = title.replace(/[\\/:*?"<>|]+/g, ' ').trim();
    const file = (clean.length <= 60 ? clean : clean.slice(0, 60).replace(/\s+\S*$/, '')) + ' – Huma report.pdf';
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([pdf], { type: 'application/pdf' })), download: file });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
}
/** The host's verdict on a browser page's streamed typing (detection/judge.mjs), from its receipt: shown with the
 *  score, and where the host enforces it, holding the score at 50 as the host does. */
let scoreShown = null, detectionShown = null;
const detectionHolds = detection => detection?.enforced === true && (detection.platform === 'mac' ? detection.band === 'likely_automated' : !(detection.band === 'likely_human' && detection.integrity === 'pass'));
function showDetection(detection) {
    if (!detection || typeof detection !== 'object') return;
    detectionShown = detection;
    if (scoreShown) { scoreShown.row.clear(); showScore(scoreShown.row, scoreShown.journal, scoreShown.replay); }
}
/** The verdict in plain lines: what it found and the top reasons. */
function detectionLines(detection) {
    if (!detection) return [];
    const label = detection.integrity === 'fail' ? 'the live typing stream couldn’t verify it'
        : detection.band === 'likely_human' ? 'typed like a person' : detection.band === 'likely_automated' ? 'typed like software' : 'not clear either way';
    const reasons = (detection.reasons ?? []).filter(r => typeof r.detail === 'string' && r.detail).slice(0, 4).map(r => r.detail);
    return [`Live typing analysis: ${label} (${Math.round(detection.humanProbability * 100)}% likely a person).` + (reasons.length ? ' ' + reasons.map(r => r[0].toUpperCase() + r.slice(1)).join('; ') + '.' : '')];
}
/** The Huma score (humaScore in publication-contract.mjs), worked out here from the proof and, when shared, the replay:
 *  what it says was typed, and on a browser page its rhythm too (replayRhythm), and the host's verdict on its live typing. */
function showScore(row, journal, replay) {
    if (!journal) { row.remove(); return; }
    scoreShown = { row, journal, replay };
    const composition = replay?.composition ?? null, detection = detectionShown;
    const rules = journal.rules ?? [], score = humaScore({ composition, typingEdits: Number(journal.typing), edits: Number(journal.edits), rules,
        presenceCount: Number(journal.presence_count), onTime: Number(journal.on_time), browser: pageBrowser, passkey: pagePasskey,
        rhythmAutomated: Boolean(pageBrowser && replay && replayRhythm(replay.frames).automated), automated: detectionHolds(detection) });
    row.row.querySelector('strong').textContent = `Huma Score: ${score.value} of 100`;
    if (printable) Object.assign(printable, { score, composition });
    row.set(score.value >= 85 ? 'ok' : 'partial', scoreLine(score));
    const { typed, checks, touch } = score.points, missed = WRITING_RULES.slice(2).filter((_, i) => rules[i + 2] === false), [wt, wc, wp] = score.weights;
    if (pageBrowser) {
        row.explain([`Typed: ${typed} of ${wt} points. ` + (composition ? `${percentLabel(score.handTyped ?? 0)} of the text was typed.` + (score.handTyped < 1 ? ' Pasted text doesn’t count.' : '')
                : 'No replay shared, so this counts typed edits.'),
            `Typing checks: ${checks} of ${wc} points. ` + (missed.length ? `${score.checksMet} of 7 met. Not met: ${missed.join(', ')}.` : 'All 7 met.'),
            `Check-ins: ${touch} of ${wp} points. ` + (score.presenceCount ? `${score.presenceOnTime} of ${score.presenceCount} answered within 10 seconds.` : 'None needed.'),
            ...(score.capped ? [detectionHolds(detection) && !(replay && replayRhythm(replay.frames).automated) ? 'Held at 50: the live typing analysis couldn’t verify it as a person’s.' : 'Held at 50: the typing didn’t look like a person’s.'] : []),
            ...detectionLines(detection), checkTier(true, score.passkey).about]);
        return;
    }
    row.explain([
        `Typed by hand: ${typed} of 70 points. ` + (composition
            ? (score.handTyped === 1 && !score.external ? 'All of the text was typed.'
                : `${percentLabel(score.handTyped)} of the text was typed${score.external ? `, ${percentLabel(score.external)} of it on another keyboard, which counts at 60%` : ''}.`
                    + (score.handTyped < 1 ? ' Pasted text doesn’t count.' : ''))
            : 'No replay shared, so typing counts at 60%.'),
        `Typing checks: ${checks} of 20 points. ` + (missed.length ? `${score.checksMet} of 7 met. Not met: ${missed.join(', ')}.`
            : 'All 7 met.'),
        `Touch ID: ${touch} of 10 points. ` + (score.presenceCount ? `${score.presenceOnTime} of ${score.presenceCount} answered within 10 seconds.` : 'None needed.'),
        ...(score.capped ? [detectionHolds(detection) ? 'Held at 50: the host’s analysis of the writing replay found it typed like software.' : 'Held at 50: the typing didn’t look like a person’s.'] : []),
        ...detectionLines(detection)]);
}
/** Whether a page's unmet rules mean some of its text wasn't typed (imported or pasted), not just a typing check. */
function notAllTyped(unmet) { return unmet.includes(WRITING_RULES[0]) || unmet.includes(WRITING_RULES[1]); }
/** One plain line for a page that checks out but misses a writing rule. */
function partialSummary(unmet) {
    const checks = unmet.filter(rule => rule !== WRITING_RULES[0] && rule !== WRITING_RULES[1]);
    if (!notAllTyped(unmet)) return 'Unchanged, but not every typing check was met: ' + checks.join(', ') + '.';
    return 'Unchanged, but not all typed' + (!pageBrowser && unmet.includes(WRITING_RULES[0]) ? ': it started from imported text' : '')
        + '.' + (checks.length ? ' Also not met: ' + checks.join(', ') + '.' : '');
}
/** "A verified human" beside the writer, when their account has a World ID (publications.mjs, documents.mjs). It says one
 *  real, unique person writes under this account, never who: only a short fingerprint of their anonymous nullifier
 *  shows, the same on every page they share. Opening it gives the proof and the command to check it with World
 *  yourself; the proof is World's to confirm. */
function showWorldID(worldId, headers) {
    const label = document.querySelector('.author');
    if (!label || worldId?.verified !== true || !/^[0-9a-f]{12}$/.test(worldId.fingerprint ?? '')) return;
    const chip = document.createElement('details'); chip.className = 'human';
    const summary = document.createElement('summary');
    const mark = document.createElement('span'); mark.className = 'human-mark'; mark.textContent = '✓'; mark.setAttribute('aria-hidden', 'true');
    summary.append(mark, 'Verified human · World ID ' + worldId.fingerprint);
    const body = document.createElement('div'); body.className = 'human-body';
    const note = document.createElement('p');
    // Written in a browser, it was scanned at its Start and again at its Finish, by the same person (publications.mjs).
    note.textContent = (Number.isFinite(worldId.startedAt)
        ? 'One real, unique person confirmed with World ID that they started this page, and again that they finished this exact text. '
        : 'One real, unique person, confirmed with World ID, wrote and shared this page. ')
        + 'It does not say who they are. Their anonymous World ID, ' + worldId.fingerprint
        + ', is the same on every page they share, so they can show these pages are theirs.';
    const check = document.createElement('p'); check.textContent = 'Check it yourself: save the proof below as proof.json, then run the command.';
    const command = document.createElement('pre'); const proof = document.createElement('pre');
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy proof'; copy.disabled = true;
    body.append(note, check, command, copy, proof);
    chip.append(summary, body);
    label.append(chip);
    chip.addEventListener('toggle', async () => {
        if (!chip.open || chip.dataset.loaded) return;
        chip.dataset.loaded = '1';
        try {
            const response = await fetch('/api/publications/' + originalID + '/worldid', { headers, redirect: 'error', signal: AbortSignal.timeout(15000) });
            const data = response.ok ? await response.json() : null;
            if (!data || !/^rp_[0-9A-Za-z_]+$/.test(data.rpId ?? '')) throw new Error();
            const text = JSON.stringify({ ...data.result, environment: data.environment }, null, 2);
            command.textContent = "curl -s -X POST https://developer.world.org/api/v4/verify/" + data.rpId + " -H 'content-type: application/json' -d @proof.json";
            proof.textContent = text; copy.disabled = false;
            copy.onclick = () => navigator.clipboard.writeText(text).then(() => { copy.textContent = 'Copied'; }, () => {});
        } catch { command.textContent = 'The proof couldn’t be loaded.'; }
    });
}
/** "Stored on Arkiv" under the writer, when the host keeps the page there (publications.mjs, arkiv-store.mjs): the
 *  entity and transaction holding its text and proof, and a command to look the proof up on Arkiv without Huma. An
 *  entity's k is the file's SHA-256, which this page has just checked, and its owner should be Huma's wallet. The files
 *  are encrypted there, so this shows they are kept, by whom and until when, not what they say. */
function showStored(stored, manifest) {
    const label = document.querySelector('.author');
    const hex = (value, length) => typeof value === 'string' && new RegExp('^0x[0-9a-fA-F]{' + length + '}$').test(value);
    const site = value => typeof value === 'string' && /^https:\/\/[a-z0-9.-]+\.arkiv\.network$/.test(value);
    const file = value => value && hex(value.entity, 64) && (value.tx === null || hex(value.tx, 64)) && Number.isFinite(value.at);
    if (!label || !manifest || !stored || !hex(stored.owner, 40) || !site(stored.explorer) || !site(stored.rpc) || !file(stored.master) || !file(stored.proof)) return;
    const network = typeof stored.network === 'string' ? stored.network.slice(0, 40) : 'Arkiv';
    const day = ms => new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const short = value => value.slice(0, 8) + '…' + value.slice(-6);
    const link = (path, value) => { const a = document.createElement('a'); a.href = stored.explorer + path + value; a.textContent = short(value); a.target = '_blank'; a.rel = 'noopener noreferrer'; return a; };
    const chip = document.createElement('details'); chip.className = 'human stored';
    const summary = document.createElement('summary');
    const mark = document.createElement('span'); mark.className = 'human-mark stored-mark'; mark.textContent = '◆'; mark.setAttribute('aria-hidden', 'true');
    summary.append(mark, 'Stored on Arkiv · ' + network);
    const body = document.createElement('div'); body.className = 'human-body';
    const note = document.createElement('p');
    note.append('Huma keeps this page’s text and proof on Arkiv, encrypted, written by Huma’s wallet ', link('/address/', stored.owner),
        '. Arkiv shows they are kept and until when, not what they say: that is what your browser just checked.');
    body.append(note);
    for (const [name, part, hash] of [['Text', stored.master, manifest.master.hash], ['Proof', stored.proof, manifest.proof.hash]]) {
        const line = document.createElement('p');
        line.append(name + ' · entity ', link('/entity/', part.entity), ...(part.tx ? [' · transaction ', link('/tx/', part.tx)] : []),
            ' · saved ' + day(part.at) + (Number.isFinite(part.expires) ? ' · expires about ' + day(part.expires) : '')
            + (part.chunks > 1 ? ' · ' + part.chunks + ' parts' : ''));
        line.title = 'k = objects/' + hash;
        body.append(line);
    }
    const query = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'arkiv_query', params: ["k = str('objects/" + manifest.proof.hash + "') AND i = u64(0)",
        { select: { key: true, owner: true, createdAt: true, expiresAt: true, attributes: { k: true, v: true } } }] });
    const text = 'curl -s ' + stored.rpc + " -H 'content-type: application/json' --data-binary @- <<'EOF'\n" + query + '\nEOF';
    const check = document.createElement('p');
    check.textContent = 'Check it yourself: this asks Arkiv for the proof’s entity. Its owner should be ' + stored.owner.toLowerCase()
        + ', and k and v should both carry the proof’s SHA-256, ' + manifest.proof.hash + '.';
    const command = document.createElement('pre'); command.textContent = text;
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy command';
    copy.onclick = () => navigator.clipboard.writeText(text).then(() => { copy.textContent = 'Copied'; }, () => {});
    body.append(check, command, copy);
    chip.append(summary, body);
    label.append(chip);
}
/** "Anchored on Arkiv" under the writer, when the host published the page's signed hash record (hash-record.mjs): hashes
 *  and the writer's signature only, public. Nothing here is taken on trust: the hashes and the signed message are
 *  compared with the manifest this page already checked the proof against. */
function showAttestation(attestation, manifest, manifestSource) {
    const label = document.querySelector('.author');
    const record = attestation?.record;
    if (!label || !manifest || !record || record.version !== 1) return;
    const matches = record.textHash === manifest.master.hash && record.proofHash === manifest.proof.hash;
    const chip = document.createElement('details'); chip.className = 'human stored';
    const summary = document.createElement('summary');
    const mark = document.createElement('span'); mark.className = 'human-mark stored-mark'; mark.textContent = matches ? '◆' : '!'; mark.setAttribute('aria-hidden', 'true');
    summary.append(mark, matches ? 'Anchored on Arkiv' : 'Anchored record does not match this page');
    const body = document.createElement('div'); body.className = 'human-body';
    const note = document.createElement('p');
    note.textContent = matches
        ? 'Huma published this page’s hashes and the writer’s signature publicly. The text and proof stay with the writer: this record only lets anyone check a copy against it.'
        : 'The hashes in the public record differ from this page’s text or proof. Do not trust the record.';
    body.append(note);
    for (const [name, value] of [['Text hash', record.textHash], ['Proof hash', record.proofHash], ['Writer', record.wallet],
        ['Signature', attestation.check?.signature === 'wallet' ? 'wallet signature checked by the host' : attestation.check?.signature === 'device' ? 'signed by the writer’s device key' : 'not signed'],
        ['Anchored', Number.isFinite(attestation.at) ? new Date(attestation.at).toLocaleString() : 'unknown']]) {
        const line = document.createElement('p'); line.textContent = name + ' · ' + String(value).slice(0, 130); body.append(line);
    }
    chip.append(summary, body);
    label.append(chip);
}
/** The writer's name and face, as huma.social states them (they aren't part of the proof). */
async function showWriterFromHost(headers) {
    try {
        const response = await fetch('/api/publications/' + originalID + '/receipt', { headers, redirect: 'error', signal: AbortSignal.timeout(15000) });
        if (response.ok) { const receipt = await response.json(); showWriter(receipt.profile, receipt.handle); showWorldID(receipt.worldId, headers); showStored(receipt.stored, publicationManifest); showAttestation(receipt.attestation, publicationManifest); showDetection(receipt.detection); }
    } catch {}
}
if (id) {
    try {
        const response = await fetch('/api/proofs/' + id);
        if (!response.ok) throw new Error('Proof not found.');
        const source = await response.text();
        loadSource(source);
        showProof('Shared proof', 'Loaded from this link');
        await check();
    } catch (error) { result.textContent = error.message; }
}
