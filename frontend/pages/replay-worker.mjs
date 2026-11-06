import init, { verify_replay, public_replay } from './replay/huma_replay_browser.js';
import { createEvidenceVerifier } from './verify-core/core.mjs';
import { boundedJSON } from './verify-core/contract.mjs';
const ready = init();
const engine = createEvidenceVerifier({
    verifyReplay: async (source, text, key) => { await ready; return JSON.parse(verify_replay(source, text, key)); },
    verifyDevice: async (evidence, report, policy) => (await import('./device-verifier.js')).verifyPortableDeviceEvidence(evidence, report, policy),
    devicePolicy: value => value,
    publicReplay: public_replay,
});
self.onmessage = async ({ data }) => {
    try {
        const policy = {}, attachments = {};
        if (data.expectedKey) policy.expectedKey = data.expectedKey;
        if (data.deviceEvidence !== undefined || data.devicePolicy !== undefined) {
            attachments.device = data.deviceEvidence;
            const { readerPolicy } = await import('./device-verifier.js');
            policy.device = readerPolicy(boundedJSON(data.devicePolicy, 16384));
        }
        const result = await engine.verify(data.document, policy, data.text, attachments);
        if (!result.verified) throw new Error('Evidence did not verify.');
        self.postMessage({ ok: true, report: result.proofReport, evidence: result });
    } catch {
        self.postMessage({ ok: false, error: 'Evidence did not verify. Check the text, proof and selected attachments.' });
    }
};
