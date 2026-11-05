import { randomBytes } from 'node:crypto';
import { digest, verifyAttestation, verifyAssertion } from './apple.mjs';
import { bindingFields, policyFromEnvironment, validateBinding } from './protocol.mjs';
export { bindingFields, policyFromEnvironment, validateBinding };
const demand = (value, message) => { if (!value) throw new Error(message); };
export function base64(value, limit = 65536) {
    demand(typeof value === 'string' && value.length <= Math.ceil(limit / 3) * 4 && /^[A-Za-z0-9+/]*={0,2}$/.test(value), 'Invalid binary encoding.');
    const bytes = Buffer.from(value, 'base64');
    demand(bytes.length > 0 && bytes.length <= limit && bytes.toString('base64') === value, 'Invalid binary encoding.');
    return bytes;
}
export class EvidenceService {
    constructor(store, policy) {
        this.store = store; this.policy = policy;
        const identity = `${policy.appID}|${policy.environment}`;
        demand(store.state.identity === identity || (!store.state.identity && Object.keys(store.state.keys).length === 0), 'Use separate evidence stores for each app identity and environment.');
        if (!store.state.identity) { store.state.identity = identity; store.save(); }
    }
    info() { return { version: 1, kind: 'apple-app-attest', platform: 'macOS', bindingVersions: [1, 2], ...this.policy }; }
    async challenge({ purpose, keyID, binding }) {
        demand(base64(keyID, 32).length === 32 && ['enroll', 'assert'].includes(purpose), 'Invalid challenge request.');
        const validated = purpose === 'assert' ? validateBinding(binding) : undefined;
        return this.store.exclusive(() => {
            const s = this.store.state, now = Date.now();
            for (const [id, challenge] of Object.entries(s.challenges)) if (challenge.expiresAt <= now) delete s.challenges[id];
            demand(Object.keys(s.challenges).length < 256 && (purpose !== 'enroll' || Object.keys(s.keys).length < 1000), 'Evidence service capacity reached.');
            if (purpose === 'assert') demand(s.keys[keyID], 'Enroll this key first.');
            const id = randomBytes(16).toString('hex'), nonce = randomBytes(32).toString('base64');
            const fields = [`huma-app-attest-${purpose}-v${validated?.version ?? 1}`, id, nonce, keyID];
            if (validated) fields.push(...bindingFields.map(field => validated[field]));
            const clientData = Buffer.from(JSON.stringify(fields)).toString('base64');
            const record = { id, nonce, purpose, keyID, binding: validated, expiresAt: now + 120000, clientData };
            s.challenges[id] = record; this.store.save(); return record;
        });
    }
    async accept({ challengeID, keyID, attestation, assertion }, purpose) {
        demand(typeof challengeID === 'string' && /^[a-f0-9]{32}$/.test(challengeID) && base64(keyID, 32).length === 32, 'Invalid evidence request.');
        const bytes = base64(purpose === 'enroll' ? attestation : assertion);
        const evidenceHash = digest(bytes).toString('hex');
        return this.store.exclusive(async () => {
            const s = this.store.state;
            const previous = s.results[challengeID];
            // Idempotent retrieval of the same accepted operation does not advance the counter.
            if (previous) {
                demand(previous.keyID === keyID && previous.evidenceHash === evidenceHash && previous.purpose === purpose, 'Challenge already consumed.');
                return previous.result;
            }
            const challenge = s.challenges[challengeID];
            demand(challenge && challenge.expiresAt > Date.now() && challenge.keyID === keyID && challenge.purpose === purpose, 'Challenge expired or consumed.');
            delete s.challenges[challengeID]; this.store.save(); // Burn before any verification, including failures.
            const payload = base64(challenge.clientData, 4096);
            let result;
            if (purpose === 'enroll') {
                demand(!s.keys[keyID], 'Key already enrolled.');
                const verified = await verifyAttestation({ attestation: bytes, payload, keyID, policy: this.policy });
                s.keys[keyID] = { ...verified, signCount: 0, enrolledAt: new Date().toISOString() };
                result = { verified: true, kind: 'apple-app-attest-enrollment', keyID, environment: verified.environment };
            } else {
                const key = s.keys[keyID]; demand(key && key.environment === this.policy.environment, 'Unknown key.');
                const verified = verifyAssertion({ assertion: bytes, payload, publicKey: key.publicKey, signCount: key.signCount, policy: this.policy });
                key.signCount = verified.signCount;
                result = { verified: true, kind: 'apple-app-attest-session', keyID, environment: key.environment,
                    signCount: key.signCount, binding: challenge.binding, challengeID, clientData: challenge.clientData,
                    assertion: bytes.toString('base64'), verifiedAt: new Date().toISOString() };
            }
            const resultIDs = Object.keys(s.results); if (resultIDs.length >= 1000) delete s.results[resultIDs[0]];
            s.results[challengeID] = { keyID, evidenceHash, purpose, result }; this.store.save(); return result;
        });
    }
}
