import { bindingFields, policyFromEnvironment, validateBinding } from './protocol.mjs';
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const demand = (value, message) => { if (!value) throw new Error(message); };
export function readerPolicy(value) {
    demand(value && typeof value.appID === 'string' && /^[A-Z0-9]{10}\.[A-Za-z0-9.-]{3,255}$/.test(value.appID) &&
        Array.isArray(value.versions) && value.versions.length > 0 && value.versions.length <= 32 &&
        value.versions.every(version => typeof version === 'string' && /^[0-9]+(?:\.[0-9]+){0,2}$/.test(version)), 'Supply a reader-owned app policy.');
    return policyFromEnvironment({ HUMA_APP_ID_PREFIX: value.appID.slice(0, 10), HUMA_SIGNING_IDENTIFIER: value.appID.slice(11),
        HUMA_ATTEST_ENVIRONMENT: value.environment, HUMA_BUNDLE_VERSIONS: value.versions.join(',') });
}

export function portableVerifier({ base64, digest, verifyArchivedAttestation, verifyAssertion }) {
    function challenge(payload, purpose, keyID, binding) {
        const fields = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
        const expected = [`huma-app-attest-${purpose}-v${purpose === 'assert' ? 2 : 1}`];
        demand(Array.isArray(fields) && fields.length === (purpose === 'assert' ? 11 : 4) &&
            typeof fields[1] === 'string' && /^[a-f0-9]{32}$/.test(fields[1]) && fields[3] === keyID,
            'Invalid portable challenge.');
        demand(base64(fields[2], 32).length === 32, 'Invalid portable nonce.');
        expected.push(fields[1], fields[2], keyID);
        if (binding) expected.push(...bindingFields.map(field => binding[field]));
        demand(fields.every((field, i) => field === expected[i]), 'Portable challenge binding mismatch.');
    }

    // report MUST come from the pinned replay verifier, never from a producer's JSON.
    async function verifyReplayDeviceBinding(binding, report) {
        const b = validateBinding(binding), journal = report?.journal;
        demand(b.version === 2 && report.verified === true && /^[a-f0-9]{64}$/.test(report.proofIdentity ?? '') && journal,
            'A verified replay proof and V2 device binding are required.');
        demand(b.proofHash === report.proofIdentity && hex(await digest(new TextEncoder().encode(b.sessionID))) === journal.sessionIDHash &&
            b.captureHead === journal.captureHead && b.editHead === journal.editHead && b.textHash === journal.rawTextHash &&
            b.checkpointHash === journal.checkpointHash && b.captureKeyHash === journal.captureKeyHash,
            'Device evidence does not bind this replay proof.');
        return b;
    }

    async function verifyPortableDeviceEvidence(evidence, report, policy) {
        demand(evidence?.version === 1 && evidence.appID === policy.appID && evidence.environment === policy.environment,
            'Device evidence does not match the reader app policy.');
        demand(base64(evidence.keyID, 32).length === 32, 'Invalid attested key identifier.');
        const binding = await verifyReplayDeviceBinding(evidence.binding, report);
        const enrollmentData = base64(evidence.enrollment?.clientData, 4096);
        const assertionData = base64(evidence.clientData, 4096);
        challenge(enrollmentData, 'enroll', evidence.keyID);
        challenge(assertionData, 'assert', evidence.keyID, binding);
        const enrolled = await verifyArchivedAttestation({ attestation: base64(evidence.enrollment?.attestation),
            payload: enrollmentData, keyID: evidence.keyID, policy });
        const assertion = await verifyAssertion({ assertion: base64(evidence.assertion), payload: assertionData,
            publicKey: enrolled.publicKey, signCount: 0, policy });
        return { verified: true, appID: policy.appID, environment: policy.environment, proofIdentity: report.proofIdentity,
            captureKeyHash: binding.captureKeyHash, appAttestKeyID: evidence.keyID, assertionCounter: assertion.signCount,
            appleReportedEnrollmentTime: enrolled.enrollmentCreatedAt,
            checks: { appleCertificateChain: true, macSecurityPolicyAtEnrollment: true, signedAppProperties: true,
                assertionSignature: true, replayBinding: true, captureKeyAssociation: 'asserted-by-attested-app',
                challengeFreshness: 'not-established-offline', globalCounterReplay: 'not-checked',
                certificateRevocation: 'not-checked', humanPresence: 'not-established', trustedTypingInterval: false } };
    }

    return { verifyReplayDeviceBinding, verifyPortableDeviceEvidence };
}
