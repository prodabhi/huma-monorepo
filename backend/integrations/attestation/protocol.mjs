export const bindingFields = ['sessionID', 'captureHead', 'editHead', 'textHash', 'proofHash', 'checkpointHash', 'captureKeyHash'];
const demand = (value, message) => { if (!value) throw new Error(message); };
export function policyFromEnvironment(env) {
    demand(/^[A-Z0-9]{10}$/.test(env.HUMA_APP_ID_PREFIX ?? ''), 'Set HUMA_APP_ID_PREFIX to the real Apple App ID prefix.');
    demand(/^[A-Za-z0-9.-]{3,255}$/.test(env.HUMA_SIGNING_IDENTIFIER ?? ''), 'Set HUMA_SIGNING_IDENTIFIER to the Mac signing identifier.');
    demand(['development', 'production'].includes(env.HUMA_ATTEST_ENVIRONMENT), 'Set HUMA_ATTEST_ENVIRONMENT explicitly.');
    const versions = (env.HUMA_BUNDLE_VERSIONS ?? '').split(',').filter(Boolean);
    demand(versions.length > 0 && versions.every(v => /^[0-9]+(?:\.[0-9]+){0,2}$/.test(v)), 'Set HUMA_BUNDLE_VERSIONS to allowed CFBundleVersion values.');
    return { appID: `${env.HUMA_APP_ID_PREFIX}.${env.HUMA_SIGNING_IDENTIFIER}`, environment: env.HUMA_ATTEST_ENVIRONMENT,
        versions, categories: env.HUMA_ATTEST_ENVIRONMENT === 'development' ? [3] : [2, 4, 6] };
}
export function validateBinding(input) {
    const current = input?.version === 2;
    demand(input && (input.version === undefined || current) && Object.keys(input).length === bindingFields.length + Number(current), 'Invalid session binding.');
    demand(typeof input.sessionID === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input.sessionID), 'Invalid session ID.');
    for (const field of bindingFields.slice(1)) demand(typeof input[field] === 'string' && /^[a-f0-9]{64}$/.test(input[field]), 'Invalid session digest.');
    return { ...(current ? { version: 2 } : {}), ...Object.fromEntries(bindingFields.map(field => [field, input[field]])) };
}
