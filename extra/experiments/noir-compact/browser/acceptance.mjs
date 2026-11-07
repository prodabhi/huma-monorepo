import { verifyCompactProof } from './compact-verifier.js';

const button = document.querySelector('#run'), status = document.querySelector('#status'), output = document.querySelector('#results');
button.onclick = async () => {
  button.disabled = true; output.textContent = ''; status.textContent = 'Checking…';
  const results = [];
  async function check(name, operation, reject = false) {
    const start = performance.now(); let error;
    try { await operation(); } catch (failure) { error = failure; }
    const passed = reject ? !!error : !error;
    results.push({ name, passed, elapsedMs: Math.round(performance.now() - start), ...(passed ? {} : { error: error?.message ?? 'Accepted invalid evidence' }) });
    output.textContent = JSON.stringify(results, null, 2);
    if (!passed) throw new Error('Failed: ' + name);
  }
  try {
    const manifest = await (await fetch('/fixtures/manifest.json')).json();
    let sample;
    for (const expected of manifest) {
      const file = await (await fetch('/fixtures/' + expected.name + '.json')).json(); sample = file;
      await check(expected.name + ': native identity, all signatures, exact text', async () => {
        const result = await verifyCompactProof(JSON.stringify(file), { text: file.text + ' \t', expectedKey: expected.keyHash });
        if (result.proofIdentity !== expected.proofIdentity || result.signaturesVerified !== expected.signatures || result.attestationVerified || result.trustedTime || result.humanAuthorshipProven) throw new Error('Wrong verified claims');
      });
    }
    const changed = (key, value) => JSON.stringify({ ...sample, [key]: value });
    const proof = atob(sample.proof);
    await check('changed proof rejected', () => verifyCompactProof(changed('proof', btoa(String.fromCharCode(proof.charCodeAt(0) ^ 1) + proof.slice(1)))), true);
    const signatures = sample.signatures.slice(); signatures[1] = signatures[0];
    await check('valid SNARK with wrong signature rejected', () => verifyCompactProof(changed('signatures', signatures)), true);
    await check('missing final signature rejected', () => verifyCompactProof(changed('signatures', sample.signatures.slice(0, -1))), true);
    await check('changed text rejected', () => verifyCompactProof(JSON.stringify(sample), { text: sample.text + '!' }), true);
    await check('lone surrogate rejected', () => verifyCompactProof(JSON.stringify(sample), { text: sample.text + '\ud800' }), true);
    await check('untrusted key rejected', () => verifyCompactProof(JSON.stringify(sample), { expectedKey: '0'.repeat(64) }), true);
    await check('export cannot choose a verification key', () => verifyCompactProof(changed('verificationKey', 'attacker')), true);
    await check('real worker cancellation', async () => {
      const controller = new AbortController(), task = verifyCompactProof(JSON.stringify(sample), {}, { signal: controller.signal });
      controller.abort();
      try { await task; } catch (error) { if (error.name === 'AbortError') return; throw error; }
      throw new Error('Cancellation did not reject');
    });
    await check('valid check after failure/cancellation', () => verifyCompactProof(JSON.stringify(sample)));
    const summary = { passed: results.length, failed: 0, crossOriginIsolated, sharedArrayBufferAvailable: typeof SharedArrayBuffer !== 'undefined', externalRequestsRequired: false };
    output.textContent = JSON.stringify({ summary, results }, null, 2);
    status.textContent = 'PASS: ' + results.length + ' browser checks';
    document.title = 'PASS · Huma compact verifier';
  } catch (error) { status.textContent = 'FAIL: ' + error.message; document.title = 'FAIL · Huma compact verifier'; }
  finally { button.disabled = false; }
};
