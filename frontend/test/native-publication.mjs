// Bundled Mac adapters + a local approval fixture. No real Privy/R2 account,
// wallet, device key or biometric prompt is used; the receipt is cached public data.
import { createRegistry } from '../registry.mjs';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const directory = await mkdtemp(path.join(tmpdir(), 'huma-native-publication-'));
const server = await createRegistry({ store: directory, publicationOptions: {
  authenticate: async token => { if (token !== 'native-fixture-owner') throw new Error('Fixture authorization rejected'); return '2'.repeat(64); },
} });
let child, timer;
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  child = spawn('python3', ['backend/zkvm/tests/native-worker.py', '--publication', '--app', 'build/Huma-r2-preview.app',
    '--probe', 'build/HumaPublicationProbe.app', '--proof', 'backend/zkvm/verifier/tests/fixtures/timed-receipt.json',
    '--output', 'build/Huma-publication-native.json'], { cwd: new URL('../../', import.meta.url),
    env: { ...process.env, HUMA_TEST_PUBLICATION: base }, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = '', handled = false, approved = false;
  child.stdout.on('data', chunk => {
    output += chunk;
    const match = output.match(/Publication fixture approval: (http:\/\/127\.0\.0\.1:[0-9]+\/share\/([a-f0-9]{64})#([a-f0-9]{64}))/);
    if (!match || handled) return;
    handled = true;
    fetch(base + '/api/publications/pending/' + match[2] + '/publish', { method: 'POST',
      headers: { Authorization: 'Bearer native-fixture-owner', 'X-Huma-Ticket': match[3] } })
      .then(async response => { if (!response.ok) throw new Error('Fixture approval failed'); approved = true; })
      .catch(error => { errors += error.message; child.kill('SIGTERM'); });
  });
  child.stderr.on('data', chunk => { if (errors.length < 8000) errors += chunk; });
  const code = await Promise.race([new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Native publication timed out')), 90000); })]);
  if (code !== 0 || !approved || !output.includes('PASS: native master/proof prepare')) throw new Error(errors + '\n' + output);
  const report = { passed: true, cachedPublicReceipt: true, newProofGenerated: false, realProviderAuthorization: false,
    r2Remote: false, masterAndProofDownloaded: true, nativeCryptographicReverification: true, linkSaveReopenAndEditInvalidation: true,
    externalNetworkDeniedForNative: true, deviceKeysOrBiometricsUsed: false };
  await writeFile(new URL('../../build/publication-native-results.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  clearTimeout(timer);
  if (child?.exitCode === null) {
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
  }
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
