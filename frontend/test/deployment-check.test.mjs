import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { checkPublicationDeployment } from '../deployment-check.mjs';

const configured = () => ({ HUMA_STORAGE_BACKEND: 'arkiv',
  ARKIV_ACCESS_KEY: 'ark_live_fixture-access', ARKIV_PRIVATE_KEY: '0x' + '1a'.repeat(32), ARKIV_ENCRYPTION_KEY: '2b'.repeat(32),
  PRIVY_APP_ID: 'fixture-app', PRIVY_APP_SECRET: 'fixture-secret' });
const origin = 'https://huma.example';

test('offline deployment check validates real built reader pins without claiming provider acceptance', async () => {
  const env = configured(), report = await checkPublicationDeployment({ env, origin });
  assert.equal(report.configuredForLiveAcceptance, true);
  assert.equal(report.offlineOnly, true);
  assert.equal(report.liveAcceptanceVerified, false);
  assert.deepEqual(report.missingAssets, []);
  assert.deepEqual(report.mismatchedPins, []);
  for (const [name, value] of Object.entries(env)) {
    if (name !== 'HUMA_STORAGE_BACKEND') assert.equal(JSON.stringify(report).includes(value), false);
  }
});

test('local storage and missing Arkiv configuration cannot pass the hosted deployment check', async () => {
  const report = await checkPublicationDeployment({ env: { PRIVY_APP_ID: 'fixture-app' }, origin });
  assert.equal(report.configuredForLiveAcceptance, false);
  assert.equal(report.arkivConfigurationValid, false);
  assert.equal(report.configuration.HUMA_STORAGE_BACKEND, false);
  assert.equal(report.configuration.ARKIV_PRIVATE_KEY, false);
  assert.equal(report.configuration.PRIVY_APP_ID, true);
});

test('malformed Arkiv keys or lifetime are rejected without echoing their values', async () => {
  for (const [name, value] of [['ARKIV_PRIVATE_KEY', '0xDO-NOT-PRINT'], ['ARKIV_ENCRYPTION_KEY', 'DO-NOT-PRINT'], ['ARKIV_EXPIRY_DAYS', '183']]) {
    const env = configured(); env[name] = value;
    const report = await checkPublicationDeployment({ env, origin });
    assert.equal(report.arkivConfigurationValid, false);
    assert.equal(report.configuredForLiveAcceptance, false);
    assert.equal(JSON.stringify(report).includes('DO-NOT-PRINT'), false);
  }
});

test('invalid daily quota or non-HTTPS/path origin blocks live configuration', async () => {
  const env = configured(); env.HUMA_DAILY_PUBLICATION_LIMIT = '2001';
  assert.equal((await checkPublicationDeployment({ env, origin })).quotaConfigurationValid, false);
  for (const value of ['http://huma.example', 'https://huma.example/path', 'https://u:p@huma.example', 'https://huma.example/#fragment']) {
    const report = await checkPublicationDeployment({ env: configured(), origin: value });
    assert.equal(report.httpsOriginProvided, false);
    assert.equal(report.configuredForLiveAcceptance, false);
  }
});

test('missing reader files and changed optimized verifier key block deployment', async t => {
  const webRoot = await mkdtemp(path.join(tmpdir(), 'huma-deployment-check-'));
  t.after(() => rm(webRoot, { recursive: true, force: true }));
  const directory = path.join(webRoot, 'dist/compact/assets');
  await mkdir(directory, { recursive: true });
  const key = await readFile(new URL('../dist/compact/assets/assurance256-v2.vk', import.meta.url)); key[0] ^= 1;
  await writeFile(path.join(directory, 'assurance256-v2.vk'), key);
  const report = await checkPublicationDeployment({ env: configured(), origin, webRoot });
  assert.equal(report.configuredForLiveAcceptance, false);
  assert.ok(report.missingAssets.includes('dist/share/index.html'));
  assert.ok(report.mismatchedPins.includes('dist/compact/assets/assurance256-v2.vk'));
});
