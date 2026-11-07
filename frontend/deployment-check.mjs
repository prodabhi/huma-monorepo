// Offline operator check. It never authenticates, contacts Arkiv or writes objects.
import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { publicationLimits } from './upload-quotas.mjs';
import { shareAssetFiles } from './share-assets.mjs';
import { ASSETS as COMPACT } from '../extra/experiments/noir-compact/browser/profile.mjs';
import { ASSETS as ASSURANCE } from '../extra/experiments/noir-compact/browser/assurance-profile.mjs';
import { VK_PIN as MEDIA } from '../extra/experiments/noir-media/reader/profile.mjs';

const root = fileURLToPath(new URL('./', import.meta.url));
const required = ['ARKIV_ACCESS_KEY', 'ARKIV_PRIVATE_KEY', 'ARKIV_ENCRYPTION_KEY', 'PRIVY_APP_ID', 'PRIVY_APP_SECRET'];
// The shapes arkiv-store.mjs insists on, checked without connecting: its account key, the encryption key and the lifetime.
const arkivValid = env => /^0x[0-9a-fA-F]{64}$/.test(env.ARKIV_PRIVATE_KEY ?? '') && /^[0-9a-fA-F]{64}$/.test(env.ARKIV_ENCRYPTION_KEY ?? '') &&
  (env.ARKIV_EXPIRY_DAYS === undefined || /^(?:[1-9]|[1-9]\d|1[0-7]\d|18[0-2])$/.test(env.ARKIV_EXPIRY_DAYS));
const files = ['pages/verify.html', 'pages/verify.mjs', 'pages/site.css', 'pages/foundation.html',
  'publication-contract.mjs', 'verify-core/browser.mjs', 'verify-core/worker.mjs',
  'verify-core/core.mjs', 'verify-core/contract.mjs', 'dist/share/index.html',
  'dist/device-verifier.js', 'dist/replay/huma_replay_browser.js', 'dist/replay/huma_replay_browser_bg.wasm',
  ...['compact-verifier.js', 'compact-worker.js', 'compact-inline.js', 'assurance-inline.js', 'media-inline.js'].map(x => 'dist/compact/' + x)];

export async function checkPublicationDeployment({ env = process.env, origin, webRoot = root } = {}) {
  const configuration = Object.fromEntries(required.map(name => [name, typeof env[name] === 'string' && !!env[name].trim()]));
  configuration.HUMA_STORAGE_BACKEND = env.HUMA_STORAGE_BACKEND === 'arkiv';
  const arkivConfigurationValid = configuration.HUMA_STORAGE_BACKEND && configuration.ARKIV_ACCESS_KEY && arkivValid(env);
  let quotaConfigurationValid = false, httpsOriginProvided = false;
  try { publicationLimits(env); quotaConfigurationValid = true; } catch {}
  try {
    const url = new URL(origin);
    httpsOriginProvided = url.protocol === 'https:' && !url.username && !url.password &&
      url.pathname === '/' && !url.search && !url.hash;
  } catch {}
  const missingAssets = [], mismatchedPins = [];
  for (const file of files) {
    try { if (!(await stat(path.join(webRoot, file))).isFile()) throw Error(); }
    catch { missingAssets.push(file); }
  }
  // Include lazy sign-in chunks, not just the page's initial script.
  try {
    const entries = await shareAssetFiles(webRoot);
    for (const entry of entries) {
      try { if (!(await stat(path.join(webRoot, 'dist/share', entry))).isFile()) throw Error(); }
      catch { missingAssets.push('dist/share/' + entry); }
    }
  } catch { missingAssets.push('dist/share/<complete-build-manifest>'); }
  for (const [name, pin] of Object.entries({ ...COMPACT, ...ASSURANCE, 'media-membership.vk': MEDIA })) {
    const file = 'dist/compact/assets/' + name;
    try {
      const bytes = await readFile(path.join(webRoot, file));
      if (bytes.length !== pin.bytes || createHash('sha256').update(bytes).digest('hex') !== pin.sha256) mismatchedPins.push(file);
    } catch { missingAssets.push(file); }
  }
  return { kind: 'huma-publication-deployment-check-v1', offlineOnly: true, environmentValuesPrinted: false,
    configuredForLiveAcceptance: Object.values(configuration).every(Boolean) && arkivConfigurationValid &&
      quotaConfigurationValid && httpsOriginProvided && !missingAssets.length && !mismatchedPins.length,
    configuration, arkivConfigurationValid, quotaConfigurationValid, httpsOriginProvided, missingAssets, mismatchedPins,
    liveAcceptanceVerified: false,
    manualChecks: ['Add this HTTPS origin to the Privy app\'s allowed origins.',
      'Run one publisher instance while staging is process-local.',
      'Approve a real Privy sign-in and share, then independently download and verify both files.'] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--origin') {
    console.error('Usage: node deployment-check.mjs --origin https://your-host.example');
    process.exitCode = 2;
  } else {
    const report = await checkPublicationDeployment({ origin: args[1] });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.configuredForLiveAcceptance ? 0 : 1;
  }
}
