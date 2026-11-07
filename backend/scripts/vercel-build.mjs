// Builds huma for Vercel into .vercel/output (Vercel's Build Output API v3), for `vercel deploy --prebuilt`.
// The web assets need Rust, Noir outputs and the proving setup that only exist on a build machine, so Vercel can't
// build them itself: run `make build-frontend build-zkvm-browser` first, then this, then deploy (deploy-vercel.sh).
//
// The site is one Node function (the host package from package-publication.mjs, run by backend/hosting/vercel.mjs)
// plus static files for everything too large for a function's 4.5 MB response: the checker and prover WebAssembly,
// the writer's assets and proving points, the deck and the sharing page's scripts. Their headers below are the ones
// frontend/registry.mjs sends for the same paths; keep the two in step.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, open, readdir, rename, rm, stat, writeFile, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { packagePublication } from './package-publication.mjs';
import { POINTS } from '../../frontend/write/pins.mjs';
import { BRIDGE_ORIGIN } from '../../frontend/worldid-verify.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const output = path.join(root, '.vercel/output'), statics = path.join(output, 'static'), fn = path.join(output, 'functions/index.func');
const web = path.join(fn, 'frontend');

// frontend/registry.mjs: `headers`, WRITE_ISOLATION and the sharing page's policy.
const BASE = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
  'Strict-Transport-Security': 'max-age=31536000', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'" };
const WRITE_ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Resource-Policy': 'same-origin' };
const SHARE_CSP = `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ${BRIDGE_ORIGIN}; frame-src 'none'; worker-src 'self'; base-uri 'none'; frame-ancestors 'none'`;
const IMMUTABLE = 'public, max-age=31536000, immutable', BINARY = 'application/octet-stream';

await rm(output, { recursive: true, force: true });
await mkdir(path.dirname(fn), { recursive: true });

// 1. The function: the reviewed host package, its production dependencies for Vercel's Linux, and the entry.
const packaged = await packagePublication(fn);
await copyFile(path.join(root, 'backend/hosting/vercel.mjs'), path.join(fn, 'vercel.mjs'));
execFileSync('npm', ['ci', '--omit=dev', '--ignore-scripts', '--os=linux', '--cpu=x64', '--no-audit', '--no-fund'], { cwd: fn, stdio: 'inherit' });
// bb.js's native `bb` programs for four platforms (130 MB): the server's checks always run bb.js as WebAssembly
// (extra/experiments/noir-compact/browser/wasm.mjs, BackendType.Wasm with the pinned .wasm), never these.
await rm(path.join(fn, 'node_modules/@aztec/bb.js/build'), { recursive: true, force: true });

// 2. Static files, moved out of the function (the server only reads them to send them). The replay verifier and
// device checker stay in the function too: the retired proof upload checks with them on the server.
const move = async (from, to) => { await mkdir(path.dirname(to), { recursive: true }); await rename(from, to); };
await move(path.join(web, 'dist/compact'), path.join(statics, 'compact'));
await rm(path.join(statics, 'compact/asset-manifest.json')); // build metadata; the server never serves it
await move(path.join(web, 'dist/write'), path.join(statics, 'write'));
await move(path.join(web, 'dist/deck'), path.join(statics, 'deck'));
await move(path.join(web, 'dist/share/assets'), path.join(statics, 'share/assets'));
await cp(path.join(web, 'dist/replay'), path.join(statics, 'replay'), { recursive: true });
await copyFile(path.join(web, 'dist/device-verifier.js'), path.join(statics, 'device-verifier.js'));

// 3. The browser prover's proving points (/write/points/19 and /20), cut from the setup and checked against their pins.
const setup = process.env.HUMA_PROVING_SETUP_FILE ?? path.join(root, 'build/research/noir-crs/bn254_g1_compressed.dat');
await mkdir(path.join(statics, 'write/points'), { recursive: true });
const handle = await open(setup).catch(() => { throw Error(`Proving setup not found at ${setup} (set HUMA_PROVING_SETUP_FILE).`); });
try {
  for (const log of [19, 20]) {
    const bytes = Buffer.alloc(32 << log);
    if ((await handle.read(bytes, 0, bytes.length, 0)).bytesRead !== bytes.length) throw Error('Short proving setup file.');
    if (createHash('sha256').update(bytes).digest('hex') !== POINTS[log]) throw Error(`Proving points 2^${log} differ from their pin.`);
    await writeFile(path.join(statics, 'write/points', String(log)), bytes);
  }
} finally { await handle.close(); }

// 4. Routing: static files first (with the server's headers), everything else to the function.
const routes = [
  { src: '^/deck$', status: 301, headers: { Location: '/deck/' } },
  { src: '^/(?:compact/.*|device-verifier\\.js|replay/huma_replay_browser(?:\\.js|_bg\\.wasm))$', headers: { ...BASE, 'Cache-Control': 'no-cache' }, continue: true },
  { src: '^/compact/assets/.*\\.(?:vk|dat)$', headers: { 'Content-Type': BINARY }, continue: true },
  { src: '^/write/[a-z0-9-]+\\.(?:js|wasm|json|vk|dat)$', headers: { ...BASE, ...WRITE_ISOLATION, 'Cache-Control': 'no-cache' }, continue: true },
  { src: '^/write/[a-z0-9-]+\\.(?:vk|dat)$', headers: { 'Content-Type': BINARY }, continue: true },
  { src: '^/write/points/(?:19|20)$', headers: { ...BASE, ...WRITE_ISOLATION, 'Content-Type': BINARY, 'Cache-Control': IMMUTABLE }, continue: true },
  { src: '^/share/assets/.*$', headers: { ...BASE, 'Content-Security-Policy': SHARE_CSP, 'Cache-Control': IMMUTABLE }, continue: true },
  { src: '^/deck/.*$', headers: BASE, continue: true },
  { handle: 'filesystem' },
  { src: '^/.*$', dest: '/index' },
];
await writeFile(path.join(output, 'config.json'), JSON.stringify({ version: 3, routes }, null, 2) + '\n');
await writeFile(path.join(fn, '.vc-config.json'), JSON.stringify({ runtime: 'nodejs24.x', handler: 'vercel.mjs', launcherType: 'Nodejs',
  shouldAddHelpers: false, supportsResponseStreaming: true, maxDuration: 60 }, null, 2) + '\n');

// 5. Sizes against Vercel's limits: 250 MB for the unzipped function.
async function size(dir) {
  let total = 0, largest = ['', 0];
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile()) continue;
    const file = path.join(entry.parentPath, entry.name), { size: bytes } = await stat(file);
    total += bytes; if (bytes > largest[1]) largest = [path.relative(dir, file), bytes];
  }
  return { total, largest };
}
const mb = bytes => (bytes / 1048576).toFixed(1) + ' MB';
const [f, s] = await Promise.all([size(fn), size(statics)]);
if (f.total > 250 * 1048576) throw Error(`The function is ${mb(f.total)}, over Vercel's 250 MB.`);
// A function's response is at most 4.5 MB: any page or asset the function still sends must fit.
for (const dir of ['pages', 'dist']) {
  const { largest } = await size(path.join(web, dir));
  if (largest[1] > 4.5 * 1000 * 1000) throw Error(`frontend/${dir}/${largest[0]} (${mb(largest[1])}) is too large for the function; serve it as a static file.`);
}
console.log(`Vercel output ready: ${path.relative(root, output)}\n  function ${mb(f.total)} (${packaged.files} host files; largest ${f.largest[0]}, ${mb(f.largest[1])})` +
  `\n  static   ${mb(s.total)} (largest ${s.largest[0]}, ${mb(s.largest[1])})`);
