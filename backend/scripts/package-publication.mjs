// Build a reviewable host context from explicit runtime files, never the checkout.
import { chmod, copyFile, mkdir, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { shareAssetFiles } from '../../frontend/share-assets.mjs';
import { ASSETS as COMPACT } from '../../extra/experiments/noir-compact/browser/profile.mjs';
import { ASSETS as ASSURANCE } from '../../extra/experiments/noir-compact/browser/assurance-profile.mjs';
import { POSTS, IMAGES } from '../../frontend/blog.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const names = (prefix, files) => files.split(' ').map(file => prefix + file);
export const fixed = [
  ...names('frontend/', 'registry.mjs registry-verifier.mjs publications.mjs publication-verifier.mjs object-store.mjs upload-quotas.mjs publication-contract.mjs replay-core.mjs requests.mjs documents.mjs deployment-check.mjs share-assets.mjs turnstile-verify.mjs sessions.mjs client-ip.mjs events.mjs worldid-verify.mjs arkiv-store.mjs hash-record.mjs server-util.mjs websocket.mjs onchain.mjs'),
  // The typing analysis of a browser page's streamed session (frontend/detection): its receiver, checks, features, traps, scoring and tables.
  ...names('frontend/detection/', 'stream.mjs session.mjs integrity.mjs features.mjs stats.mjs keyboard.mjs traps.mjs score.mjs judge.mjs baseline.mjs model.mjs thresholds.json bigrams.json wordfreq.json'),
  'frontend/write/canary.mjs',
  // Writing in the browser: the page, its pins (the server checks the proving points against them) and its build.
  'frontend/pages/write.html', 'frontend/write/pins.mjs',
  ...names('frontend/dist/write/', 'write.js prover.js bb-thread.js replay.js grammar.js writer-actions.js recorder.wasm witness.wasm grammar.wasm barretenberg-threads.wasm g2.dat'
    + ' long-chunk.vk long-final1024.vk long-final4096.vk long-final10000.vk long2-final1024.vk long2-final4096.vk long2-final10000.vk'
    + ['chunk1024', 'final1024', 'chunk4096', 'final4096', 'chunk10000', 'final10000'].map(n => ` long3-${n}.json long3-${n}.vk long3-${n}-evm.vk`).join('')),
  ...names('frontend/verify-core/', 'browser.mjs worker.mjs core.mjs contract.mjs node.mjs node-worker.mjs node-engine.mjs'),
  ...names('frontend/pages/', 'ask.html ask.js guide-prove.html guide-detector.html robots.txt sitemap.xml llms.txt download.html download.js privacy.html terms.html partials/nav.html partials/footer.html partials/footer-compact.html partials/cta-short.html partials/cta-end.html notfound.html appcast.xml verify.html verify.mjs writer.html writer.mjs track.mjs visit.mjs replay-player.mjs site.css replay-worker.mjs brand/huma-mark.svg brand/icon-512.png fonts/inter.woff2 fonts/OFL.txt fonts/newsreader-latin.woff2 fonts/newsreader-latin-ext.woff2 fonts/NEWSREADER-OFL.txt img/og-page.png img/og-home.jpg'),
  // A shared page's PDF report: its maker, fonts, QR code (MIT) and PDF library (MIT), loaded only when it's made.
  ...names('frontend/pages/', 'report-pdf.mjs fonts/tinos-report.ttf fonts/tinos-bold-report.ttf fonts/TINOS-OFL.txt vendor/qr/qr.mjs vendor/qr/LICENSE.txt vendor/pdf-lib/pdf-lib.mjs vendor/pdf-lib/fontkit.js vendor/pdf-lib/LICENSE-pdf-lib.txt vendor/pdf-lib/LICENSE-fontkit.txt'),
  // The blog (frontend/blog.mjs lists its posts and pictures).
  'frontend/blog.mjs', 'frontend/pages/blog/index.html', ...POSTS.map(post => `frontend/pages/blog/${post}.html`), ...IMAGES.map(image => 'frontend/pages/blog/img/' + image),
  // The landing page (foundation.html at /): the page, its scripts, mark, fonts, hero poster.
  ...names('frontend/pages/', 'foundation.html foundation.css foundation.js foundation-logo.svg fonts/geist-mono.woff2 fonts/GEIST-OFL.txt foundation-media/hero-art.webp'),
  ...names('frontend/dist/', 'device-verifier.js replay/huma_replay_browser.js replay/huma_replay_browser_bg.wasm'),
  ...names('frontend/dist/compact/', 'compact-verifier.js compact-worker.js compact-inline.js assurance-inline.js media-inline.js long-inline.js asset-manifest.json'),
  ...names('extra/experiments/noir-compact/browser/', 'core.mjs profile.mjs wasm.mjs node-verifier.mjs assurance-core.mjs assurance-profile.mjs assurance-node.mjs final-text.mjs'),
  'backend/integrations/noir/long/reader.mjs',
  ...names('extra/experiments/noir-media/reader/', 'core.mjs profile.mjs node-verifier.mjs assets/media-membership.vk'),
  ...names('backend/integrations/attestation/', 'portable.mjs portable-core.mjs protocol.mjs service.mjs apple.mjs certificates/Apple_App_Attestation_Root_CA.pem certificates/AppleRootCA-G3.cer'),
];

export async function packagePublication(destination) {
  destination = path.resolve(destination);
  if (destination === root || root.startsWith(destination + path.sep)) throw Error('Use a new output directory.');
  const mapping = new Map(fixed.map(file => [file, file]));
  for (const [output, input] of Object.entries({ 'package.json': 'backend/hosting/package.json', 'package-lock.json': 'backend/hosting/package-lock.json',
    Dockerfile: 'backend/hosting/Dockerfile', '.dockerignore': 'backend/hosting/.dockerignore' })) mapping.set(output, input);
  for (const name of Object.keys({ ...COMPACT, ...ASSURANCE })) {
    mapping.set('extra/experiments/noir-compact/browser/assets/' + name, 'extra/experiments/noir-compact/browser/assets/' + name);
    mapping.set('frontend/dist/compact/assets/' + name, 'frontend/dist/compact/assets/' + name);
  }
  mapping.set('frontend/dist/compact/assets/media-membership.vk', 'frontend/dist/compact/assets/media-membership.vk');
  for (const name of await shareAssetFiles(path.join(root, 'frontend'))) mapping.set('frontend/dist/share/' + name, 'frontend/dist/share/' + name);
  // Optional public research deck. It is a compiled directory already served by
  // the website, restricted to the same static extensions as its HTTP route.
  async function deck(directory = '') {
    for (const entry of await readdir(path.join(root, 'frontend/dist/deck', directory), { withFileTypes: true })) {
      const name = path.posix.join(directory, entry.name);
      if (entry.isDirectory()) await deck(name);
      else if (entry.isFile() && /^[A-Za-z0-9_./-]+\.(?:html|js|css|woff2|jpg|txt)$/.test(name)) mapping.set('frontend/dist/deck/' + name, 'frontend/dist/deck/' + name);
    }
  }
  await deck();
  // Resolve every input before creating output. A symlink cannot pull unrelated
  // files into the artifact, and missing build inputs leave no partial package.
  for (const input of mapping.values()) {
    const source = path.join(root, input);
    if ((await realpath(source)) !== source || !(await stat(source)).isFile()) throw Error('Unexpected or missing hosting input: ' + input);
  }
  await mkdir(destination, { mode: 0o700 }); // Refuse overwriting any prior bundle.
  const files = {}, directories = new Set([destination]);
  for (const [output, input] of [...mapping].sort(([a], [b]) => a.localeCompare(b))) {
    const target = path.join(destination, output);
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(path.join(root, input), target);
    // Public verifier keys can originate in private research directories. Give
    // the host user read access to copies without altering original permissions.
    await chmod(target, 0o644);
    for (let dir = path.dirname(target); dir !== destination; dir = path.dirname(dir)) directories.add(dir);
    const bytes = await readFile(target);
    files[output] = { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
  }
  const manifest = { kind: 'huma-publication-host-bundle-v1', credentialsIncluded: false,
    privateDraftsIncluded: false, provingToolsIncluded: false, files };
  await writeFile(path.join(destination, 'bundle-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  await chmod(path.join(destination, 'bundle-manifest.json'), 0o644);
  for (const directory of directories) await chmod(directory, 0o755);
  return { directory: destination, files: mapping.size, bytes: Object.values(files).reduce((n, file) => n + file.bytes, 0) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw Error('Usage: node backend/scripts/package-publication.mjs <new-output-directory>');
  console.log(JSON.stringify(await packagePublication(process.argv[2])));
}
