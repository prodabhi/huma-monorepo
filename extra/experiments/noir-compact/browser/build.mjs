import { build } from 'esbuild';
import { readFile, mkdir, copyFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ASSETS } from './profile.mjs';
import { VK_PIN } from '../../noir-media/reader/profile.mjs';
import { ASSETS as POLICY_ASSETS } from './assurance-profile.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
if (process.argv.slice(2).some(a => a !== '--web')) throw new Error('Unknown build option.');
const outdir = path.resolve(here, process.argv.includes('--web') ? '../../../../frontend/dist/compact' : '../../../../build/research/noir-compact-browser');
const packageInfo = JSON.parse(await readFile(path.join(here, 'node_modules/@aztec/bb.js/package.json')));
if (packageInfo.version !== '5.2.1') throw new Error('Unexpected cryptographic SDK version.');
await mkdir(path.join(outdir, 'assets'), { recursive: true });
for (const [name, pin] of Object.entries({ ...ASSETS, ...POLICY_ASSETS })) {
  const source = path.join(here, 'assets', name), bytes = await readFile(source);
  if (bytes.length !== pin.bytes || createHash('sha256').update(bytes).digest('hex') !== pin.sha256) throw new Error('Asset pin mismatch: ' + name);
  await copyFile(source, path.join(outdir, 'assets', name));
}
let replaced = 0;
const mediaKey = await readFile(path.resolve(here, '../../noir-media/reader/assets/media-membership.vk'));
if (mediaKey.length !== VK_PIN.bytes || createHash('sha256').update(mediaKey).digest('hex') !== VK_PIN.sha256) throw new Error('Media key pin mismatch.');
await writeFile(path.join(outdir, 'assets/media-membership.vk'), mediaKey);
const result = await build({
  absWorkingDir: here, entryPoints: { 'compact-verifier': 'client.mjs', 'compact-worker': 'worker.mjs', 'compact-inline': 'inline.mjs', 'media-inline': '../../noir-media/reader/inline.mjs', 'assurance-inline': 'assurance-inline.mjs', 'long-inline': '../../../../backend/integrations/noir/long/reader.mjs' },
  external: ['node:*'],
  outdir, bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
  legalComments: 'eof', metafile: true,
  plugins: [{ name: 'pinned-local-wasm', setup(builder) {
    builder.onLoad({ filter: /bb\.js\/dest\/browser\/barretenberg_wasm\/fetch_code\/browser\/index\.js$/ }, async () => {
      replaced++;
      return { contents: await readFile(path.join(here, 'asset-loader.mjs'), 'utf8'), loader: 'js', resolveDir: here };
    });
  } }],
});
if (replaced !== 1) throw new Error('The expected SDK asset loader was not replaced exactly once.');
if (Object.keys(result.metafile.inputs).some(p => /fetch_code\/browser\/barretenberg(?:-threads)?\.js$/.test(p))) throw new Error('Unexpected embedded WASM download code.');
const allAssets = { ...ASSETS, ...POLICY_ASSETS, 'media-membership.vk': VK_PIN };
await writeFile(path.join(outdir, 'asset-manifest.json'), JSON.stringify({ sdk: '5.2.1', assets: allAssets, inputFiles: Object.keys(result.metafile.inputs).length }, null, 2) + '\n');
console.log(JSON.stringify({ outdir, sdk: packageInfo.version, pinnedAssets: Object.keys(allAssets).length, bytes: Object.values(result.metafile.outputs).reduce((n, f) => n + f.bytes, 0) }));
