// Builds huma.social/write into frontend/dist/write: the page script, the prover worker and bb.js's thread worker, the
// three Rust WebAssembly modules (the recorder from extra/experiments/noir-compact/native, the witness solver from
// backend/integrations/noir/witness, Harper's grammar checks from backend/integrations/grammar), bb.js's threaded WebAssembly, and
// the pinned programs and keys. Every pin is checked.
// Usage (from frontend/): node write/build.mjs
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROGRAMS } from './pins.mjs';
import { KEYS, KEYS2, KEYS3 } from '../../backend/integrations/noir/long/reader.mjs';
import { ASSETS } from '../../extra/experiments/noir-compact/browser/profile.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), root = path.resolve(here, '../..'), out = path.join(root, 'frontend/dist/write');
const browser = path.join(root, 'extra/experiments/noir-compact/browser'), bb = path.join(browser, 'node_modules/@aztec/bb.js');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
if (JSON.parse(await readFile(path.join(bb, 'package.json'), 'utf8')).version !== '5.2.1') throw new Error('Unexpected bb.js version.');

// --js-only rebuilds just the page scripts (esbuild) into the existing dist/write, keeping its WebAssembly, programs
// and keys: for a change to the editor's JavaScript on a machine without the Rust and Noir build outputs.
const jsOnly = process.argv.includes('--js-only');
if (!jsOnly) {
// The Rust modules, from their pinned lockfiles. The recorder takes its randomness from the page.
const cargo = (dir, target, env = {}) => execFileSync('cargo', ['rustc', '--release', '--locked', '--lib', '--crate-type', 'cdylib',
  '--target', 'wasm32-unknown-unknown', '--target-dir', path.join(root, 'build', target)], { cwd: path.join(root, dir), stdio: 'inherit', env: { ...process.env, ...env } });
cargo('extra/experiments/noir-compact/native', 'web-recorder-target');
cargo('backend/integrations/noir/witness', 'witness-target', { RUSTFLAGS: '--cfg getrandom_backend="unsupported"' });
// Harper's grammar checks, the same as the Mac app's; its random numbers come from the page (grammar-worker.mjs).
cargo('backend/integrations/grammar', 'web-grammar-target', { RUSTFLAGS: '--cfg getrandom_backend="custom"' });

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await copyFile(path.join(root, 'build/web-recorder-target/wasm32-unknown-unknown/release/huma_compact_experiment.wasm'), path.join(out, 'recorder.wasm'));
await copyFile(path.join(root, 'build/witness-target/wasm32-unknown-unknown/release/huma_witness.wasm'), path.join(out, 'witness.wasm'));
await copyFile(path.join(root, 'build/web-grammar-target/wasm32-unknown-unknown/release/huma_grammar.wasm'), path.join(out, 'grammar.wasm'));
for (const name of ['barretenberg-threads.wasm', 'g2.dat']) {
  const bytes = await readFile(path.join(browser, 'assets', name));
  if (bytes.length !== ASSETS[name].bytes || sha(bytes) !== ASSETS[name].sha256) throw new Error('Asset pin mismatch: ' + name);
  await writeFile(path.join(out, name), bytes);
}
// Programs, as the Mac engine stages them (backend/integrations/noir/package.py), and every key a reader checks.
for (const [name, pin] of Object.entries(PROGRAMS)) {
  const program = JSON.parse(await readFile(path.join(root, 'build/research/noir-long3', name, `target/huma_long3_${name}.json`), 'utf8'));
  if (sha(program.bytecode) !== pin.bytecode) throw new Error('Program pin mismatch: ' + name);
  await writeFile(path.join(out, `long3-${name}.json`), JSON.stringify({ noir_version: program.noir_version, bytecode: program.bytecode, abi: program.abi }));
}
for (const [prefix, pins] of [['long-', KEYS], ['long2-', KEYS2], ['long3-', KEYS3]]) for (const [name, pin] of Object.entries(pins)) {
  const bytes = await readFile(path.join(browser, 'assets', prefix + name + '.vk'));
  if (sha(bytes) !== pin || (prefix === 'long3-' && sha(bytes) !== PROGRAMS[name].vk)) throw new Error('Key pin mismatch: ' + prefix + name);
  await writeFile(path.join(out, prefix + name + '.vk'), bytes);
}

}
// bb.js loads its WebAssembly and thread worker from this folder, never from a network address of its own.
const swaps = {
  [/fetch_code\/browser\/index\.js$/.source]: `export async function fetchCode(shared) {
    if (!shared) throw new Error('Proving here needs a cross-origin isolated page.');
    const response = await fetch(new URL('./barretenberg-threads.wasm', self.location.href), { credentials: 'omit', redirect: 'error' });
    return new Uint8Array(await response.arrayBuffer());
  }`,
  [/barretenberg_wasm_thread\/factory\/browser\/index\.js$/.source]: `import { readinessListener } from '${bb}/dest/browser/barretenberg_wasm/helpers/browser/index.js';
  export async function createThreadWorker() {
    const worker = new Worker(new URL('./bb-thread.js', import.meta.url), { type: 'module' });
    await new Promise(resolve => readinessListener(worker, resolve));
    return worker;
  }`,
  [/barretenberg_wasm_main\/factory\/browser\/index\.js$/.source]: `export async function createMainWorker() { throw new Error('The prover runs bb.js in its own worker.'); }`,
};
const plugin = { name: 'huma-write', setup(b) {
  for (const [filter, contents] of Object.entries(swaps)) b.onLoad({ filter: new RegExp(filter) }, () => ({ contents, loader: 'js', resolveDir: here }));
  // The reader's lazy loaders for the /verify page and Node; this page brings its own keys and checker.
  b.onResolve({ filter: /noir-compact\/browser\/(assurance-profile|profile|wasm)\.mjs$/ }, args => args.kind === 'dynamic-import'
    ? { path: 'unavailable', namespace: 'huma-write' } : undefined);
  b.onLoad({ filter: /^unavailable$/, namespace: 'huma-write' }, () => ({ contents: 'throw new Error("Not available on this page.");', loader: 'js' }));
} };
await build({
  entryPoints: { write: path.join(here, 'editor.mjs'), prover: path.join(here, 'prover-worker.mjs'), replay: path.join(root, 'frontend/pages/replay.mjs'), grammar: path.join(here, 'grammar-worker.mjs'), 'writer-actions': path.join(here, 'writer-actions.mjs'),
    'bb-thread': path.join(bb, 'dest/browser/barretenberg_wasm/barretenberg_wasm_thread/factory/browser/thread.worker.js') },
  bundle: true, format: 'esm', platform: 'browser', target: 'es2022', outdir: out, minify: true, legalComments: 'eof',
  external: ['node:*', '/write/replay.js'], nodePaths: [path.join(browser, 'node_modules'), path.join(root, 'frontend/node_modules')], plugins: [plugin], logLevel: 'warning',
});
const files = ['write.js', 'prover.js', 'bb-thread.js', 'replay.js', 'grammar.js', 'writer-actions.js', 'recorder.wasm', 'witness.wasm', 'grammar.wasm'];
const sizes = await Promise.all(files.map(async f => (await readFile(path.join(out, f))).length));
console.log('Built frontend/dist/write: ' + files.map((f, i) => `${f} ${(sizes[i] / 1024).toFixed(0)} KB`).join(', '));
