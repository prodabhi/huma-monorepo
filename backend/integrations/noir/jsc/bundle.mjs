// Bundles a staged engine's worker.mjs (with its readers) into one worker.js for HumaScriptHost, macOS's own
// JavaScriptCore.
// Usage (from package.py): node backend/integrations/noir/jsc/bundle.mjs <staged NoirEngine folder>
import { writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url)), root = path.resolve(here, '../../../..');
const engine = path.resolve(process.argv[2] ?? '');
const { build } = createRequire(path.join(root, 'frontend/package.json'))('esbuild');
const shim = name => path.join(here, 'shims', name + '.mjs');
const aliases = { 'node:fs/promises': shim('fs'), 'node:child_process': shim('child_process'), 'node:crypto': shim('crypto'),
  'node:path': shim('path'), 'node:url': shim('url') };
const result = await build({
  entryPoints: [path.join(here, 'entry.mjs')], bundle: true, write: false, format: 'esm', platform: 'neutral', target: 'es2022',
  mainFields: ['module', 'main'], conditions: ['import', 'default'], nodePaths: [path.join(root, 'frontend/node_modules')],
  define: { 'import.meta.url': 'globalThis.__humaWorkerURL' }, legalComments: 'none', logLevel: 'warning',
  plugins: [{ name: 'huma-engine', setup(b) {
    b.onResolve({ filter: /^node:/ }, args => aliases[args.path] ? { path: aliases[args.path] } : { errors: [{ text: 'No ' + args.path + ' in the engine.' }] });
    b.onResolve({ filter: /^\.\/worker\.mjs$/ }, () => ({ path: path.join(engine, 'worker.mjs') }));
    // Browser-only helpers the readers import lazily; never reached in the engine.
    b.onResolve({ filter: /experiments\/noir-compact\/browser\// }, () => ({ path: shim('unavailable') }));
  } }],
});
const [output] = result.outputFiles;
if (/^\s*(import|export)\s/m.test(output.text) || output.text.includes('import.meta')) throw new Error('The bundle still has module syntax.');
// One async function, so the worker's top-level awaits run as a classic script; the host waits for it to settle.
await writeFile(path.join(engine, 'worker.js'), '(async () => {\n' + output.text + '\n})()\n', { mode: 0o644 });
console.log(`Bundled worker.js (${(output.text.length / 1024).toFixed(0)} KB) for JavaScriptCore.`);
