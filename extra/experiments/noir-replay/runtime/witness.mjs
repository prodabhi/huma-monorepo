import { readFile, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { Noir } from '@noir-lang/noir_js';

// Native-app experiment only. No browser capture, RPC, network prover or key access.
const started = performance.now();
try {
  const [artifactPath, inputPath, outputPath] = process.argv.slice(2);
  if (!artifactPath || !inputPath || !outputPath) throw new Error('arguments');
  const raw = await readFile(inputPath);
  if (raw.length > 32 * 1024 * 1024) throw new Error('size');
  const artifact = JSON.parse(await readFile(artifactPath, 'utf8'));
  if (!artifact.noir_version.startsWith('1.0.0-beta.25+')) throw new Error('version');
  function exact(value) {
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error('integer');
      return String(value);
    }
    if (Array.isArray(value)) return value.map(exact);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, exact(v)]));
    return value;
  }
  const inputs = exact(JSON.parse(raw));
  const loaded = performance.now();
  const noir = new Noir(artifact);
  const { witness } = await noir.execute(inputs, async () => { throw new Error('foreign call disabled'); });
  const solved = performance.now();
  await writeFile(outputPath, witness, { mode: 0o600 });
  process.stdout.write(JSON.stringify({ sdk: '1.0.0-beta.25', loadMs: loaded - started,
    executeMs: solved - loaded, totalMs: performance.now() - started, witnessBytes: witness.length }));
} catch {
  // Do not echo private inputs, SDK assertion values or witness bytes to logs.
  process.stderr.write('Local Noir witness generation failed.\n');
  process.exitCode = 1;
}
