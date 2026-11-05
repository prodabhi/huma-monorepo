// Executes the pinned batch circuit with the engine's noir_js and writes its witness.
// node witness.mjs <noir_js index.mjs> <circuit.json> <witness out>  (inputs JSON on stdin)
import { readFile, writeFile } from 'node:fs/promises';

const [noirJs, circuitPath, out] = process.argv.slice(2);
const parts = [];
for await (const part of process.stdin) parts.push(part);
const inputs = JSON.parse(Buffer.concat(parts));
const { Noir } = await import(noirJs);
const { witness, returnValue } = await new Noir(JSON.parse(await readFile(circuitPath, 'utf8')))
  .execute(inputs, async () => { throw new Error('foreign calls disabled'); });
await writeFile(out, witness, { flag: 'wx', mode: 0o600 });
process.stdout.write(JSON.stringify({ returnValue: '0x' + BigInt(returnValue).toString(16).padStart(64, '0') }));
