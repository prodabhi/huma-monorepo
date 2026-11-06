// Writes, for each case, test/fixtures/<case>/page-proof.json (the public page proof's evidence fields, as a browser page
// proof carries them, with its parts' and final public inputs) and evidence.json (for the contract tests: the writer key
// and signed events converted exactly as the server converts a page proof, frontend/onchain.mjs evidenceCall). Input: the long3 case files the fixtures' proofs were made from (long_cases.rs output, `capsule`).
// Usage: node scripts/evidence-fixtures.mjs <case dir with long-case-*.json>
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const { evidenceCall } = await import(new URL('../../../frontend/onchain.mjs', import.meta.url).href);
const b64 = bytes => Buffer.from(bytes).toString('base64');
for (const name of ['long-case-400', 'long-case-1500', 'long-case-4200']) {
  const c = JSON.parse(readFileSync(path.join(process.argv[2], name + '.json'), 'utf8')), k = c.capsule, dir = path.join(here, '../test/fixtures', name);
  const parts = readdirSync(dir).filter(d => /^part\d+$/.test(d)).sort((a, b) => a.slice(4) - b.slice(4));
  const pageProof = { kind: 'huma-long-assurance-public-proof-v3', profile: 'assurance-long-v3', publicKey: b64(k.public_key), events: c.events,
    checkpointRoots: k.checkpoint_roots, presenceRoots: k.presence_roots, signatures: k.signatures.map(b64), presenceSignatures: k.presence_signatures.map(b64),
    chunkInputs: parts.map(p => b64(readFileSync(path.join(dir, p, 'public_inputs')))), finalInputs: b64(readFileSync(path.join(dir, 'final/public_inputs'))) };
  writeFileSync(path.join(dir, 'page-proof.json'), JSON.stringify(pageProof, null, 1) + '\n');
  const { writer, events } = evidenceCall(pageProof);
  const out = { x: writer.x, y: writer.y, kinds: events.map(e => e.kind), roots: events.map(e => e.root), r: events.map(e => e.r), s: events.map(e => e.s) };
  writeFileSync(path.join(dir, 'evidence.json'), JSON.stringify(out, null, 1) + '\n');
  console.log(name, events.length, 'events');
}
