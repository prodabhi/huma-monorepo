// Labels a real session for the report: a page shared on a registry (its store's records/<id>, which keeps the
// detection's feature values, never the raw events past a day) becomes a labelled session file. Consented sessions
// only: ask the writer first. Usage (from frontend/):
//   node detection/eval/label.mjs <store directory> <publication id> human|bot [modality] [generator]
// `modality` is what the writer used (physical_keyboard, touch, ime, mixed); the stored verdict's is the default.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [store, id, label, modality, generator] = process.argv.slice(2);
if (!store || !/^[a-f0-9]{64}$/.test(id ?? '') || !['human', 'bot'].includes(label)) {
  console.error('Usage: node detection/eval/label.mjs <store directory> <publication id> human|bot [modality] [generator]'); process.exit(2);
}
const record = JSON.parse(await readFile(path.join(store, 'publications', 'records', id), 'utf8'));
const detection = record.detection;
if (!detection?.features) { console.error('This page was shared without a typing verdict (no features kept).'); process.exit(1); }
const session = { label, generator: label === 'human' ? 'human' : (generator ?? 'unknown'), modality: modality ?? detection.modality, platform: detection.platform ?? 'web',
  publication: id, labelledAt: new Date().toISOString(), features: detection.features,
  integrity: { status: detection.integrity, failures: (detection.reasons ?? []).filter(r => r.feature.startsWith('integrity:')).map(r => ({ check: r.feature.slice(10), detail: r.detail })), penalties: [] },
  traps: detection.traps ?? {}, measures: detection.measures ?? {} };
await mkdir(path.join(here, 'sessions'), { recursive: true });
const file = path.join(here, 'sessions', `${label}-${id.slice(0, 12)}.json`);
await writeFile(file, JSON.stringify(session));
console.log('Labelled', file);
