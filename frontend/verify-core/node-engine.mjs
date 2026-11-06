// Internal worker engine. Public Node callers use node.mjs for resource bounds.
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { initSync, verify_replay, public_replay } from '../dist/replay/huma_replay_browser.js';
import { verifyCompactPublic } from '../../extra/experiments/noir-compact/browser/node-verifier.mjs';
import { verifyMediaPublic } from '../../extra/experiments/noir-media/reader/node-verifier.mjs';
import { verifyAssurancePublic } from '../../extra/experiments/noir-compact/browser/assurance-node.mjs';
import { verifyLongNode } from '../../backend/integrations/noir/long/reader.mjs';
import { readerPolicy, verifyPortableDeviceEvidence } from '../../backend/integrations/attestation/portable.mjs';
import { createEvidenceVerifier } from './core.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
initSync({ module: await readFile(new URL('../dist/replay/huma_replay_browser_bg.wasm', import.meta.url)) });
export const engine = createEvidenceVerifier({
  verifyReplay: async (source, text, key) => JSON.parse(verify_replay(source, text, key)),
  verifyCompact: verifyCompactPublic, verifyAssurance: verifyAssurancePublic, verifyLong: verifyLongNode, verifyMedia: verifyMediaPublic, verifyDevice: verifyPortableDeviceEvidence,
  devicePolicy: readerPolicy, publicReplay: public_replay,
});
