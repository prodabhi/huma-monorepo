// Asset imports resolve against the registry's public, explicit asset routes.
import init, { verify_replay, public_replay } from '../replay/huma_replay_browser.js';
import { readerPolicy, verifyPortableDeviceEvidence } from '../device-verifier.js';
import { createEvidenceVerifier } from './core.mjs';
// The replay engine is 2.4 MB; only older replay proofs need it, so load it on first use.
let ready;
const replay = () => (ready ??= init());
const engine = createEvidenceVerifier({
  verifyReplay: async (source, text, key) => { await replay(); return JSON.parse(verify_replay(source, text, key)); },
  verifyCompact: async (source, options) => {
    const { verifyCompactInline } = await import('../compact/compact-inline.js');
    return verifyCompactInline(source, options);
  },
  verifyMedia: async (source, options) => {
    const { verifyMediaInline } = await import('../compact/media-inline.js');
    return verifyMediaInline(source, options);
  },
  verifyAssurance: async (source, options) => {
    const { verifyAssuranceInline } = await import('../compact/assurance-inline.js');
    return verifyAssuranceInline(source, options);
  },
  verifyLong: async (source, options) => {
    const { verifyLongInline } = await import('../compact/long-inline.js');
    // A page written on this computer's own server (localhost, while developing) carries its passkey for that origin.
    return verifyLongInline(source, options, self.location.hostname === 'localhost' ? { passkeyRelyingParties: [{ id: self.location.hostname, origin: self.location.origin }] } : {});
  },
  verifyDevice: verifyPortableDeviceEvidence, devicePolicy: readerPolicy,
  publicReplay: async source => { await replay(); return public_replay(source); },
});
let busy = false;
self.onmessage = async ({ data }) => {
  // Sent first by a page that's still downloading what it will check (browser.mjs, prepare); no reply.
  if (data?.command === 'prepare') { import('../compact/long-inline.js').then(m => m.prepareLongInline()).catch(() => {}); return; }
  if (busy) return;
  busy = true;
  try {
    if (!['verify', 'envelope'].includes(data?.command)) throw new Error('Unsupported command.');
    const result = data.command === 'verify' ? await engine.verify(data.source, data.policy, data.content, data.attachments)
      : await engine.envelope(data.source, data.policy, data.content, data.attachments);
    self.postMessage({ result });
  } catch { self.postMessage({ error: 'Local evidence check failed.' }); }
  finally { self.close(); }
};
