// World ID (IDKit) on the write page: how a writer signs in (signInWithWorldID), once per browser. It shows one real,
// unique person writes under the account, and the account is that World ID's own (the server checks the proof,
// publications.mjs / worldid-verify.mjs), so a writer finishes documents only once signed in this way. Every page they
// share then shows that same anonymous World ID, on any device: their way to claim their pages. Off, and nothing is
// loaded, when the server has no World ID keys (GET /api/worldid says appId: null).
//
// What is asked for is Proof of Human and nothing weaker (a unique person is what the badge says), and the proof is
// made for this browser's publishing key (linkSignal), so it can link no other account. World App shows the writer
// what they are proving; the signing key never leaves the server (POST /api/worldid/context signs each request).
//
// A writer who scans nothing, declines in World App or lets it run out isn't signed in, so can't finish: they keep
// writing. Where World ID is only a badge (config.required false), an account without one can still link it at Finish
// (verifiedAuthor) or finish without it.
import { linkedWorldID, linkSignal, linkWorldID, worldIDSignIn } from './account.mjs';

export const SKIPPED = 'Finished without World ID.';
export const REQUIRED = 'Verify you’re human with World ID to finish.';
export const SIGN_IN = 'Sign in with World ID to keep and share your documents.';
const WAIT = 5 * 60 * 1000;
const DECLINED = new Set(['user_rejected', 'verification_rejected', 'user_presence_failed']);

let config = null;
/** { appId, rpId, action, environment } when World ID is on here, else null (or the server can't be asked). */
export function worldIDConfig() {
  config ??= fetch('/api/worldid').then(r => (r.ok ? r.json() : null)).then(value => (typeof value?.appId === 'string' && value.appId ? value : null), () => null);
  return config;
}
/** Whether World ID is on here. */
export const worldIDOn = async () => (await worldIDConfig()) !== null;
/** Whether finishing a document here needs a World ID. */
export const worldIDRequired = async () => (await worldIDConfig())?.required === true;

const $ = id => document.getElementById(id);
/** The QR for `uri`, as one SVG path (qr.mjs is the site's own copy, loaded when it's wanted). */
async function drawQR(uri) {
  const { default: encodeQR } = await import(new URL('/vendor/qr/qr.mjs', location.origin).href);
  const rows = encodeQR(uri, 'raw', { ecc: 'medium', border: 0 }), size = rows.length;
  let path = '';
  rows.forEach((row, y) => row.forEach((on, x) => { if (on) path += `M${x} ${y}h1v1h-1z`; }));
  $('worldidQR').innerHTML = `<svg viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" aria-hidden="true"><path fill="currentColor" d="${path}"/></svg>`;
}
const failure = code => (DECLINED.has(code) ? 'World ID was declined' : code === 'timed_out' ? 'World ID ran out of time' : 'World ID couldn’t be confirmed');

/**
 * A World ID proof made for `signal`: shows a QR and a link for World App and waits for the writer. Resolves
 * { proof } (the IDKit result) or { proof: null, reason } when World ID is off (reason null), skipped, declined or
 * timed out. It never rejects.
 */
export async function proveHuman(signal, { after: then } = {}) {
  const world = await worldIDConfig();
  if (!world) return { proof: null, reason: null };
  const dialog = $('worldid'), status = $('worldidStatus'), open = $('worldidOpen');
  const after = then ?? (world.required ? REQUIRED : SKIPPED);
  $('worldidSkip').textContent = then || world.required ? 'Cancel' : 'Finish Without It';
  const cancel = new AbortController();
  const stop = () => cancel.abort();
  const timer = setTimeout(stop, WAIT);
  $('worldidSkip').onclick = stop; dialog.oncancel = stop;
  try {
    status.textContent = 'Getting a request ready…'; open.hidden = true; $('worldidQR').replaceChildren();
    if (!dialog.open) dialog.showModal();
    const { rp_context } = await fetch('/api/worldid/context', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: cancel.signal })
      .then(r => (r.ok ? r.json() : Promise.reject(new Error('context'))));
    const { IDKit, proofOfHuman } = await import('@worldcoin/idkit-core');
    const request = await IDKit.request({ app_id: world.appId, action: world.action, rp_context, allow_legacy_proofs: true,
      environment: world.environment }).preset(proofOfHuman({ signal }));
    await drawQR(request.connectorURI);
    open.href = request.connectorURI; open.hidden = false;
    status.textContent = 'Waiting for World App…';
    const done = await request.pollUntilCompletion({ signal: cancel.signal, timeout: WAIT });
    if (done.success) return { proof: done.result, reason: null };
    return { proof: null, reason: failure(done.error) + '. ' + after };
  } catch {
    return { proof: null, reason: (cancel.signal.aborted ? 'World ID wasn’t completed' : 'World ID couldn’t be reached') + '. ' + after };
  } finally {
    clearTimeout(timer); dialog.oncancel = null;
    if (dialog.open) dialog.close();
  }
}

/**
 * Signs this browser in with World ID: a QR for World App, made for this browser's publishing key, then the server
 * checks it with World and links the key to that World ID's account. Resolves the account ({ wallet, name }), or
 * { reason } when it didn't happen: World ID off, cancelled, declined, timed out or refused.
 */
export async function signInWithWorldID() {
  if (!(await worldIDOn())) return { reason: 'Sign-in isn’t set up here yet.' };
  const { proof, reason } = await proveHuman(await linkSignal(), { after: SIGN_IN });
  if (!proof) return { reason };
  try { return await worldIDSignIn(proof); } catch (e) { return { reason: e.message || 'Couldn’t sign in with World ID.' }; }
}

/**
 * Before a document is finished, signed in: the account's World ID, linked the first time (a QR for World App, then
 * the server checks it with World). Resolves { ok: true, worldId, linkedNow } once the account has one (worldId as
 * readers see it), or { ok: false, reason } when it isn't linked: cancelled, declined, timed out, or held by another
 * account.
 */
export async function verifiedAuthor() {
  let linked;
  try { linked = await linkedWorldID(); } catch (e) { return { ok: false, reason: e.message || 'Couldn’t reach your account. Try again.' }; }
  if (linked) return { ok: true, worldId: linked, linkedNow: false };
  const { proof, reason } = await proveHuman(await linkSignal());
  if (!proof) return { ok: false, reason };
  try { return { ok: true, worldId: await linkWorldID(proof), linkedNow: true }; }
  catch (e) { return { ok: false, reason: e.message || 'World ID couldn’t be confirmed.' }; }
}
