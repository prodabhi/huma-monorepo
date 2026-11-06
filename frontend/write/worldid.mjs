// World ID (IDKit) on the write page. Every document is started and finished by one real, unique person: Start
// Recording asks for a World ID made for that writing session (scanAtStart; the host confirms it while the writer is
// already typing, confirmStart, and that also signs a new writer in), and Finish asks again for one made for the
// finished page's text and proof (finishWithWorldID). The server checks both with World and that they're the same
// person, the account's (publications.mjs / worldid-verify.mjs). Every page
// then shows that same anonymous World ID, on any device: the writer's way to claim their pages. Off, and nothing is
// loaded, when the server has no World ID keys (GET /api/worldid says appId: null).
//
// What is asked for is Proof of Human and nothing weaker (a unique person is what the badge says), and the proof is
// made for this browser's publishing key (linkSignal), so it can link no other account. World App shows the writer
// what they are proving; the signing key never leaves the server (POST /api/worldid/context signs each request).
//
// A writer who scans nothing, declines in World App or lets it run out isn't signed in, so can't finish: they keep
// writing. Where World ID is only a badge (config.required false), an account without one can still link it at Finish
// (verifiedAuthor) or finish without it.
import { linkedWorldID, linkSignal, linkWorldID, worldIDSignIn, startSignal, worldIDStart } from './account.mjs';

export const SKIPPED = 'Finished without World ID.';
export const REQUIRED = 'Verify you’re human with World ID to finish.';
export const SIGN_IN = 'Sign in with World ID to keep and share your documents.';
export const START = 'Verify you’re human with World ID to start writing.';
export const FINISH = 'Verify you’re human with World ID to finish and share this page.';
// What the dialog says, for each time World ID is asked.
const LEADS = {
  signin: 'Huma accounts are for real people. Scan with World App to sign in. Every page you share shows the same anonymous World ID, so you can show they’re yours. It never says who you are.',
  start: 'Every Huma document is started by a real person. Scan with World App to start writing: it ties you to this document, never says who you are.',
  finish: 'And finished by the same person. Scan with World App again to seal this page: it ties you to this exact text and its proof.',
};
const WAIT = 5 * 60 * 1000;
const DECLINED = new Set(['user_rejected', 'verification_rejected', 'user_presence_failed']);

let config = null, hostMissing = false;
/** { appId, rpId, action, environment } when World ID is on here, else null (or the server can't be asked). A host that
 *  says it's missing its World ID keys (production without them) is remembered: nothing can be shared from it. */
export function worldIDConfig() {
  config ??= fetch('/api/worldid').then(r => (r.ok ? r.json() : null)).then(value => { hostMissing = value?.missing === true; return typeof value?.appId === 'string' && value.appId ? value : null; }, () => null);
  return config;
}
/** Whether World ID is on here. */
export const worldIDOn = async () => (await worldIDConfig()) !== null;
export const WORLD_ID_UNCONFIGURED = 'This host isn’t set up for World ID, so pages can’t be shared from it.';
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
export async function proveHuman(signal, { after: then, lead = 'signin', cancel: outside } = {}) {
  const world = await worldIDConfig();
  if (!world) return { proof: null, reason: null };
  const dialog = $('worldid'), status = $('worldidStatus'), open = $('worldidOpen');
  const after = then ?? (world.required ? REQUIRED : SKIPPED);
  $('worldidLead').textContent = LEADS[lead] ?? LEADS.signin;
  $('worldidSkip').textContent = then || world.required ? 'Cancel' : 'Finish Without It';
  const cancel = new AbortController();
  const stop = () => cancel.abort();
  const timer = setTimeout(stop, WAIT);
  $('worldidSkip').onclick = stop; dialog.oncancel = stop;
  // The caller can call it off too (`cancel`): a share whose upload failed closes the scan it started alongside.
  if (outside?.aborted) stop(); else outside?.addEventListener('abort', stop, { once: true });
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
    // Asked twice a second, so the page moves on soon after World App answers.
    const done = await request.pollUntilCompletion({ signal: cancel.signal, timeout: WAIT, pollInterval: 500 });
    if (done.success) return { proof: done.result, reason: null };
    return { proof: null, reason: failure(done.error) + '. ' + after };
  } catch {
    return { proof: null, reason: (cancel.signal.aborted ? 'World ID wasn’t completed' : 'World ID couldn’t be reached') + '. ' + after };
  } finally {
    clearTimeout(timer); dialog.oncancel = null; outside?.removeEventListener('abort', stop);
    if (dialog.open) dialog.close();
  }
}
/** Gets World ID ready ahead of its first scan, while the page loads: the server's config and IDKit's code, so the
 *  first QR waits only for World's bridge. */
export function prepareWorldID() {
  worldIDConfig().then(world => { if (world) import('@worldcoin/idkit-core').catch(() => {}); });
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
 * Start Recording's World ID scan, for writing session `nonce`: a QR for World App made for this session and this
 * browser's key. Resolves { ok: true, proof } as soon as World App answers (proof null where World ID is off or only a
 * badge: nothing to send), or { ok: false, reason } when it wasn't completed. The host confirms it separately
 * (confirmStart), so writing can begin without waiting for that round trip.
 */
export async function scanAtStart(nonce) {
  const world = await worldIDConfig();
  if (hostMissing) return { ok: false, reason: WORLD_ID_UNCONFIGURED };
  if (!world?.required) return { ok: true, proof: null };
  const { proof, reason } = await proveHuman(await startSignal(nonce), { after: START, lead: 'start' });
  return proof ? { ok: true, proof } : { ok: false, reason };
}
/** Sends a Start scan to the host, which checks it with World, keeps it with the session, and signs this browser in to
 *  that World ID's account if it isn't yet. Resolves the account ({ wallet, name }); rejects with the host's reason.
 *  A dropped connection or a busy host (no answer, or a 5xx) is tried again a few times; a refusal is not. */
export async function confirmStart(nonce, proof) {
  for (let attempt = 1; ; attempt++) {
    try { return await worldIDStart(nonce, proof); }
    catch (e) {
      if ((e.status && e.status < 500) || attempt === 4) throw e;
      await new Promise(resolve => setTimeout(resolve, 1500 * attempt));
    }
  }
}
/**
 * Finish's World ID, for the finished page (`signal`: its text and proof, publication-contract.mjs pageSignal): the
 * proof sent with the share, or null where World ID is off or only a badge. Throws when it's required and wasn't given.
 * `cancel` (an AbortSignal) calls the scan off, as when the share it goes with can't happen.
 */
export async function finishWithWorldID(signal, { cancel } = {}) {
  const world = await worldIDConfig();
  if (!world?.required) return null;
  const { proof, reason } = await proveHuman(signal, { after: FINISH, lead: 'finish', cancel });
  if (!proof) throw new Error(reason ?? FINISH);
  return proof;
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
