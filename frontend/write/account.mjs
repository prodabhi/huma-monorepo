// The writer's account in this browser. Sign-in is with World ID, right here (worldid.mjs, worldIDSignIn): the server
// links this browser's publishing key to the account that World ID holds. (Privy sign-in, on Huma's sign-in page, is
// off for now; its code is kept below, commented out.) From then on this page signs its own requests with that key: it
// keeps documents in the account (documents.mjs) and makes a page's view link at Finish without another tab.
import { b64, signDER, writingKey } from './recorder.mjs';
import { pageSignal, accountSignal, worldIDSigninMessage, documentRequestMessage, publicationMessage, replayMessage, listedMessage, titleMessage, signinMessage, removalMessage, cleanTitle, digest, FULL_LINK, SHORT_LINK, SIGNIN_PENDING } from '../publication-contract.mjs';
import { hex } from '../verify-core/contract.mjs';
import { humanToken } from './turnstile.mjs';
import { track } from '../pages/track.mjs';

const ACCOUNT = 'huma-account', PROFILE = 'huma-profile', PASSKEYS = 'huma-passkeys';
const encoder = new TextEncoder();

/** This browser's publishing key (kept like the writing key, apart from it) and its public key as x9.63 hex. */
let keyPromise;
function publishingKey() {
  keyPromise ??= writingKey('publish').then(async pair => ({ pair, publicKey: hex(await crypto.subtle.exportKey('raw', pair.publicKey)) }));
  return keyPromise;
}
const signed = async text => signDER((await publishingKey()).pair.privateKey, encoder.encode(text));

/** Who is signed in here: { wallet, name }, or null. */
export function account() {
  try { const value = JSON.parse(localStorage.getItem(ACCOUNT) ?? 'null'); return value?.wallet ? value : null; } catch { return null; }
}
export function signOut() { try { localStorage.removeItem(ACCOUNT); localStorage.removeItem(PROFILE); localStorage.removeItem(PASSKEYS); } catch {} }

/** Signs this browser in with a World ID made for its publishing key (worldid.mjs signInWithWorldID), the request
 *  signed by that key. The server checks it with World; the account is that World ID's own, the same on every device,
 *  and links this browser's key as a Privy sign-in did. Resolves { wallet, name }: `wallet` names the account, it is
 *  no wallet. */
export async function worldIDSignIn(proof) {
  const { publicKey } = await publishingKey(), body = JSON.stringify({ publicKey, proof });
  const signature = await signed(worldIDSigninMessage(publicKey, await digest(encoder.encode(body))));
  const response = await fetch('/api/worldid/signin', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Huma-Signature': signature }, body });
  const reply = await response.json().catch(() => ({}));
  if (!response.ok || reply.status !== 'signed-in' || !reply.wallet) throw new Error(reply.error ?? 'Couldn’t sign in with World ID.');
  const value = { wallet: reply.wallet, name: typeof reply.account === 'string' ? reply.account.slice(0, 200) : null };
  try { localStorage.setItem(ACCOUNT, JSON.stringify(value)); } catch {}
  track('signed_in');
  return value;
}

// Privy sign-in, off for now: World ID signs writers in instead (worldIDSignIn above). Kept to turn back on.
//
// // The sign-in this browser started (SIGNIN_PENDING) is kept on this site, so the sign-in page links only a key
// // whose sign-in began here.
// async function begin() {
//   const { publicKey } = await publishingKey(), code = hex(crypto.getRandomValues(new Uint8Array(32)));
//   try { localStorage.setItem(SIGNIN_PENDING, code); } catch {}
//   return { code, publicKey };
// }
// /** Who signed in for `code`, once the account has linked this browser; null until then. The read is signed with this
//  *  browser's publishing key, which shows the server the key the account linked is this browser's. */
// async function linked(code) {
//   const { publicKey } = await publishingKey();
//   const response = await fetch('/api/publications/signin', { headers: { 'X-Huma-Signin': code, 'X-Huma-Signature': await signed(signinMessage(code, publicKey)) } }).catch(() => null);
//   if (response?.status === 409) throw new Error('This browser is already linked to another account.');
//   const reply = response?.ok ? await response.json().catch(() => null) : null;
//   if (reply?.status !== 'signed-in' || !reply.device || !reply.wallet) return null;
//   const value = { wallet: reply.wallet, name: typeof reply.account === 'string' ? reply.account.slice(0, 200) : null };
//   try { localStorage.setItem(ACCOUNT, JSON.stringify(value)); localStorage.removeItem(SIGNIN_PENDING); } catch {}
//   return value;
// }
// /** Sign-in in this tab, with nothing recording: to Huma's sign-in page and straight back to `returnTo`. */
// export async function signInHere(returnTo) {
//   const { code, publicKey } = await begin();
//   track('sign_in_started');
//   location.href = `/share/signin?web&return=${encodeURIComponent(returnTo)}#${code}.${publicKey}`;
// }
// /** Back from signing in: finishes it when the account has linked this browser. */
// export async function finishSignIn() {
//   let code = null;
//   try { code = localStorage.getItem(SIGNIN_PENDING); } catch {}
//   if (!code || account()) return account();
//   for (let i = 0; i < 3; i++) {
//     if (i) await new Promise(resolve => setTimeout(resolve, 700));
//     const me = await linked(code);
//     if (me) { track('signed_in'); return me; }
//   }
//   // A sign-in left unfinished isn't waited for again on every page load.
//   try { localStorage.removeItem(SIGNIN_PENDING); } catch {}
//   return null;
// }
// /**
//  * Sign-in while writing, which mustn't leave this tab: a small window (`popup`, opened by the click so it isn't
//  * blocked) signs in and closes itself, and this resolves once the account links this browser.
//  */
// export async function signIn(popup) {
//   const { code, publicKey } = await begin();
//   const url = `/share/signin?web#${code}.${publicKey}`;
//   track('sign_in_started');
//   if (popup && !popup.closed) popup.location.href = url;
//   else if (!window.open(url, 'huma-signin', 'popup,width=480,height=720')) throw new Error('Allow pop-ups for huma.social, then try again.');
//   for (let i = 0; i < 300; i++) {
//     await new Promise(resolve => setTimeout(resolve, 2000));
//     const me = await linked(code);
//     if (me) { track('signed_in'); return me; }
//   }
//   throw new Error('Sign-in didn’t finish. Try again.');
// }

/** A request about this account's documents, signed by the publishing key. */
async function request(method, pathname, body = '') {
  const { publicKey } = await publishingKey(), time = Date.now();
  const signature = await signed(documentRequestMessage(method, pathname, time, await digest(encoder.encode(body))));
  const response = await fetch(pathname, { method, ...(method === 'POST' ? { body } : {}),
    headers: { 'Content-Type': 'application/json', 'X-Huma-Key': publicKey, 'X-Huma-Time': String(time), 'X-Huma-Signature': signature } });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) signOut();
  if (!response.ok) throw Object.assign(new Error(data.error ?? 'Couldn’t reach your account.'), { status: response.status });
  return data;
}
/** The writer's name, face and handle, kept in the account and shown on pages they share: { name, avatar, handle? }, or null. */
export function profile() {
  try { const value = JSON.parse(localStorage.getItem(PROFILE) ?? 'null'); return value?.name && value.avatar ? value : null; } catch { return null; }
}
/** The account's profile, brought into this browser (set on another device, or kept here before). */
export async function loadProfile() {
  const { profile: kept } = await request('GET', '/api/documents/profile');
  if (kept) try { localStorage.setItem(PROFILE, JSON.stringify(kept)); } catch {}
  return kept ?? profile();
}
export async function saveProfile(value) {
  const { profile: kept } = await request('POST', '/api/documents/profile', JSON.stringify(value));
  try { localStorage.setItem(PROFILE, JSON.stringify(kept)); } catch {}
  return kept;
}
/** Whether a handle belongs to someone: true, false (free), or null when it can't be told. */
export async function handleTaken(handle) {
  const response = await fetch('/api/writers/' + encodeURIComponent(handle)).catch(() => null);
  return response?.status === 404 ? false : response?.ok ? true : null;
}
/** A new face: a short seed the site draws (/avatar/<seed>.svg), made the way the Mac makes one. */
export const newFace = () => Array.from(crypto.getRandomValues(new Uint8Array(10)), b => 'abcdefghijkmnpqrstuvwxyz23456789'[b % 32]).join('');
export const faceURL = seed => '/avatar/' + encodeURIComponent(seed) + '.svg';

// Passkeys: the account's own (Touch ID, Face ID, Windows Hello or a security key) approve check-ins alongside this
// browser's writing key, and a page whose every check-in they approved shows the passkey check. Only each one's
// credential id and P-256 public key are kept, here and in the account (documents.mjs).
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const fromBase64url = text => fromBase64(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4));
const keepPasskeys = list => { try { localStorage.setItem(PASSKEYS, JSON.stringify({ wallet: account()?.wallet, passkeys: list })); } catch {} return list; };
/** The account's passkeys known in this browser: [{ id, publicKey, rpId }]. */
export function passkeys() {
  try { const value = JSON.parse(localStorage.getItem(PASSKEYS) ?? 'null'); return value?.wallet && value.wallet === account()?.wallet && Array.isArray(value.passkeys) ? value.passkeys : []; } catch { return []; }
}
/** The ones for this site, which are the only ones a browser lets it use. */
export const sitePasskeys = () => passkeys().filter(p => p.rpId === location.hostname);
/** Whether this browser can use passkeys here at all (a site on an IP address can't have one). */
export const passkeysWork = () => Boolean(window.PublicKeyCredential && navigator.credentials) && !/^[\d.]+$|:/.test(location.hostname);
/** The account's passkeys, brought into this browser; any added here that the account missed go up now. */
export async function loadPasskeys() {
  let { passkeys: kept = [] } = await request('GET', '/api/documents/passkeys');
  for (const missing of passkeys().filter(p => !kept.some(k => k.id === p.id)))
    kept = (await request('POST', '/api/documents/passkeys', JSON.stringify(missing)).catch(() => null))?.passkeys ?? [...kept, missing];
  return keepPasskeys(kept);
}
/**
 * Adds a passkey for this site: call it straight from a click, as browsers ask. Only P-256 (ES256) keys, which the
 * recorder and every reader check; kept in this browser at once, and in the account a moment later.
 */
export async function addPasskey() {
  if (!account()) throw new Error('Sign in to add a passkey.');
  const name = profile()?.name ?? 'Huma writer';
  const credential = await navigator.credentials.create({ publicKey: {
    rp: { id: location.hostname, name: 'Huma' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    excludeCredentials: sitePasskeys().map(p => ({ type: 'public-key', id: fromBase64url(p.id) })),
    attestation: 'none', timeout: 120000 } });
  const spki = credential?.response?.getPublicKey?.();
  const key = spki && await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']).catch(() => null);
  if (!key) throw new Error('This passkey can’t be used with Huma. Try another.');
  const added = { id: credential.id, publicKey: b64(new Uint8Array(await crypto.subtle.exportKey('raw', key))), rpId: location.hostname };
  const here = keepPasskeys([...passkeys().filter(p => p.id !== added.id), added]);
  // Usable here at once; the account gets it meanwhile (and loadPasskeys sends it again if this fails).
  request('POST', '/api/documents/passkeys', JSON.stringify(added)).then(({ passkeys: kept }) => keepPasskeys(kept), () => {});
  return here;
}
/**
 * A check-in's passkey approval, for the recorder's challenge (base64): starts the browser's passkey prompt at once,
 * so it must be called within the click that approved. Resolves with what the recorder checks, or null (no passkey
 * here, cancelled or failed), and never rejects.
 */
export function passkeyAssertion(challenge) {
  const mine = sitePasskeys();
  if (!mine.length || !passkeysWork()) return Promise.resolve(null);
  try {
    return navigator.credentials.get({ publicKey: { challenge: fromBase64(challenge), rpId: location.hostname,
      allowCredentials: mine.map(p => ({ type: 'public-key', id: fromBase64url(p.id) })), userVerification: 'required', timeout: 60000 } })
      .then(credential => {
        const used = mine.find(p => p.id === credential?.id), r = credential?.response;
        if (!used || !r?.signature) return null;
        // WebAuthn's ES256 signature is already DER.
        return { public_key: used.publicKey, authenticator_data: b64(new Uint8Array(r.authenticatorData)),
          client_data_json: b64(new Uint8Array(r.clientDataJSON)), signature: b64(new Uint8Array(r.signature)) };
      }, () => null);
  } catch { return Promise.resolve(null); }
}

export const accountDocuments = async () => (await request('GET', '/api/documents')).documents ?? [];
export const accountDocument = id => request('GET', '/api/documents/' + id);
export const saveToAccount = record => request('POST', '/api/documents/' + record.id, JSON.stringify(record));
export const deleteFromAccount = id => request('POST', '/api/documents/' + id + '/delete');
/** The account's World ID as readers see it ({ fingerprint, … }), or null when none is linked yet (documents.mjs). */
export const linkedWorldID = async () => (await request('GET', '/api/documents/worldid')).worldId ?? null;
/** What a World ID linking this account is made for: this browser's publishing key. */
export const linkSignal = async () => accountSignal((await publishingKey()).publicKey);
/** Links a World ID made for linkSignal() to the account, once; resolves it as readers see it. */
export const linkWorldID = async proof => (await request('POST', '/api/documents/worldid', JSON.stringify({ proof }))).worldId;

/**
 * The page's view link: the server checks the proof, then stores the page under this account, signed by the
 * publishing key. Returns the link's path: the short /p/<code>#<key>, or /original/<id>#<token> if that can't be made.
 * With Turnstile on, a page written here is shared with a fresh Turnstile token (`turnstile`, or one got just before
 * sharing, asked twice); it throws NOT_CONFIRMED (turnstile.mjs) when the browser isn't confirmed.
 * `humanProof`, when given, is asked for a World ID proof made for this page's signal (worldid.mjs): the proof, or null
 * to share without it. It runs before Turnstile's token is got, which expires in minutes, so a slow scan can't spend it.
 */
export async function publish(proved, { replay = false, listed = false, title = '', turnstile, humanProof } = {}) {
  const me = account();
  if (!me) throw new Error('Sign in to get a link.');
  // The person check runs while the page uploads and is checked, not after, unless a World ID scan comes first: then
  // it's got after the scan, as its token expires in minutes.
  const early = turnstile ? Promise.resolve(turnstile) : humanProof ? null : humanToken('publish').catch(() => humanToken('publish'));
  early?.catch(() => {});
  const prepared = await fetch('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof: proved.envelope,
      master: { base64: b64(encoder.encode(proved.text)), mediaType: 'text/plain;charset=utf-8' }, ...(replay && proved.replay ? { replay: proved.replay } : {}) }) });
  const ticket = await prepared.json().catch(() => ({}));
  if (!prepared.ok || !/^[a-f0-9]{64}$/.test(ticket.id ?? '')) throw new Error(ticket.error ?? 'The page couldn’t be checked.');
  const pending = await (await fetch('/api/publications/pending/' + ticket.id, { headers: { Authorization: 'Bearer ' + ticket.ticket } })).json();
  const [{ publicKey }, worldId] = await Promise.all([publishingKey(), humanProof ? humanProof(pageSignal(pending.manifest)) : null]);
  const person = await (early ?? humanToken('publish').catch(() => humanToken('publish')));
  const response = await fetch('/api/publications/pending/' + ticket.id + '/publish-device', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Huma-Ticket': ticket.ticket },
    body: JSON.stringify({ publicKey, wallet: me.wallet, signature: await signed(publicationMessage(pending.manifest)), ...(profile() ? { profile: profile() } : {}),
      listed: Boolean(listed), ...(cleanTitle(title) ? { title: cleanTitle(title) } : {}), ...(person ? { turnstile: person } : {}), ...(worldId ? { worldId } : {}) }) });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) signOut();
  if (!response.ok || !FULL_LINK.test(data.path ?? '')) throw new Error(data.error ?? 'Couldn’t make the link.');
  // The page's own id (its manifest's hash) is in its link; the upload ticket's id is another.
  return { path: SHORT_LINK.test(data.short ?? '') ? data.short : await shorten(data.path), id: data.path.match(FULL_LINK)[1] };
}
/** Turns a shared page's writing replay on (the signed replay) or off (null). Only the browser that shared it can. */
export async function setReplay(id, replay) {
  const { publicKey } = await publishingKey();
  const signature = await signed(replayMessage(id, replay === null ? null : await digest(encoder.encode(replay))));
  const response = await fetch('/api/publications/' + id + '/replay', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey, replay, signature }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? 'Couldn’t change the replay. Try again.');
  return data.replay === true;
}
/** Shows a shared page on the writer's page (huma.social/@handle) or takes it off. Any browser signed in to its account can. */
/** Takes a shared page down: its link stops working. Any browser signed in to its account can. */
export async function removeShared(id) {
  const { publicKey } = await publishingKey();
  const response = await fetch('/api/publications/' + id + '/remove', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey, signature: await signed(removalMessage(id)) }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok && response.status !== 410) throw new Error(data.error ?? 'Couldn’t take the page down. Try again.');
}
/** The page a short link (/p/<code>#key) names, as the server keeps it: its id, or null. */
export async function shortTarget(path) {
  const code = path?.match(/^\/p\/([A-Za-z0-9]{8,12})(#|$)/)?.[1];
  if (!code) return null;
  const reply = await fetch('/api/publications/short/' + code).then(r => (r.ok ? r.json() : null)).catch(() => null);
  return /^[a-f0-9]{64}$/.test(reply?.id ?? '') ? reply.id : null;
}
/** Renames a shared page where it's listed; any browser signed in to its account can. */
export async function setTitle(id, title) {
  const { publicKey } = await publishingKey(), time = Date.now();
  const response = await fetch('/api/publications/' + id + '/title', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey, title, time, signature: await signed(titleMessage(id, title, time)) }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? 'Couldn’t rename it. Try again.');
  return data.title;
}
export async function setListed(id, listed) {
  const { publicKey } = await publishingKey(), time = Date.now();
  const response = await fetch('/api/publications/' + id + '/listed', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey, listed, time, signature: await signed(listedMessage(id, listed, time)) }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? 'Couldn’t change Your Page. Try again.');
  return data.listed === true;
}
/**
 * How a shared page is shown now, from its receipt: { replay, listed, handle }, each null when it can't be told
 * (handle: the writer's, or null without one).
 */
export async function pageShown(id, token) {
  const reply = await fetch('/api/publications/' + id + '/receipt', { headers: token ? { Authorization: 'Bearer ' + token } : {} })
    .then(r => (r.ok ? r.json() : null)).catch(() => null);
  const flag = value => (typeof value === 'boolean' ? value : null);
  return { replay: flag(reply?.replay), listed: flag(reply?.listed), handle: typeof reply?.handle === 'string' ? reply.handle : null };
}
/** The short link (/p/<code>#<key>) for a page's full one, made by the server as for the Mac; the full one if it can't. */
export async function shorten(path) {
  const full = path?.match(FULL_LINK);
  if (!full) return path;
  const reply = await fetch('/api/publications/' + full[1] + '/short', { method: 'POST', headers: full[2] ? { Authorization: 'Bearer ' + full[2] } : {} })
    .then(r => (r.ok ? r.json() : null)).catch(() => null);
  return SHORT_LINK.test(reply?.path ?? '') ? reply.path : path;
}
