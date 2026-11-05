// A writer's documents, kept under their account so they open on any device after sign-in: drafts as they're written,
// and finished ones with their proof and view link. Requests come from /write signed by that browser's publishing key,
// which the account's wallet linked to it at sign-in (publications.mjs, /api/publications/signin), as a Mac is linked.
import { createHash, createPublicKey } from 'node:crypto';
import { documentRequestMessage, writerProfile, writerHandle, writerLevel, isPageLink, TIER_ORDER } from './publication-contract.mjs';
import { clientIP } from './client-ip.mjs';
import { accountSignal, publicWorldID, NOT_VERIFIED, WORLD_ID_LIMIT, WORLD_ID_TAKEN } from './worldid-verify.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const fail = (status, message) => Object.assign(new Error(message), { status });
// A signed request is good for five minutes, and only once.
const WINDOW = 5 * 60 * 1000;
export const DOCUMENT_LIMIT = 4 * 1024 * 1024, DOCUMENTS_PER_ACCOUNT = 500, PASSKEYS_PER_ACCOUNT = 10;
/** What an account keeps in all: the stored versions of its documents, each counted at its size in the list. */
export const ACCOUNT_BYTES = 50 * 1024 * 1024, ACCOUNT_FULL = 'Your account is full. Delete some documents to add more.';
// Request bodies being read at once, overall and from one address: a body is read only after its headers show a
// linked key, and holds its declared length (or the route's limit when it declares none) until it's read.
const READING_LIMIT = 64 * 1024 * 1024, READING_PER_CLIENT = 16 * 1024 * 1024;
const SIGN_IN = 'Sign in to keep documents in your account.', MISMATCH = 'The request signature doesn’t match.';
/** The key a browser's publishing key is found under, to learn whose it is. */
export const deviceOwnerKey = publicKey => 'owners/' + hash('huma-device-owner-v1\0' + publicKey);
/** Whose a browser's publishing key is ({ owner, wallet }, written at sign-in), or null. */
export async function deviceOwner(objectStore, publicKey) {
  try { return JSON.parse((await objectStore.get(deviceOwnerKey(publicKey), 16384)).toString('utf8')); } catch { return null; }
}

/** The writer's name and face (as the Mac sets them, Profile.swift) and their handle, under their account. */
export const profileKey = owner => 'documents/' + hash('huma-profile-v1\0' + owner);
/** Who holds a handle: { owner }, or { owner: null } once released. */
export const handleKey = handle => 'handles/' + hash('huma-handle-v1\0' + handle);
/** The account's World ID (worldid-verify.mjs), written once when it's linked: what every page it shares carries.
 *  Each World ID environment keeps its own, so a staging link never counts in production. */
export const worldIDKey = (owner, environment) => 'documents/' + hash('huma-world-id-v1\0' + environment + '\0' + owner);
/** Which account holds a World ID ({ owner }, by its nullifier): one World ID links to one account. */
const nullifierKey = (nullifier, environment) => 'documents/' + hash('huma-world-nullifier-v1\0' + environment + '\0' + nullifier);
/** The World ID linked to `owner` in `environment` (the verified record), or null. */
export async function accountWorldID(objectStore, owner, environment) {
  try {
    const record = JSON.parse((await objectStore.get(worldIDKey(owner, environment), 2 * WORLD_ID_LIMIT)).toString('utf8'));
    return typeof record?.nullifier === 'string' ? record : null;
  } catch { return null; }
}
/** Every page an account shared and hasn't removed (publications.mjs), newest first: what its writer page shows. */
export const writersIndexKey = owner => 'writers-index/' + hash(owner);
export const WRITER_PAGES = 2000, WRITER_PAGES_SHOWN = 200;
/** A kept value and its version for compare-and-swap, or `empty` when there's none. */
export async function readState(objectStore, key, empty) {
  const stored = await objectStore.quotaRead(key);
  return { value: stored ? JSON.parse(stored.bytes.toString('utf8')) : empty, version: stored?.version ?? null };
}
/** Changes a kept value by compare-and-swap: `update` gets what's there and returns what replaces it. */
export async function changeState(objectStore, key, empty, update) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const { value, version } = await readState(objectStore, key, empty), next = update(value);
    if (await objectStore.quotaCAS(key, version, Buffer.from(JSON.stringify(next)))) return { before: value, after: next };
  }
  throw fail(503, 'Busy right now. Try again.');
}
/** A writer's public page: their profile, their record over every page they shared, their level and the pages they chose to show. */
export function writerPage(profile, index, now = Date.now()) {
  const pages = Array.isArray(index) ? index : [], scores = pages.map(p => p.score).filter(Number.isInteger);
  const since = pages.length ? Math.min(...pages.map(p => (Number.isFinite(p.at) ? p.at : now))) : null;
  const best = pages.reduce((top, p) => (TIER_ORDER.indexOf(p.tier) > TIER_ORDER.indexOf(top) ? p.tier : top), null);
  const record = { pages: pages.length, average: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null, since, best };
  return { profile: { name: profile.name, avatar: profile.avatar, handle: profile.handle }, record,
    level: writerLevel({ ...record, days: since === null ? 0 : Math.floor((now - since) / 86400000) }),
    pages: pages.filter(p => p.listed === true && isPageLink(p.path)).sort((a, b) => b.at - a.at).slice(0, WRITER_PAGES_SHOWN)
      .map(({ title, words, score, tier, at, path }) => ({ title, words, score, tier, at, path })) };
}

/** What a list item's version takes up (items kept before sizes were counted take none until saved again). */
const sizeOf = item => (Number.isSafeInteger(item?.size) && item.size > 0 ? item.size : 0);
const exact = (value, max) => (typeof value === 'string' && value.length <= max ? value : '');
const clean = (value, max) => (typeof value === 'string' ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, max) : '');
/** The list entry for a document: what Your Documents shows without opening it. */
function entry(record) {
  return { id: record.id, title: clean(record.title, 120), text: clean(record.text, 300), words: Number.isSafeInteger(record.words) ? record.words : 0,
    status: record.status === 'proved' ? 'proved' : 'draft', score: Number.isInteger(record.score) ? record.score : null,
    created: Number(record.created) || 0, updated: Number(record.updated) || 0,
    ...(isPageLink(record.shared) ? { shared: record.shared } : {}),
    ...(/^[a-f0-9]{64}$/.test(record.publication ?? '') ? { publication: record.publication } : {}) };
}

const P256_SPKI = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
/** A passkey the account approves check-ins with, exactly as /write registered it, or null: its credential id
 *  (base64url), its P-256 public key (base64 of the 65-byte uncompressed point, on the curve) and its site. */
export function passkeyEntry(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join() !== 'id,publicKey,rpId') return null;
  const { id, publicKey, rpId } = value;
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,1366}$/.test(id)) return null;
  if (typeof rpId !== 'string' || rpId.length > 253 || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(rpId)) return null;
  if (typeof publicKey !== 'string' || !/^[A-Za-z0-9+/]{87}=$/.test(publicKey)) return null;
  const point = Buffer.from(publicKey, 'base64');
  if (point.length !== 65 || point[0] !== 4 || point.toString('base64') !== publicKey) return null;
  try { createPublicKey({ key: Buffer.concat([P256_SPKI, point]), format: 'der', type: 'spki' }); } catch { return null; }
  return { id, publicKey, rpId };
}

export function createDocuments({ objectStore, deviceKey, deviceSigned, worldId = null, now = Date.now }) {
  const seen = new Map();
  // Each account has one list (changed by compare-and-swap) of its documents, each pointing at its current version;
  // a version is written once under the account and its own hash, and the one it replaces is deleted.
  const listKey = owner => 'documents/' + hash('huma-documents-v1\0' + owner);
  const versionKey = (owner, bytes) => 'documents/' + hash('huma-document-version-v1\0' + owner + '\0' + hash(bytes));
  const passkeysKey = owner => 'documents/' + hash('huma-passkeys-v1\0' + owner);
  const read = (key, empty) => readState(objectStore, key, empty), change = (key, empty, update) => changeState(objectStore, key, empty, update);
  /** Gives `handle` to `owner` unless someone else holds it. */
  const claim = (handle, owner) => change(handleKey(handle), null, held => {
    if (held?.owner && held.owner !== owner) throw fail(409, 'That handle is taken.');
    return { owner };
  });
  /** Lets go of `owner`'s handle, so another writer can take it. */
  const release = (handle, owner) => change(handleKey(handle), null, held => (held?.owner === owner ? { owner: null } : held ?? { owner: null }));

  /** Who a request says it comes from, checked before its body is read: a well-formed key, time and signature
   *  (canonical base64) and the account that key is linked to. The signature itself covers the body (`signed`). */
  async function caller(req) {
    const publicKey = deviceKey(req.headers['x-huma-key']), time = Number(req.headers['x-huma-time']), signature = req.headers['x-huma-signature'];
    if (!publicKey || !Number.isSafeInteger(time) || typeof signature !== 'string') throw fail(401, SIGN_IN);
    if (signature.length > 200 || Buffer.from(signature, 'base64').toString('base64') !== signature) throw fail(401, MISMATCH);
    if (Math.abs(now() - time) > WINDOW) throw fail(401, 'This computer’s clock is off. Check its time and try again.');
    const binding = await deviceOwner(objectStore, publicKey);
    if (!binding || typeof binding.owner !== 'string' || !/^[a-f0-9]{64}$/.test(binding.owner)) throw fail(401, SIGN_IN);
    return { publicKey, time, signature, owner: binding.owner };
  }
  /** The account behind a signed request, or a 401. Once only: kept by key and the message signed (never by the
   *  signature's bytes, which can be written more than one way), marked used before anything else is awaited. */
  function signed(from, req, pathname, body) {
    // Oldest first (a Map keeps the order they were added), so the sweep stops at the first one still fresh.
    for (const [key, at] of seen) { if (at >= now() - WINDOW * 2) break; seen.delete(key); }
    const message = documentRequestMessage(req.method, pathname, from.time, hash(body)), once = hash(from.publicKey + '\0' + message);
    if (seen.has(once)) throw fail(401, 'This request was already used.');
    if (!deviceSigned(from.publicKey, message, from.signature)) throw fail(401, MISMATCH);
    seen.set(once, now());
    return from.owner;
  }
  /** A signed request's body (empty unless it's a POST), read once its headers check out, and the account behind it. */
  async function signer(req, pathname, limit) {
    const from = await caller(req), body = req.method === 'POST' ? await readBody(req, limit) : Buffer.alloc(0);
    return { body, owner: signed(from, req, pathname, body), publicKey: from.publicKey };
  }
  let reading = 0; const readingFrom = new Map();
  async function readBody(req, limit) {
    const declared = req.headers['content-length'] === undefined ? null : Number(req.headers['content-length']);
    if (declared !== null && !(Number.isSafeInteger(declared) && declared >= 0)) throw fail(400, 'Invalid request.');
    if (declared > limit) throw fail(413, 'This document is too large to keep in your account.');
    const held = declared ?? limit, client = clientIP(req), theirs = readingFrom.get(client) ?? 0;
    if (reading + held > READING_LIMIT || theirs + held > READING_PER_CLIENT) throw fail(503, 'Busy right now. Try again.');
    reading += held; readingFrom.set(client, theirs + held);
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > held) throw fail(413, 'This document is too large to keep in your account.'); chunks.push(chunk); }
      return Buffer.concat(chunks);
    } finally {
      reading -= held;
      const left = readingFrom.get(client) - held;
      if (left > 0) readingFrom.set(client, left); else readingFrom.delete(client);
    }
  }
  const removeVersion = key => (key ? objectStore.remove(key).catch(() => {}) : null);

  return async function handle(req, res, pathname, { json }) {
    // A writer's page (huma.social/@handle), for anyone: one read each for the handle, its account's pages and profile.
    const writer = pathname.match(/^\/api\/writers\/([^/]{1,64})$/);
    if (writer) {
      if (req.method !== 'GET') throw fail(405, 'Method not allowed.');
      const none = () => fail(404, 'No writer with that handle.');
      let handle;
      try { handle = writerHandle(decodeURIComponent(writer[1])); } catch { throw none(); }
      const owner = (await read(handleKey(handle), null)).value?.owner;
      if (typeof owner !== 'string' || !/^[a-f0-9]{64}$/.test(owner)) throw none();
      const [{ value: index }, { value: stored }, human] = await Promise.all([read(writersIndexKey(owner), []), read(profileKey(owner), null),
        worldId?.enabled ? accountWorldID(objectStore, owner, worldId.environment) : null]);
      let profile = null;
      try { profile = writerProfile(stored); } catch {}
      if (profile?.handle !== handle) throw none();
      json(res, 200, { ...writerPage(profile, index, now()), ...(human ? { worldId: publicWorldID(human) } : {}) }); return true;
    }
    if (!pathname.startsWith('/api/documents')) return false;
    // The writer's name and face (as the Mac sets them, Profile.swift), shown on every page they share, and the
    // handle their writer page is found by. A handle is held by one account; changing it lets the old one go.
    if (pathname === '/api/documents/profile') {
      const { body, owner } = await signer(req, pathname, 4096);
      const current = async () => { try { return writerProfile((await read(profileKey(owner), null)).value); } catch { return null; } };
      if (req.method === 'GET') { json(res, 200, { profile: await current() }); return true; }
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      let value;
      try { value = JSON.parse(body.toString('utf8')); } catch { throw fail(400, 'JSON required.'); }
      if (!value || typeof value !== 'object') throw fail(400, 'Choose a name up to 40 characters.');
      // The profile is replaced only at the version this request read (compare-and-swap), and the handle it names is
      // claimed just before: racing requests can't leave one account holding handles its profile doesn't show.
      for (let attempt = 0; ; attempt++) {
        const { value: stored, version } = await read(profileKey(owner), null);
        const was = typeof stored?.handle === 'string' ? stored.handle : null;
        // A profile sent without `handle` keeps the one the account has; null or '' lets it go.
        const profile = writerProfile(value.handle === undefined && was ? { ...value, handle: was } : value);
        if (!profile) throw fail(400, 'Choose a name up to 40 characters.');
        const handle = profile.handle ?? null;
        if (handle) await claim(handle, owner);
        let written;
        try { written = await objectStore.quotaCAS(profileKey(owner), version, Buffer.from(JSON.stringify(profile))); }
        catch (error) { if (handle && handle !== was) await release(handle, owner).catch(() => {}); throw error; }
        if (written) {
          if (was && was !== handle) await release(was, owner).catch(() => {});
          json(res, 200, { profile }); return true;
        }
        // Another request changed the profile first: let this handle go unless that profile holds it, and try again.
        const latest = (await read(profileKey(owner), null).catch(() => null))?.value;
        if (handle && latest?.handle !== handle) await release(handle, owner).catch(() => {});
        if (attempt === 2) throw fail(409, 'Your profile changed on another device. Try again.');
      }
    }
    // The account's World ID (worldid-verify.mjs): linked once, from a signed-in browser, before its first page is
    // finished there. The proof is made for that browser's publishing key, so it can't be used for another account,
    // and a World ID links to one account only. Every page the account shares then carries it (publications.mjs).
    if (pathname === '/api/documents/worldid') {
      const { body, owner, publicKey } = await signer(req, pathname, WORLD_ID_LIMIT + 1024);
      const environment = worldId?.environment ?? 'production', linked = worldId?.enabled ? await accountWorldID(objectStore, owner, environment) : null;
      if (req.method === 'GET') { json(res, 200, { worldId: publicWorldID(linked) }); return true; }
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      if (!worldId?.enabled) throw fail(404, 'World ID is off.');
      if (linked) { json(res, 200, { worldId: publicWorldID(linked) }); return true; }
      let value;
      try { value = JSON.parse(body.toString('utf8')); } catch { throw fail(400, 'JSON required.'); }
      if (!value?.proof || typeof value.proof !== 'object' || Array.isArray(value.proof)) throw fail(400, 'Invalid World ID proof.');
      const result = await worldId.verify(value.proof, accountSignal(publicKey));
      if (!result.ok) throw fail(result.status === 400 ? 403 : result.status, NOT_VERIFIED);
      // The first account to link a World ID holds it.
      const holder = nullifierKey(result.record.nullifier, environment), holderOf = async () => {
        try { return JSON.parse((await objectStore.get(holder, 1024)).toString('utf8')).owner; } catch { return null; }
      };
      try { await objectStore.put(holder, Buffer.from(JSON.stringify({ owner }))); } catch {}
      const held = await holderOf();
      if (!held) throw fail(503, 'Busy right now. Try again.');
      if (held !== owner) throw fail(409, WORLD_ID_TAKEN);
      try { await objectStore.put(worldIDKey(owner, environment), Buffer.from(JSON.stringify(result.record))); } catch {}
      const kept = await accountWorldID(objectStore, owner, environment);
      if (!kept) throw fail(503, 'Busy right now. Try again.');
      if (kept.nullifier !== result.record.nullifier) throw fail(409, 'Your account is already linked to another World ID.');
      json(res, 200, { worldId: publicWorldID(kept) }); return true;
    }
    // The account's passkeys (up to 10), which approve check-ins written in a browser: only their public keys.
    if (pathname === '/api/documents/passkeys') {
      const { body, owner } = await signer(req, pathname, 4096);
      const kept = list => (Array.isArray(list) ? list.map(passkeyEntry).filter(Boolean).slice(0, PASSKEYS_PER_ACCOUNT) : []);
      if (req.method === 'GET') {
        let passkeys = [];
        try { passkeys = kept((await read(passkeysKey(owner), [])).value); } catch {}
        json(res, 200, { passkeys }); return true;
      }
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      let value;
      try { value = JSON.parse(body.toString('utf8')); } catch { throw fail(400, 'JSON required.'); }
      const passkey = passkeyEntry(value);
      if (!passkey) throw fail(400, 'Invalid passkey.');
      const { after } = await change(passkeysKey(owner), [], list => {
        const others = kept(list).filter(k => k.id !== passkey.id);
        if (others.length >= PASSKEYS_PER_ACCOUNT) throw fail(429, `An account keeps up to ${PASSKEYS_PER_ACCOUNT} passkeys.`);
        return [...others, passkey];
      });
      json(res, 200, { passkeys: after }); return true;
    }
    const match = pathname.match(/^\/api\/documents(?:\/([a-f0-9]{20})(\/delete)?)?$/);
    if (!match) throw fail(404, 'Not found.');
    const [, id, remove] = match;
    if (req.method === 'GET') {
      const { owner } = await signer(req, pathname, 0), { value: list } = await read(listKey(owner), []);
      if (!id) { json(res, 200, { documents: list.map(({ key: _, size: __, ...shown }) => shown) }); return true; }
      const item = list.find(d => d.id === id);
      if (!item) throw fail(404, 'Document not found.');
      json(res, 200, JSON.parse((await objectStore.get(item.key, DOCUMENT_LIMIT)).toString('utf8'))); return true;
    }
    if (req.method !== 'POST' || !id) throw fail(405, 'Method not allowed.');
    const { body, owner } = await signer(req, pathname, DOCUMENT_LIMIT);
    if (remove) {
      const { before } = await change(listKey(owner), [], list => list.filter(d => d.id !== id));
      await removeVersion(before.find(d => d.id === id)?.key);
      json(res, 200, { status: 'deleted' }); return true;
    }
    let value;
    try { value = JSON.parse(body.toString('utf8')); } catch { throw fail(400, 'JSON required.'); }
    if (!value || typeof value !== 'object' || value.id !== id || !value.doc || typeof value.doc !== 'object') throw fail(400, 'Invalid document.');
    // Kept as sent: the text and its formatting, and for a finished document what it proved (never the keystrokes).
    const record = { ...entry(value), doc: value.doc,
      ...(value.status === 'proved' && value.proof && typeof value.proof === 'object' ? { proof: {
        envelope: exact(value.proof.envelope, DOCUMENT_LIMIT), report: value.proof.report, text: exact(value.proof.text, 200000), replay: exact(value.proof.replay, DOCUMENT_LIMIT) } } : {}) };
    const bytes = Buffer.from(JSON.stringify(record)), key = versionKey(owner, bytes);
    // Checked before the version is written, and again as the list changes.
    const full = list => list.reduce((total, d) => total + (d.id === id ? 0 : sizeOf(d)), bytes.length) > ACCOUNT_BYTES;
    if (full((await read(listKey(owner), [])).value)) throw fail(413, ACCOUNT_FULL);
    await objectStore.put(key, bytes);
    let before, seenList = [];
    try {
      ({ before } = await change(listKey(owner), [], list => {
        seenList = list;
        const was = list.find(d => d.id === id);
        // A finished document stays finished: a late draft save from another tab can't undo it.
        if (was?.status === 'proved' && record.status !== 'proved') throw fail(409, 'This document is finished.');
        if (!was && list.length >= DOCUMENTS_PER_ACCOUNT) throw fail(429, `An account keeps up to ${DOCUMENTS_PER_ACCOUNT} documents. Delete some to add more.`);
        if (full(list)) throw fail(413, ACCOUNT_FULL);
        return [{ ...entry(record), key, size: bytes.length }, ...list.filter(d => d.id !== id)];
      }));
    } catch (error) {
      // The version just written goes, unless it's the one the list already points at (the same bytes saved again).
      if ([409, 413, 429].includes(error.status) && !seenList.some(d => d.key === key)) await removeVersion(key);
      throw error;
    }
    const replaced = before.find(d => d.id === id)?.key;
    if (replaced !== key) await removeVersion(replaced);
    json(res, 200, { status: 'saved' }); return true;
  };
}
