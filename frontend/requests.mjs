// Writing requests: a teacher or editor makes a link, writers send back pages they shared from Huma, and the
// requester's private inbox lists them. No accounts: the inbox opens with a key only its creator has.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256Hex as hash, fail } from './server-util.mjs';

const clean = (value, limit) => typeof value === 'string' ? value.normalize('NFC').replace(/\p{C}+/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, limit) : '';
export const MAX_SUBMISSIONS = 500;
const storageKey = id => 'requests/' + hash('huma-request-v1\0' + id);

export function createRequests({ objectStore, page, shortPage = async () => null, now = Date.now, perHour = 200 }) {
  let window = { start: 0, count: 0 };
  // Requests change as pages arrive, so each change is a compare-and-swap; a write that lost a race retries.
  const read = async id => {
    const stored = await objectStore.quotaRead(storageKey(id));
    if (!stored) throw fail(404, 'This request link isn’t valid.');
    return { value: JSON.parse(stored.bytes), version: stored.version };
  };
  const load = async id => (await read(id)).value;
  async function change(id, update) {
    for (let attempt = 0; attempt < 8; attempt++) {
      const { value, version } = await read(id), result = update(value);
      if (!result.changed || await objectStore.quotaCAS(storageKey(id), version, Buffer.from(JSON.stringify(value)))) return result;
    }
    throw fail(503, 'Busy right now. Try again.');
  }
  const owner = (req, value) => {
    const key = req.headers.authorization?.match(/^Bearer ([a-f0-9]{64})$/)?.[1];
    if (!key || !timingSafeEqual(Buffer.from(hash(key), 'hex'), Buffer.from(value.keyHash, 'hex'))) throw fail(404, 'This request link isn’t valid.');
  };
  async function body(req) {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 4096) throw fail(413, 'Too much to send.'); chunks.push(chunk); }
    try { const value = JSON.parse(Buffer.concat(chunks)); if (value && typeof value === 'object' && !Array.isArray(value)) return value; } catch {}
    throw fail(400, 'Invalid request.');
  }
  const summary = ({ title, from, note, created }) => ({ title, from, note, created });

  return async function handle(req, res, pathname, { json }) {
    if (!pathname.startsWith('/api/requests')) return false;
    if (req.method === 'POST' && pathname === '/api/requests') {
      const value = await body(req), title = clean(value.title, 120), from = clean(value.from, 60), note = clean(value.note, 400);
      if (!title || !from) throw fail(400, 'Add what to write and your name.');
      if (now() - window.start > 3600000) window = { start: now(), count: 0 };
      if (++window.count > perHour) throw fail(429, 'Too many new requests right now. Try again in a little while.');
      const id = randomBytes(16).toString('hex'), key = randomBytes(32).toString('hex');
      const request = { title, from, note, created: now(), keyHash: hash(key), submissions: [] };
      if (!await objectStore.quotaCAS(storageKey(id), null, Buffer.from(JSON.stringify(request)))) throw fail(503, 'Busy right now. Try again.');
      json(res, 201, { id, key }); return true;
    }
    const match = pathname.match(/^\/api\/requests\/([a-f0-9]{32})(\/submit|\/inbox)?$/);
    if (!match) throw fail(404, 'Not found.');
    const [, id, part] = match;
    if (req.method === 'GET' && !part) { json(res, 200, summary(await load(id))); return true; }
    if (req.method === 'GET' && part === '/inbox') {
      const value = await load(id); owner(req, value);
      json(res, 200, { ...summary(value), submissions: value.submissions }); return true;
    }
    if (req.method === 'POST' && part === '/submit') {
      const value = await body(req);
      // The shared link as the writer copied it, on any host: /original/<id>#<token>, or the short /p/<code>#<key>,
      // whose code and key open the page together (publications.mjs).
      const pasted = typeof value.link === 'string' ? value.link.trim() : '';
      const full = pasted.match(/\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/), short = pasted.match(/\/p\/([A-Za-z0-9]{8,12})#([A-Za-z0-9]{16})$/);
      const shortID = short ? await shortPage(short[1]) : null;
      if (!full && !shortID) throw fail(400, 'Paste the link Huma gave you. It ends with a code after #.');
      const [pageID, token] = full ? [full[1], full[2]] : [shortID, short[1] + '.' + short[2]];
      await load(id); // a request that doesn't exist, before any work on the page
      let checked;
      try { checked = await page(pageID, token, id, value.signature); }
      catch (error) { throw fail(error.status === 410 ? 410 : 404, error.status === 410 ? 'The writer removed this page.' : 'That link doesn’t open a shared page.'); }
      const result = await change(id, request => {
        if (request.submissions.some(s => s.page === pageID)) return { status: 'already-sent', from: request.from };
        if (request.submissions.length >= MAX_SUBMISSIONS) throw fail(429, 'This request is full.');
        request.submissions.push({ page: pageID, token, name: checked.profile?.name ?? null, avatar: checked.profile?.avatar ?? null,
          words: checked.words, fromMac: checked.fromMac, at: now() });
        return { status: 'sent', from: request.from, changed: true };
      });
      delete result.changed;
      json(res, 200, result); return true;
    }
    throw fail(405, 'Method not allowed.');
  };
}
