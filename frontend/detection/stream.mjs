// The editor's event stream, received live: while a page is written in a browser, its collector (frontend/write/collector.mjs)
// sends the editor's raw events every few seconds over a WebSocket (/api/sessions/stream, websocket.mjs), in signed,
// numbered batches. Each batch is kept with the time it arrived, so a log posted all at once at Finish, or one with a
// clock that runs faster than this server's, can be told from a page that was really being written
// (detection/integrity.mjs). Batches live in memory and in one append-only file per session under `directory`, for a
// day (sessions.mjs SESSION_LIFETIME), and only aggregates outlive them (the page's detection record).
import { createHmac, createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, readdir, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { SESSION_LIFETIME } from '../sessions.mjs';

export const STREAM_LIMITS = Object.freeze({
  /** One batch: at most this many bytes of JSON and this many events. */
  batchBytes: 256 * 1024, batchEvents: 4000,
  /** One session: at most this many events and bytes, about a day of brisk typing with the pointer moving. */
  sessionEvents: 400000, sessionBytes: 24 * 1024 * 1024,
  /** Sessions kept in memory at once (older ones stay in their files) and open connections at once. */
  sessionsInMemory: 2000, connections: 4000, connectionsPerClient: 8,
});
const SWEEP_EVERY = 10 * 60 * 1000, EVENT_KEYS = 14, STRING_LIMIT = 256;
const sha256 = value => createHash('sha256').update(value).digest('hex');

/** The session key the server hands out with a nonce (hex): HMAC of the nonce under the server's secret, so no key
 *  needs keeping. The browser signs each batch with it; the server recomputes it from the nonce. */
export const sessionKey = (secret, nonce) => createHmac('sha256', secret).update('huma-session-key-v1\0' + nonce).digest('hex');
/** What a batch's `hmac` must be: HMAC(key, index ‖ sha256(JSON of the events)). The browser computes the same with
 *  WebCrypto over the JSON it sends; the server over the events as parsed and re-serialized (the same text in V8). */
export const batchMAC = (key, index, events) => createHmac('sha256', Buffer.from(key, 'hex')).update(index + '\0' + sha256(JSON.stringify(events))).digest('hex');
export const streamFile = (directory, nonce) => path.join(directory, sha256('huma-stream-v1\0' + nonce) + '.ndjson');

const nonceOK = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
/** One event as the collector sends it: a small flat object of numbers, short strings, booleans and nulls. */
function cleanEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  const keys = Object.keys(event);
  if (keys.length > EVENT_KEYS || !Number.isSafeInteger(event.s) || typeof event.ev !== 'string' || !Number.isFinite(event.t)) return null;
  for (const key of keys) {
    const value = event[key];
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'number') { if (!Number.isFinite(value)) return null; continue; }
    if (typeof value === 'string') { if (value.length > STRING_LIMIT) return null; continue; }
    return null;
  }
  return event;
}
/** The once-per-session facts the first batch carries, kept as sent within limits. */
function cleanMeta(meta) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return null;
  const out = {};
  for (const [key, value] of Object.entries(meta).slice(0, 24)) {
    if (typeof value === 'string') out[key] = value.slice(0, 512);
    else if (typeof value === 'number' && Number.isFinite(value) || typeof value === 'boolean' || value === null) out[key] = value;
  }
  return out;
}

/**
 * `live(nonce)` says whether a nonce was issued here and no page has used it yet (sessions.mjs). `secret` is the
 * server's session secret (sessionKey). Returns the receiver: `accept(connection, client)` takes a WebSocket connection,
 * `read(nonce)` gives a session's stream back, `sweep()` drops what's past its lifetime.
 */
export function createStreams({ directory, secret, live, now = Date.now, limits = {} }) {
  const L = { ...STREAM_LIMITS, ...limits };
  const sessions = new Map(), clients = new Map();
  let open = 0, swept = 0, ready = null;
  const prepare = () => (ready ??= mkdir(directory, { recursive: true, mode: 0o700 }).catch(() => {}));

  function session(nonce) {
    let s = sessions.get(nonce);
    if (!s) {
      if (sessions.size >= L.sessionsInMemory) sessions.delete(sessions.keys().next().value);
      s = { nonce, started: now(), expected: 0, events: 0, bytes: 0, batches: [], meta: null, trap: null, connection: null, writing: Promise.resolve() };
      sessions.set(nonce, s);
    }
    return s;
  }
  /** Keeps one batch: in memory and on disk (appended; a failed write is logged by its absence, never fatal). */
  function keep(s, line) {
    s.batches.push(line); s.events += line.events.length;
    const text = JSON.stringify(line) + '\n';
    s.bytes += text.length;
    s.writing = s.writing.then(() => prepare()).then(() => appendFile(streamFile(directory, s.nonce), text, { mode: 0o600 })).catch(() => {});
  }
  /** Validates one message from a connection and keeps it. Returns the reply to send; throws { code, message } to close. */
  async function take(s, message, bytes) {
    if (bytes > L.batchBytes) throw refusal(1009, 'Batch too large');
    let batch;
    try { batch = JSON.parse(message); } catch { throw refusal(1007, 'Not JSON'); }
    if (!batch || typeof batch !== 'object' || batch.session !== s.nonce) throw refusal(1008, 'Wrong session');
    const { index, sentAt, hmac, events } = batch;
    if (!Number.isSafeInteger(index) || index < 0 || !Number.isFinite(sentAt) || typeof hmac !== 'string' || !Array.isArray(events)) throw refusal(1008, 'Bad batch');
    if (events.length > L.batchEvents) throw refusal(1009, 'Batch too large');
    if (hmac !== batchMAC(sessionKey(secret, s.nonce), index, events)) throw refusal(1008, 'Bad signature');
    // A batch already kept (its ack was lost on the way) is acknowledged again, not kept twice.
    if (index < s.expected) return { ack: index };
    if (index > s.expected) throw refusal(1008, 'Gap in the stream');
    const clean = events.map(cleanEvent);
    if (clean.some(event => event === null)) throw refusal(1008, 'Bad event');
    if (s.events + clean.length > L.sessionEvents || s.bytes + bytes > L.sessionBytes) throw refusal(1009, 'Session too long');
    const line = { index, sentAt, receivedAt: now(), events: clean };
    if (batch.meta !== undefined && s.meta === null) { s.meta = cleanMeta(batch.meta); line.meta = s.meta; }
    if (typeof batch.trap === 'string' && batch.trap !== '' && !s.trap) { s.trap = batch.trap.slice(0, STRING_LIMIT); line.trap = s.trap; }
    s.expected = index + 1;
    keep(s, line);
    return { ack: index };
  }
  const refusal = (code, message) => Object.assign(new Error(message), { code });

  return {
    /** A connection (websocket.mjs) from `client` (its address bucket, for limits): the first message names the
     *  session; every message is a batch. The session must be live, so a stream can't be started for a page already
     *  shared, or with a nonce this server never issued. */
    accept(connection, client = 'unknown') {
      sweep();
      const mine = clients.get(client) ?? 0;
      if (open >= L.connections || mine >= L.connectionsPerClient) { connection.close(1013, 'Busy'); return; }
      open++; clients.set(client, mine + 1);
      let s = null, busy = Promise.resolve();
      const finish = () => { open--; const left = clients.get(client) - 1; left ? clients.set(client, left) : clients.delete(client); if (s?.connection === connection) s.connection = null; };
      connection.on('close', finish);
      connection.on('error', () => {});
      connection.on('message', message => {
        busy = busy.then(async () => {
          if (connection.closed) return;
          try {
            if (!s) {
              let nonce = null;
              try { nonce = JSON.parse(message)?.session; } catch {}
              if (!nonceOK(nonce)) throw refusal(1008, 'Bad session');
              const known = sessions.get(nonce);
              if (!known && !(await live(nonce))) throw refusal(1008, 'No such session');
              s = known ?? session(nonce);
              if (s.started + SESSION_LIFETIME <= now()) throw refusal(1008, 'Session over');
              // A page that reconnects (a dropped connection) replaces its old connection; two at once is one page.
              if (s.connection && s.connection !== connection) s.connection.close(1000, 'Replaced');
              s.connection = connection;
            }
            connection.send(JSON.stringify(await take(s, message, Buffer.byteLength(message))));
          } catch (error) {
            if (!error.code) throw error;
            try { connection.send(JSON.stringify({ error: error.message })); } catch {}
            connection.close(error.code, error.message);
          }
        }).catch(() => { connection.close(1011, 'Error'); });
      });
    },
    /** One batch sent over HTTP (POST /api/sessions/stream), for hosts that can't take WebSockets (Vercel): the same
     *  checks as a WebSocket message, and the same reply, { ack } or { error }. Batches must still arrive in order. */
    async post(message, client = 'unknown') {
      sweep();
      let nonce = null;
      try { nonce = JSON.parse(message)?.session; } catch {}
      try {
        if (!nonceOK(nonce)) throw refusal(1008, 'Bad session');
        const known = sessions.get(nonce);
        if (!known && !(await live(nonce))) throw refusal(1008, 'No such session');
        const s = known ?? session(nonce);
        if (s.started + SESSION_LIFETIME <= now()) throw refusal(1008, 'Session over');
        // One batch at a time per session, as on a connection.
        const reply = (s.posting ?? Promise.resolve()).then(() => take(s, message, Buffer.byteLength(message)));
        s.posting = reply.catch(() => {});
        return await reply;
      } catch (error) {
        if (!error.code) throw error;
        return { error: error.message };
      }
    },
    /** A session's stream so far: { nonce, started, batches: [{ index, sentAt, receivedAt, events }], meta, trap, events },
     *  from memory or its file; null when nothing was streamed for it. */
    async read(nonce) {
      if (!nonceOK(nonce)) return null;
      let s = sessions.get(nonce);
      if (s) await s.writing;
      else {
        let text;
        try { text = await readFile(streamFile(directory, nonce), 'utf8'); } catch { return null; }
        s = { nonce, started: null, batches: [], meta: null, trap: null };
        for (const line of text.split('\n')) {
          if (!line) continue;
          let batch; try { batch = JSON.parse(line); } catch { continue; }
          if (batch.index !== s.batches.length) break; // a torn file ends at its last whole batch
          s.batches.push(batch);
          if (batch.meta !== undefined && s.meta === null) s.meta = batch.meta;
          if (typeof batch.trap === 'string' && !s.trap) s.trap = batch.trap;
        }
        s.started = s.batches[0]?.receivedAt ?? null;
      }
      if (!s.batches.length) return null;
      return { nonce, started: s.started, batches: s.batches, meta: s.meta, trap: s.trap, events: s.batches.flatMap(batch => batch.events) };
    },
    /** Drops sessions past their lifetime, from memory now and from disk in the background; at most every ten minutes. */
    sweep(force = false) { return sweep(force); },
    /** Closes every open stream (tests). */
    close() { for (const s of sessions.values()) s.connection?.close(1001, 'Going away'); sessions.clear(); },
    get size() { return sessions.size; },
  };
  function sweep(force = false) {
    const at = now();
    if (!force && at - swept < SWEEP_EVERY) return Promise.resolve();
    swept = at;
    for (const [nonce, s] of sessions) if (s.started + SESSION_LIFETIME <= at) { s.connection?.close(1000, 'Session over'); sessions.delete(nonce); }
    return (async () => {
      let names = [];
      try { names = await readdir(directory); } catch { return; }
      for (const name of names) {
        if (!name.endsWith('.ndjson')) continue;
        const file = path.join(directory, name);
        try { if ((await stat(file)).mtimeMs + SESSION_LIFETIME <= at) await unlink(file); } catch {}
      }
    })();
  }
}
