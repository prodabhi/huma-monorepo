// The editor's raw events, kept for the server's typing analysis (frontend/detection): keys, input, compositions and the
// caret inside the editor; the pointer, wheel, selection, focus and visibility on the page. Every handler only pushes
// a small object to a buffer; nothing is measured here. Every few seconds the buffer goes to huma.social over a
// WebSocket (/api/sessions/stream, frontend/detection/stream.mjs), or POSTs to the same path where WebSockets can't
// connect (Vercel), in numbered batches signed with the session's key, each
// acknowledged by its number; unacknowledged batches are sent again, in order, after a dropped connection. The stream
// is the server's: it never comes back to the page.
const FLUSH_MS = 2500, IDLE_TIMEOUT = 1500, RECONNECT_MS = [1000, 2000, 4000, 8000, 15000, 30000];
/** Pointer samples kept per second (coalesced samples can come faster than any hand moves). */
const POINTER_PER_SECOND = 250;
/** Events kept in all; past this only keys and input are kept, so a long session can't grow without bound. */
const EVENT_LIMIT = 380000;
const encoder = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');

/** The timer's resolution: the smallest nonzero gap in 200 quick readings of performance.now(). */
export function timerResolution(now = () => performance.now()) {
  let least = Infinity, previous = now();
  for (let i = 0; i < 200; i++) { const t = now(); const gap = t - previous; if (gap > 0 && gap < least) least = gap; previous = t; }
  return least === Infinity ? null : least;
}
/** Whether a function is the browser's own (a wrapper around it isn't). */
const native = f => { try { return typeof f === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(f)); } catch { return false; } };
/** What the page can say about itself, once per session. `consoleNative`: the console's methods are the browser's own;
 *  software that hides from the DevTools probe (automation.mjs runtimeProbe) replaces them. */
export function sessionMeta(win = globalThis) {
  const nav = win.navigator ?? {};
  let coarse = null; try { coarse = win.matchMedia?.('(pointer: coarse)').matches ?? null; } catch {}
  const con = win.console;
  return { ua: String(nav.userAgent ?? ''), platform: String(nav.platform ?? ''), lang: String(nav.language ?? ''), webdriver: nav.webdriver ?? null,
    timer: timerResolution(), coarse, touch: Boolean(nav.maxTouchPoints > 0 || 'ontouchstart' in win), coi: win.crossOriginIsolated ?? null,
    cores: nav.hardwareConcurrency ?? null, origin: Number.isFinite(win.performance?.timeOrigin) ? win.performance.timeOrigin : null,
    consoleNative: con ? ['log', 'groupEnd', 'debug', 'info', 'error', 'table'].every(name => native(con[name])) : null,
    toStringNative: native(Function.prototype.toString) };
}
/** HMAC(key, index ‖ sha256(json)) as the server computes it (detection/stream.mjs batchMAC), with WebCrypto. */
export async function signBatch(key, index, json) {
  const digest = hex(await crypto.subtle.digest('SHA-256', encoder.encode(json)));
  return hex(await crypto.subtle.sign('HMAC', key, encoder.encode(index + '\0' + digest)));
}
export const importKey = keyHex => crypto.subtle.importKey('raw', Uint8Array.from(keyHex.match(/../g), b => parseInt(b, 16)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

/**
 * `editor`: the element whose keys and input are kept (only events inside it). `caret()`: the editor's own selection
 * offset and document size, from its model. `trap()`: the honeypot field's value. `url`: the stream's address.
 * Returns the collector: start(session, keyHex) opens the stream; flush() sends what's buffered and resolves once
 * it's acknowledged (or gives up after `wait` ms); stop() sends the rest and closes.
 */
export function createCollector({ editor, caret = () => null, trap = () => '', url = '/api/sessions/stream', win = globalThis, doc = win.document } = {}) {
  const buffer = [], queue = [];
  let seq = 0, kept = 0, index = 0, session = null, key = null, socket = null, timer = 0, retry = 0, closed = true, meta = null, waiting = [];
  let pointerSecond = 0, pointerCount = 0, connected = false, acked = -1, trapSent = false, refused = null;
  const opts = { passive: true, capture: true };
  const push = event => { if (kept < EVENT_LIMIT || /^(kd|ku|bi|cs|ce)$/.test(event.ev)) { buffer.push(event); kept++; } };
  const stamp = e => (Number.isFinite(e.timeStamp) ? e.timeStamp : win.performance.now());
  const listeners = [];
  const on = (target, type, handler) => { target.addEventListener(type, handler, opts); listeners.push([target, type, handler]); };

  // `cap`: the input device Chrome says the event came from (UIEvent.sourceCapabilities): 0 a keyboard or mouse, 1 one that
  // fires touch events, null none known (other browsers, and possibly keys injected by a driver).
  const cap = e => (e.sourceCapabilities === undefined ? undefined : e.sourceCapabilities === null ? null : e.sourceCapabilities.firesTouchEvents ? 1 : 0);
  on(editor, 'keydown', e => push({ s: seq++, ev: 'kd', t: stamp(e), code: e.code ?? null, key: e.key ?? null, kc: e.keyCode ?? null, shift: e.shiftKey ?? null,
    mod: (e.metaKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.altKey ? 4 : 0), rep: e.repeat ?? null, trusted: e.isTrusted, comp: e.isComposing ?? null, cap: cap(e) }));
  on(editor, 'keyup', e => push({ s: seq++, ev: 'ku', t: stamp(e), code: e.code ?? null, key: e.key ?? null, shift: e.shiftKey ?? null, trusted: e.isTrusted, comp: e.isComposing ?? null }));
  on(editor, 'beforeinput', e => {
    const at = caret();
    push({ s: seq++, ev: 'bi', t: stamp(e), it: e.inputType ?? null, data: typeof e.data === 'string' ? e.data.slice(0, 200) : null, comp: e.isComposing ?? null,
      trusted: e.isTrusted, caret: at?.caret ?? null, size: at?.size ?? null });
  });
  on(editor, 'compositionstart', e => push({ s: seq++, ev: 'cs', t: stamp(e), trusted: e.isTrusted }));
  on(editor, 'compositionend', e => push({ s: seq++, ev: 'ce', t: stamp(e), data: typeof e.data === 'string' ? e.data.slice(0, 200) : null, trusted: e.isTrusted }));
  // Reading the editor by copying from it (the text itself isn't kept, only that it happened).
  for (const type of ['copy', 'cut', 'paste']) on(doc, type, e => push({ s: seq++, ev: type, t: stamp(e), trusted: e.isTrusted, inside: Boolean(editor.contains?.(e.target)) }));
  on(doc, 'pointermove', e => {
    const second = Math.floor(stamp(e) / 1000);
    if (second !== pointerSecond) { pointerSecond = second; pointerCount = 0; }
    for (const p of e.getCoalescedEvents?.() ?? [e]) {
      if (++pointerCount > POINTER_PER_SECOND) return;
      push({ s: seq++, ev: 'pm', t: stamp(p), x: p.clientX, y: p.clientY, pt: p.pointerType ?? null, trusted: e.isTrusted });
    }
  });
  for (const type of ['pointerdown', 'pointerup']) on(doc, type, e => push({ s: seq++, ev: type === 'pointerdown' ? 'pd' : 'pu', t: stamp(e), x: e.clientX, y: e.clientY, pt: e.pointerType ?? null,
    trusted: e.isTrusted, inside: Boolean(editor.contains?.(e.target)) }));
  on(doc, 'wheel', e => push({ s: seq++, ev: 'wh', t: stamp(e), dy: e.deltaY, trusted: e.isTrusted }));
  on(doc, 'selectionchange', e => push({ s: seq++, ev: 'sc', t: stamp(e), hidden: doc.hidden, focused: doc.hasFocus?.() ?? null }));
  on(doc, 'visibilitychange', e => push({ s: seq++, ev: 'vc', t: stamp(e), hidden: doc.hidden, focused: doc.hasFocus?.() ?? null }));
  for (const type of ['focus', 'blur']) on(win, type, e => push({ s: seq++, ev: type, t: stamp(e), hidden: doc.hidden, focused: doc.hasFocus?.() ?? null }));

  /** The next batch from the buffer, signed; null when there's nothing to send. */
  async function nextBatch() {
    if (!buffer.length && (meta !== null || index > 0) && !(trap() && !trapSent)) return null;
    const events = buffer.splice(0, buffer.length), json = JSON.stringify(events);
    const head = { session, index, sentAt: win.performance.now(), hmac: await signBatch(key, index, json) };
    if (meta === null) { meta = sessionMeta(win); head.meta = meta; }
    const filled = trap();
    if (filled && !trapSent) { head.trap = String(filled); trapSent = true; }
    // The events' JSON goes exactly as it was signed; the server signs them again as parsed and re-serialized.
    const text = JSON.stringify(head).slice(0, -1) + ',"events":' + json + '}';
    return { index: index++, text };
  }
  // A host that can't take WebSockets (Vercel's functions) gets the same signed batches as POSTs to the same path, one at
  // a time and in order: the page switches once its first WebSocket attempts fail without ever opening.
  let http = false, failures = 0, posting = false;
  const postURL = () => { const target = new URL(url, win.location?.href ?? 'http://localhost/'); target.protocol = target.protocol.replace(/^ws/, 'http'); return target.href; };
  function received(reply) {
    if (Number.isSafeInteger(reply?.ack)) {
      acked = Math.max(acked, reply.ack);
      while (queue.length && queue[0].index <= reply.ack) queue.shift();
      waiting = waiting.filter(({ upTo, resolve }) => (acked >= upTo ? (resolve(true), false) : true));
    }
    if (reply?.error) { refused = reply.error; }
  }
  async function post() {
    if (posting || refused) return;
    posting = true;
    try {
      for (let item = queue.find(i => !i.sent); item && !refused; item = queue.find(i => !i.sent)) {
        let reply;
        try {
          const response = await win.fetch(postURL(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: item.text, credentials: 'same-origin' });
          reply = await response.json();
        } catch { return; } // offline or busy: the next flush tries again
        item.sent = true; connected = true; received(reply);
      }
    } finally { posting = false; }
  }
  function send() {
    if (http) { post(); return; }
    if (socket?.readyState === 1) for (const item of queue) if (!item.sent) { socket.send(item.text); item.sent = true; }
  }
  function connect() {
    if (closed || socket || http) return;
    let ws;
    try { ws = new win.WebSocket(url); } catch { http = true; send(); return; }
    socket = ws;
    let opened = false;
    ws.onopen = () => { opened = true; retry = 0; connected = true; for (const item of queue) item.sent = false; send(); };
    ws.onmessage = ({ data }) => { let reply = null; try { reply = JSON.parse(data); } catch {} received(reply); };
    ws.onclose = () => {
      if (socket === ws) socket = null;
      if (!opened && !connected && ++failures >= 2 && win.fetch) { http = true; for (const item of queue) item.sent = false; send(); return; }
      if (!closed && !refused) schedule();
    };
    ws.onerror = () => {};
  }
  function schedule() { if (closed || timer) return; const ms = RECONNECT_MS[Math.min(retry++, RECONNECT_MS.length - 1)]; timer = win.setTimeout(() => { timer = 0; connect(); }, ms); }
  async function flush() {
    const batch = await nextBatch();
    if (batch) { queue.push({ ...batch, sent: false }); send(); }
    if (!socket && !closed) connect();
    return batch?.index ?? index - 1;
  }
  let loop = 0;
  function tick() {
    if (closed) return;
    const idle = win.requestIdleCallback ?? (callback => callback());
    idle(() => { flush().catch(() => {}).finally(() => { if (!closed) loop = win.setTimeout(tick, FLUSH_MS); }); }, { timeout: IDLE_TIMEOUT });
  }
  return {
    /** Starts streaming for `session` (the nonce), signing with `keyHex` (the session key). */
    async start(sessionNonce, keyHex) {
      session = sessionNonce; key = await importKey(keyHex); closed = false; refused = null;
      connect(); loop = win.setTimeout(tick, FLUSH_MS);
    },
    /** Sends what's buffered now and resolves true once the server has acknowledged everything so far, false after
     *  `wait` ms without. */
    async flush(wait = 4000) {
      if (closed && !queue.length) return acked >= index - 1;
      const upTo = await flush();
      if (acked >= upTo) return true;
      return new Promise(resolve => { waiting.push({ upTo, resolve }); win.setTimeout(() => { waiting = waiting.filter(w => w.resolve !== resolve); resolve(acked >= upTo); }, wait); });
    },
    /** Sends the rest, closes the stream, and stops listening. */
    async stop(wait = 4000) {
      if (closed) return acked >= index - 1;
      const done = await this.flush(wait);
      closed = true; win.clearTimeout(loop); win.clearTimeout(timer); timer = 0;
      for (const [target, type, handler] of listeners) target.removeEventListener(type, handler, opts);
      listeners.length = 0;
      try { socket?.close(1000); } catch {}
      socket = null;
      return done;
    },
    /** Whether the server has taken anything yet, how many batches are unacknowledged, and why it refused, if it did. */
    get state() { return { connected, acked, pending: queue.length, refused, buffered: buffer.length, index }; },
  };
}
