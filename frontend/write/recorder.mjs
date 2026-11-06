// The page's side of the recorder (Rust, web.rs in experiments/noir-compact/native, as WebAssembly): it passes text
// and key events in, and signs what the recorder asks with this browser's writing key, which can't be exported.
const decoder = new TextDecoder(), encoder = new TextEncoder();
export const b64 = bytes => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

/** WebCrypto's P-256 signature (r ‖ s) in the DER form the recorder and every reader check. */
export function der(raw) {
  const integer = bytes => {
    let i = 0; while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const body = bytes[i] & 0x80 ? [0, ...bytes.subarray(i)] : [...bytes.subarray(i)];
    return [0x02, body.length, ...body];
  };
  const r = integer(raw.subarray(0, 32)), s = integer(raw.subarray(32, 64));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

/** Loads the recorder from its WebAssembly bytes. */
export async function loadRecorder(bytes) {
  let memory;
  const { instance } = await WebAssembly.instantiate(bytes, { env: {
    huma_random: (pointer, length) => { crypto.getRandomValues(new Uint8Array(memory.buffer, pointer, length)); },
  } });
  const x = instance.exports; memory = x.memory;
  /** One command in, its result out; a refused command throws its reason. */
  return function call(command) {
    const input = encoder.encode(JSON.stringify(command)), pointer = x.huma_alloc(input.length);
    new Uint8Array(memory.buffer, pointer, input.length).set(input);
    const reply = x.huma_web(pointer, input.length);
    x.huma_free(pointer, input.length);
    const head = new DataView(memory.buffer, reply, 4).getUint32(0, true), length = head & 0x7fffffff;
    const body = JSON.parse(decoder.decode(new Uint8Array(memory.buffer, reply + 4, length)));
    x.huma_free(reply, 4 + length);
    if (head >>> 31) throw new Error(body);
    return body;
  };
}

/**
 * One recording: every call is serialized, so the recorder sees events in order even while a signature is awaited.
 * `pair` is a CryptoKeyPair whose private key can sign but never be exported.
 */
export class Recording {
  constructor(call, pair) { this.call = call; this.pair = pair; this.queue = Promise.resolve(); this.waiting = 0; this.passkey = false; this.passkeySkipped = false; }
  /** `passkey` ({ rp_id, origin }): every approved check-in is also approved with the account's passkey.
   *  `nonce` (32 hex characters, from sessionNonce in session.mjs): the server's session nonce, which becomes the
   *  page's public nonce so the server can check its writing time at publish. */
  static async start(call, pair, { initialText = '', unix = Date.now(), id = crypto.randomUUID().toUpperCase(), passkey = null, nonce = null } = {}) {
    const recording = new Recording(call, pair);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    await recording.run({ command: 'start', id, public_key: b64(publicKey), unix, initial_text: initialText, ...(passkey ? { passkey } : {}), ...(nonce ? { nonce } : {}) });
    recording.passkey = Boolean(passkey);
    return recording;
  }
  /** Runs one command, then signs whatever it asks for until it asks for nothing. */
  run(command) { return this.enqueue(() => this.call(command)); }
  enqueue(work) {
    this.waiting++;
    const step = this.queue.then(async () => {
      let result = await work();
      while (result?.sign) {
        result = this.call({ command: 'signed', signature: await signDER(this.pair.privateKey, unb64(result.sign)) });
      }
      return result;
    }).finally(() => { this.waiting--; });
    this.queue = step.catch(() => {});
    return step;
  }
  /**
   * A check-in approved in passkey mode. The recorder answers with the passkey challenge, and `ask` (the browser's
   * passkey prompt) resolves with the assertion or null. With nothing queued, as during a check-in, the challenge is
   * asked for at once, so the prompt opens within the click that approved, as Safari requires. Without an assertion
   * (cancelled, failed, refused) the check-in goes on as a plain approval, and the page keeps the basic check.
   */
  approve(elapsed, ask) {
    const command = { command: 'presence_respond', outcome: 'approved', elapsed };
    const begin = () => { const result = this.call(command); return { result, asked: result?.passkey && !this.passkeySkipped ? ask(result.passkey) : null }; };
    let early = null;
    if (!this.waiting) try { early = begin(); } catch (error) { early = { error }; }
    return this.enqueue(async () => {
      const { result, asked, error } = early ?? begin();
      if (error) throw error;
      if (!result?.passkey) return result;
      const assertion = await asked;
      if (assertion) try { return this.call({ command: 'passkey_assertion', ...assertion }); } catch {}
      this.passkeySkipped = true;
      return this.call({ command: 'passkey_skip' });
    });
  }
  edit(text, source, elapsed) { return this.run({ command: 'edit', text, source, elapsed }); }
  key(kind, code, modifiers, elapsed) { return this.run({ command: 'key', kind, code, modifiers, elapsed }); }
  checkpoint(elapsed, force = false) { return this.run({ command: 'checkpoint', unix: Date.now(), elapsed, force }); }
  presenceIssue(reason, elapsed) { return this.run({ command: 'presence_issue', reason, elapsed }); }
  presenceRespond(outcome, elapsed) { return this.run({ command: 'presence_respond', outcome, elapsed }); }
  finish(elapsed) { return this.run({ command: 'finish', unix: Date.now(), elapsed }); }
  cut(minimum) { return this.run({ command: 'cut', minimum }); }
  chunk(index) { return this.run({ command: 'chunk', index }); }
  info() { return this.run({ command: 'info' }); }
  proveInput() { return this.run({ command: 'prove_input' }); }
}

/** A P-256 signature of `bytes`, DER and base64, as the recorder and the server check it. */
export async function signDER(privateKey, bytes) {
  return b64(der(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes))));
}

/** One of this browser's keys: made once, kept in IndexedDB, usable only for signing and never exportable. `p256` is
 *  the writing key, which signs recordings; `publish` signs for the account (account.mjs). */
export async function writingKey(name = 'p256') {
  const db = await new Promise((resolve, reject) => {
    const open = indexedDB.open('huma-writing', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
  });
  const read = () => new Promise((resolve, reject) => {
    const get = db.transaction('keys').objectStore('keys').get(name); get.onsuccess = () => resolve(get.result); get.onerror = () => reject(get.error);
  });
  let key = await read();
  if (!key) {
    key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await new Promise((resolve, reject) => {
      const put = db.transaction('keys', 'readwrite').objectStore('keys').put(key, name); put.onsuccess = resolve; put.onerror = () => reject(put.error);
    });
  }
  db.close();
  return key;
}
