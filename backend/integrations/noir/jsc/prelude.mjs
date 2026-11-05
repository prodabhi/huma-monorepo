// Globals the engine's code expects from Node or a browser, for macOS's built-in JavaScript engine (JavaScriptCore).
// Everything that touches the system goes through __host, which the native host (extra/Sources/HumaScriptHost) provides.
import { Buffer } from 'buffer';

const host = globalThis.__host;
globalThis.Buffer = Buffer;
globalThis.console ??= { log() {}, info() {}, warn() {}, error() {}, debug() {} };
globalThis.queueMicrotask ??= callback => { Promise.resolve().then(callback); };
globalThis.setTimeout ??= (callback, ms = 0, ...args) => host.setTimeout(() => callback(...args), Number(ms) || 0);
globalThis.clearTimeout ??= id => host.clearTimeout(id);
globalThis.performance ??= { now: () => host.now() };

// UTF-8, as the WHATWG Encoding standard defines it (lone surrogates become U+FFFD; fatal decoding throws).
class TextEncoder {
  get encoding() { return 'utf-8'; }
  encode(input = '') { return Buffer.from(String(input).toWellFormed(), 'utf8'); }
  encodeInto(input, view) {
    const bytes = this.encode(input);
    let read = 0, written = 0;
    for (const char of String(input).toWellFormed()) {
      const size = Buffer.byteLength(char, 'utf8');
      if (written + size > view.length) break;
      view.set(bytes.subarray(written, written + size), written);
      written += size; read += char.length;
    }
    return { read, written };
  }
}
class TextDecoder {
  constructor(label = 'utf-8', options = {}) {
    if (!/^utf-?8$/i.test(label)) throw new RangeError('Only UTF-8 is supported.');
    this.fatal = Boolean(options.fatal); this.ignoreBOM = Boolean(options.ignoreBOM);
  }
  get encoding() { return 'utf-8'; }
  decode(input) {
    if (input === undefined) return '';
    let bytes = input instanceof Uint8Array ? input : ArrayBuffer.isView(input)
      ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(input);
    if (this.fatal && !host.validUTF8(copy(bytes))) throw new TypeError('The encoded data was not valid utf-8.');
    if (!this.ignoreBOM && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) bytes = bytes.subarray(3);
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('utf8');
  }
}
globalThis.TextEncoder ??= TextEncoder;
globalThis.TextDecoder ??= TextDecoder;
globalThis.atob ??= text => Buffer.from(String(text), 'base64').toString('latin1');
globalThis.btoa ??= text => {
  if (/[^\u0000-ÿ]/.test(text)) throw new Error('btoa: characters outside Latin-1');
  return Buffer.from(String(text), 'latin1').toString('base64');
};

/** The bytes of any view, as a Uint8Array that starts at offset 0 of its own buffer (what the host reads). */
export function copy(view) {
  const bytes = view instanceof Uint8Array ? view : new Uint8Array(view.buffer ?? view, view.byteOffset ?? 0, view.byteLength);
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength ? bytes : new Uint8Array(bytes);
}

// Web Crypto: only what the readers use (SHA-256, and ECDSA P-256 raw keys checking P1363 signatures).
const keys = new WeakMap();
const subtle = {
  async digest(algorithm, data) {
    if ((algorithm?.name ?? algorithm) !== 'SHA-256') throw new Error('Only SHA-256 is supported.');
    return host.sha256(copy(data)).buffer;
  },
  async importKey(format, keyData, algorithm, extractable, usages) {
    if (format !== 'raw' || algorithm?.name !== 'ECDSA' || algorithm.namedCurve !== 'P-256' || usages.join() !== 'verify')
      throw new Error('Only raw ECDSA P-256 verification keys are supported.');
    const key = Object.freeze({ type: 'public', algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, extractable, usages: ['verify'] });
    keys.set(key, copy(keyData));
    return key;
  },
  async verify(algorithm, key, signature, data) {
    if (algorithm?.name !== 'ECDSA' || (algorithm.hash?.name ?? algorithm.hash) !== 'SHA-256' || !keys.has(key))
      throw new Error('Only ECDSA with SHA-256 is supported.');
    return host.p256Verify(keys.get(key), copy(signature), copy(data));
  },
};
globalThis.crypto ??= { subtle, getRandomValues: array => { array.set(host.random(array.byteLength).subarray(0, array.length)); return array; } };

// process: environment, stdin as one chunk, stdout/stderr, exit.
const write = fd => (data, encoding, callback) => {
  if (typeof encoding === 'function') callback = encoding;
  host.write(fd, copy(typeof data === 'string' ? Buffer.from(data, 'utf8') : data));
  if (callback) queueMicrotask(() => callback(null));
  return true;
};
globalThis.process ??= {
  env: host.env(),
  platform: 'darwin',
  exitCode: undefined,
  umask: () => 0o077,
  getuid: () => host.uid(),
  exit(code) { host.exit(code ?? process.exitCode ?? 0); },
  stdout: { write: write(1) },
  stderr: { write: write(2) },
  stdin: { async *[Symbol.asyncIterator]() { yield Buffer.from(host.stdin()); } },
};
