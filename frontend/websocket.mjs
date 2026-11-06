// A WebSocket server (RFC 6455) small enough to live beside the registry's own `node:http` server, for the editor's
// event stream (detection/stream.mjs): the handshake, masked frames from the client, fragmented messages, ping, pong
// and close. Text messages only, up to `maxMessage` bytes; anything else closes the socket. No dependency.
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
/** The Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key. */
export const acceptKey = key => createHash('sha1').update(key + GUID).digest('base64');
const CLOSE = 8, PING = 9, PONG = 10, TEXT = 1, BINARY = 2, CONTINUATION = 0;

/** Whether `req` asks to become a WebSocket. */
export const isUpgrade = req => /^websocket$/i.test(req.headers.upgrade ?? '') && /\bupgrade\b/i.test(req.headers.connection ?? '');

/**
 * Takes over `socket` for a WebSocket: answers the handshake (or refuses it with 400 and returns null) and returns a
 * connection that emits 'message' (a string), 'close' ({ code }) and 'error'. `head` is what the client sent after the
 * request's headers.
 */
export function upgrade(req, socket, head, { maxMessage = 1024 * 1024 } = {}) {
  const key = req.headers['sec-websocket-key'];
  if (!isUpgrade(req) || req.headers['sec-websocket-version'] !== '13' || typeof key !== 'string' || Buffer.from(key, 'base64').length !== 16) {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); socket.destroy(); return null;
  }
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`);
  return new Connection(socket, head, maxMessage);
}

export class Connection extends EventEmitter {
  constructor(socket, head, maxMessage) {
    super();
    this.socket = socket; this.maxMessage = maxMessage; this.buffer = Buffer.alloc(0); this.parts = []; this.partsLength = 0; this.opcode = null;
    this.closed = false; this.closing = false;
    socket.setNoDelay?.(true);
    socket.on('data', chunk => this.feed(chunk));
    socket.on('error', error => { this.emit('error', error); this.finish(1006); });
    socket.on('close', () => this.finish(1006));
    socket.on('end', () => this.finish(1006));
    if (head?.length) this.feed(head);
  }
  /** Sends one text message. */
  send(text) {
    if (this.closed || this.closing) return false;
    const payload = Buffer.from(String(text), 'utf8');
    this.socket.write(Buffer.concat([frameHead(TEXT, payload.length), payload]));
    return true;
  }
  /** Closes with a status code, after sending it to the client. */
  close(code = 1000, reason = '') {
    if (this.closed || this.closing) return;
    this.closing = true;
    const text = Buffer.from(reason, 'utf8').subarray(0, 123), payload = Buffer.alloc(2 + text.length);
    payload.writeUInt16BE(code, 0); text.copy(payload, 2);
    try { this.socket.write(Buffer.concat([frameHead(CLOSE, payload.length), payload])); } catch {}
    const socket = this.socket;
    setTimeout(() => socket.destroy(), 1000).unref();
    socket.end();
    this.finish(code);
  }
  finish(code) {
    if (this.closed) return;
    this.closed = true; this.buffer = Buffer.alloc(0); this.parts = [];
    this.emit('close', { code });
  }
  feed(chunk) {
    if (this.closed) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    if (this.buffer.length > this.maxMessage + 14) { this.close(1009, 'Too large'); return; }
    for (;;) {
      const frame = readFrame(this.buffer);
      if (frame === null) return;
      if (frame === false) { this.close(1002, 'Bad frame'); return; }
      this.buffer = this.buffer.subarray(frame.size);
      if (!this.take(frame)) return;
    }
  }
  /** One frame in; false once the connection is closing. */
  take({ fin, opcode, payload }) {
    if (opcode === CLOSE) {
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
      if (!this.closing) { this.closing = true; try { this.socket.write(Buffer.concat([frameHead(CLOSE, 2), Buffer.from([code >> 8, code & 255])])); } catch {} this.socket.end(); }
      this.finish(code); return false;
    }
    if (opcode === PING) { if (!this.closing) this.socket.write(Buffer.concat([frameHead(PONG, payload.length), payload])); return true; }
    if (opcode === PONG) return true;
    if (opcode === BINARY) { this.close(1003, 'Text only'); return false; }
    if (opcode === TEXT) { if (this.opcode !== null) { this.close(1002, 'Bad frame'); return false; } this.opcode = TEXT; }
    else if (opcode === CONTINUATION) { if (this.opcode === null) { this.close(1002, 'Bad frame'); return false; } }
    else { this.close(1002, 'Bad frame'); return false; }
    this.parts.push(payload); this.partsLength += payload.length;
    if (this.partsLength > this.maxMessage) { this.close(1009, 'Too large'); return false; }
    if (!fin) return true;
    const message = Buffer.concat(this.parts); this.parts = []; this.partsLength = 0; this.opcode = null;
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(message); } catch { this.close(1007, 'Bad text'); return false; }
    this.emit('message', text);
    return !this.closed && !this.closing;
  }
}

/** The header of a frame the server sends (never masked). */
export function frameHead(opcode, length) {
  if (length < 126) return Buffer.from([0x80 | opcode, length]);
  if (length < 65536) { const head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(length, 2); return head; }
  const head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(length), 2); return head;
}
/** One client frame from the front of `buffer`: null when it isn't all here yet, false when it's malformed. */
export function readFrame(buffer) {
  if (buffer.length < 2) return null;
  const fin = Boolean(buffer[0] & 0x80), rsv = buffer[0] & 0x70, opcode = buffer[0] & 0x0f, masked = Boolean(buffer[1] & 0x80);
  let length = buffer[1] & 0x7f, at = 2;
  if (rsv || !masked) return false; // no extensions; a client must mask
  if (opcode >= 8 && (!fin || length > 125)) return false; // control frames are short and whole
  if (length === 126) { if (buffer.length < 4) return null; length = buffer.readUInt16BE(2); at = 4; }
  else if (length === 127) { if (buffer.length < 10) return null; const big = buffer.readBigUInt64BE(2); if (big > BigInt(Number.MAX_SAFE_INTEGER)) return false; length = Number(big); at = 10; }
  if (buffer.length < at + 4 + length) return null;
  const mask = buffer.subarray(at, at + 4), payload = Buffer.from(buffer.subarray(at + 4, at + 4 + length));
  for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
  return { fin, opcode, payload, size: at + 4 + length };
}
