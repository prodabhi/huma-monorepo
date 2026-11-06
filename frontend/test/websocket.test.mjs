import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { upgrade, isUpgrade, acceptKey, readFrame, frameHead } from '../websocket.mjs';

// An echo server on the registry's kind of http server, for a browser's WebSocket (Node's own client here).
async function echoServer(t, options) {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  const events = [];
  server.on('upgrade', (req, socket, head) => {
    const connection = upgrade(req, socket, head, options);
    if (!connection) return;
    connection.on('message', text => { events.push(['message', text]); connection.send('echo:' + text); });
    connection.on('close', ({ code }) => events.push(['close', code]));
    connection.on('error', () => {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { port: server.address().port, events };
}
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const until = async (test, ms = 2000) => { const end = Date.now() + ms; while (!test() && Date.now() < end) await wait(10); assert.ok(test(), 'timed out'); };
/** A client frame: masked, as browsers send them. */
function clientFrame(opcode, payload, { fin = true } = {}) {
  const bytes = Buffer.from(payload), mask = Buffer.from([1, 2, 3, 4]), masked = Buffer.from(bytes);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
  const head = frameHead(opcode, bytes.length); head[0] = (fin ? 0x80 : 0) | opcode; head[1] |= 0x80;
  return Buffer.concat([head, mask, masked]);
}
function rawClient(port) {
  const socket = net.connect(port, '127.0.0.1'); const chunks = [];
  socket.on('data', chunk => chunks.push(chunk));
  return new Promise((resolve, reject) => {
    socket.once('connect', () => {
      socket.write('GET /api/sessions/stream HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
      resolve({ socket, chunks, received: () => Buffer.concat(chunks).toString('latin1') });
    });
    socket.once('error', reject);
  });
}

test('the handshake answers with the accept key, and messages echo both ways', async t => {
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='); // RFC 6455 §1.3
  assert.ok(isUpgrade({ headers: { upgrade: 'websocket', connection: 'keep-alive, Upgrade' } }));
  assert.equal(isUpgrade({ headers: {} }), false);
  const { port, events } = await echoServer(t);
  const ws = new WebSocket(`ws://127.0.0.1:${port}/api/sessions/stream`);
  const got = [];
  ws.onmessage = e => got.push(e.data);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  ws.send('hello'); ws.send('x'.repeat(70000)); ws.send('héllo ✓');
  await until(() => got.length === 3);
  assert.deepEqual(got, ['echo:hello', 'echo:' + 'x'.repeat(70000), 'echo:héllo ✓']);
  ws.close(1000);
  await until(() => events.some(([kind]) => kind === 'close'));
  assert.deepEqual(events.at(-1), ['close', 1000]);
});

test('fragmented messages are joined, pings are answered, and bad frames close the socket', async t => {
  const { port, events } = await echoServer(t);
  const { socket, received } = await rawClient(port);
  await until(() => received().includes('\r\n\r\n'));
  assert.match(received(), /^HTTP\/1\.1 101 /);
  socket.write(clientFrame(1, 'one ', { fin: false })); socket.write(clientFrame(0, 'two ', { fin: false })); socket.write(clientFrame(0, 'three'));
  await until(() => events.length === 1);
  assert.deepEqual(events[0], ['message', 'one two three']);
  socket.write(clientFrame(9, 'ping'));
  await until(() => received().includes('ping'));
  const pong = readFrame(Buffer.concat([Buffer.from([0x8a | 0, 4 | 0x80]), Buffer.from([0, 0, 0, 0]), Buffer.from('ping')]));
  assert.equal(pong.opcode, 10);
  // A binary frame isn't accepted: the server closes with 1003.
  socket.write(clientFrame(2, Buffer.from([1, 2, 3])));
  await until(() => events.some(([kind]) => kind === 'close'));
  assert.deepEqual(events.at(-1), ['close', 1003]);
  socket.destroy();
});

test('unmasked frames, oversized messages and a bad handshake are refused', async t => {
  const { port, events } = await echoServer(t, { maxMessage: 100 });
  const { socket, received } = await rawClient(port);
  await until(() => received().includes('\r\n\r\n'));
  socket.write(clientFrame(1, 'x'.repeat(200)));
  await until(() => events.some(([kind]) => kind === 'close'));
  assert.deepEqual(events.at(-1), ['close', 1009]);
  socket.destroy();
  const unmasked = readFrame(Buffer.from([0x81, 0x05, 104, 101, 108, 108, 111]));
  assert.equal(unmasked, false);
  assert.equal(readFrame(Buffer.from([0x81])), null);
  // A plain GET on the upgrade path isn't a WebSocket.
  const plain = await new Promise(resolve => {
    const s = net.connect(port, '127.0.0.1', () => s.write('GET /x HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n'));
    const chunks = []; s.on('data', c => chunks.push(c)); s.on('close', () => resolve(Buffer.concat(chunks).toString()));
  });
  assert.match(plain, /^HTTP\/1\.1 400 /);
});
