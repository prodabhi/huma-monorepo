// Loopback-only acceptance server. No uploads, writes, credentials or public registry.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ASSETS } from './profile.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../../build/research/noir-compact-browser');
const allowed = new Map([
  ['/', ['acceptance.html', 'text/html']], ['/acceptance.js', ['acceptance.mjs', 'text/javascript']],
  ['/compact-verifier.js', ['compact-verifier.js', 'text/javascript']], ['/compact-worker.js', ['compact-worker.js', 'text/javascript']],
  ...['manifest', 'Bucket50', 'Bucket250', 'BucketUnicode'].map(n => ['/fixtures/' + n + '.json', ['fixtures/' + n + '.json', 'application/json']]),
  ...Object.keys(ASSETS).map(n => ['/assets/' + n, ['assets/' + n, n.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream']]),
]);
const server = http.createServer(async (req, res) => {
  const route = new URL(req.url, 'http://localhost').pathname;
  const file = req.method === 'GET' ? allowed.get(route) : undefined;
  const headers = {
    'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    ...(process.env.HUMA_NOIR_SHARED === '1' ? { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' } : {}),
  };
  if (!file) { res.writeHead(404, headers); res.end(); return; }
  try {
    const source = route === '/' || route === '/acceptance.js' ? here : root;
    const data = await readFile(path.join(source, file[0]));
    res.writeHead(200, { ...headers, 'Content-Type': file[1] }); res.end(data);
    console.log(JSON.stringify({ method: 'GET', path: route, bytes: data.length }));
  } catch { res.writeHead(503, headers); res.end('Prepare the verifier build and public fixtures first.'); }
});
server.listen(Number(process.env.HUMA_NOIR_PORT ?? 4324), '127.0.0.1', () => console.log(JSON.stringify({ url: 'http://127.0.0.1:' + server.address().port, shared: process.env.HUMA_NOIR_SHARED === '1' })));
