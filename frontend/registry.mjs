import http from 'node:http';
import { readFile, writeFile, mkdir, rename, readdir, unlink, stat, open } from 'node:fs/promises';
import { brotliCompress, constants as zlib } from 'node:zlib';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createRequests } from './requests.mjs';
import { createPublications, deviceKey, deviceSigned } from './publications.mjs';
import { createDocuments } from './documents.mjs';
import { configuredTurnstile, turnstileRoutes, TURNSTILE_SCRIPT_ORIGIN } from './turnstile-verify.mjs';
import { configuredEvents, eventRoutes } from './events.mjs';
import { configuredWorldID, worldIDRoutes, BRIDGE_ORIGIN } from './worldid-verify.mjs';
import { AVATAR_SEED, writerHandle, isPageLink } from './publication-contract.mjs';
import { POINTS } from './write/pins.mjs';
import { Avatar, Style } from '@dicebear/core';
import dylan from '@dicebear/styles/dylan.json' with { type: 'json' };
import { fail as failure } from './server-util.mjs';
import { upgrade as upgradeSocket } from './websocket.mjs';
import { clientAddress } from './sessions.mjs';
import { POSTS, IMAGES } from './blog.mjs';

// Writers' faces: DiceBear "Dylan" (Natalia Spivak, CC BY 4.0), the same face for the same seed.
// Made once per seed and kept (at most a few thousand). Its metadata, which credits the artist and license, stays.
let dylanStyle = null;
const faces = new Map();
function face(seed) {
    let svg = faces.get(seed);
    if (svg) return svg;
    dylanStyle ??= new Style(dylan);
    svg = new Avatar(dylanStyle, { seed }).toString().replace(/<!--[\s\S]*?-->/g, '');
    if (faces.size >= 2000) faces.delete(faces.keys().next().value);
    faces.set(seed, svg);
    return svg;
}
// The Mac app version /download/Huma.dmg serves; backend/scripts/upload-release.mjs uploads releases/Huma-<version>.dmg.
const HUMA_RELEASE = '0.1.10';
// The Mac app's proving points (64 MB that don't compress), kept out of the installer; the app checks their fingerprint.
const PROVING_SETUP = 'engine/bn254_g1_compressed-3e1ac096.dat';
// Whether each of these is in R2 yet, asked at most once a minute.
const releaseChecks = new Map();
// Writing in the browser (frontend/write, built into dist/write): its prover needs threads, so the page and everything it
// loads are cross-origin isolated. Only these files, by name.
const WRITE_ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cross-Origin-Resource-Policy': 'same-origin' };
// With Turnstile on (turnstile-verify.mjs), the write page also loads Cloudflare's widget: its script and its frame.
// Both come from challenges.cloudflare.com, which serves them ready for a cross-origin isolated page (CORP
// cross-origin on the script; the frame is allowed cross-origin-isolated), so the page keeps its isolation.
// With World ID on (worldid-verify.mjs) it also reaches World's bridge, which carries the proof from World App back to the page.
const writePolicy = (turnstile, world) => turnstile.enabled || world.enabled ? { 'Content-Security-Policy': `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'${turnstile.enabled ? ' ' + TURNSTILE_SCRIPT_ORIGIN : ''}; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'${turnstile.enabled ? ' ' + TURNSTILE_SCRIPT_ORIGIN : ''}${world.enabled ? ' ' + BRIDGE_ORIGIN : ''}; frame-src ${turnstile.enabled ? TURNSTILE_SCRIPT_ORIGIN : "'none'"}; base-uri 'none'; frame-ancestors 'none'` } : {};
const WRITE_TYPES = { '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json', '.vk': 'application/octet-stream', '.dat': 'application/octet-stream' };
// The first 2^19 or 2^20 proving points, which a browser needs to prove a page: read once from the setup the Mac app
// downloads (HUMA_PROVING_SETUP_FILE, the development copy, or R2), checked against their pins, kept in memory.
const points = new Map();
function provingPoints(log, publications) {
    if (!points.has(log)) points.set(log, (async () => {
        const length = 32 << log, file = process.env.HUMA_PROVING_SETUP_FILE ?? path.join(root, '../build/research/noir-crs/bn254_g1_compressed.dat');
        let bytes = Buffer.alloc(length);
        try {
            const handle = await open(file);
            try { if ((await handle.read(bytes, 0, length, 0)).bytesRead !== length) throw new Error('Short setup file.'); } finally { await handle.close(); }
        } catch {
            const response = await fetch(publications.releaseURL(PROVING_SETUP), { headers: { Range: `bytes=0-${length - 1}` }, signal: AbortSignal.timeout(60000) });
            bytes = Buffer.from(await response.arrayBuffer());
        }
        if (bytes.length !== length || createHash('sha256').update(bytes).digest('hex') !== POINTS[log]) throw new Error('Proving points differ from their pin.');
        return bytes;
    })().catch(error => { points.delete(log); throw error; }));
    return points.get(log);
}

const root = fileURLToPath(new URL('./', import.meta.url));
// The research deck is built by Vite from deck/ into dist/deck, served read-only at /deck/.
const deckRoot = path.resolve(root, 'dist/deck');
const deckTypes = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.jpg': 'image/jpeg', '.txt': 'text/plain' };
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
// Consume a bounded excess before answering 413 so a nearly complete request
// does not get reset while the client is still sending its final bytes.
const MAX_REJECTED_BODY_BYTES = MAX_UPLOAD_BYTES + 65536;
const headers = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    'Strict-Transport-Security': 'max-age=31536000', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()', 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'" };
const json = (res, status, data) => { res.writeHead(status, { ...headers, 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
/** An unexpected error as the server's log keeps it: its stack and what caused it, with Arkiv's access key (part of its
 *  RPC address, which the Arkiv SDK's errors quote) taken out. */
const unexpected = error => [error?.stack ?? String(error), error?.cause?.shortMessage, error?.cause?.details].filter(Boolean).join('\n')
    .replace(/ark_live_[A-Za-z0-9_-]+/g, 'ark_live_…').split('\n').slice(0, 16).join('\n');
// Static files: browsers keep them and ask each time whether they changed (ETag), so a repeat visit only downloads
// what did. Large text and WebAssembly files are brotli-compressed once, in the background, and sent that way to
// browsers that accept it (the 10 MB proof checker becomes 2 MB); until that's done they go out as they are.
const statics = new Map();
// The site's pages share their nav and footer: a page's <!--#include footer--> is pages/partials/footer.html, put in
// when the page is first sent and again whenever it or a partial changes.
const PARTIALS = ['nav', 'footer', 'footer-compact', 'cta-short', 'cta-end'], INCLUDE = /<!--#include ([a-z-]+)-->/g;
async function staticFile(file, type) {
    const parts = type === 'text/html' ? await Promise.all(PARTIALS.map(name => staticFile(path.join(root, 'pages/partials', name + '.html'), 'text/x-partial')
        .then(part => [name, part], () => [name, null]))) : [];
    const { mtimeMs } = await stat(file), stamp = [mtimeMs, ...parts.map(([, part]) => part?.mtimeMs)].join();
    let entry = statics.get(file);
    if (entry?.stamp === stamp) return entry;
    let body = await readFile(file);
    if (parts.length) {
        const found = Object.fromEntries(parts);
        body = Buffer.from(body.toString('utf8').replace(INCLUDE, (marker, name) => found[name]?.body.toString('utf8') ?? marker));
    }
    entry = { mtimeMs, stamp, body, br: null, etag: 'W/"' + createHash('sha256').update(body).digest('base64url').slice(0, 22) + '"' };
    statics.set(file, entry);
    if (body.length >= 32768 && /^(text\/|application\/(wasm|json|xml)|image\/svg)/.test(type)) {
        brotliCompress(body, { params: { [zlib.BROTLI_PARAM_QUALITY]: 11, [zlib.BROTLI_PARAM_SIZE_HINT]: body.length } },
            (error, compressed) => { if (!error && compressed.length < body.length) entry.br = compressed; });
    }
    return entry;
}
function sendStatic(req, res, entry, extra) {
    const reply = { ...headers, 'Cache-Control': 'no-cache', ...extra, ETag: entry.etag, Vary: 'Accept-Encoding' };
    // Caddy may mark the tag weak or add its encoding to it, so look for the tag's value.
    if (req.headers['if-none-match']?.includes(entry.etag.slice(3, -1))) { res.writeHead(304, reply); res.end(); return; }
    const br = entry.br && /\bbr\b/.test(req.headers['accept-encoding'] ?? '');
    const body = br ? entry.br : entry.body;
    res.writeHead(200, { ...reply, ...(br ? { 'Content-Encoding': 'br' } : {}), 'Content-Length': body.length }); res.end(body);
}
// The checker's largest files are compressed at start, so the first reader after a deploy already gets them small.
for (const [file, type] of [['dist/compact/assets/barretenberg.wasm', 'application/wasm'], ['dist/compact/long-inline.js', 'text/javascript'],
    ['dist/device-verifier.js', 'text/javascript']]) staticFile(path.join(root, file), type).catch(() => {});

function readUpload(req) {
    return new Promise((resolve, reject) => {
        const chunks = []; let size = 0, oversized = false;
        const finish = (error, source) => {
            clearTimeout(timer); req.off('data', data); req.off('end', end); req.off('error', aborted); req.off('aborted', aborted);
            if (error) { req.pause(); reject(error); } else resolve(source);
        };
        const data = chunk => {
            size += chunk.length;
            if (size > MAX_REJECTED_BODY_BYTES) finish(failure(413, 'Payload exceeds 2 MB.'));
            else if (size > MAX_UPLOAD_BYTES) { oversized = true; chunks.length = 0; }
            else if (!oversized) chunks.push(chunk);
        };
        const end = () => oversized ? finish(failure(413, 'Payload exceeds 2 MB.')) : finish(null, Buffer.concat(chunks).toString('utf8'));
        const aborted = () => finish(failure(400, 'Upload interrupted.'));
        const timer = setTimeout(() => finish(failure(408, 'Upload timed out.')), 10000);
        req.on('data', data); req.once('end', end); req.once('error', aborted); req.once('aborted', aborted);
    });
}
function verifyPublic(source) {
    return new Promise((resolve, reject) => {
        const worker = spawn(process.execPath, ['--max-old-space-size=128', fileURLToPath(new URL('./registry-verifier.mjs', import.meta.url))], { stdio: ['pipe', 'pipe', 'pipe'] });
        const chunks = []; let size = 0, settled = false;
        const finish = (error, record) => {
            if (settled) return;
            settled = true; clearTimeout(timer); worker.kill('SIGKILL');
            if (error) reject(error); else resolve(record);
        };
        const timer = setTimeout(() => finish(failure(422, 'Verification exceeded its resource limit.')), 10000);
        worker.stdout.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_UPLOAD_BYTES) finish(failure(422, 'Public record exceeds limits.'));
            else chunks.push(chunk);
        });
        worker.stderr.on('data', () => {}); // Drain; never expose private request/error bytes.
        worker.stdin.on('error', () => finish(failure(422, 'Verifier stopped before completion.')));
        worker.once('error', () => finish(failure(422, 'Verification failed.')));
        worker.once('close', code => code === 0 && size > 0
            ? finish(null, Buffer.concat(chunks).toString('utf8')) : finish(failure(422, 'Proof does not match text or is unsupported.')));
        worker.stdin.end(source);
    });
}

export async function createRegistry({ store = path.join(root, 'data'), publicationOptions = {}, allowLegacyUploads = false } = {}) {
    await mkdir(store, { recursive: true });
    // One Turnstile check for the page's own gate and for publishing (tests pass theirs in publicationOptions).
    const turnstile = publicationOptions.turnstile ?? configuredTurnstile();
    const world = publicationOptions.worldId ?? configuredWorldID();
    const publications = createPublications({ directory: path.join(store, 'publications'), ...publicationOptions, turnstile, worldId: world });
    const humanCheck = turnstileRoutes(turnstile), worldCheck = worldIDRoutes(world);
    const visits = eventRoutes(publicationOptions.events ?? configuredEvents());
    const released = async key => {
        let check = releaseChecks.get(key);
        if (!check || check.at < Date.now() - 60000) releaseChecks.set(key, check = { at: Date.now(), ready: await publications.releaseExists(key) });
        return check.ready;
    };
    const requests = createRequests({ objectStore: publications.objectStore, page: publications.requestPage, shortPage: publications.shortPage });
    const documents = createDocuments({ objectStore: publications.objectStore, deviceKey, deviceSigned, worldId: world });
    const ids = new Set((await readdir(store)).filter(name => /^[a-f0-9]{64}\.json$/.test(name)).map(name => name.slice(0, -5)));
    let admitted = 0;
    let storageTail = Promise.resolve();
    async function persist(id, record) {
        const prior = storageTail; let release;
        storageTail = new Promise(resolve => { release = resolve; });
        await prior;
        try {
            if (ids.has(id)) return;
            if (ids.size >= 1000) throw failure(507, 'Registry is full.');
            const temporary = path.join(store, id + '.tmp-' + randomUUID());
            try {
                await writeFile(temporary, record, { mode: 0o600 });
                await rename(temporary, path.join(store, id + '.json'));
                ids.add(id);
            } catch (error) { await unlink(temporary).catch(() => {}); throw error; }
        } finally { release(); }
    }
    const server = http.createServer(async (req, res) => {
        let reserved = false;
        try {
            const url = new URL(req.url, 'http://localhost');
            if (req.method === 'POST') {
                const origin = req.headers.origin;
                if (origin && origin !== `http://${req.headers.host}` && origin !== `https://${req.headers.host}`) throw failure(403, 'Origin not allowed.');
            }
            if (await publications.handle(req, res, url.pathname, { json, headers })) return;
            if (await requests(req, res, url.pathname, { json })) return;
            if (await documents(req, res, url.pathname, { json })) return;
            if (await humanCheck(req, res, url.pathname, { json })) return;
            if (await worldCheck(req, res, url.pathname, { json })) return;
            if (await visits(req, res, url.pathname, { json })) return;
            const files = { '/device-verifier.js': ['dist/device-verifier.js', 'text/javascript'], '/replay-worker.js': ['pages/replay-worker.mjs', 'text/javascript'], '/replay/huma_replay_browser.js': ['dist/replay/huma_replay_browser.js', 'text/javascript'], '/replay/huma_replay_browser_bg.wasm': ['dist/replay/huma_replay_browser_bg.wasm', 'application/wasm'], '/': ['pages/foundation.html', 'text/html'], '/verify': ['pages/verify.html', 'text/html'], '/site.css': ['pages/site.css', 'text/css'], '/brand/mark.svg': ['pages/brand/huma-mark.svg', 'image/svg+xml'], '/brand/huma-mark.svg': ['pages/brand/huma-mark.svg', 'image/svg+xml'], '/brand/icon-512.png': ['pages/brand/icon-512.png', 'image/png'], '/download': ['pages/download.html', 'text/html'], '/privacy': ['pages/privacy.html', 'text/html'], '/prove-you-didnt-use-ai': ['pages/guide-prove.html', 'text/html'], '/ai-detector-false-positive': ['pages/guide-detector.html', 'text/html'], '/robots.txt': ['pages/robots.txt', 'text/plain; charset=utf-8'], '/sitemap.xml': ['pages/sitemap.xml', 'application/xml'], '/llms.txt': ['pages/llms.txt', 'text/plain; charset=utf-8'], '/terms': ['pages/terms.html', 'text/html'], '/appcast.xml': ['pages/appcast.xml', 'application/xml'], '/download.js': ['pages/download.js', 'text/javascript'], '/ask': ['pages/ask.html', 'text/html'], '/ask.js': ['pages/ask.js', 'text/javascript'], '/fonts/inter.woff2': ['pages/fonts/inter.woff2', 'font/woff2'], '/fonts/newsreader-latin.woff2': ['pages/fonts/newsreader-latin.woff2', 'font/woff2'], '/fonts/newsreader-latin-ext.woff2': ['pages/fonts/newsreader-latin-ext.woff2', 'font/woff2'], '/fonts/NEWSREADER-OFL.txt': ['pages/fonts/NEWSREADER-OFL.txt', 'text/plain'], '/img/og-page.png': ['pages/img/og-page.png', 'image/png'], '/img/og-home.jpg': ['pages/img/og-home.jpg', 'image/jpeg'], '/fonts/OFL.txt': ['pages/fonts/OFL.txt', 'text/plain'], '/verify.js': ['pages/verify.mjs', 'text/javascript'], '/foundation-logo.svg': ['pages/foundation-logo.svg', 'image/svg+xml'], '/foundation.css': ['pages/foundation.css', 'text/css'], '/foundation.js': ['pages/foundation.js', 'text/javascript'], '/fonts/geist-mono.woff2': ['pages/fonts/geist-mono.woff2', 'font/woff2'], '/fonts/GEIST-OFL.txt': ['pages/fonts/GEIST-OFL.txt', 'text/plain'], '/vendor/qr/qr.mjs': ['pages/vendor/qr/qr.mjs', 'text/javascript'], '/vendor/qr/LICENSE.txt': ['pages/vendor/qr/LICENSE.txt', 'text/plain'], '/vendor/pdf-lib/pdf-lib.mjs': ['pages/vendor/pdf-lib/pdf-lib.mjs', 'text/javascript'], '/vendor/pdf-lib/fontkit.js': ['pages/vendor/pdf-lib/fontkit.js', 'text/javascript'], '/vendor/pdf-lib/LICENSE-pdf-lib.txt': ['pages/vendor/pdf-lib/LICENSE-pdf-lib.txt', 'text/plain'], '/vendor/pdf-lib/LICENSE-fontkit.txt': ['pages/vendor/pdf-lib/LICENSE-fontkit.txt', 'text/plain'], '/report-pdf.mjs': ['pages/report-pdf.mjs', 'text/javascript'], '/fonts/tinos-report.ttf': ['pages/fonts/tinos-report.ttf', 'font/ttf'], '/fonts/tinos-bold-report.ttf': ['pages/fonts/tinos-bold-report.ttf', 'font/ttf'], '/fonts/TINOS-OFL.txt': ['pages/fonts/TINOS-OFL.txt', 'text/plain'] };
            // Explicit reader assets only; never expose circuit witnesses or experiment sources.
            for (const file of ['compact-verifier.js', 'compact-worker.js', 'compact-inline.js', 'media-inline.js', 'assurance-inline.js', 'long-inline.js', 'assets/long-chunk.vk', 'assets/long-final1024.vk', 'assets/long-final4096.vk', 'assets/long-final10000.vk', 'assets/long2-final1024.vk', 'assets/long2-final4096.vk', 'assets/long2-final10000.vk', 'assets/long3-chunk1024.vk', 'assets/long3-final1024.vk', 'assets/long3-chunk4096.vk', 'assets/long3-final4096.vk', 'assets/long3-chunk10000.vk', 'assets/long3-final10000.vk', 'assets/assurance256.vk', 'assets/assurance256-v2.vk', 'assets/assurance256-cp32.vk', 'assets/assurance64.vk', 'assets/assurance128-cp32.vk', 'assets/assurance-abi.json', 'assets/assurance-cp32-abi.json', 'assets/media-membership.vk', 'assets/cast256.vk', 'assets/journal-abi.json', 'assets/g2.dat', 'assets/barretenberg.wasm', 'assets/barretenberg-threads.wasm']) {
                const type = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.json') ? 'application/json' : 'application/octet-stream';
                files['/compact/' + file] = ['dist/compact/' + file, type];
            }
            for (const file of ['browser.mjs', 'worker.mjs', 'core.mjs', 'contract.mjs']) {
                files['/verify-core/' + file] = ['verify-core/' + file, 'text/javascript'];
            }
            files['/publication-contract.mjs'] = ['publication-contract.mjs', 'text/javascript'];
            files['/replay-core.mjs'] = ['replay-core.mjs', 'text/javascript'];
            files['/replay-player.js'] = ['pages/replay-player.mjs', 'text/javascript'];
            files['/writer.mjs'] = ['pages/writer.mjs', 'text/javascript'];
            files['/track.js'] = ['pages/track.mjs', 'text/javascript'];
            files['/visit.js'] = ['pages/visit.mjs', 'text/javascript'];
            files['/blog'] = ['pages/blog/index.html', 'text/html'];
            for (const post of POSTS) files['/blog/' + post] = ['pages/blog/' + post + '.html', 'text/html'];
            for (const image of IMAGES) files['/blog/img/' + image] = ['pages/blog/img/' + image, 'image/webp'];
            // A writer's page, huma.social/@handle: the page asks /api/writers/<handle> for what to show (or says there's no such writer).
            const handle = req.method === 'GET' ? url.pathname.match(/^\/@([^/]{1,64})$/)?.[1] : undefined;
            if (handle !== undefined) { try { writerHandle(decodeURIComponent(handle)); files[url.pathname] = ['pages/writer.html', 'text/html']; } catch {} }
            if (req.method === 'GET' && (url.pathname === '/write' || url.pathname.startsWith('/write/'))) {
                const log = url.pathname.match(/^\/write\/points\/(19|20)$/)?.[1];
                if (log) {
                    const body = await provingPoints(Number(log), publications);
                    res.writeHead(200, { ...headers, ...WRITE_ISOLATION, 'Content-Type': 'application/octet-stream', 'Content-Length': body.length,
                        'Cache-Control': 'public, max-age=31536000, immutable' }); res.end(body); return;
                }
                const name = url.pathname === '/write' ? null : url.pathname.slice('/write/'.length);
                if (name !== null && !/^[a-z0-9-]+\.(js|wasm|json|vk|dat)$/.test(name)) throw failure(404, 'Not found.');
                const [file, type] = name === null ? ['pages/write.html', 'text/html'] : ['dist/write/' + name, WRITE_TYPES[path.extname(name)]];
                const entry = await staticFile(path.join(root, file), type).catch(() => { throw failure(404, 'Not found.'); });
                sendStatic(req, res, entry, { ...WRITE_ISOLATION, ...(name === null ? writePolicy(turnstile, world) : {}), 'Content-Type': type }); return;
            }
            if (req.method === 'GET' && url.pathname === '/api/publication-config') {
                json(res, 200, { privyAppId: process.env.PRIVY_APP_ID ?? null, storage: publications.storage }); return;
            }
            if (req.method === 'GET' && (url.pathname.startsWith('/share/assets/') || url.pathname === '/share/signin' || /^\/share\/[a-f0-9]{64}$/.test(url.pathname))) {
                const name = url.pathname.startsWith('/share/assets/') ? url.pathname.slice('/share/assets/'.length) : null;
                if (name && name.match(/^[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:js|css|wasm)$/)?.[0] !== name) throw failure(404, 'Not found.');
                const type = name?.endsWith('.js') ? 'text/javascript' : name?.endsWith('.css') ? 'text/css' : name?.endsWith('.wasm') ? 'application/wasm' : 'text/html';
                const entry = await staticFile(path.join(root, 'dist/share', name ? 'assets/' + name : 'index.html'), type).catch(() => { throw failure(404, 'Sharing page is not built.'); });
                // Vite puts a content hash in every asset's name, so those never change.
                sendStatic(req, res, entry, { 'Referrer-Policy': 'no-referrer', 'Content-Type': type, ...(name ? { 'Cache-Control': 'public, max-age=31536000, immutable' } : {}),
                    // World ID sign-in (share/src/WorldSignIn.jsx) reaches World's bridge, which carries the proof from World App.
                    // Privy sign-in, off for now, also needed https://auth.privy.io and https://*.rpc.privy.systems (connect),
                    // and https://auth.privy.io as a child and frame (see Privy's CSP guide).
                    'Content-Security-Policy': `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ${BRIDGE_ORIGIN}; frame-src 'none'; worker-src 'self'; base-uri 'none'; frame-ancestors 'none'` }); return;
            }
            if (req.method === 'GET' && /^\/verify\/[a-f0-9]{64}$/.test(url.pathname)) files[url.pathname] = files['/verify'];
            // Writing requests: make one, the writer's page for it, and the requester's inbox (its key stays in the #).
            if (req.method === 'GET' && /^\/r\/[a-f0-9]{32}(\/inbox)?$/.test(url.pathname)) files[url.pathname] = files['/ask'];
            // The Mac app comes straight from Cloudflare R2 through a one-hour signed link. Until it's uploaded
            // (checked at most once a minute), the button returns to the download page, which says so.
            const faceSeed = url.pathname.match(/^\/avatar\/([^/]+)\.svg$/)?.[1];
            if (req.method === 'GET' && faceSeed !== undefined) {
                if (!AVATAR_SEED.test(faceSeed)) throw failure(404, 'Not found.');
                const body = Buffer.from(face(faceSeed));
                res.writeHead(200, { ...headers, 'Content-Type': 'image/svg+xml', 'Content-Length': body.length, 'X-Content-Type-Options': 'nosniff',
                    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'", 'Cache-Control': 'public, max-age=31536000, immutable' });
                res.end(body); return;
            }
            if (req.method === 'GET' && url.pathname === '/engine/proving-setup') {
                let location = null;
                if (await released(PROVING_SETUP)) try { location = publications.releaseURL(PROVING_SETUP); } catch {}
                if (!location) throw failure(404, 'Not found.');
                res.writeHead(302, { ...headers, Location: location }); res.end(); return;
            }
            if (req.method === 'GET' && url.pathname === '/download/Huma.dmg') {
                const key = `releases/Huma-${HUMA_RELEASE}.dmg`;
                let location = null;
                if (await released(key)) try { location = publications.releaseURL(key); } catch {}
                res.writeHead(302, { ...headers, Location: location ?? '/download#soon' }); res.end(); return;
            }
            // The landing page's picture (pages/foundation-media/), kept a day in the browser.
            const media = url.pathname.match(/^\/foundation-media\/([a-z0-9-]+\.(jpg|webp))$/);
            if (req.method === 'GET' && media) {
                const body = await readFile(path.join(root, 'pages/foundation-media', media[1])).catch(() => { throw failure(404, 'Not found.'); });
                res.writeHead(200, { ...headers, 'Content-Type': media[2] === 'jpg' ? 'image/jpeg' : 'image/webp', 'Cache-Control': 'public, max-age=86400', 'Content-Length': body.length }); res.end(body); return;
            }
            // The landing page used to live at /foundation.
            if (req.method === 'GET' && url.pathname === '/foundation') { res.writeHead(301, { ...headers, Location: '/' }); res.end(); return; }
            if (req.method === 'GET' && url.pathname === '/deck') { res.writeHead(301, { ...headers, Location: '/deck/' }); res.end(); return; }
            if (req.method === 'GET' && url.pathname.startsWith('/deck/')) {
                const file = path.resolve(deckRoot, url.pathname === '/deck/' ? 'index.html' : decodeURIComponent(url.pathname.slice(6)));
                const type = deckTypes[path.extname(file)];
                if (!file.startsWith(deckRoot + path.sep) || !type) throw failure(404, 'Not found.');
                const body = await readFile(file).catch(() => { throw failure(404, 'Not found.'); });
                res.writeHead(200, { ...headers, 'Content-Type': type }); res.end(body); return;
            }
            // A finished page to look at before writing one: the shared link set in HUMA_EXAMPLE_LINK (path and token).
            if (req.method === 'GET' && url.pathname === '/example') {
                // A shared page's link, full (/original/<id>#<token>) or short (/p/<code>#<key>), with or without the site
                // it was copied from (only the path and key are kept); anything else goes home.
                const example = (process.env.HUMA_EXAMPLE_LINK ?? '').trim().replace(/^https?:\/\/[^/]+/, '');
                res.writeHead(302, { ...headers, Location: isPageLink(example) ? example : '/' }); res.end(); return;
            }
            // A shared page, by its full link or its short one (/p/<code>, publications.mjs). The page reads its id from
            // huma-page; the key after the # never reaches this server.
            const short = req.method === 'GET' ? url.pathname.match(/^\/p\/([A-Za-z0-9]{8,12})$/)?.[1] : null;
            const shared = url.pathname.match(/^\/original\/([a-f0-9]{64})$/)?.[1] ?? (short ? await publications.shortPage(short) : null);
            if (short && !shared) throw failure(404, 'Not found.');
            if (req.method === 'GET' && shared) {
                // A pasted link shows a card in chats and mail: who wrote it (if they chose a name), never the text.
                const name = await publications.previewName(shared), escape = value => value.replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
                const title = name ? escape(name) + ' typed this · Huma' : 'Typed by a person · Huma';
                const tags = `<meta property="og:type" content="article">\n<meta property="og:site_name" content="Huma">\n<meta property="og:title" content="${title}">\n` +
                    `<meta property="og:description" content="Typed key by key in Huma. Open the link to check it yourself.">\n` +
                    `<meta property="og:image" content="https://huma.social/img/og-page.png">\n<meta property="og:image:width" content="1200">\n<meta property="og:image:height" content="630">\n` +
                    `<meta name="twitter:card" content="summary_large_image">\n<meta name="twitter:site" content="@huma_social">\n<meta name="huma-page" content="${shared}">\n<title>${title}</title>\n` +
                    // Only people with the link (and its key) can read the page, so it stays out of search.
                    `<meta name="robots" content="noindex">\n` +
                    // The checker's engine (2 MB compressed) starts downloading with the page; the check reuses it from the cache.
                    `<link rel="preload" href="/compact/assets/barretenberg.wasm" as="fetch" crossorigin="anonymous">`;
                // Sent already in reader view, so the verification tool never flashes up before the script runs.
                const body = Buffer.from((await staticFile(path.join(root, 'pages/verify.html'), 'text/html')).body.toString('utf8').replace(/<!-- tags:[^]*?<!-- \/tags -->/, () => tags)
                    .replace('<body>', '<body class="reader">').replace('<h1 class="page-title">Verify a proof.</h1>', '<h1 class="page-title">Shared on Huma.</h1>')
                    .replace('<p class="page-lead">Runs in your browser. Nothing is uploaded.</p>', '<p class="page-lead">Your browser checks this page itself.</p>'));
                res.writeHead(200, { ...headers, 'Content-Type': 'text/html', 'Content-Length': body.length }); res.end(body); return;
            }
            if (req.method === 'GET' && files[url.pathname]) {
                const [file, type] = files[url.pathname];
                // The landing page's globe draws CARTO's basemap (tiles, glyphs, sprites). MapLibre's worker takes its
                // policy from its own script's response, so the vendor files carry the same one.
                const csp = url.pathname === '/' ? { 'Content-Security-Policy': `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'` } : {};
                // Fonts, the vendored libraries and the blog's pictures rarely change, so browsers may keep them for a week.
                const cache = /^\/(fonts|vendor|blog\/img)\//.test(url.pathname) ? { 'Cache-Control': 'public, max-age=604800' } : {};
                sendStatic(req, res, await staticFile(path.join(root, file), type), { ...csp, ...cache, 'Content-Type': type }); return;
            }
            const lookupID = url.pathname.match(/^\/api\/proofs\/([a-f0-9]{64})$/)?.[1];
            if (req.method === 'GET' && lookupID) {
                try { const record = await readFile(path.join(store, lookupID + '.json')); res.writeHead(200, { ...headers, 'Content-Type': 'application/json' }); res.end(record); }
                catch { json(res, 404, { error: 'Proof not found.' }); }
                return;
            }
            if (req.method !== 'POST' || url.pathname !== '/api/proofs') throw failure(404, 'Not found.');
            // Old records remain readable. New hosted writes must use the
            // approved master+proof flow and its durable uploader quotas.
            // Only isolated compatibility harnesses opt into the retired API.
            if (!allowLegacyUploads) throw failure(410, 'Proof-only uploads are retired. Share the master and proof together.');
            if (!(req.headers['content-type'] ?? '').startsWith('application/json')) throw failure(415, 'JSON required.');
            if (Number(req.headers['content-length'] ?? 0) > MAX_REJECTED_BODY_BYTES) throw failure(413, 'Payload exceeds 2 MB.');
            if (admitted >= 2) throw failure(429, 'Verifier busy; retry later.');
            // Reserve before reading: slow uploads count against the same two-job limit.
            admitted++; reserved = true;
            const record = await verifyPublic(await readUpload(req));
            const id = createHash('sha256').update(record).digest('hex');
            await persist(id, record);
            json(res, 201, { id });
        } catch (error) {
            // A person who follows a wrong link in a browser gets a page, not an error object.
            if (error.status === 404 && req.method === 'GET' && !req.url.startsWith('/api/') && /text\/html/.test(req.headers.accept ?? '') && !res.headersSent) {
                const page = (await staticFile(path.join(root, 'pages/notfound.html'), 'text/html').catch(() => null))?.body;
                if (page) { res.writeHead(404, { ...headers, 'Content-Type': 'text/html; charset=utf-8' }); res.end(page); return; }
            }
            // An error no handler expected (no status) is logged here, never sent: it may quote private input.
            if (!error.status) console.error(new Date().toISOString(), req.method, String(req.url).split('?')[0], unexpected(error));
            if (!res.headersSent && !res.destroyed) {
                res.setHeader('Connection', 'close');
                json(res, error.status ?? 400, { error: error.status ? error.message : 'Invalid request.' });
            } else res.end();
        } finally { if (reserved) admitted--; }
    });
    // The editor's event stream (detection/stream.mjs): a WebSocket from the write page, same origin only.
    server.on('upgrade', (req, socket, head) => {
        const origin = req.headers.origin, host = req.headers.host;
        const pathname = (() => { try { return new URL(req.url, 'http://localhost').pathname; } catch { return null; } })();
        if (pathname !== '/api/sessions/stream' || !origin || !host || (origin !== `http://${host}` && origin !== `https://${host}`)) { socket.destroy(); return; }
        const connection = upgradeSocket(req, socket, head);
        if (connection) publications.streams.accept(connection, clientAddress(req));
    });
    server.requestTimeout = 60000; server.headersTimeout = 10000;
    server.once('close', () => { publications.close(); });
    server.streams = publications.streams;
    return server;
}
export const server = await createRegistry();
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const host = process.env.HUMA_REGISTRY_HOST ?? '127.0.0.1';
    const port = Number(process.env.HUMA_REGISTRY_PORT ?? 4318);
    server.listen(port, host, () => console.log(`Huma proof registry: http://${host}:${port}`));
}
