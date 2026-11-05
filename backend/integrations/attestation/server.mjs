import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceStore } from './store.mjs';
import { EvidenceService, policyFromEnvironment } from './service.mjs';

export function makeServer(service) {
    let active = 0; const limits = new Map();
    const send = (res, status, value) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(value)); };
    const server = http.createServer(async (req, res) => {
        if (req.method === 'GET' && req.url === '/v1/info') { send(res, 200, service.info()); return; }
        if (req.method !== 'POST' || !['/v1/challenges', '/v1/enroll', '/v1/assert'].includes(req.url)) { send(res, 404, { error: 'Not found.' }); return; }
        if (req.headers.origin) { send(res, 403, { error: 'Native clients only.' }); return; }
        if (!(req.headers['content-type'] ?? '').startsWith('application/json')) { send(res, 415, { error: 'JSON required.' }); return; }
        const now = Date.now();
        for (const [ip, entry] of limits) if (entry.until < now) limits.delete(ip);
        const ip = req.socket.remoteAddress ?? '';
        const count = limits.get(ip) ?? { hits: 0, until: now + 60000 };
        if (active >= 2 || ++count.hits > 60 || limits.size >= 1000) { send(res, 429, { error: 'Retry later.' }); return; }
        limits.set(ip, count); active++;
        try {
            let size = 0; const chunks = [];
            for await (const chunk of req) { size += chunk.length; if (size > 96 * 1024) { send(res, 413, { error: 'Evidence too large.' }); return; } chunks.push(chunk); }
            const data = JSON.parse(Buffer.concat(chunks));
            const result = req.url === '/v1/challenges' ? await service.challenge(data) : await service.accept(data, req.url === '/v1/enroll' ? 'enroll' : 'assert');
            send(res, 200, result);
        } catch { send(res, 422, { error: 'Evidence rejected. Check enrollment, challenge freshness and the configured app identity.' }); }
        finally { active--; }
    });
    server.requestTimeout = 15000; server.headersTimeout = 10000;
    return server;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const policy = policyFromEnvironment(process.env); // Missing identity disables startup; no simulated acceptance.
    const store = new EvidenceStore(process.env.HUMA_ATTEST_DATA ?? fileURLToPath(new URL('./data/', import.meta.url)));
    let service;
    try { service = new EvidenceService(store, policy); } catch (error) { store.close(); throw error; }
    const server = makeServer(service);
    const host = process.env.HUMA_ATTEST_HOST ?? '127.0.0.1', port = Number(process.env.HUMA_ATTEST_PORT ?? 4319);
    server.listen(port, host, () => console.log(`Huma device evidence service: http://${host}:${port}`));
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => { store.close(); process.exit(0); }));
}
