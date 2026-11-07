// The Vercel function: the same request handler as the self-hosted server (frontend/registry.mjs), without listen().
// backend/scripts/vercel-build.mjs puts this file at the root of the host package it builds into .vercel/output.
// Vercel's code folder is read-only; the server's own folder goes to /tmp, which lasts only as long as the instance,
// so pages, proofs and accounts must live in R2 (HUMA_STORAGE_BACKEND=r2) or Arkiv.
process.env.HUMA_DATA_DIR ||= '/tmp/huma-data';
const { server } = await import('./frontend/registry.mjs');

export default function handler(req, res) {
  server.emit('request', req, res);
}
