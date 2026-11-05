// Uploads the Mac app's proving points to R2 as engine/bn254_g1_compressed-3e1ac096.dat (PROVING_SETUP in
// web/registry.mjs). Release builds leave these 64 MB out of the installer; on first use the app downloads them through
// huma.social/engine/proving-setup and checks the same fingerprint (HumaCore ProvingSetup).
// Run from web/: node --env-file=../.env.local ../scripts/upload-engine.mjs
import { openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = new URL('../../', import.meta.url).pathname;
const { S3Client, PutObjectCommand, HeadObjectCommand } =
  await import(pathToFileURL(createRequire(root + 'frontend/package.json').resolve('@aws-sdk/client-s3')).href);
const SHA256 = '3e1ac09652ee9df779a4955fb8f7050620c7b1ee7f18566581bd00326b06be37', Key = 'engine/bn254_g1_compressed-3e1ac096.dat';
// The same first 2^21 points integrations/noir/package.py takes from the published setup.
const body = Buffer.alloc((1 << 21) * 32), fd = openSync(root + 'build/research/noir-crs/bn254_g1_compressed.dat', 'r');
try { if (readSync(fd, body, 0, body.length, 0) !== body.length) throw new Error('The setup file is too short.'); } finally { closeSync(fd); }
if (createHash('sha256').update(body).digest('hex') !== SHA256) throw new Error('The proving points differ from the pinned fingerprint.');
const client = new S3Client({ region: 'auto', endpoint: process.env.R2_ENDPOINT,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET;

const existing = await client.send(new HeadObjectCommand({ Bucket, Key })).catch(() => null);
if (existing) { console.log(`${Key} is already uploaded.`); process.exit(0); }
for (let attempt = 1; ; attempt++) {
  try {
    await client.send(new PutObjectCommand({ Bucket, Key, Body: body, ContentType: 'application/octet-stream', IfNoneMatch: '*',
      CacheControl: 'public, max-age=31536000, immutable' }), { abortSignal: AbortSignal.timeout(600000) });
    break;
  } catch (error) { if (attempt === 4) throw error; }
}
const head = await client.send(new HeadObjectCommand({ Bucket, Key }));
if (head.ContentLength !== body.length) throw new Error('Uploaded size differs.');
console.log(`Uploaded ${Key}: ${body.length} bytes, sha256 ${SHA256}`);
