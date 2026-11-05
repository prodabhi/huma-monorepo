// Uploads the landing page's hero video to R2 as media/hero-v1.mp4 (HERO_VIDEO in web/registry.mjs). huma.social then
// sends browsers there for /foundation-media/hero.mp4 through a signed link, so the video doesn't come from the server.
// Run from web/: node --env-file=../.env.local ../scripts/upload-media.mjs
// A name is written once: for a new video, bump the version here and in HERO_VIDEO.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = new URL('../../', import.meta.url).pathname;
const { S3Client, PutObjectCommand, HeadObjectCommand } =
  await import(pathToFileURL(createRequire(root + 'frontend/package.json').resolve('@aws-sdk/client-s3')).href);
const Key = readFileSync(root + 'frontend/registry.mjs', 'utf8').match(/const HERO_VIDEO = '(media\/[a-z0-9-]+\.mp4)'/)?.[1];
if (!Key) throw new Error('HERO_VIDEO is missing from web/registry.mjs.');
const file = process.argv[2] ?? root + 'frontend/pages/foundation-media/hero.mp4', body = readFileSync(file);
const client = new S3Client({ region: 'auto', endpoint: process.env.R2_ENDPOINT,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET;

const existing = await client.send(new HeadObjectCommand({ Bucket, Key })).catch(() => null);
if (existing) {
  if (existing.ContentLength !== body.length) throw new Error(`${Key} already holds a different file. Bump the version in HERO_VIDEO.`);
  console.log(`${Key} is already uploaded.`); process.exit(0);
}
for (let attempt = 1; ; attempt++) {
  try {
    await client.send(new PutObjectCommand({ Bucket, Key, Body: body, ContentType: 'video/mp4', IfNoneMatch: '*',
      CacheControl: 'public, max-age=31536000, immutable' }), { abortSignal: AbortSignal.timeout(300000) });
    break;
  } catch (error) { if (attempt === 4) throw error; }
}
const head = await client.send(new HeadObjectCommand({ Bucket, Key }));
if (head.ContentLength !== body.length) throw new Error('Uploaded size differs.');
console.log(`Uploaded ${Key}: ${body.length} bytes, sha256 ${createHash('sha256').update(body).digest('hex')}`);
