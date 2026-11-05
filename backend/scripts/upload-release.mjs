// Uploads the notarized build/release/Huma.dmg to R2 as releases/Huma-<version>.dmg, which huma.social/download/Huma.dmg
// serves through a one-hour signed link. Run from web/: node --env-file=../.env.local ../scripts/upload-release.mjs
// Parts of 16 MB, each retried, so a slow or flaky connection doesn't restart the whole file.
import { readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = new URL('../../', import.meta.url).pathname;
// The S3 client is installed with the web host, not next to this script.
const { S3Client, CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, HeadObjectCommand } =
  await import(pathToFileURL(createRequire(root + 'frontend/package.json').resolve('@aws-sdk/client-s3')).href);
const version = readFileSync(root + 'extra/Resources/Info.plist', 'utf8').match(/<key>CFBundleShortVersionString<\/key>\s*<string>([\d.]+)<\/string>/)?.[1];
const served = readFileSync(root + 'frontend/registry.mjs', 'utf8').match(/const HUMA_RELEASE = '([\d.]+)'/)?.[1];
if (!version || version !== served) throw new Error(`App version ${version} doesn't match HUMA_RELEASE ${served} in web/registry.mjs.`);
const file = process.argv[2] ?? root + 'build/release/Huma.dmg', size = statSync(file).size, Key = `releases/Huma-${version}.dmg`, PART = 16 * 1024 * 1024;
const client = new S3Client({ region: 'auto', endpoint: process.env.R2_ENDPOINT,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET;

const { UploadId } = await client.send(new CreateMultipartUploadCommand({ Bucket, Key, ContentType: 'application/x-apple-diskimage' }));
const fd = openSync(file, 'r'), parts = [], whole = createHash('sha256');
try {
  for (let start = 0, number = 1; start < size; start += PART, number++) {
    const body = Buffer.alloc(Math.min(PART, size - start)); readSync(fd, body, 0, body.length, start); whole.update(body);
    for (let attempt = 1; ; attempt++) {
      try {
        const { ETag } = await client.send(new UploadPartCommand({ Bucket, Key, UploadId, PartNumber: number, Body: body }), { abortSignal: AbortSignal.timeout(300000) });
        parts.push({ PartNumber: number, ETag }); break;
      } catch (error) { if (attempt === 4) throw error; }
    }
    process.stdout.write(`part ${number}/${Math.ceil(size / PART)}\n`);
  }
  await client.send(new CompleteMultipartUploadCommand({ Bucket, Key, UploadId, MultipartUpload: { Parts: parts } }));
} catch (error) {
  await client.send(new AbortMultipartUploadCommand({ Bucket, Key, UploadId })).catch(() => {});
  throw error;
} finally { closeSync(fd); }
const head = await client.send(new HeadObjectCommand({ Bucket, Key }));
if (head.ContentLength !== size) throw new Error('Uploaded size differs.');
console.log(`Uploaded ${Key}: ${size} bytes, sha256 ${whole.digest('hex')}`);
