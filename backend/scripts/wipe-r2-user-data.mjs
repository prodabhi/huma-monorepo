// Empties huma.social's user data in R2 before launch: shared pages, accounts, documents, profiles, handles, writer
// records and sign-in links. Releases (releases/), the proving setup (engine/), site media (media/) and deploys
// (deploy/) are kept. Lists what it would remove unless --delete is given.
//   cd web && node --env-file=../.env.local ../scripts/wipe-r2-user-data.mjs            (counts only)
//   cd web && node --env-file=../.env.local ../scripts/wipe-r2-user-data.mjs --delete   (removes them)
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../frontend/package.json', import.meta.url));
const { S3Client, ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');

// Every prefix the server writes user data under (frontend/object-store.mjs objectKey and quotaKey).
const USER_DATA = ['objects', 'records', 'quotas', 'devices', 'removed', 'requests', 'short', 'replays', 'writers', 'owners',
  'documents', 'handles', 'writers-index', 'listed'].map(name => name + '/');
const remove = process.argv.includes('--delete');
for (const name of ['R2_ENDPOINT', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY']) if (!process.env[name]) throw new Error(name + ' is missing.');
const c = new S3Client({ region: 'auto', endpoint: process.env.R2_ENDPOINT,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET;

async function* keys(Prefix) {
  for (let ContinuationToken; ;) {
    const page = await c.send(new ListObjectsV2Command({ Bucket, Prefix, ContinuationToken }));
    for (const item of page.Contents ?? []) yield item.Key;
    if (!page.IsTruncated) return;
    ContinuationToken = page.NextContinuationToken;
  }
}
// Everything else in the bucket, so it's clear what stays.
const kept = new Map();
for await (const key of keys('')) if (!USER_DATA.some(p => key.startsWith(p))) kept.set(key.split('/')[0] + '/', (kept.get(key.split('/')[0] + '/') ?? 0) + 1);

let total = 0;
for (const prefix of USER_DATA) {
  let batch = [], count = 0;
  const flush = async () => {
    if (remove && batch.length) await c.send(new DeleteObjectsCommand({ Bucket, Delete: { Objects: batch.map(Key => ({ Key })), Quiet: true } }));
    batch = [];
  };
  for await (const key of keys(prefix)) { count++; batch.push(key); if (batch.length === 1000) await flush(); }
  await flush();
  if (count) console.log(`${remove ? 'removed' : 'would remove'} ${count} under ${prefix}`);
  total += count;
}
console.log(`${remove ? 'Removed' : 'Would remove'} ${total} objects.`);
console.log('Kept:', [...kept].map(([p, n]) => `${p} ${n}`).join(', ') || 'nothing else');
if (!remove) console.log('Run again with --delete to remove them, then redeploy (backend/scripts/ship.sh --web) so the server starts clean.');
