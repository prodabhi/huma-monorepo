// Lets huma.social use files it links to in R2 (the hero video) inside WebGL: GET and HEAD from huma.social only.
// The bucket had no CORS rules before, so nothing else is replaced. Run from web/: node --env-file=../.env.local <this file>
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const { S3Client, PutBucketCorsCommand, GetBucketCorsCommand } =
  await import(pathToFileURL(createRequire(new URL('../../frontend/package.json', import.meta.url).pathname).resolve('@aws-sdk/client-s3')).href);
const c = new S3Client({ region: 'auto', endpoint: process.env.R2_ENDPOINT,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const Bucket = process.env.R2_BUCKET;
const rule = { AllowedOrigins: ['https://huma.social'], AllowedMethods: ['GET', 'HEAD'], AllowedHeaders: ['Range'],
  ExposeHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges'], MaxAgeSeconds: 86400 };
const existing = await c.send(new GetBucketCorsCommand({ Bucket })).then(r => r.CORSRules ?? [], () => []);
const same = existing.length === 1 && ['AllowedOrigins', 'AllowedMethods'].every(k => JSON.stringify(existing[0][k]) === JSON.stringify(rule[k]));
if (same) { console.log('CORS already set.'); process.exit(0); }
if (existing.length) { console.log('The bucket has other CORS rules; not replacing them:', JSON.stringify(existing)); process.exit(1); }
await c.send(new PutBucketCorsCommand({ Bucket, CORSConfiguration: { CORSRules: [rule] } }));
console.log('CORS set:', JSON.stringify((await c.send(new GetBucketCorsCommand({ Bucket }))).CORSRules));
