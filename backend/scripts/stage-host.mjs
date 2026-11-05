// Puts the server package on R2 as deploy/host.tgz and writes a 15-minute signed GET link to argv[3] (mode 600),
// so the server downloads it from Cloudflare instead of over a slow ssh upload. Run from web/ with the R2 env.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
// The S3 client is installed with the web host, not next to this script.
const { S3Client, PutObjectCommand } = await import(pathToFileURL(createRequire(new URL('../../frontend/package.json', import.meta.url).pathname).resolve('@aws-sdk/client-s3')).href);

const [file, out] = process.argv.slice(2);
const endpoint = new URL(process.env.R2_ENDPOINT), bucket = process.env.R2_BUCKET, key = 'deploy/host.tgz';
const accessKeyId = process.env.R2_ACCESS_KEY_ID, secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
const body = readFileSync(file);
const client = new S3Client({ region: 'auto', endpoint: endpoint.origin, forcePathStyle: true, credentials: { accessKeyId, secretAccessKey } });
await client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentType: 'application/gzip' }));

const sha256 = value => createHash('sha256').update(value).digest('hex');
const time = new Date().toISOString().replace(/[-:]|\.\d{3}/g, ''), day = time.slice(0, 8), scope = `${day}/auto/s3/aws4_request`;
const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const query = Object.entries({ 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${accessKeyId}/${scope}`,
  'X-Amz-Date': time, 'X-Amz-Expires': '900', 'X-Amz-SignedHeaders': 'host' })
  .map(([k, v]) => `${encode(k)}=${encode(v)}`).sort().join('&');
const resource = `/${bucket}/${key.split('/').map(encode).join('/')}`;
const request = ['GET', resource, query, `host:${endpoint.host}`, '', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
const hmac = (k, v) => createHmac('sha256', k).update(v).digest();
const signingKey = ['auto', 's3', 'aws4_request'].reduce(hmac, hmac('AWS4' + secretAccessKey, day));
const signature = createHmac('sha256', signingKey).update(['AWS4-HMAC-SHA256', time, scope, sha256(request)].join('\n')).digest('hex');
writeFileSync(out, `https://${endpoint.host}${resource}?${query}&X-Amz-Signature=${signature}\n${sha256(body)}\n`, { mode: 0o600 });
console.log(`Staged ${key} on R2 (${body.length} bytes)`);
