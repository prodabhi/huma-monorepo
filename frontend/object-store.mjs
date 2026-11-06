import { createHash, createHmac } from 'node:crypto';
import { mkdir, open, readdir, rename, unlink, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { ArkivObjectStore } from './arkiv-store.mjs';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function objectKey(key) {
  if (typeof key !== 'string' || key.match(/^(?:objects|records|quotas|devices|removed|requests|short|replays|writers|owners|documents|handles|writers-index|listed|sessions)\/[a-f0-9]{64}$/)?.[0] !== key) throw new Error('Invalid object key.');
  return key;
}
export function checked(bytes, key, limit) {
  if (bytes.length > limit || (key.startsWith('objects/') && sha256(bytes) !== key.slice(8))) throw new Error('Stored object failed integrity check.');
  return bytes;
}
export const QUOTA_STATE_LIMIT = 512 * 1024;
const RELEASE_KEY = /^releases\/Huma-\d+\.\d+\.\d+\.dmg$/;
// The landing page's video, kept in R2 so it doesn't come from this server (backend/scripts/upload-media.mjs).
const MEDIA_KEY = /^media\/[a-z0-9-]+\.(?:mp4|webm)$/;
// The Mac app's proving points, downloaded once on first use (HumaCore ProvingSetup; scripts/upload-engine.mjs).
const ENGINE_KEY = /^engine\/[a-z0-9_-]+\.dat$/;
const servable = key => RELEASE_KEY.test(key) || MEDIA_KEY.test(key) || ENGINE_KEY.test(key);
export function quotaKey(key) {
  objectKey(key);
  // Changeable state: upload quotas, writing requests (requests.mjs) and whether a page shows its replay
  // (publications.mjs). Everything else is written once.
  // and each account's list of documents (documents.mjs), whose versions are written once beside it;
  // writer pages: who holds each handle, each account's shared pages, and whether a page shows on its writer's page.
  // and when this server issued browser pages' session nonces (sessions.mjs).
  if (!/^(?:quotas|requests|replays|documents|handles|writers-index|listed|sessions)\//.test(key)) throw new Error('Invalid quota key.');
  return key;
}
export function quotaWrite(key, version, bytes) {
  quotaKey(key);
  if (!(version === null || (typeof version === 'string' && version.length > 0 && version.length <= 256)) ||
      !bytes.length || bytes.length > QUOTA_STATE_LIMIT) throw new Error('Invalid quota state.');
}
async function localRead(file, limit) {
  const handle = await open(file, 'r');
  try {
    if ((await handle.stat()).size > limit) throw new Error('Stored object exceeds limit.');
    const bytes = await handle.readFile();
    if (bytes.length > limit) throw new Error('Stored object exceeds limit.');
    return bytes;
  } finally { await handle.close(); }
}
const requestSignal = signal => signal ? AbortSignal.any([signal, AbortSignal.timeout(20000)]) : AbortSignal.timeout(20000);
// Windows refuses to replace a file another handle has open (EPERM/EBUSY/EACCES); a reader holds it only for a moment.
async function renameOver(from, to) {
  for (let attempt = 0; ; attempt++) {
    try { return await rename(from, to); }
    catch (error) {
      if (!['EPERM', 'EBUSY', 'EACCES'].includes(error.code) || attempt >= 40) throw error;
      await new Promise(resolve => setTimeout(resolve, 5 + attempt));
    }
  }
}
export class LocalObjectStore {
  constructor(directory) { this.directory = directory; this.kind = 'local'; }
  async put(key, bytes) {
    objectKey(key);
    checked(bytes, key, bytes.length);
    const file = path.join(this.directory, key);
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    try { await writeFile(file, bytes, { flag: 'wx', mode: 0o600 }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      if (!(await this.get(key, bytes.length)).equals(Buffer.from(bytes))) throw new Error('Immutable object differs.');
    }
  }
  async get(key, limit) { return checked(await localRead(path.join(this.directory, objectKey(key)), limit), key, limit); }
  /** The IDs stored under `records/` (every publication), so a removal can see who else uses a file. */
  async recordIDs() {
    try { return (await readdir(path.join(this.directory, 'records'))).filter(name => /^[a-f0-9]{64}$/.test(name)); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  }
  /** Deletes a shared page's file when its writer removes the link. Only page files can be deleted. */
  async remove(key) {
    if (!/^(objects|documents)\//.test(objectKey(key))) throw new Error('Only page files and documents can be removed.');
    await unlink(path.join(this.directory, key)).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
  async quotaRead(key, signal) {
    signal?.throwIfAborted();
    try {
      const bytes = await localRead(path.join(this.directory, quotaKey(key)), QUOTA_STATE_LIMIT);
      return { bytes, version: sha256(bytes) };
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async quotaCAS(key, version, bytes, signal) {
    quotaWrite(key, version, bytes); signal?.throwIfAborted();
    const file = path.join(this.directory, key), temporary = file + '.tmp-' + randomUUID();
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    let lock;
    try { lock = await open(file + '.lock', 'wx', 0o600); }
    catch (error) { if (error.code === 'EEXIST') return false; throw error; }
    try {
      if ((await this.quotaRead(key, signal))?.version !== (version ?? undefined)) return false;
      const output = await open(temporary, 'wx', 0o600);
      try { await output.writeFile(bytes); await output.sync(); } finally { await output.close(); }
      signal?.throwIfAborted(); await renameOver(temporary, file);
      return true;
    } finally {
      await lock.close(); await unlink(file + '.lock'); await unlink(temporary).catch(() => {});
    }
  }
  close() {}
}
export class R2ObjectStore {
  constructor({ endpoint, bucket, accessKeyId, secretAccessKey, client } = {}) {
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket ?? '')) throw new Error('R2 bucket is required.');
    this.bucket = bucket; this.kind = 'r2';
    if (client) { this.client = client; return; } // Explicit dependency injection for local transport tests.
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
        url.pathname !== '/' || !/^[a-f0-9]{32}(?:\.(?:eu|fedramp))?\.r2\.cloudflarestorage\.com$/.test(url.hostname) ||
        !accessKeyId || !secretAccessKey) throw new Error('Complete server-side R2 configuration is required.');
    this.signing = { host: url.host, accessKeyId, secretAccessKey };
    this.client = new S3Client({ endpoint: url.origin, region: 'auto', forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey }, maxAttempts: 2,
      requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED',
      requestHandler: { requestTimeout: 15000, connectionTimeout: 5000, httpsAgent: { keepAlive: true, maxSockets: 4 } } });
  }
  async put(key, bytes) {
    objectKey(key);
    checked(bytes, key, bytes.length);
    try {
      await this.client.send(new PutObjectCommand({ Bucket: this.bucket, Key: key, Body: bytes,
        ContentType: 'application/octet-stream', ContentLength: bytes.length, IfNoneMatch: '*' }), { abortSignal: AbortSignal.timeout(20000) });
    } catch (error) {
      if (error.$metadata?.httpStatusCode !== 412 && error.name !== 'PreconditionFailed') throw new Error('R2 upload failed.');
      if (!(await this.get(key, bytes.length)).equals(Buffer.from(bytes))) throw new Error('Immutable R2 object differs.');
    }
  }
  async read(key, limit, signal) {
    const response = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: objectKey(key) }), { abortSignal: requestSignal(signal) });
    const body = response.Body;
    try {
      if (!body || (response.ContentLength !== undefined && response.ContentLength > limit)) throw new Error('R2 object exceeds limit.');
      const chunks = []; let count = 0;
      for await (const chunk of body) {
        count += chunk.length;
        if (count > limit) throw new Error('R2 object exceeds limit.');
        chunks.push(Buffer.from(chunk));
      }
      return { bytes: checked(Buffer.concat(chunks), key, limit), version: response.ETag };
    } finally { body?.destroy?.(); }
  }
  async get(key, limit) { return (await this.read(key, limit)).bytes; }
  async recordIDs() {
    const ids = []; let ContinuationToken;
    do {
      const page = await this.client.send(new ListObjectsV2Command({ Bucket: this.bucket, Prefix: 'records/', ContinuationToken }),
        { abortSignal: AbortSignal.timeout(20000) });
      for (const item of page.Contents ?? []) if (/^records\/[a-f0-9]{64}$/.test(item.Key)) ids.push(item.Key.slice(8));
      ContinuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (ContinuationToken);
    return ids;
  }
  async remove(key) {
    if (!/^(objects|documents)\//.test(objectKey(key))) throw new Error('Only page files and documents can be removed.');
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }), { abortSignal: AbortSignal.timeout(20000) });
  }
  async quotaRead(key, signal) {
    quotaKey(key);
    try {
      const value = await this.read(key, QUOTA_STATE_LIMIT, signal);
      if (typeof value.version !== 'string' || !value.version || value.version.length > 256) throw new Error('Quota ETag is missing.');
      return value;
    } catch (error) { if (error.$metadata?.httpStatusCode === 404 || error.name === 'NoSuchKey') return null; throw error; }
  }
  async quotaCAS(key, version, bytes, signal) {
    quotaWrite(key, version, bytes);
    try {
      await this.client.send(new PutObjectCommand({ Bucket: this.bucket, Key: key, Body: bytes,
        ContentType: 'application/json', ContentLength: bytes.length,
        ...(version === null ? { IfNoneMatch: '*' } : { IfMatch: version }) }), { abortSignal: requestSignal(signal) });
      return true;
    } catch (error) {
      if ([409, 412].includes(error.$metadata?.httpStatusCode) || error.name === 'PreconditionFailed') return false;
      throw error;
    }
  }
  /** Whether a release (or the landing video) is uploaded yet, so a link never lands on an R2 error. */
  async releaseExists(key) {
    if (!servable(key)) return false;
    try { await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }), { abortSignal: AbortSignal.timeout(10000) }); return true; }
    catch { return false; }
  }
  /** A short-lived SigV4 query-signed GET for a release or the landing video, so the file comes straight from Cloudflare.
   *  Releases download as a file; the video plays in the page. */
  releaseURL(key, seconds = 3600, at = new Date()) {
    if (!this.signing || !servable(key)) throw new Error('Invalid release key.');
    const { host, accessKeyId, secretAccessKey } = this.signing;
    const time = at.toISOString().replace(/[-:]|\.\d{3}/g, ''), day = time.slice(0, 8), scope = `${day}/auto/s3/aws4_request`;
    const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
    const query = Object.entries({ 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${accessKeyId}/${scope}`,
      'X-Amz-Date': time, 'X-Amz-Expires': String(seconds), 'X-Amz-SignedHeaders': 'host',
      ...(RELEASE_KEY.test(key) ? { 'response-content-disposition': `attachment; filename="${key.slice('releases/'.length)}"` } : {}) })
      .map(([k, v]) => `${encode(k)}=${encode(v)}`).sort().join('&');
    const resource = `/${this.bucket}/${key.split('/').map(encode).join('/')}`;
    const request = ['GET', resource, query, `host:${host}`, '', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
    const hmac = (k, v) => createHmac('sha256', k).update(v).digest();
    const signingKey = ['auto', 's3', 'aws4_request'].reduce(hmac, hmac('AWS4' + secretAccessKey, day));
    const signature = createHmac('sha256', signingKey).update(['AWS4-HMAC-SHA256', time, scope, sha256(request)].join('\n')).digest('hex');
    return `https://${host}${resource}?${query}&X-Amz-Signature=${signature}`;
  }
  close() { this.client.destroy(); }
}
export function configuredObjectStore(directory, env = process.env) {
  if (!env.HUMA_STORAGE_BACKEND || env.HUMA_STORAGE_BACKEND === 'local') return new LocalObjectStore(directory);
  // Arkiv holds pages, proofs, records, documents, links and sessions; the daily upload counters stay in this folder.
  if (env.HUMA_STORAGE_BACKEND === 'arkiv') return new ArkivObjectStore({ local: new LocalObjectStore(directory), env });
  if (env.HUMA_STORAGE_BACKEND !== 'r2') throw new Error('Unknown storage backend.');
  return new R2ObjectStore({ endpoint: env.R2_ENDPOINT, bucket: env.R2_BUCKET,
    accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY });
}
