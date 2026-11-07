import { mkdir, open, readdir, rename, unlink, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { ArkivObjectStore } from './arkiv-store.mjs';
import { sha256Hex as sha256 } from './server-util.mjs';

export function objectKey(key) {
  if (typeof key !== 'string' || key.match(/^(?:objects|records|quotas|devices|removed|requests|short|replays|writers|owners|documents|handles|writers-index|listed|sessions)\/[a-f0-9]{64}$/)?.[0] !== key) throw new Error('Invalid object key.');
  return key;
}
export function checked(bytes, key, limit) {
  if (bytes.length > limit || (key.startsWith('objects/') && sha256(bytes) !== key.slice(8))) throw new Error('Stored object failed integrity check.');
  return bytes;
}
export const QUOTA_STATE_LIMIT = 512 * 1024;
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
/** Only page files, documents and their licensed copies can be deleted; everything else is written once. */
function removable(key) {
  if (!/^(objects|documents|dataset)\//.test(objectKey(key))) throw new Error('Only page files and documents can be removed.');
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
    removable(key);
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
      signal?.throwIfAborted(); await rename(temporary, file);
      return true;
    } finally {
      await lock.close(); await unlink(file + '.lock'); await unlink(temporary).catch(() => {});
    }
  }
  close() {}
}
export function configuredObjectStore(directory, env = process.env) {
  if (!env.HUMA_STORAGE_BACKEND || env.HUMA_STORAGE_BACKEND === 'local') return new LocalObjectStore(directory);
  // Arkiv holds pages, proofs, records, documents, links and sessions; the daily upload counters stay in this folder.
  if (env.HUMA_STORAGE_BACKEND === 'arkiv') return new ArkivObjectStore({ local: new LocalObjectStore(directory), env });
  throw new Error('Unknown storage backend.');
}
