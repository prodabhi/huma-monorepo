import { setTimeout as delay } from 'node:timers/promises';
import { exactKeys, fullMatch } from './verify-core/contract.mjs';
import { MASTER_LIMIT, PROOF_LIMIT } from './publication-contract.mjs';
import { sha256Hex as hash, fail, isHash as validHash } from './server-util.mjs';

const validDay = value => fullMatch(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/, value) && new Date(value + 'T00:00:00.000Z').toISOString().slice(0, 10) === value;
const MAX_RESERVATIONS = 2000;

export function publicationLimits(env = process.env) {
  const setting = (name, fallback, max) => {
    const value = env[name] === undefined ? fallback : fullMatch(/^[1-9][0-9]*$/, env[name]) ? Number(env[name]) : NaN;
    if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error('Invalid publication limit: ' + name);
    return value;
  };
  return {
    globalCount: setting('HUMA_DAILY_PUBLICATION_LIMIT', 1000, MAX_RESERVATIONS),
    globalBytes: setting('HUMA_DAILY_UPLOAD_BYTES', 1024 ** 3, Number.MAX_SAFE_INTEGER),
    uploaderCount: setting('HUMA_UPLOADER_DAILY_PUBLICATION_LIMIT', 30, MAX_RESERVATIONS),
    uploaderBytes: setting('HUMA_UPLOADER_DAILY_UPLOAD_BYTES', 128 * 1024 ** 2, Number.MAX_SAFE_INTEGER),
  };
}
function ledger(source, day) {
  if (!source) return { kind: 'huma-publication-quota-v1', day, reservations: [] };
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(source));
  exactKeys(value, ['kind', 'day', 'reservations']);
  if (value.kind !== 'huma-publication-quota-v1' || value.day !== day ||
      !Array.isArray(value.reservations) || value.reservations.length > MAX_RESERVATIONS) throw new Error('Invalid quota ledger.');
  const ids = new Set();
  for (const entry of value.reservations) {
    exactKeys(entry, ['id', 'owner', 'bytes'], ['proof', 'repeat']);
    if (!validHash(entry.id) || !validHash(entry.owner) || ids.has(entry.id) || !Number.isSafeInteger(entry.bytes) ||
        (entry.proof !== undefined && !validHash(entry.proof)) || (entry.repeat !== undefined && entry.repeat !== true) ||
        entry.bytes < 1 || entry.bytes > MASTER_LIMIT + PROOF_LIMIT) throw new Error('Invalid quota reservation.');
    ids.add(entry.id);
  }
  return value;
}

/// One conditional ledger update accounts for BOTH global and uploader usage.
/// Reservations include storage failures; retrying the same publication is free.
/// An uploader sharing a proof again the same day (its files are already stored) counts only against their own
/// allowance, so a few accounts re-sharing one page can't use up everyone's.
export class PublicationQuotas {
  constructor(store, { limits = publicationLimits(), now = Date.now } = {}) {
    this.store = store; this.limits = limits; this.now = now;
    const keys = ['globalCount', 'globalBytes', 'uploaderCount', 'uploaderBytes'];
    exactKeys(limits, keys);
    if (keys.some(k => !Number.isSafeInteger(limits[k]) || limits[k] < 1) ||
        limits.globalCount > MAX_RESERVATIONS || limits.uploaderCount > MAX_RESERVATIONS) throw new Error('Invalid publication quota policy.');
  }
  day() { return new Date(this.now()).toISOString().slice(0, 10); }
  async reserve({ id, owner, bytes, proof, day = this.day() }) {
    try {
      if (!validHash(id) || !validHash(owner) || !validDay(day) || !Number.isSafeInteger(bytes) || (proof !== undefined && !validHash(proof)) ||
          bytes < 1 || bytes > MASTER_LIMIT + PROOF_LIMIT) throw new Error('Invalid quota request.');
      const key = 'quotas/' + hash('huma-publication-quota-v1\0' + day), signal = AbortSignal.timeout(20000);
      for (let attempt = 0; attempt < 8; attempt++) {
        signal.throwIfAborted();
        const previous = await this.store.quotaRead(key, signal), value = ledger(previous?.bytes, day);
        const existing = value.reservations.find(entry => entry.id === id);
        if (existing) {
          if (existing.owner !== owner || existing.bytes !== bytes) throw new Error('Quota reservation differs.');
          return { day };
        }
        const counted = value.reservations.filter(entry => !entry.repeat), used = counted.reduce((total, entry) => total + entry.bytes, 0);
        const own = value.reservations.filter(entry => entry.owner === owner);
        const ownBytes = own.filter(entry => !entry.repeat).reduce((total, entry) => total + entry.bytes, 0), p = this.limits;
        const repeat = proof !== undefined && own.some(entry => entry.proof === proof);
        if (value.reservations.length >= MAX_RESERVATIONS || own.length >= p.uploaderCount ||
            (!repeat && (counted.length >= p.globalCount || used + bytes > p.globalBytes || ownBytes + bytes > p.uploaderBytes)))
          throw fail(429, 'Daily publication allowance reached. Try again after the next UTC day.');
        value.reservations.push({ id, owner, bytes, ...(proof !== undefined ? { proof } : {}), ...(repeat ? { repeat } : {}) });
        if (await this.store.quotaCAS(key, previous?.version ?? null, Buffer.from(JSON.stringify(value)), signal)) return { day };
        await delay(20 + Math.floor(Math.random() * 60), undefined, { signal });
      }
      throw fail(503, 'Publication quota is busy. Retry this approval.');
    } catch (error) {
      if (error.status === 429 || error.status === 503) throw error;
      throw fail(503, 'Publication allowance could not be checked. No upload was started.');
    }
  }
}
