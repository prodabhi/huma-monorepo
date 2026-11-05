// Arkiv as the object store (HUMA_STORAGE_BACKEND=arkiv): pages, proofs, records, documents, short links, writer pages
// and sessions are kept as Arkiv entities (https://docs.arkiv.network), through the same put/get/quota interface as the
// local-folder and R2 stores (object-store.mjs), so nothing that stores something needs to know where it goes.
//
// What is different about Arkiv, and what this does about it:
//   Public.     Anyone can read an entity. Every payload is encrypted here (AES-256-GCM, ARKIV_ENCRYPTION_KEY, the key
//               name as authenticated data) before it is written, so what is on Arkiv is unreadable noise to everyone
//               but this server. The logical key (a kind and a hash, like records/<id>) is public; the link key that
//               opens a private page is never stored (only its hash is, inside the encrypted record).
//   Small.      A bytes value holds up to 128 KiB, and so does a whole transaction (measured on Rabdi: 120 KiB in one
//               transaction is accepted, 136 KiB is refused, however it is split into entities). So an object is split
//               into 120 KiB chunks, one entity each, and no more than 120 KiB goes in a transaction: a big object is
//               several, written one after another. A page is read only once every chunk of one write is there; half a
//               write is ignored and cleaned up by the next write of that key.
//   Queryable.  Besides the encrypted payload, every entity carries typed, indexed columns (Arkiv's SQL-like queries): the
//               key and its kind, when it was written, its size, and for a publication record the hash of the account that
//               shared it. find() queries them (a writer's pages, what changed since, newest first). The sensitive fields
//               (the link key's hash, titles, names) stay inside the encrypted payload.
//   Expiring.   Every entity has an expiry (ARKIV_EXPIRY_DAYS, default 180; the chain allows at most 7,884,000 blocks, about
//               182 days). Nothing renews them yet: see ARKIV.md.
//   No CAS.     Compare-and-swap (changeable state: documents, handles, sessions...) is done here, under a lock per
//               key and with the version checked before the replacing batch (old chunks deleted, new ones created in
//               one transaction). That is exact for one server writing; two servers on one wallet could race.
//   Quotas.     The daily upload counters (quotas/) change on every upload, so they stay in the local folder.
//
// The chain itself is behind a small interface (list, listKeys, write) so tests use an in-memory one; createArkivChain
// is the real one, on the Arkiv SDK, and needs ARKIV_ACCESS_KEY and a funded ARKIV_PRIVATE_KEY.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { objectKey, checked, quotaKey, quotaWrite } from './object-store.mjs';
import { ATTESTATION_KEY } from './hash-record.mjs';

export const CHUNK_BYTES = 120 * 1024; // under the 128 KiB a bytes value may hold
export const MAX_EXPIRY_DAYS = 182; // Arkiv's longest lifetime is 7,884,000 blocks of two seconds
export const TX_BYTES = 120 * 1024;     // payload per transaction: Arkiv refuses a transaction past about 128 KiB
const BATCH_ENTITIES = 16;             // chunks (and deletions) per transaction
const CACHE_ENTRIES = 256, CACHE_BYTES = 1024 * 1024, GONE_MS = 60000;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const notFound = key => Object.assign(new Error('Stored object not found: ' + key), { code: 'ENOENT', name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } });
const kindOf = key => key.slice(0, key.indexOf('/'));
const DAY = 86400000;
/** When a write was made, from its write ID (g starts with the time in base 36, ms). */
const writtenAt = g => parseInt(g.slice(0, 10), 36);
/** The account that shared a publication record (its ownerHash, a hash: no name or address), or null. Only records have one. */
const ownerOf = (key, bytes) => {
  if (!key.startsWith('records/')) return null;
  try { const owner = JSON.parse(bytes.toString('utf8')).ownerHash; return typeof owner === 'string' && /^[a-f0-9]{64}$/.test(owner) ? owner : null; } catch { return null; }
};

/** AES-256-GCM with a fresh 12-byte nonce: nonce | ciphertext | tag. The key name is authenticated, so a payload can't be moved to another key. */
export function seal(secret, key, bytes) {
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', secret, nonce);
  cipher.setAAD(Buffer.from(key));
  return Buffer.concat([nonce, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
}
export function open(secret, key, sealed) {
  if (sealed.length < 12 + 16) throw new Error('Stored object failed integrity check.');
  const decipher = createDecipheriv('aes-256-gcm', secret, sealed.subarray(0, 12));
  decipher.setAAD(Buffer.from(key)); decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  try { return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]); }
  catch { throw new Error('Stored object failed integrity check.'); }
}

export class ArkivObjectStore {
  /**
   * `local`: where the daily counters (quotas/) stay. `chain`: the Arkiv connection (tests pass an in-memory one; else
   * createArkivChain(env), on first use). `env`: ARKIV_ENCRYPTION_KEY (64 hex digits), ARKIV_EXPIRY_DAYS.
   */
  constructor({ local, chain = null, env = process.env, now = Date.now } = {}) {
    if (!local) throw new Error('Arkiv storage needs a local store for the daily counters.');
    const hex = env.ARKIV_ENCRYPTION_KEY ?? '';
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Set ARKIV_ENCRYPTION_KEY to 64 hex digits (node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"): Arkiv data is public, so it is stored encrypted.');
    this.secret = Buffer.from(hex, 'hex'); this.local = local; this.chain = chain; this.env = env; this.now = now; this.kind = 'arkiv';
    this.days = Number(env.ARKIV_EXPIRY_DAYS ?? 180);
    this.locks = new Map(); this.cache = new Map(); this.gone = new Map();
  }
  async #connection() { return (this.chain ??= await createArkivChain(this.env)); }
  /** Where a write is kept: its first chunk's entity, the transaction that made it (null when this server didn't just
   *  write it), how many chunks, when it was written and about when it expires (ms). */
  #stored(entity, tx, chunks, at) {
    return { entity, tx, chunks, at, expires: Number.isInteger(this.days) ? at + this.days * DAY : null };
  }
  /** Runs `work` once the earlier work on `key` has finished, so a key is read and replaced by one caller at a time. */
  #locked(key, work) {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(work);
    const tail = run.catch(() => {});
    this.locks.set(key, tail);
    tail.then(() => { if (this.locks.get(key) === tail) this.locks.delete(key); });
    return run;
  }
  #remember(key, value) {
    this.cache.delete(key);
    if (value && value.bytes.length <= CACHE_BYTES) {
      this.cache.set(key, value);
      while (this.cache.size > CACHE_ENTRIES) this.cache.delete(this.cache.keys().next().value);
    }
  }
  /**
   * What is stored under `key`: { bytes, version, entities } for the newest complete write, or null. `entities` is
   * every entity of the key (older writes and half writes too), so the next write can delete what it replaces.
   */
  async #read(key) {
    const goneUntil = this.gone.get(key);
    if (goneUntil !== undefined) { if (goneUntil > this.now()) return null; this.gone.delete(key); }
    const cached = this.cache.get(key);
    if (cached) return cached;
    const rows = await (await this.#connection()).list(key);
    if (!rows.length) return null;
    const byWrite = new Map();
    for (const row of rows) { const group = byWrite.get(row.g) ?? []; group.push(row); byWrite.set(row.g, group); }
    const complete = [...byWrite.entries()].filter(([, group]) => group.length === group[0].n && new Set(group.map(r => r.i)).size === group[0].n)
      .sort(([a], [b]) => (a < b ? 1 : -1));
    const entities = rows.map(r => r.key);
    if (!complete.length) return { bytes: null, version: null, entities };
    const [g, group] = complete[0];
    const sealed = Buffer.concat(group.sort((a, b) => a.i - b.i).map(r => r.body));
    const value = { bytes: open(this.secret, key, sealed), version: group[0].v, entities, stored: this.#stored(group[0].key, null, group.length, writtenAt(g)) };
    this.#remember(key, value);
    return value;
  }
  /** Replaces what is stored under `key` (the entities in `replace`, if any) with `bytes`, in as few transactions as it fits. */
  async #write(key, bytes, replace = []) {
    const chain = await this.#connection();
    const sealed = seal(this.secret, key, bytes), version = sha256(bytes);
    const g = this.now().toString(36).padStart(10, '0') + '-' + randomBytes(6).toString('hex'), n = Math.max(1, Math.ceil(sealed.length / CHUNK_BYTES));
    const at = this.now(), owner = ownerOf(key, bytes), plainSize = bytes.length;
    const creates = Array.from({ length: n }, (_, i) => ({ k: key, p: kindOf(key), g, v: version, i, n, at, size: plainSize, ...(owner ? { owner } : {}), body: sealed.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES) }));
    // As many chunks to a transaction as the payload limit allows (usually one: a chunk is nearly the limit).
    const transactions = []; let current = [], size = 0;
    for (const c of creates) {
      if (current.length && (size + c.body.length > TX_BYTES || current.length >= BATCH_ENTITIES)) { transactions.push(current); current = []; size = 0; }
      current.push(c); size += c.body.length;
    }
    transactions.push(current);
    let first; // the receipt of the transaction holding the first chunk: { tx, entities }
    if (transactions.length === 1 && replace.length <= BATCH_ENTITIES) first = await chain.write({ creates, deletes: replace }); // one transaction: replaced atomically
    else {
      // Several transactions: the new chunks first (nobody reads them until all are there), then the old ones go.
      for (const batch of transactions) { const receipt = await chain.write({ creates: batch, deletes: [] }); first ??= receipt; }
      for (let at = 0; at < replace.length; at += BATCH_ENTITIES) await chain.write({ creates: [], deletes: replace.slice(at, at + BATCH_ENTITIES) });
    }
    this.gone.delete(key);
    // The keys of the new entities aren't known without asking; the next write finds them again (cache entities: null).
    const stored = this.#stored(first?.entities?.[0] ?? null, first?.tx ?? null, n, at);
    this.#remember(key, { bytes: Buffer.from(bytes), version, entities: null, stored });
    return stored;
  }
  async #entities(key, cached) { return cached.entities ?? (await (await this.#connection()).list(key)).map(r => r.key); }

  /** Stores `bytes` under `key` once. Returns where it is kept ({ entity, tx, chunks, at, expires }), also when it already was. */
  async put(key, bytes) {
    objectKey(key);
    checked(bytes, key, bytes.length);
    return this.#locked(key, async () => {
      const current = await this.#read(key);
      if (current?.bytes) {
        if (!current.bytes.equals(Buffer.from(bytes))) throw new Error('Immutable object differs.');
        return current.stored ?? null;
      }
      return this.#write(key, bytes, current ? await this.#entities(key, current) : []); // a half write is cleared away
    });
  }
  /** Anchors a public, unencrypted record (hash-record.mjs) under `attestations/<id>`: one entity anyone can query, in
   *  place of the encrypted ones. Written once; asking again returns where it already is. Returns { entity, tx, at, expires }. */
  async anchor(key, bytes) {
    if (!ATTESTATION_KEY.test(key)) throw new Error('Invalid attestation key.');
    if (bytes.length > CHUNK_BYTES) throw new Error('Attestation too large.');
    return this.#locked(key, async () => {
      const chain = await this.#connection(), [existing] = await chain.list(key);
      if (existing) {
        if (!existing.body.equals(Buffer.from(bytes))) throw new Error('Immutable attestation differs.');
        return { entity: existing.key, tx: null, at: writtenAt(existing.g), expires: null };
      }
      const at = this.now(), g = at.toString(36).padStart(10, '0') + '-' + randomBytes(6).toString('hex');
      const receipt = await chain.write({ creates: [{ k: key, p: 'attestations', g, v: sha256(bytes), i: 0, n: 1, at, size: bytes.length, body: Buffer.from(bytes) }], deletes: [] });
      const { entity = null, tx = null } = { entity: receipt?.entities?.[0], tx: receipt?.tx };
      return { entity, tx, at, expires: Number.isInteger(this.days) ? at + this.days * DAY : null };
    });
  }
  /** The record anchored for a page: { bytes, entity, at }, or null. It is read back from the chain, not trusted from memory. */
  async anchored(key) {
    if (!ATTESTATION_KEY.test(key)) throw new Error('Invalid attestation key.');
    const [row] = await (await this.#connection()).list(key);
    return row ? { bytes: row.body, entity: row.key, at: writtenAt(row.g) } : null;
  }
  /** Which chain this is and whose wallet writes Huma's entities, so a reader can look them up themselves:
   *  { network, chainId, explorer, rpc (its public endpoint, without the access key), owner }, or null. */
  async network() { return (await this.#connection()).network ?? null; }
  async get(key, limit) {
    objectKey(key);
    const current = await this.#locked(key, () => this.#read(key));
    if (!current?.bytes) throw notFound(key);
    return checked(current.bytes, key, limit);
  }
  /**
   * Queries what is stored, newest first, by the columns Arkiv indexes: `kind` (objects, records, documents...), `owner` (a
   * publication record's account hash), `since` (written at or after, in ms) and `limit` (up to 1000). Returns
   * [{ key, at, owner, size }]; the payloads stay encrypted until get() or quotaRead() reads one.
   */
  async find({ kind, owner, since, limit = 100 } = {}) {
    if (typeof kind !== 'string' || !/^[a-z-]+$/.test(kind)) throw new Error('Choose a kind to query.');
    if (owner !== undefined && !/^[a-f0-9]{64}$/.test(owner)) throw new Error('Invalid owner.');
    if (since !== undefined && !(Number.isSafeInteger(since) && since >= 0)) throw new Error('Invalid time.');
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new Error('Choose a limit from 1 to 1000.');
    return (await this.#connection()).find({ kind, owner, since, limit });
  }
  /** The IDs stored under `records/` (every publication), so a removal can see who else uses a file. */
  async recordIDs() {
    const keys = await (await this.#connection()).listKeys('records');
    return [...new Set(keys.map(k => k.match(/^records\/([a-f0-9]{64})$/)?.[1]).filter(Boolean))];
  }
  /** Deletes a shared page's file when its writer removes the link. Only page files and documents can be deleted. */
  async remove(key) {
    if (!/^(objects|documents)\//.test(objectKey(key))) throw new Error('Only page files and documents can be removed.');
    await this.#locked(key, async () => {
      const chain = await this.#connection();
      const keys = (await chain.list(key)).map(r => r.key);
      for (let at = 0; at < keys.length; at += BATCH_ENTITIES) await chain.write({ creates: [], deletes: keys.slice(at, at + BATCH_ENTITIES) });
      this.cache.delete(key); this.gone.set(key, this.now() + GONE_MS); // the index may still list it for a moment
    });
  }
  async quotaRead(key, signal) {
    if (key.startsWith('quotas/')) return this.local.quotaRead(key, signal);
    quotaKey(key); signal?.throwIfAborted();
    const current = await this.#locked(key, () => this.#read(key));
    return current?.bytes ? { bytes: current.bytes, version: current.version } : null;
  }
  async quotaCAS(key, version, bytes, signal) {
    if (key.startsWith('quotas/')) return this.local.quotaCAS(key, version, bytes, signal);
    quotaWrite(key, version, bytes); signal?.throwIfAborted();
    return this.#locked(key, async () => {
      const current = await this.#read(key);
      if ((current?.bytes ? current.version : null) !== (version ?? null)) return false;
      await this.#write(key, bytes, current ? await this.#entities(key, current) : []);
      return true;
    });
  }
  close() { this.local.close?.(); this.chain?.close?.(); }
}

/**
 * The real Arkiv connection (the SDK, @arkiv-network/sdk): list(k) → every chunk of a key, listKeys(kind) → every key of
 * a kind, write({ creates, deletes }) → one transaction, { tx, entities } (its hash and the created entities' keys, in
 * order), and network: the chain and the wallet's address. Needs ARKIV_ACCESS_KEY (hub.arkiv.network/access-keys) and
 * ARKIV_PRIVATE_KEY, a testnet account with funds (hub.arkiv.network/faucet): every write is a paid transaction.
 */
export async function createArkivChain(env = process.env) {
  const accessKey = env.ARKIV_ACCESS_KEY ?? '', privateKey = env.ARKIV_PRIVATE_KEY ?? '';
  if (!accessKey) throw new Error('Set ARKIV_ACCESS_KEY (a free key from hub.arkiv.network/access-keys).');
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error('Set ARKIV_PRIVATE_KEY to the private key (0x…) of an Arkiv testnet account with funds (hub.arkiv.network/faucet).');
  // The chain refuses a lifetime past 7,884,000 blocks (two seconds each): about 182 days.
  const days = Number(env.ARKIV_EXPIRY_DAYS ?? 180);
  if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) throw new Error(`ARKIV_EXPIRY_DAYS must be a whole number of days from 1 to ${MAX_EXPIRY_DAYS} (Arkiv's longest lifetime).`);
  const { createPublicClient, createWalletClient, ExpirationTime } = await import('@arkiv-network/sdk');
  const { rabdi } = await import('@arkiv-network/sdk/chains');
  const { and, eq, gte, asc, desc } = await import('@arkiv-network/sdk/query');
  const { defineSchema, str, u64, bytes } = await import('@arkiv-network/sdk/schema');
  const { http } = await import('viem');
  const { privateKeyToAccount, nonceManager } = await import('viem/accounts');
  const chain = rabdi({ accessKey });
  const publicClient = createPublicClient({ chain, transport: http() });
  // Every write comes from this one wallet, and a share sends several at once (its text, proof and replay): the nonce
  // manager gives each its own nonce, as the chain refuses two with the same ("replacement transaction underpriced").
  const walletClient = createWalletClient({ chain, transport: http(), account: privateKeyToAccount(privateKey, { nonceManager }) });
  // One entity per chunk. k: the logical key and p: its kind are indexed (queries); g: which write, v: its version (the
  // content hash), i and n: this chunk and how many there are.
  // Indexed (queryable): k, p, i (0 is a key's first chunk, one row per key), at (written, ms), owner (records only).
  const Objects = defineSchema('huma-object', { k: str().indexed(), p: str().indexed(), i: u64().indexed(), at: u64().indexed(), owner: str().indexed().optional(),
    g: str(), v: str(), n: u64(), size: u64(), body: bytes() });
  const network = { network: chain.name, chainId: chain.id, explorer: chain.blockExplorers.default.url,
    rpc: new URL(chain.rpcUrls.default.http[0]).origin, owner: walletClient.account.address }; // the access key is in the URL's path
  const PAGE = 20; // a page of bodies stays well under an RPC endpoint's response cap
  const pages = async (where, select) => {
    const rows = [];
    for (let offset = 0; ; offset += PAGE) {
      const page = await publicClient.select(select).from(Objects).where(where).orderBy(asc('$key')).limit(PAGE).offset(offset).fetch();
      rows.push(...page.entities);
      if (page.entities.length < PAGE) return rows;
    }
  };
  const hexBytes = value => Buffer.from(String(value).replace(/^0x/, ''), 'hex');
  return {
    network,
    async list(k) {
      const rows = await pages(eq('k', k), { $key: true, g: true, v: true, i: true, n: true, body: true });
      return rows.map(r => ({ key: r.$key, g: String(r.g.value), v: String(r.v.value), i: Number(r.i.value), n: Number(r.n.value), body: hexBytes(r.body.value) }));
    },
    async find({ kind, owner, since, limit }) {
      const where = and(eq('p', kind), eq('i', u64(0n)), ...(owner ? [eq('owner', owner)] : []), ...(since !== undefined ? [gte('at', u64(BigInt(since)))] : []));
      const rows = [];
      for (let offset = 0; rows.length < limit; offset += 100) {
        const page = await publicClient.select({ k: true, at: true, owner: true, size: true }).from(Objects).where(where).orderBy(desc('at'))
          .limit(Math.min(100, limit - rows.length)).offset(offset).fetch();
        rows.push(...page.entities.map(r => ({ key: String(r.k.value), at: Number(r.at.value), owner: r.owner ? String(r.owner.value) : null, size: Number(r.size.value) })));
        if (page.entities.length < 100) break;
      }
      return rows;
    },
    async listKeys(kind) {
      const rows = await pages(eq('p', kind), { k: true });
      return rows.map(r => String(r.k.value));
    },
    async write({ creates, deletes }) {
      const { txHash, createdEntities } = await walletClient.executeBatch({
        ...(creates.length ? { creates: creates.map(c => ({ schema: Objects, expiration: ExpirationTime.fromDays(days),
          values: { k: c.k, p: c.p, g: c.g, v: c.v, i: u64(BigInt(c.i)), n: u64(BigInt(c.n)), at: u64(BigInt(c.at)), size: u64(BigInt(c.size)),
            ...(c.owner ? { owner: c.owner } : {}), body: c.body } })) } : {}),
        ...(deletes.length ? { deletes: deletes.map(entityKey => ({ entityKey })) } : {}),
      });
      return { tx: txHash, entities: createdEntities };
    },
  };
}
