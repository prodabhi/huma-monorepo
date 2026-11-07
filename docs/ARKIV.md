# Arkiv as Huma's storage

`HUMA_STORAGE_BACKEND=arkiv`, the hosted site's storage, keeps what Huma stores on [Arkiv](https://docs.arkiv.network)
instead of a local folder: shared pages (text and proofs), publication records, accounts' documents, short links, writer pages,
and handles. Everything that stores something goes through one interface
(`object-store.mjs`), so the app is unchanged; `arkiv-store.mjs` is the new backend behind it.

## Turn it on

1. Get a free **access key** at [hub.arkiv.network/access-keys](https://hub.arkiv.network/access-keys).
2. Make an account and **fund it** from the [faucet](https://hub.arkiv.network/faucet). Every write is a paid transaction
   on Arkiv's testnet (Rabdi). Make a key with
   `node -e "const {generatePrivateKey,privateKeyToAccount}=require('viem/accounts');const k=generatePrivateKey();console.log(k,privateKeyToAccount(k).address)"`
   (run in `../frontend/`), send the address to the faucet, and keep the private key secret.
3. Make an **encryption key** and back it up: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
   Arkiv data is public, so everything is stored encrypted. **Lose this key and nothing stored can be read again.**
4. In `.env`:

   ```
   HUMA_STORAGE_BACKEND=arkiv
   ARKIV_ACCESS_KEY=...
   ARKIV_PRIVATE_KEY=0x...
   ARKIV_ENCRYPTION_KEY=...        # 64 hex digits
   ARKIV_EXPIRY_DAYS=180           # 1 to 182
   ```

5. Start as usual: `node --env-file=../.env registry.mjs`. A missing value is named in the error.

Pages already stored in the local folder are not copied over; the Arkiv backend starts empty.

## How it stores things

- **One entity per chunk.** A `bytes` value holds up to 128 KiB, and so does a whole transaction (measured on Rabdi: a
  batch of 120 KiB is accepted, 136 KiB is refused, however many entities it holds). So an object is encrypted, split
  into 120 KiB chunks and written as entities of the schema `huma-object` (`k` the key and `p` its kind, both indexed;
  `g` which write, `v` its version; `i` and `n` the chunk and how many), one transaction per chunk. A write is read only
  once every chunk is there, so half a write is ignored and cleared by the next write of that key.
- **Queryable.** Each entity also carries typed, indexed columns that Arkiv's SQL-like queries use: `k` (the key), `p` (its
  kind), `i` (0 for a key's first chunk, so a query gets one row per key), `at` (written, ms), `size`, and, for a
  publication record, `owner` (the hash of the account that shared it). `store.find({ kind, owner, since, limit })` runs
  such a query, newest first: a writer's pages, or what changed since a time. The app doesn't call it yet; it still reads
  by exact key. The owner hash is public and links one account's pages together; the title, the link key's hash and
  everything else stay in the encrypted payload.
- **Encrypted.** AES-256-GCM, a fresh nonce for each write, the key name as authenticated data (so a payload can't be
  moved to another key). What is public is the key (a kind and a hash, like `records/<id>`), the sizes and the times.
  The link key that opens a private page is never stored: only its hash is, inside the encrypted record.
- **Changeable state** (documents, handles, listed pages, replay choices, writing requests) is replaced by
  compare-and-swap: under a lock per key, the version is checked, then one transaction deletes the old chunks and
  creates the new ones. This is exact for **one server** writing with one wallet; two servers could race.
- **Daily upload counters** (`quotas/`) change on every upload, and **browser sessions' nonces** (`sessions/`) on every
  Start Recording, so both stay in the local folder: a transaction each would keep a writer waiting several seconds to
  begin, for state that lapses within a day.
- **Not on Arkiv:** the proving points (16 to 32 MB) and the Mac installer. They are too big for entities: the browser's
  proving points are static files of the website, and the Mac app's installer and proving setup are GitHub release assets
  (`frontend/releases.mjs`).

## How anyone can check it

A page shared while Arkiv is the store has `stored` in its record, and the page's receipt
(`GET /api/publications/<id>/receipt`) passes it on: the network, its explorer and public RPC endpoint, the address of
the server's wallet (`owner`), and for the text and the proof each the entity of its first chunk, the transaction that
made it (null when the file was already there from an earlier page and the server restarted since), how many chunks,
when it was written and about when it expires (from `ARKIV_EXPIRY_DAYS`).

The reader page shows it under the writer as **Stored on Arkiv**, with links to the explorer (`/entity/`, `/tx/`,
`/address/`) and a `curl` command that asks Arkiv's public endpoint (no access key) for the proof's entity:

```
curl -s https://rpc.rabdi.db-chain.testnet.arkiv.network -H 'content-type: application/json' --data-binary @- <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"arkiv_query","params":["k = str('objects/<proof sha256>') AND i = u64(0)",{"select":{"key":true,"owner":true,"createdAt":true,"expiresAt":true,"attributes":{"k":true,"v":true}}}]}
EOF
```

Its `owner` should be the server's wallet, and `k` and `v` should both carry the proof's SHA-256, which the reader's
browser has already checked against the file it downloaded. The body is encrypted, so this shows the file is kept, by
whom and until when (blocks of two seconds), not what it says. Pages shared before this, or on another store, show
nothing.

## Limits to know

- **Entities expire.** Every one is created with `ARKIV_EXPIRY_DAYS` (default 180). Arkiv allows at most 7,884,000 blocks
  (about 182 days), so a longer value is refused. **Nothing renews them yet**, so a deployment needs a job that extends
  entities before they lapse (the SDK has `extendEntity`), or pages disappear after about six months.
- **Cost and speed.** Every write is a transaction with gas, and one confirmed (measured) takes roughly 3 to 10 seconds. A
  small page, record or state change is one transaction. A 1 MB file is nine, one after another; a 32 MB page would be
  about 270 and take tens of minutes.
- **Confidentiality is from the public, not the host.** The server holds the encryption key, so it can read everything. Encrypting with a key that only the link holds would be a different design.
- **Testnet.** Arkiv's Rabdi network may be reset. Treat it as a hackathon backend, not a place to keep the only copy.

## Tests

`cd frontend && node --test test/arkiv-store.test.mjs`. They run against an in-memory chain that behaves like Arkiv (separate
entities per chunk, a transaction per write, a 128 KiB limit): round trips, chunking, encryption and tampering, write-once
pages, compare-and-swap with ten concurrent writers, half writes, removal, and a whole page shared through the real
registry and read back after a restart. **They do not talk to Arkiv.** The SDK calls in `createArkivChain` are checked
only as far as: it builds the clients and its query reaches Arkiv's RPC (answering 401 for a made-up access key). A write
to the real chain needs your funded account.
