# Feature: On-chain verification for Huma docs

Status: proposed, not started. World ID and Arkiv work is set aside for now.

## Where we are today

- Verification is **off-chain**. On publish, the server runs the Rust verifier (`verifyPublicationUpload`, `../frontend/publications.mjs:65`) and rejects the upload if the proof does not verify.
- Readers re-check the proof in their browser (`../frontend/pages/verify.mjs`).
- The wallet signature is checked locally with viem's `verifyMessage`. It is not a contract call.
- The on-chain batch route was retired in 0.2 (VISION.md:19). The old code is archived in `../extra/experiments/onchain/`.
- README lists on-chain proof verification as "Not implemented or deployed".

## Why consider it

- Trustless public check: contracts and dapps can verify a doc without trusting Huma's server.
- Composability: contracts can gate things on "written by a human" (airdrops, DAO votes, paid content).
- Permanent public timestamp and record, even if Huma's host goes down.
- Censorship resistance: no single party can quietly remove or change a result.
- Can tie a World ID check to a doc on-chain (WORLD-ID.md:87 lists this as not yet done).

## Costs and risks

- Verifying zkVM or Noir proofs on-chain is expensive in gas and needs a verifier contract that someone maintains.
- Receipts are large (RISC Zero receipts were about 590 KB, VISION.md:264).
- Writers would need to send transactions.
- Local re-verification already gives most of the trust benefit.

## Options

1. **Full on-chain proof verification.** A verifier contract checks the proof. Most trustless, highest cost. Needs a supported verifier for our proof system (VISION.md:262).
2. **Anchor only (recommended starting point).** Post the doc hash and an attestation on-chain (an EAS-style registry or Arkiv). Keep proof verification off-chain. Gives timestamp and composability cheaply. Note that anchoring a hash is not the same as verifying the proof (README §44).
3. **Stay off-chain.** The current state.

## Open questions

- Which chain, and who pays the gas (writer, Huma, or a paymaster)?
- Which proof system would the verifier target (RISC Zero or Noir)?
- Should the attestation include the World ID fingerprint?
- Is the on-chain record optional per doc, or on by default?

## Implementation sketch (option 2)

1. Define the attestation schema: doc hash, proof hash, writer wallet, timestamp.
2. Add a publish step after server-side proof verification that submits the attestation.
3. Show the on-chain record on the verify page (`../frontend/pages/verify.mjs`).
4. Reuse ideas from `../extra/experiments/onchain/` where they still fit.
5. Add tests next to the existing publication tests in `../frontend/test/`.

## Todo

### 1. Keep user data local only
- [ ] Stop uploading drafts and finished docs to the server (`documents/` in `../frontend/documents.mjs`).
- [ ] Stop uploading page text (`objects/<hash>` masters) in `../frontend/publications.mjs`.
- [ ] Keep drafts, text, proofs and replays on the writer's device only (IndexedDB in `../frontend/write/library.mjs`, local files on the Mac).
- [ ] Decide how users back up or move docs between devices (the PDF report from `../frontend/write/report.mjs` is the likely answer).
- [ ] Accept that docs no longer open on other devices after sign-in, and tell users.

### 2. Store hashes, not proofs or text
- [ ] Stop storing the zk proof bytes and the replay file on the server and in Arkiv; keep only `hash(text)` and `hash(proof)`.
- [ ] Define a signed hash record: text hash, proof hash, writer wallet or device key, timestamp, signature. The signature is what ties it to Huma and the writer.
- [ ] Decide where the hash record lives (small registry or on-chain anchor, see option 2 above).
- [ ] Update the verify page (`../frontend/pages/verify.mjs`) so the owner presents the text and proof (file or PDF), and the page checks them against the stored hashes and re-verifies the proof.
- [ ] Remove or replace public view links, short links and writer pages, since the server no longer holds the text.
- [ ] Add tests next to `../frontend/test/publications.test.mjs`.

### 3. World ID at start and at report time
- [ ] At the start of writing, verify World ID and bind it to the session's key.
- [ ] At report time, verify World ID again with the final text hash and proof hash as the signal, so the person is tied to this exact text and proof.
- [ ] Do not re-prompt World ID during writing; it proves a unique person, not that the same person is still typing.
- [ ] Use the existing passkey check-ins for light mid-session "same person" checks (see `../frontend/documents.mjs` passkeys).
- [ ] Show the World ID fingerprint and the passkey check count in the report (`../frontend/write/report.mjs`).
- [ ] Decide whether the end-of-document World ID prompt is optional, or reuses the account's link for short drafts.
- [ ] Note: World ID was set aside earlier in this conversation; start this item only when we pick it back up.

### 4. Anchor the signed hash record on-chain
- [ ] Pick the chain and who pays gas (writer, Huma, or a paymaster).
- [ ] Choose the registry: an EAS-style attestation or Arkiv.
- [ ] Define the attestation schema from item 2's signed hash record: text hash, proof hash, writer wallet, timestamp, optionally the World ID fingerprint.
- [ ] Submit the attestation after the proof is verified (off-chain) and the record is signed.
- [ ] Show the on-chain record on the verify page (`../frontend/pages/verify.mjs`).
- [ ] Reuse ideas from `../extra/experiments/onchain/` where they still fit.
- [ ] Add tests in `../frontend/test/`.
- [ ] Note: this anchors hashes only; the proof itself is still verified off-chain (README §44).

### 5. Move all storage to Arkiv, with one signature
- [ ] Decide how this fits items 1 and 2: items 1 and 2 keep text and proofs local and store only hashes, while this item stores everything on Arkiv. Pick one direction, or use Arkiv for the data that must stay shareable.
- [ ] Move every store to Arkiv: records, text and proofs, documents, short links, writer pages, sessions (`HUMA_STORAGE_BACKEND=arkiv`, already supported in `../frontend/arkiv-store.mjs`).
- [ ] Keep splitting big objects into 120 KiB chunks (already done), and add an explicit manifest or next-chunk link so the chunks form a verifiable chain (a linked list), not only an index.
- [ ] Keep payloads encrypted (AES-256-GCM) except the public verification record (see the Arkiv opinion above).
- [ ] One signature per publish: the user signs once to authorize it, and our own wallet submits every chunk transaction. The user never signs per chunk.
- [ ] Decide between a server relayer wallet (already works today, no new setup) and a smart wallet (ERC-4337 with batched user operations, session keys, and a paymaster). Check first that Arkiv's chain supports a bundler and EntryPoint.
- [ ] Renew or extend entities before they expire (about 182 days), since nothing renews them yet.
- [ ] Keep the writing experience unchanged: uploads run in the background after the user clicks publish, with a progress state and retries, and no extra prompts.
- [ ] Add tests (the in-memory chain used by existing Arkiv tests in `../frontend/test/arkiv-store.test.mjs`).

### 6. Make Huma track-ready (World ID and Arkiv)

World ID track:
- [ ] Write the integration debrief (short section in `WORLD-ID.md`): time to first success, friction, missing docs or capability, and the one improvement with the greatest impact.
- [ ] Phrase the trust moment clearly: "before a page is published and badged as human-written, we need to know the author is a unique human."
- [ ] State why Proof of Human is the minimum sufficient credential and why Selfie Check or Passport is not (already argued in `WORLD-ID.md`; make it visible in the README and demo).
- [ ] Make the demo show a successful verification and at least one alternative path: cancel, rejection, or wrong or unavailable credential, with the on-screen message for each.
- [ ] Optional: on-chain World ID check (see item 3 and feature.md option 1).

Arkiv track:
- [ ] Confirm with the organizers whether prior work breaks the "built from scratch at ETHGlobal Mumbai" rule. Do this first.
- [ ] Make the signed hash record public and queryable on Arkiv (items 2 and 4), and have the verify page read it from Arkiv so a user-visible feature depends on it.
- [ ] Renew or extend entities before they expire (see item 5).
- [ ] Create `/arkiv/schema.md`: entities, queried fields, owners, expiry.
- [ ] Create `/arkiv/friction.md`: what got in the way, what broke, what was expected, how to reproduce.
- [ ] Create `/arkiv/reach.md`: who it is for, can they try it today, will we keep building after Mumbai.
- [ ] Create `/arkiv/why-arkiv.md`: what users would lose with Postgres, and what we kept off Arkiv and why.
- [ ] Create `/arkiv/how-you-use-arkiv.md`: how filters, ownership and expiry fit the app, and what each Arkiv feature changes for users.
- [ ] README: list the wallet address(es) that wrote the entities and one query the judges can run.
- [ ] Add an open-source LICENSE at the repo root and an AI-usage statement in the README.
- [ ] Make sure the app writes to Arkiv's current testnet with `@arkiv-network/sdk` and at least one visible feature reads from it.

### Not in this todo yet
- Removing the servers entirely (World ID and Privy still need a backend; hash records still need somewhere to live).
