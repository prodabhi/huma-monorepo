# Remaining work

Status as of 2026-11-06. All timings below were measured on this Mac (8 cores, 16 GB) and on Base Sepolia today.

## Where things stand

- **On-chain verification is live** (`backend/onchain`, HumaPagesV4 `0xe2ddc02dc6f5b1a01270014a4d294f7ef6fcfe4b` on Base
  Sepolia). It checks everything Huma's reader checks:
  - every ZK proof;
  - the part linkage and the statement bounds;
  - the writer key's P-256 signature on every event;
  - the Poseidon2 event digest;
  - the nonce's binding to the key;
  - passkey approvals.

  Every contract's source is verified on Basescan, Sourcify and Blockscout. `node backend/onchain/audit.mjs` re-checks
  it all on-chain (51 checks).
- **The flow:** Finish → **Verify On-Chain** (the `/write` finished dialog) → the browser proves the page again in the
  EVM format → the server's relayer submits it → `/verify` shows **Verified on-chain**. It's off unless
  `HUMA_RELAYER_KEY` and `HUMA_ONCHAIN_CONTRACT` are set; the current flow doesn't depend on it.
- **Sign-in:** the World ID popup now appears before a new document. World ID is still required at Finish and share
  (`worldid-verify.mjs:53`, `publications.mjs` `confirmWorldID`).

## Where the time goes today (a short page: 2 parts + final, 9 signed events)

| Step | Where | Time |
|---|---|---|
| Typing → part proofs (normal format) | browser, in the background while typing | hidden |
| Finish: last part + final + check | browser | ~4–15 s (final ~3–12 s, check ~3 s) |
| **Verify On-Chain: EVM proofs** | browser worker, 4 threads | **21.7–23.1 s** (part 7.4–11.2 s each, final 3.8–4.2 s) |
| Relay → Base Sepolia → recorded | server + chain | 5.5–6.7 s (1 transaction) |
| Longer pages on-chain | server + chain | 19.3 s (14 parts, 4 tx), 29.1 s (38 parts, 6 tx) |

A part closes every 600 operations or 8 signed events (`OPS`, `SLOTS` in `backend/integrations/noir/long3/prover.nr`).
So a page needs about one part per 100–150 typed characters. Every part is proved twice when the page goes on-chain:
once in the normal format, again in the EVM format.

## Making recording → proof → on-chain faster (most gain first)

1. **Prove the EVM parts in the background while typing.**
   - Today the EVM proofs only start when Verify On-Chain is clicked. Each closed part could be proved in both formats
     as it closes (`PageProver.startIfIdle` in `frontend/write/prove.mjs`), so that only the final EVM proof (~4 s)
     remains after Finish.
   - Verify On-Chain then drops from ~22 s + 6 s to ~4 s + 6 s.
   - Cost: twice the CPU while typing. Run it only when on-chain is on, and only after the normal proof of that part.
2. **One proof format instead of two (the structural fix).**
   - The browser would prove only EVM (keccak) proofs of the same circuits, and readers would verify those: bb.js
     verifies keccak proofs too, against the pinned `EVM_KEYS`.
   - That halves all proving, and every page is on-chain-ready at Finish with no extra step.
   - Needs:
     - a new page-proof kind, verified by verify-core, the reader and the Mac engine;
     - the EVM keys pinned there;
     - old v3 pages kept readable.
3. **Reuse the solved witness.** `prove-evm` solves each part's witness again (`witness.wasm`), although the normal proof
   of that part already solved the same input. Keep the solved witness per part in the worker, keyed by the input's
   hash, and reuse it.
4. **Use every core after Finish.**
   - Today `proveForChain` proves the parts one after another on the main prover, which has half the cores because the
     writer might still type. It uses the second prover only for the final proof.
   - After Finish nobody is typing: split the parts across both provers, as `finish()` already does, and give them all
     the cores. That's roughly 2× on 8 or more cores.
5. **Warm up the EVM keys with the prover.** `warm()` loads programs, bb.js and the proving points. Also fetching and
   pin-checking the EVM keys there would take the ~1–3 s of warm-up out of the first EVM proof (the first proof took
   11.2 s, the next 7.4 s).
6. **Send batch transactions back to back.**
   - Long pages wait for each transaction's receipt before sending the next (4 tx = 19 s). The relayer could send them
     all at once with consecutive nonces, since the contract's session state only needs them in order, and then wait
     for the last. That's ~6–8 s for any length.
   - Also answer the browser with the transaction hash at once and show "Confirming…", instead of holding the request
     open.
7. **Measure the recorder itself before changing it.**
   - Per keystroke, the editor calls `recording.edit` and `recording.checkpoint`
     (`frontend/write/editor.mjs:1219`), into the WebAssembly recorder, with a WebCrypto signature at each signed
     checkpoint.
   - Add timing around those calls (p50/p95 per keystroke) before optimizing. If they're above a frame (16 ms), batch the
     edits per animation frame.
8. **Bigger or smaller parts** (needs circuit changes, so only with a decision).
   - `OPS = 600` and `SLOTS = 8` set how often a part closes. Larger parts mean fewer proofs but bigger circuits and
     slower parts.
   - The current trade-off is 2^19 gates, ~3 s per part on 8 threads in the normal format.

## Still open

- **Pages finished earlier can't go on-chain.** The inputs for the EVM proofs exist only in the tab that finished the
  page. Keep them (they're private) in the browser's own storage with the page, so Verify On-Chain also works later
  from Your Documents.
- **Mac app pages** (v2 and assurance proofs) have no on-chain path. Only pages written in the browser do.
- **Production:**
  - deploy to Base mainnet (`HUMA_CHAIN=base`) with a funded relayer, and alert on its balance;
  - turn the in-memory per-IP limit (10 an hour) into a shared daily cap when there's more than one server.
- **Arkiv storage expires** after `ARKIV_EXPIRY_DAYS` (≤ 182) and nothing renews it yet (`frontend/ARKIV.md`). It needs a
  renewal job (`extendEntity`) or a durable copy.
- **Rotate the secrets** that were pasted into chat: the Arkiv, Privy and World signing keys, and the Etherscan API key.
- **forge-std** isn't committed (`backend/onchain/lib/` is ignored). Install it before `forge test`.
- **HumaPagesV3** (`0x4e79…687f`) is superseded by V4. Its two test-page records stay on V3; `/verify` reads V4 only.
