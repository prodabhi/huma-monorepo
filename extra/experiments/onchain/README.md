# On-chain records (retired in 0.2)

Huma 0.1 recorded verified pages on Base Sepolia through the HumaPages contract (`contracts/`, moved here from the repo root).
0.2 removed it: pages are stored on huma.social (Cloudflare R2) and every reader still checks the proof
in their own browser. These files are kept for reference and are not built, served or tested.

- `relayer.mjs`: the server's relayer wallet that sent page proofs to HumaPages (was `web/relayer.mjs`).
- `chain.mjs`: the reader's Base lookup (was `integrations/noir/long/chain.mjs`).
- `relayer.test.mjs`: their tests (was `web/test/relayer.test.mjs`).
- `contracts/`: HumaPages and its Noir verifier contracts (Foundry), with their deploy script and tests.
- `batch/`: the 4-page batch circuit for one EVM proof per batch (was `integrations/noir/batch`).
- `prover/`: the prover's batch route and its Poseidon2 commitments (were `prover/src/batch.rs` and `commit.rs`).
