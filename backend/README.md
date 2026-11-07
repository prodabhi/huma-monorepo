# Backend

Services, proof infrastructure, deployment packaging and operational tooling
live here. The browser-facing Node server remains in `frontend/` because its
routes and static application are one deployable unit.

## Directory guide

| Location | Purpose |
| --- | --- |
| `hosting/` | Production container manifest and acceptance checks |
| `integrations/attestation/` | Apple attestation verifier and service |
| `integrations/grammar/` | Native grammar-checking bridge |
| `integrations/noir/` | Pinned Noir preparation, readers and packaging |
| `prover/` | Optional Rust server-side prover |
| `scripts/` | Repository build, release and hosting scripts |
| `zkvm/` | Historical RISC Zero workspace and independent verifier |

## Common checks

Run these from the repository root:

```sh
cargo test --manifest-path backend/prover/Cargo.toml
npm test --prefix backend/integrations/attestation
cargo test --manifest-path backend/zkvm/Cargo.toml \
  -p huma-replay-core -p huma-replay-verifier --locked
```

See each component's README for its environment and toolchain requirements. The
end-to-end application build is documented in the root README.
