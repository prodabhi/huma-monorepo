# huma-prover

> **Not part of the current setup.** Huma proves every page on the writer's device. This server stays for writers
> who opt in to server proving (Settings → Where proofs are made). The on-chain batch route was retired with Base in
> 0.2 and is archived in `extra/experiments/onchain/prover/`.

One Rust process for every proof Huma makes on a server:

- `POST /v1/pages/prove` makes **opt-in page proofs**. A writer who picks "Huma prover" in the app sends the same private request the Mac's own worker would get. The server runs the same pinned engine and returns only the public proof, and the Mac verifies that proof locally before using it. Requests are never stored or logged, and each one's workspace is deleted when it ends. Limited per client address.
- `GET /healthz` reports what this instance can prove and how busy it is.

Barretenberg (`bb`) does the proving math. This server keeps it busy without running out of memory:

- Jobs are admitted by memory budget, not by count: about 2 GB for a short page and 3 GB for a long page.
- The wait line is bounded. A full line answers 503 with `Retry-After`.
- Each proof gets every core. Measured on a 16-core M-series Mac:

| Proof | On the Mac app (2 threads) | On this server |
|---|---|---|
| 64-character page | about 3 s | 1.8 s |
| 128-character page | about 6 s | 2.8 s |
| 256-character page | about 11 s | 5.1 s |

## Run

```sh
HUMA_NODE_ENGINE=1 \
  python3 backend/integrations/noir/package.py build/prover-engine  # stage the pinned engine (new directory)
cargo build --release --manifest-path backend/prover/Cargo.toml
HUMA_ENGINE_DIR="$PWD/build/prover-engine" \
  ./backend/prover/target/release/huma-prover
```

| Variable | Default | Meaning |
|---|---|---|
| `HUMA_PROVER_ADDR` | `127.0.0.1:4330` | Listen address. Put TLS in front of it for real use. |
| `HUMA_ENGINE_DIR` | (none) | Staged engine. Every file is checked against its manifest at startup. |
| `HUMA_PROVER_MEMORY_GB` | ¾ of RAM | Memory budget shared by all jobs. |
| `HUMA_PROVER_THREADS` | all cores | Threads per proof. |
| `HUMA_PROVER_QUEUE` | 32 | Jobs allowed to wait. |
| `HUMA_PROVER_PAGES_PER_HOUR` | 30 | Page proofs per client address. Behind a proxy, every client shares the proxy's address. |

## Test

```sh
cargo test --manifest-path backend/prover/Cargo.toml            # admission, limits, request shape
HUMA_PROVER_E2E_URL=http://127.0.0.1:4330 \
  swift test --package-path extra --filter RemoteProverTests     # a real page, verified on the Mac
```

On Linux, stage an engine with Linux builds of `node`, `bb` and `capture-input`; `package.py` currently stages the macOS arm64 tools. The macOS network sandbox for the worker applies only on macOS.
