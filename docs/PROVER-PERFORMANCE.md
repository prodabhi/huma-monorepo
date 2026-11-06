# Huma prover performance

Measured on October 23, 2026, against the current packaged Noir prover and verifier.
The app's shipped profiles, pins and acceptance results are unchanged. This document
records the profiling method, the measured limits of the current prover, and three
right-sized profiles that prove the same public statements with 14–36% fewer gates.
Those profiles are research candidates; wiring them into the app is a separate,
reviewed change.

Related data: [prover-performance-attack.json](../backend/integrations/noir/results/prover-performance-attack.json).
Reproducible circuits, witnesses, keys and proofs:
`build/research/noir-profile-sizing/{short-tight8,medium-tight32,long-tight32}`.

## Result

| Fixture | Current gates | Tight gates | Gates | Prove 2 threads | Witness | Public inputs |
|---|---:|---:|---:|---:|---:|---|
| 40 chars (201 ops) | 260,386 | 165,765 | −36.3% | 2.38 s → 1.60 s | 0.50 s → 0.31 s | identical |
| 120 chars (601 ops) | 522,977 | 449,968 | −14.0% | 4.57 s → 4.06 s | ~1.19 s → ~1.05 s* | identical |
| 250 chars (1,251 ops) | 969,400 | 796,569 | −17.8% | 8.44 s → 6.88 s | 2.08 s → 1.82 s | identical |

\*Inferred from the ACIR opcode ratio; every other witness figure is measured with
the bundled Noir runtime. "Identical" means byte-for-byte equality of the proof's
public inputs with a proof of the same capture under the original profile. The
signed journal, checkpoint signatures, presence signatures, ABI and composite
statement identity do not change.

Two headline facts:

- Prove time follows circuit gate count: the large circuits run at about
  **8.6–8.7 µs/gate on two threads**, while smaller ones run at 9–9.6 µs/gate
  because fixed proof work does not shrink.
- The current profiles are over-provisioned for their sessions: 201 of 372 operation
  slots, 40 of 256 text bytes, 80 of 132 key samples. The unrolled circuit pays for
  every unused slot.

## 1. Where the gates go

Measured on the 40-character circuit (260,386 gates) by joining
`bb gates --include_gates_per_opcode` with the artifact's raw-deflate
`debug_symbols` (`acir_locations` + `location_tree`). This attributes each ACIR
opcode to a source line.

| Source | Gates | Share |
|---|---:|---:|
| Replay interpreter (`src/main.nr`) | 141,553 | 54.4% |
| Behavior, origin and presence (`src/assurance.nr`) | 28,415 | 10.9% |
| Poseidon2 permutation | 25,612 | 9.8% |
| SHA-256 | 25,553 | 9.8% |
| Field range checks (`assert_max_bit_size`) | 16,177 | 6.2% |
| Commitment packing (`src/commit.nr`) | 5,192 | 2.0% |
| Canonical text policy (`src/bytes.nr`) | 3,773 | 1.4% |

By ACIR opcode class: assertions 63.3%, range checks 17.2%, Brillig hints 13.4%,
memory reads 3.3%, Poseidon2 blackbox 1.8%. These source lines account for 246,345
of 260,386 gates (94.6%); the remainder is setup and ACIR flattening without a
mapped source span.

The largest individual source lines are:

| Line | Gates |
|---|---:|
| `std/hash/mod.nr:118` Poseidon2 permutation | 25,612 |
| `std/field/mod.nr:17` `assert_max_bit_size` | 16,121 |
| `sha256.nr:104` SHA-256 compression | 15,792 |
| `main.nr:188` backward `next_times` pass | 11,686 |
| `main.nr:106` elapsed-time select | 7,346 |
| `assurance.nr:57` `rate_ring` modulo 20 | 4,880 |
| `main.nr:61` padding/opcode branch | 4,550 |
| `main.nr:71` scalar validity | 4,372 |
| `main.nr:80` removed-text extraction | 4,092 |
| `main.nr:98` begin-source check | 4,092 |

There is no single removable hotspot. After protocol hashing (Poseidon2 and
SHA-256, about 20% of gates) and behavior analysis (about 11%), the rest is a long
tail of boolean and range constraints in the unrolled replay machine. Removing any
one line saves a few percent.

## 2. What did not help

| Candidate | Measurement | Verdict |
|---|---|---|
| `noir-rollup` verifier target | 7.72 s prove at 2 threads, 15,360-byte proof | 6% faster than `noir-recursive`; requires a different reader target and pins. Rejected for 6%. |
| `evm` verifier target | 8.36 s prove, 10,304-byte proof | Slower. Rejected. |
| Limb-based operation decoding (remove u64 division/masking) | 254,850 vs 260,386 gates (−2.1%) | Not worth a private-ABI and protocol change. |
| Remove 16/17-bit bounded arithmetic | 621,137 vs 522,977 gates (+18.8%) | The current bounds are already the cheap form. |
| Constant-folded u64 extraction variant | −50,665 gates (−9.7%) | Overstates a real rewrite: downstream comparisons folded away. Not a valid semantics-preserving change. |
| Drop phase polynomial assertions | −34,786 gates (−6.7%) | Weakens the replay relation. Rejected. |

Verification is already cheap: native verification takes about 16–22 ms and the
browser WASM reader 0.1–0.3 s in the existing acceptance. No verifier change is
justified by these measurements; the attack is entirely on proving work.

## 3. Capacity right-sizing

The circuit capacities are compile-time globals. Padding slots execute the full
interpreter body, and byte capacity sizes the dynamic text assembly, so unused
capacity is paid for on every proof. The three candidates keep the circuit source
and signed capture, change only these globals, and are rebuilt from the same input:

| Candidate | OPS | SCALARS | BYTES | SAMPLES | CPS | PRES |
|---|---:|---:|---:|---:|---:|---:|
| `short-tight8` | 204 | 64 | 64 | 84 | 8 | 8 |
| `medium-tight32` | 660 | 128 | 128 | 252 | 32 | 8 |
| `long-tight32` | 1,272 | 256 | 256 | 504 | 32 | 8 |

`CPS` is deliberately unchanged per tier. `Journal.checkpoint_roots` is a public
array of length `CPS`, so changing it would change the reader ABI and the public
input length. Keeping `CPS` preserves the existing ABI assets.

Gate breakdown of the changes:

| Change | Gates |
|---|---:|
| Long: OPS 1,536 → 1,272 only | 869,019 |
| Long: + BYTES 1,024 → 256 | 800,122 |
| Long: + SAMPLES 516 → 504, CPS 28 | 789,495 |
| Long: `CPS` 32 (ABI preserved) | 796,569 |
| Short: OPS 372 → 204 only | 197,324 |
| Short: + BYTES 256 → 64 | 179,977 |
| Short: + SAMPLES 132 → 84, CPS 4 | 158,691 |
| Short: + SCALARS 64 → 48 | 155,120 |
| Short: `CPS` 8 (ABI preserved) | 165,765 |
| Medium: OPS 756 → 660 only | 486,683 |
| Medium: + BYTES 512 → 128, SAMPLES 252, CPS 32 | 449,968 |

Staged program data (`noir_version`, `bytecode`, `abi`) is about 1.3 MB, 3.9 MB and
7.4 MB; the full compiled artifacts with debug data are 1.8 MB, 5.2 MB and 9.7 MB.
Each VK is 3,680 bytes. The three staged programs add about 12.7 MB, less than two
current full-profile programs.

### Candidate pins

| Candidate | VK SHA-256 | Bytecode SHA-256 |
|---|---|---|
| `short-tight8` | `799b5ec7f640ba5d114e83415bf6e0cec5a60058d2c3e219ceddfc8257b57db8` | `ac8e05e00d82c5dfffdd5496d90a7083c373a320169b614bee4f8878f907940a` |
| `medium-tight32` | `0949fdc43359c8ec758d75b706a70b458e212026ac364b9b49c27310bdbe4f6d` | `81a1df97ab27d005f08bc38b6cf98a41c310cd01c9380938d3c64cfab6e6dce8` |
| `long-tight32` | `3a541bb46bc39663b59c3fc8b3df84806489721dc9e7c7ce951a8ec68824c5aa` | `7d44317e8808bf27e5fb5b8d673d5dad2f3f8cfb4bb9a4a4e6e7a4afc96559d4` |

## 4. Thread scaling

The same circuit and witness, with `HARDWARE_CONCURRENCY` and `RAYON_NUM_THREADS`
set per run and `nice 10`:

| Circuit | 2 threads | 4 threads | 8 threads | 16 threads |
|---|---:|---:|---:|---:|
| 969k baseline | 8.21–8.44 s | 5.00 s | 3.36 s | 2.89–2.98 s |
| 797k tight | 6.88 s | 4.12 s | 2.89 s | — |
| 166k tight | 1.60 s | 0.99 s | 0.66 s | — |

Total CPU work is almost flat: 14.6 user-seconds at 2 threads, 16.5 at 8 and 20.5 at
16. Eight threads is the practical knee. Four threads remove 39% of wall time;
eight remove 59% for about 13% more total CPU work. Four-thread CPU time was not
recorded separately.

The app currently hard-codes two threads for prover children and deliberately
rejects shell overrides. Changing that default is a thermal/product decision, not
a code defect.

## 5. Complete-service projection

`INFERENCE`: prove + witness + 20 ms native verification + the measured 280 ms
worker/parent overhead. These are projections, not a new app acceptance run.

| Fixture | Current app (2T) | Tight (2T) | Tight (4T) | Tight (8T) |
|---|---:|---:|---:|---:|
| 40 chars | 3.08 s | 2.21 s | 1.60 s | — |
| 120 chars | 5.93 s | 5.41 s | 3.79 s | — |
| 250 chars | 10.81 s | 9.00 s | 6.24 s | 5.01 s |

The 250-character case reaches the five-second boundary only with eight threads,
because witness generation alone is 1.82 s. For that case, proving chunks during
writing (the existing long-session path) is the architectural answer: the seal-time
final step is about three seconds rather than a full-session proof.

## 6. What was verified, and what was not

Verified for each candidate:

- A real proof from the original signed capture, using disposable software keys.
- Native `bb verify` acceptance at the thread counts shown above.
- Byte-identical public inputs to a proof of the same capture under the original
  profile, including the 4,544-byte larger-profile input.
- The candidate proofs bind the same journal. The original checkpoint and presence
  signatures were not re-verified in this run because no signature envelope was
  assembled; identical public inputs mean the existing capsule remains applicable.

Not verified here:

- No app target was rebuilt and no new profile was registered, pinned or bundled.
- No independent WASM verification was run against a new VK pin; the reader pins
  verification keys by hash, so this requires the registration step.
- No owner key, Touch ID prompt, provider account, upload or chain transaction was
  used.
- The policy and boundary witness suites were not rerun for the tight circuits.

## 7. Integration plan

Add tight tiers *ahead of* the existing profiles and keep the current profiles as
fallbacks. This is additive and backwards compatible: the tight proof has the same
statement, so old and new proofs remain valid.

1. Generate each tier's circuit and VK, then run the existing per-profile
   constraint and boundary suites (`assurance_checks.py`, `bucket_checks.py`) and
   prove one complete signed fixture.
2. Register the profile name, public ABI reference, program, VK and bytecode pin in
   `../backend/integrations/noir/worker.mjs`.
3. Add the reader pin and VK asset in
   `../extra/experiments/noir-compact/browser/assurance-profile.mjs` and `browser/assets/`,
   then verify an exported proof through the browser/Node SDK.
4. Extend `../extra/experiments/noir-compact/native/src/profile_fit.rs` with the new
   candidate limits and selection order; extend `assurance_input.rs` so the
   private arrays are padded or rejected at the new exact capacities.
5. Update `../backend/integrations/noir/prepare.py`, `package.py` and the app engine staging
   with the new programs, VKs, pins and manifests.
6. Decide the final-proof thread policy after thermal testing. Four threads is the
   conservative fast setting; eight is the knee for the largest tier.
7. Rebuild the app and rerun the Swift/Node/Chrome acceptance, including
   save/reopen, altered-proof rejection and local master/proof publication.
8. Keep the existing profiles selectable so sessions that exceed a tight tier still
   prove without truncation.

A tier must fit all five dimensions: operations, maximum concurrent scalars, final
raw UTF-8 bytes, key samples and checkpoints. The native replay already computes
the operation stream and prefixes; confirm it exposes maximum concurrent scalar
occupancy before relying on `SCALARS` right-sizing for new text sizes.

## 8. Reproduction

Gate count and per-opcode data:

```sh
build/research/noir-tools/noir/nargo compile --print-acir
build/research/noir-tools/bb/bb gates \
  -b target/huma_compact_experiment.json -t noir-recursive --include_gates_per_opcode
```

Right-sizing an existing prepared profile:

```sh
cp -R build/research/noir-capacity/short64-cp8-v2 /tmp/tight
# Replace the OPS/SCALARS/BYTES/SAMPLES/CPS globals in src/main.nr.
# Truncate ops/origins/timings in inputs.json to the new capacities.
# Regenerate Prover.toml with assurance_cases.fixture.toml.
build/research/noir-tools/noir/nargo execute
build/research/noir-tools/bb/bb write_vk \
  -b target/huma_compact_experiment.json -o setup -t noir-recursive \
  -c build/research/noir-crs
build/research/noir-tools/bb/bb prove \
  -b target/huma_compact_experiment.json -w target/huma_compact_experiment.gz \
  -o proof -k setup/vk -t noir-recursive -c build/research/noir-crs
build/research/noir-tools/bb/bb verify \
  -p proof/proof -i proof/public_inputs -k setup/vk -t noir-recursive \
  -c build/research/noir-crs
```

Set `HARDWARE_CONCURRENCY` and `RAYON_NUM_THREADS` for thread measurements. The
source-line attribution uses `nargo compile --print-acir`, the artifact's
raw-deflate `debug_symbols` and the `gates_per_opcode` array; the exact join is
described in the results JSON.

## 9. Caveats

- Measurements are single runs on one Apple M4 Max with 16 cores; treat small
  differences as noise.
- Fixtures use disposable software keys and simulated input. They are not Touch ID,
  Apple attestation or real-user acceptance.
- The tight profiles are capacity choices, not a security change. Every assertion,
  signature, commitment and writing rule remains in the relation.
- This is not an independent audit. It is a measured engineering attack on latency.
