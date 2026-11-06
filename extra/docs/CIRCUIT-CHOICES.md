# Circuit choices

Every choice in Huma's page proof, what it costs, and why. Measured 29 October 2026 on the v3 circuits
(`backend/integrations/noir/long3/prover.nr`), bb 5.2.1, Noir 1.0.0-beta.25, MacBook Pro M4 Max.

## What the proof has to do

- Show the page's text came from the recorded edits, labelled typed, pasted or other.
- Show the typing checks passed, and that Touch ID was answered at the checkpoints the Mac signed.
- Keep keystroke timing private. Timing identifies people ([Acien et al. 2021](https://arxiv.org/abs/2101.05570)).
- Prove on the writer's own Mac or browser, never on a server, at low cost.
- Check in a browser in seconds.
- Target: research papers of 100,000 characters.

## Where the cost goes today

A part proof costs about `63,000 + 18.7 × capacity + 608 × operations` gates. Fitted to six builds; each is within 1%.

| Circuit | Gates | Proving size |
| --- | ---: | ---: |
| Part, 160 operations, 1,024 characters | 179,366 | 2^18 |
| Part, 600 operations, 1,024 characters | 447,482 | 2^19 |
| Part, 600 operations, 4,096 characters | 504,948 | 2^19 |
| Part, 600 operations, 10,000 characters | 615,484 | 2^20 |
| Final, 1,024 / 4,096 / 10,000 characters | 205,090 / 485,849 / 1,027,301 | 2^18 / 2^19 / 2^20 |

Inside a 600-operation part (1,024 tier): the replay machine is 63% of gates, the typing checks 22% and Poseidon2
hashing 14%. The largest single line is the typing-speed ring's `downs % 20`, at 22,332 gates
(`extra/experiments/noir-compact/src/assurance.nr:57`).

A typed character costs 5 operations: key down, begin edit, insert, end edit, key up (1,500-character case: 7,516
operations).

## The choices

| # | Choice today | What it costs | Verdict |
| --- | --- | --- | --- |
| 1 | UltraHonk with zero knowledge, Poseidon2 transcript (`-t noir-recursive`) | 14.6 KB a proof, about 15 ms to check in a browser | **Keep.** Universal setup, runs in bb.js, and the zero-knowledge flavour keeps timing private. |
| 2 | P-256 signatures checked by the reader, not in the circuit. The key is bound through the session nonce. | Free in the circuit | **Keep.** With recursion removed, it's what made v3 eight times faster than v2 (15 s against 121 s for 600 characters). Signatures are public data, so nothing private leaves. |
| 3 | The whole text buffer is hashed for each part's start and end (`prover.nr:41-52`) | 18.7 gates per character of capacity, in every part. At 100,000 characters: 1.9 million gates a part. | **Change in v4.** Store the text in blocks under a Merkle root, so a part opens only the blocks it edits. |
| 4 | The cursor moves one character per operation (`ops.rs:83-84`) | Clicking 10,000 characters back costs 10,000 operations, about 17 parts. | **Change in v4.** Moving within a block stays local; jumping to another block is one operation. |
| 5 | Edit positions are 16 bits (`ops.rs:74`) | No page can pass 65,535 characters | **Change in v4** to 32 bits. |
| 6 | Three text tiers (1,024 / 4,096 / 10,000). Every part is proved again when the text outgrows its tier. | Wasted work, and a bug class (stale-tier parts, fixed 29 Oct) | **Drop in v4.** With blocks, a part costs the same at any length. |
| 7 | The final step walks the whole text (`prover.nr:401-462`) | About 100 gates a character: 1 million at 10,000, 10 million at 100,000 | **Change in v4.** The reader rebuilds the text's Merkle root from the published text (cheap in JavaScript), so the final step stays small. |
| 8 | 160 operations a part | One proof per ~30 characters. Each part pays the fixed 63,000 gates. | **600 in v3** (below). In v4, set once the block overhead is measured: fill 2^19 with margin. |
| 9 | Five operations per typed character | 3,000 gates a character | **Change in v4.** One "type at the cursor" operation for the common case: 3 operations a character, 40% less work. |
| 10 | Typing-speed ring indexed by `downs % 20` | 22,332 gates a part (5%) | **Change in v4.** Carry the ring position instead of dividing. |
| 11 | Every part proof is published; the reader checks each one | 14.6 KB a part | **Folding works, for v4** (Chonk, below): up to 34 parts in one 23 KB proof. Not for 0.2: the fold can't survive an app restart and Chonk has no external audit yet. |
| 12 | Proofs stored as JSON with base64 | A third bigger than raw | **Done:** pages are saved compressed (4.4× smaller on the Mac). Downloads to be served gzip, which measured within 3% of raw bytes. |
| 13 | 2^21-point proving setup (64 MB) | First-run download | **Revisit in v4.** Without the 2^20 final step, 2^19 (16 MB) may do, which matters for the web version. |
| 14 | Witnesses were built in JavaScript (noir_js) inside JavaScriptCore, through `HumaScriptHost` | JavaScriptCore fell off a cliff at 2^19: 44 s for a 600-operation part, against 1.5 s in Node, and stayed slow afterwards. A 588-character page took 315 s. | **Done: native.** `backend/integrations/noir/witness` runs Noir's own solver (v1.0.0-beta.25) as a 2 MB tool. Its witnesses are byte-identical to noir_js for all six programs, in 0.6 s a part (1.5 s for the 10,000 final step). The engine dropped its 3.6 MB of WebAssembly; Node (116 MB) was not needed. |

## Proving time in the app, measured end to end

A 588-character recording from the real Swift recorder (3,007 operations), through the app's engine. The Mac was
also busy with other work (load average 10 to 25), so these are upper bounds.

| | 160 operations, JavaScript witnesses | 600 operations, JavaScript witnesses | 600 operations, native witnesses |
| --- | ---: | ---: | ---: |
| Whole page from scratch, 11 threads | 42 s | 315 s | **15.6 s** |
| Whole page from scratch, 2 threads | | 456 s | **37.6 s** |
| Finish with 5 of 6 parts proved while writing, 11 threads | | | **5.7 s** |
| Finish, same, 2 threads | | | **12.9 s** |
| Page proof | 419 KB | 143 KB | 143 KB |

Finish uses every performance core but one (`LocalProofWorker.finishingThreads`), so 11 on this Mac. A 600-operation
part alone: 0.6 s witness, then 5.5 s to prove on 2 threads, 3.6 s on 4, 2.6 s on 11.

## Part size: 160 or 600 operations (v3)

Same load, 4 threads, 1,024 tier, three runs each:

| | 160 operations | 600 operations |
| --- | ---: | ---: |
| Witness | 0.68 s | 1.48 s |
| Prove (median) | 1.46 s | 3.42 s |
| Proving work per keystroke | 1× | 0.62× |
| Proofs for a 1,500-character page | 47 | 13 |

600 fits each tier's part in 2^19 (1,024 and 4,096) or 2^20 (10,000); 640 pushed the 4,096 part to 2^20. The app
closes a part at a pause once it holds 450 operations, so most parts are full. Cost: the last part at Finish grows
from about 1 s to about 2.5 s on 4 threads. It proves alongside the final step, so Finish grows by less.

## Folding (Chonk)

Measured on this Mac with bb 5.2.1 (8 threads, under other load, so timings vary up to 2×). Scripts and logs:
the session scratchpad's `chonk/`.

| Parts folded | Fold, total | Last steps (tail + final proof) | Proof | Check (native / bb.js in a browser engine) | Memory |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2.8 s | 1.1 + 1.9 s | 23 KB | 38 ms / 53-63 ms | 1.3 GB |
| 4 | 10.2 s | 1.4 + 2.0 s | 23 KB | 37 ms | 1.4 GB |
| 8 (4,096 tier) | 16.7 s | 1.3 + 2.6 s | 23 KB | 35 ms | 1.5 GB |
| 16 (10,000 tier) | 29.3 s | 1.3 + 2.1 s | 23 KB | 28 ms | 1.8 GB |
| 23 (most with one part per step) | 57-67 s | 1.3 + 3-3.8 s | 23 KB | 31-45 ms | 1.8 GB |
| 34 (three parts per step) | 61 s | 1.2 + 2.6 s | 23 KB | | 1.8 GB |

- **Size:** always 23,328 bytes compressed, whatever the count. Today a 1,500-character page publishes 13 part proofs
  (190 KB); folded it would be 23 KB.
- **Cost:** folding a part takes 1.3-2 s on 8 threads, against 2.7-2.9 s to prove it alone, so folding doesn't add
  work. It needs 1.3-1.8 GB of memory.
- **Circuit change:** a folded part can't have public inputs. The part's boundary moves to `return_data`; the
  constraints stay the same.
- **Limits:** at most 34 parts in one proof (`CHONK_MAX_NUM_APPS`). A 9,000-character page (80 parts) would need three
  proofs, about 70 KB.
- **While writing:** the number of parts is fixed when the fold starts. Declaring the maximum and padding the rest at
  Finish works (20 pads took 5.1 s). But the fold lives only in the running bb process: quitting Huma loses it, and
  nothing saves it to disk.
- **Audit:** Chonk's source says its internal audit is done and its external audit hasn't started.

Verdict: worth it for v4, where block text makes parts cheaper to fold. Folding 13 parts at Finish would take about
20 s today, against 5.7 s now. For 0.2, keep one proof per part, since those survive restarts and are audited.

## Proving in a browser (huma.social/write)

The same circuits, proved in the browser with no server: the recorder (`extra/experiments/noir-compact/native/src/web.rs`) and
the witness solver (`backend/integrations/noir/witness`) are the Mac's Rust compiled to WebAssembly; bb.js 5.2.1 proves on
several threads. Measured in Chrome on this Mac while it was busy (load average 10 to 30):

| | Chrome | Mac app (native) |
| --- | ---: | ---: |
| Witness, 600-operation part | 0.85 s (also 0.93 s in JavaScriptCore, so Safari has no cliff) | 0.6 s |
| Prove a part, 8 threads | 20 to 31 s | 2.6 s (11 threads) |
| Final step, 1,024 tier | 1.9 to 15 s | 0.9 s |
| Proving points (first time a page loads) | 16 MB, 1.4 s to set up | already on the Mac |

A 212-character page written in Chrome: both parts proved while writing, 2 s after Finish, and /verify accepted the
evidence file. Every browser proof checked with native `bb verify`.

Readers now tell browser pages apart from the proof alone: no key press carries the Mac's input origin
(`origin_present` is 0). Such a page reads "Typed in Huma" (one product name everywhere, no "browser" or "Mac" labels), never
"Typed by a person", and scores at half weight
(35 typed, 10 typing checks, 5 check-ins), so at most 50 (`humaScore` in `frontend/publication-contract.mjs`). This holds
only for honest pages: a forger who rebuilds the recorder can claim Mac origins, and nothing proves a page came from
the real Mac app until App Attest or DeviceCheck evidence is in the proof.

## Typing checks (huma.social/write)

`frontend/write/typing.mjs` judges key presses as they arrive and stops the recording when typing is impossible for a
person (keys released within 12 ms, presses within 12 ms, a rhythm within 3 ms, identical holds), or, after 250 keys,
when its rhythm follows neither words nor hands (Mann-Whitney z below 1 for both: word starts slower than inside
words, one hand slower than two). Pointer jumps to every click and `navigator.webdriver` stop it too.

| | Result |
| --- | --- |
| Claude in Chrome typing (keys 0.1 ms apart) | stopped after 20 keys |
| Delays drawn at random, ~1,000-key page | 95% stopped, mostly at key 250 (`frontend/test/typing.test.mjs`) |
| Simulated people with weaker patterns than either real page | 0% stopped |
| Two real Mac pages (Swayam, 177 and 194 keys) | all signals natural; word starts z 2.7 and 1.1, hands z 2.3 and 3.4 |
| Delays modelled on people (word starts, hands, rollover) | passes: timing alone can't tell |

The page check is a speed bump: software that drives the recorder directly never meets it. Enforcement belongs in the
proof (below).

## v4 circuits: provenance and typing rules in the proof

1. **Where each character came from, proved.** Tag every character in the text buffer with its source (typed, pasted,
   other) as edits apply; the final step outputs the origin of every character of the final text (or its hash, with
   the mask beside the text). Readers then mark pasted text on every page without the writer sharing a replay, which
   today reveals deleted drafts. Undo and redo bring text back as "other" unless the circuit tracks deleted origins.
2. **The typing signals as proved rules.** Rollover, hand alternation, word-start pauses and corrections are running
   sums per key press (a few additions each), so they fit the per-part behaviour state at little cost.
3. **Noir 1.0.0** (released 29 October 2026) pairs with Barretenberg 6.0.0; bb.js 6 isn't on npm yet (latest 5.3.0).
   Move once both are out and two weeks old, which is mid-November at the earliest, and fold 1 and 2 into the same new
   keys, so pages change format once.

## Proposed order

1. 0.2 ships v3 with 600-operation parts, native witnesses, compressed pages and gzip downloads.
2. v4 for long documents: block text with a Merkle root (3, 4, 6, 7), 32-bit positions (5), one operation per typed
   character (9), the cheaper speed ring (10), and folding at Finish (11).
3. Before building v4, prototype the block buffer alone to get its fixed cost per part. That sets the part size (8)
   and the setup size (13).
