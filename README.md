# Huma: proofs, storage and verification

Huma is a native Mac writing app that captures a signed creation history,
creates a proof locally, saves a portable proof package and lets anyone verify
it independently. Formatting stays in the editor; the proof binds the text.

**Active delivery goal, October 23, 2026:** writing, capture, proof creation,
portable files, and **R2-hosted master copies with their proofs**. Coinbase sign-in
will authorize hosted publication; anyone can download shared evidence and verify
it locally. Local files continue to work without an account or blockchain. Social
posting stays removed. R2 and Coinbase delivery are in progress, not yet a live
deployment. Proof validity comes from cryptographic checks, not the host's verdict.

Read the numbered questions in order. The implementation details at the end are
for anyone who wants to build or inspect it.

**Where this is going:** [VISION.md](VISION.md) reframes Huma from an app that
proves one document into a network where people build a verified human track
record from everyday creation, checked where content is read, with physical
co-presence between users as the moat. The mechanisms are in
[HUMAN-PRESENCE.md](HUMAN-PRESENCE.md) and [MEDIA-PROVENANCE.md](MEDIA-PROVENANCE.md).

The long-term vision includes capture clients on **Mac, iPhone, iPad and Android**,
an open evidence format, feed integrations and a verification SDK. Each content
type carries appropriate evidence: writing history, camera or microphone capture,
edits and supported device attestations. Witnessed captures add to the longer-term
network. Creators choose what to disclose; readers can check shared evidence.

The broader content and mobile vision remains research. This release focuses on
the small proof-file workflow above. The Mac now uses Noir for new short
recordings. Noir is the Mac app's only prover. Media experiments have
separate measured acceptance.

- [The idea and current state](#the-idea-and-current-state)
- [Writing and formatting](#writing-and-formatting)
- [Capture, signatures and Touch ID](#capture-signatures-and-touch-id)
- [Proofs, privacy and performance](#proofs-privacy-and-performance)
- [Identity, time and independent verification](#identity-time-and-independent-verification)
- [Saving and verifying proofs](#saving-and-verifying-proofs)
- [Human assurance and the remaining work](#human-assurance-and-the-remaining-work)
- [Current issues and how you can help](#current-issues-and-how-you-can-help)
- [Build, verify and inspect the implementation](#build-verify-and-inspect-the-implementation)

## The idea and current state

### 1. What is Huma?

Huma is a **network for verifiable content and creator provenance**. Creators should be able to attach
privacy-preserving evidence of how their text, images, audio and video were
created, captured and edited. Anyone receiving that content should be able to
check its evidence independently. An optional account history aggregates verified
captures, supported presence and witness evidence. It provides context about a
creator; every new item still needs its own content-bound evidence.

The first working workflow is writing on Mac. A writer records a session, seals
it with a signing key and generates a proof locally. The editor feels like a
calm, Notion-inspired page; the evidence records the process underneath it.

The broader product applies that creation-to-verification flow to all four media:

| Content | Evidence the product aims to provide | Delivery |
| --- | --- | --- |
| Text | Signed writing history, input provenance, presence and privately checked writing rules | Mac capture/replay proof works; stronger rules are being integrated |
| Images | Supported camera/capture evidence, content integrity and edit provenance | Planned |
| Audio | Supported microphone/recording evidence, content integrity and edit provenance | Planned |
| Video | Supported camera/microphone evidence, recording continuity and edit provenance | Planned |

Each format needs its own capture and proof design. A shared verification format
and reader should make those different evidence types understandable together.

The intended flow is:

```text
Create or capture → seal evidence → optionally prove private checks → publish by choice
                                                               ↓
                                             verify in the feed + update track record
```

### 2. What problem are we trying to solve?

We want to make **AI-generated or automated content expensive to misrepresent
as human-created or authentically captured content**, across text, images,
audio and video.

Today, a recipient often gets a finished file and a claim about where it came
from. Huma's approach is to attach checkable process evidence: how content was
created or captured, which changes are covered, and which device and presence
claims are supported. The goal is useful provenance at the moment of sharing.

The security target is economic as well as technical: make accepted fakes demand
substantial attention or resources while honest creators can work naturally.
We will measure that cost by content type and attack, alongside false positives
and creator friction. The first implementation and measurements concern Mac writing.

### 3. What does a successful Huma verification establish?

For the current Mac writing workflow, it establishes that shared text matches a
recorded writing history whose replay, commitments and checkpoint signatures satisfy the pinned proof program.
Readers can check that evidence themselves while the writer keeps detailed
keystrokes and intermediate drafts private.

That is useful provenance: a signed, checkable account of a process. Additional
layers establish device/app provenance, presence at checkpoints and compliance
with a writing policy. Each layer adds a specific piece of evidence.

The broader product will use the same discipline for media: verify the particular
capture, integrity and editing claims covered by its evidence. A photograph,
recording and writing session have different provenance requirements.

Creative intent and the truth of a scene are separate from provenance. For
example, someone can transcribe AI-generated writing or film a staged scene.
Those concrete attacks help define what each content workflow should establish.
Account history and witness facts add context without changing the statement
verified for this particular item. Different signing keys are counted as keys,
unless stronger enrollment evidence justifies a device count.

### 4. What works today?

| Area | Current state |
| --- | --- |
| Native Mac writing and formatting | Implemented; selected capture/save/reopen paths tested |
| Exact text comparison with a defined whitespace policy | Implemented and tested |
| Signed capture and sealing | Implemented; earlier Secure Enclave capture exercised |
| New Touch ID-only recording path | Compiles and storage tests pass; actual user fingerprint acceptance remains pending |
| Real local session proof | Bundled Noir generation, save/reopen, offline verification and local master/proof sharing tested; the Mac has one proving path |
| Portable evidence package | Shared Swift/JS statement contract, verified Mac export, reusable verifier and local registry transport implemented; existing proof formats remain supported |
| Faster Noir prover | Automatically selects a complete-history circuit; measured 2.35s proving / 3.08s complete service for 40 characters, 4.58s / 5.93s for 120, and 8.20s / 10.81s for 250 |
| Master and proof sharing | R2/S3 storage adapter, Coinbase approval page, Mac handoff and independently checked downloads implemented locally; live R2 and Coinbase acceptance pending |
| Apple app/device evidence | Verification components exist; real provisioned Mac enrollment remains unvalidated |
| Presence and private writing rules | Full experimental Noir proof verifies replay, origin fields, presence and nine writing rules through the Mac, shared SDK/browser and sharing service |
| Shared media capture contract | Image/audio/video session signatures tested on Mac, typechecked for iOS; real experimental media membership proofs verify in Node and browser; sensor/scene-policy work remains |
| Score out of 100 | Not calibrated or shipped |
| On-chain attestation/proof verification | Not implemented or deployed |
| iOS and Android apps | Not implemented |
| Public open-source distribution | Local source exists; public release, licensing and auditable distribution remain unfinished |

**New short recordings now use Noir in the Mac app.** The bundled service was
tested with an original signed Swift software capture. Real fingerprint and
provisioned Apple evidence acceptance remain separate requirements.

### 5. Why build the Mac app first?

Mac writing is the current implementation scope. It is a useful creation
environment with
native signing and biometric APIs that a normal website does not provide.

The ordinary editor targets macOS 14 or later. The stronger App Attest path has
additional OS, hardware, signing and provisioning requirements. Being able to
open the editor does not mean a device qualifies for an attested provenance tier.

Phones remain future clients. Windows Hello, security keys, paired devices and
other platform fallbacks are ideas to evaluate, not working Huma integrations.

iOS and Android are core to the long-term product vision. They bring Huma to
everyday writing, photography, voice and video creation. Each client will use
the platform's supported capture and hardware-security mechanisms while sharing
the same public verification approach. Delivery follows the Mac text milestones.

### 6. Why is there an app for the creator but only a browser for the reader?

The creator needs a way to capture events and establish where the signing evidence
came from. Native platform capabilities help with that. Checking a finished
proof is mathematical verification over public data and can run in a browser.

Huma does not offer a plain browser page as a trusted capture source. Running ZK
math in a browser would not, by itself, establish that its input log came from
physical typing. The browser is the reader in the current design.

## Writing and formatting

Questions 7–38 explain the first implemented workflow: text creation on Mac.
Media capture and mobile clients follow the broader vision above and the roadmap
in question 45. Keyboard-specific checks apply to writing sessions.

### 7. What does a normal writing session look like?

Start a page and format it normally. When you want to record evidence, explicitly
start a signed session. Existing text becomes an **imported baseline**. Write,
revise and then seal the session. Generate a replay proof and choose what to share.

Starting a new signed session retains earlier session history separately. It
does not relabel existing writing as freshly typed. No sign-in is needed for
writing, proof creation, storage or verification.

### 8. Can we keep Notion-style formatting?

Yes. The Mac editor supports headings and inline formatting such as bold,
italic, underline, strikethrough, code font and links. A `.huma` document stores
the page's presentation separately from the plain text used for verification.

This is a writing workspace inspired by Notion, not a complete Notion clone.
Collaboration, a general database system and every Notion block are not implemented.

### 9. Does formatting affect a proof?

Changing a font or making the same words bold does not change the verified plain
text. The title is also separate metadata.

Actual characters do matter. If a list, checkbox or quote is represented by
characters inserted into the text, those characters are included in the
commitment. Replacing characters to create a visual style also changes the text.

This lets a platform display the same verified words with its own typography.
It does not make arbitrary rewrites or punctuation changes equivalent.

### 10. How are spaces handled? Should we remove them or encode them?

Keep meaningful spaces. Removing all spaces would make different texts collide
under an overly loose comparison rule.

Huma's current policy is `trailing-ascii-space-tab-v1`: ignore **only ASCII spaces
and tabs at the end of the entire text** when preparing or comparing its verified
representation. Text is encoded as UTF-8; encoding is not a reason to erase spaces.

| Two copies | Match under this policy? |
| --- | --- |
| `Hello` and `Hello ` | Yes |
| `Hello` and `Hello` followed by a tab | Yes |
| `Hello world` and `Helloworld` | No |
| `Hello` and a leading space followed by `Hello` | No |
| `Hello` and `Hello` followed by a newline | No |
| ASCII space and nonbreaking space | No |

Internal spaces, line breaks, CRLF differences, punctuation and Unicode sequences
remain significant. Visually identical composed/decomposed Unicode is not silently
normalized. The stored draft and private history retain the original characters.

A raw text edit invalidates the app's saved session proof even when a reader's
comparison would tolerate that final space or tab. Formatting alone does not.

### 11. What happens when text is pasted, imported or dictated?

During recording, the Mac editor has a **zero-character paste allowance**.
Command-V, normal/plain/rich-text paste, pasteboard imports and text drops are
blocked. The status bar shows “Typing only · paste disabled”. Ordinary typed
input and formatting remain available. Pasting into an unrecorded draft is
recorded as pasted/imported material, not freshly typed writing.

The capture format records input source labels, including typing, paste,
composition, dictation, replacement, import and unknown input. Readers can inspect
the proved source counts rather than relying on a claim attached to the text.

A general replay proof supports ordinary workflows, including imported material.
The new experimental writing policy separately checks for an empty baseline and
typing-labeled edits throughout. Its result is shown alongside proof validity;
a pasted session can have a valid replay and fail that stricter policy. Even one
pasted character fails the existing `typing_edits_only` rule. This rule already
lives inside the pinned ZK circuit; the editor guard adds enforcement at entry.
A future nonzero allowance would need an explicit versioned policy.

We also need to track the origins of the text that survives revisions. Counting
paste events alone is insufficient: a person could paste, delete or replace
sections, and event totals would not tell a reader which final characters were typed.
That richer origin policy is not implemented yet.

### 12. What does saving or exporting reveal?

The Mac's **Export → Evidence package** wraps the verified text and current proof
in the shared format. It keeps detailed history private and does not generate a
new proof, sign again or request Touch ID. The browser reader can import it. Its
statement is checked against the underlying proof; a package label or hash alone
is not treated as verification. Existing disclosure exports remain separate.

A `.huma` file preserves text, formatting and private session history. A plain
`.txt` export preserves text only. Treat the document file as private writing data;
its contents are not made confidential merely because a ZK proof exists.

Public proof export can omit the detailed history. The author can optionally
reveal the public signing key or explicitly export the full session for inspection.
New Noir proofs already include the public key and signatures. Their optional
`huma-writing-disclosure-v1` export can attach a raw session for inspection; the
reader verifies its nested proof and does not certify that additional history.
Public sharing strips the disclosure. Sharing a proof is different from sharing
the complete draft file.

## Capture, signatures and Touch ID

### 13. What exactly gets recorded?

Huma records edits and key-down/key-up samples inside its editor, together with
ordering and elapsed-time fields. Edits identify a location, removed text length,
inserted text and input source. Modifier information is part of key sampling.

New Mac capture also binds OS-reported event source PID, source state, keyboard
type and repeat status into the signed history. These details remain private;
the proof can publish aggregate source coverage.

Capture is limited to Huma's editor. It needs no system-wide keyboard logger or
Accessibility permission. Physical keyboards, posted events and virtual HID devices
still need the four-source experiment before source metadata becomes a physical-input rule.

### 14. Are all keystrokes signed?

Every captured record contributes to an ordered hash chain. A checkpoint signs
the current chain head, so its signature covers the preceding committed records.
The app does not ask the Secure Enclave to create a separate signature per key.

For new recordings, checkpoints are made at start and seal, and automatically
after **256 new capture records or 10 seconds with new input**. An idle interval
does not generate duplicate signatures. A final seal must cover the entire session.

Older recordings keep every original checkpoint. Reducing the cadence for new
sessions does not prune or re-sign historical evidence. The longer automatic
interval leaves more unsealed input if recording stops abruptly.

### 15. What is a hash chain, in normal language?

Each new record incorporates the previous chain head into its hash. It is like
numbering pages while giving every page a fingerprint of everything before it.
Changing, removing or rearranging a committed record changes later heads.

A hash chain detects inconsistency. The checkpoint signatures authenticate which
key approved those heads. Neither mechanism alone establishes that the original
records were genuine human actions.

### 16. Where does the signing key live?

The native recording path uses a persistent P-256 signing key in the Mac's Secure
Enclave. It refuses a software-key fallback for signed native capture.

The new storage path saves Apple's encrypted key representation in a private local
file, not an exported raw private key. The key is protected by the currently
enrolled fingerprint set. It does not silently read or replace the older
login-Keychain capture identity.

There is a separate experimental test harness that creates disposable software
keys. Those test proofs demonstrate cryptographic behavior and performance;
they do not attest the development Mac or a human writer.

### 17. Why does the app ask for Touch ID? Do we always need it?

The Mac recording path asks for Touch ID at start and seal. The new presence
flow also schedules occasional checks while recording: a three-minute floor
plus a random delay, averaging 12.5 minutes between scheduled checks.

Each presence check pauses input, creates a fresh nonce bound to the current
session head and requests fresh fingerprint approval within ten seconds. Both
the challenge and its resolution become capture records. Missed and late checks
remain visible. Durability checkpoints continue without a prompt per keystroke.

These approvals authorize use of the capture key. They are not required by ZK
mathematics itself. Stronger evidence of presence is a product policy decision,
and frequent challenges would need to earn their cost through attack testing.

The new path has no Huma password fallback. macOS may still require an OS unlock
step after restart or biometric lockout. The Touch ID-only path has compiled and
passed storage tests, but its full user-approved fingerprint flow still needs
live acceptance. No security-key fallback is implemented.

### 18. Could an agent write text and generate a proof without me approving it?

Anyone can generate a proof about data they possess, or construct a synthetic log
that meets a mathematical relation. A proof is not a request for permission.
That is why genuine capture and key provenance matter separately.

The app's new signed recording flow asks you to authorize its key at start and
seal. Existing logs can be proved later without asking you to approve every step
of the proving computation. Development tests use software keys, not your identity.

Touch ID approval also does not certify that every intervening edit was yours.
A real person can approve a prompt while a script types. That remains an attack
to evaluate, not something the signature makes impossible.

### 19. Why might macOS ask for a password or Keychain access?

Recording uses fingerprint approval through the Secure Enclave capture key.
Optional device enrollment has its own local Keychain state. The app no longer
loads social-provider credentials or asks you to connect a publishing account.
Proof generation is local computation over an already sealed session; it does
not need an account password or a network login.

## Proofs, privacy and performance

### 20. What does the current proof actually check?

For new recordings, the Noir circuit replays the compact edit/input history,
checks the final canonical text hash and proves the origin, presence and nine
experimental writing-rule calculations. Every P-256 checkpoint and approved
presence signature is mandatory in the composite verifier outside the circuit.
Before proving or accepting a saved proof for a draft, the native adapter also
checks its complete original signed log against every compact input and public
proof field. It never re-signs old recordings or drops history to fit.

Older RISC Zero proofs retain their original verifier, which checks the native
UTF-16 replay, SHA-256 chains and checkpoint signatures inside the zkVM.

It emits a public summary, called a journal, bound into the proof. That includes
text commitments, chain/checkpoint digests, a capture-key fingerprint, counts and
supported device-reported time fields. The detailed edits and timing samples can
remain private.

The verifier accepts only the pinned program. A proof file cannot choose its own
program or verification key and thereby define what “verified” means.

### 21. Why do we talk about both ZK and a zkVM?

**Zero knowledge** describes a proof that can establish a specified relation
without revealing its private inputs. A **zkVM** is one way to build that proof:
run a program in a virtual machine and prove that it executed correctly.

They are not two separate proof features the writer needs to choose between.
The current Mac app uses Noir circuits. The earlier RISC Zero zkVM and Groth16
proving paths have been removed from the app. The portable verification SDK also
reads historical research formats.

### 22. What is Noir, and why might it be faster?

Noir expresses the checks as a specialized circuit rather than proving every
instruction of a general-purpose program. A well-designed circuit can eliminate
work that the general replay program pays for.

This is not an automatic speedup. JSON serialization, repeated text snapshots,
cryptographic signatures, buffer sizes and long edit histories all cost gates.
The circuit must retain the checks we intend to claim. Noir's own
[circuit guide](https://noir-lang.org/docs/guides/thinking_in_circuits) explains
why ordinary program structure does not automatically produce an efficient circuit.

The experiments use Noir `1.0.0-beta.25` with patched Barretenberg `5.2.1` and ZK
enabled. An isolated newer compiler comparison did not solve the memory problem.
These are pinned research tools, not a production security endorsement.

### 23. What is the latest fast-proof result?

The current Mac service automatically selects the smallest circuit that fits
the **complete signed session**, including every intermediate revision, key event,
checkpoint and presence response. All profiles use the same writing rules and
signature construction. Nothing is removed to fit a smaller circuit.

| Simulated writing session | Original checkpoint signatures | Proving | Complete Mac service |
| --- | --- | --- | --- |
| 40 characters | 4 | 2.35s | 3.08s |
| 120 characters | 9 | 4.58s | 5.93s |
| 30 characters over five minutes | 32 | 4.53s | 5.90s |
| 250 characters | 24 | 8.20s | 10.81s |

These fresh two-thread measurements use disposable software keys and simulated
input. The complete service includes input validation, worker startup, witness
generation, proving and verification. Save/reopen, altered-proof rejection and
local master/proof upload, download and independent re-verification also pass.
The full acceptance sequence includes those extra actions and takes longer.

The current profiles are `assurance64-v1` (372 operations, 64 intermediate Unicode
scalars, 132 key events, eight checkpoints), `assurance128-cp32-v1` (756 operations,
128 scalars, 260 key events, 32 checkpoints), and `assurance256-cp32-v1` (1,536
operations, 256 scalars, 516 key events, 32 checkpoints). Each allows eight presence
responses and four UTF-8 bytes per scalar. A small draft with more checkpoints
uses a larger circuit. The largest profile retains the ten-second checkpoint
cadence. [Current app acceptance](integrations/noir/results/adaptive-app-acceptance.json).

The five-second complete-service target is met by the short fixture. Larger
sessions and 10k-character support remain open. A separate capacity-profiling
attack measured 14–36% fewer gates by right-sizing each profile to its actual
session; those tighter profiles are research candidates, not the shipped baseline.
See [PROVER-PERFORMANCE.md](PROVER-PERFORMANCE.md). Earlier measurements follow as
research history, rather than the current app baseline.

The previous eight-slot V5 profile remains supported. On its saved 250-character
Swift test capture, **proving took 7.780
seconds** on two threads. Witness generation took 2.144 seconds; the complete
native service call, including validation and worker startup, took **10.869
seconds**. The worker's witness/prove/verification segment took 9.941 seconds.
These are distinct timing scopes, not interchangeable latency claims.

All seven original checkpoint signatures and both presence signatures are
retained. Save/reopen, altered-proof rejection, master/proof sharing, download
and native re-verification passed. The entire acceptance sequence took 14.342
seconds. Tests use a disposable software key and simulated input/times, not the
owner's fingerprint. The five-second target remains open.

The runtime and precompiled circuit/key are bundled: the app does not compile
the circuit or download a prover when you click Create Proof. A fresh capture
that exceeds the short profile keeps its writing and full signed history; it
cannot silently truncate history or start a long fallback proof.

[Optimized app acceptance](integrations/noir/results/optimized-app-acceptance.json)
records this result, the rejected candidates and the remaining bottleneck.
The earlier V4 app pipeline measured 11.267 seconds for witness/prove/verification;
[its report](integrations/noir/results/native-app-acceptance.json) remains historical
evidence. Earlier compact-profile measurements follow for comparison.

The eight-slot V5 circuit reduces 1,041,574 to 926,956 gates by expressing equivalent
replay checks more efficiently. SHA-256, edit replay, source/presence bindings and
all nine writing rules remain in the relation; every original signature remains
mandatory. Twelve replay-semantic cases, 22 full-policy witness cases and three
deliberately weakened controls check the rewrite. Controls receive no keys or
proofs. The original V4 statement is unchanged; V5 has its own pinned program key
and proof identity. V4 and RISC Zero files retain their verifiers.

Moving public-text hashing out of the circuit saved only about 6% of gates and
was not adopted. Splitting opcode arguments increased gates and was rejected.
Native kernel profiling identifies elliptic-curve commitments as the largest
remaining proving cost. Gate reduction alone has not met the latency target.

The selected small circuits use 260,386 and 522,977 gates. The initial
307,342/527,504-gate candidates and a numeric-bound rewrite did not reach the
desired prover size buckets. The selected circuits retain the established replay
arithmetic and change only fixed capacities. Forty-two policy/tamper witnesses,
ten Unicode/deletion boundary witnesses and seven independent WASM proof checks
cover the small circuits. [Research evidence](integrations/noir/results/short-bucket-sizing.json).

A compact-format prototype uses one reusable circuit for different sessions.
On the development M4 Max, with eight proving threads and prepared assets:

| Synthetic session | Signed checkpoints checked | Warm witness + proof + verification |
| --- | ---: | ---: |
| 50 individually recorded ASCII characters | 2 | 4.783 seconds |
| 250 individually recorded ASCII characters | 5 | 4.566 seconds |
| Unicode, revisions and paste fixture | 3 | 4.485 seconds |

The **same compiled artifact and verification key** were used for all three.
Each row generated a real proof and checked every actual signature. These are
three different workloads, not repeated measurements establishing a latency guarantee.

The profile supports at most 1,536 operations, 256 intermediate Unicode scalars,
1,024 final raw UTF-8 bytes and eight checkpoint slots. Exceeding a capacity
rejects the session; it never discards history to fit.

A subsequent live-capture adapter test recorded 250 individual edits, signed
five checkpoints as capture progressed, saved/reopened the draft, and generated
a proof using the same fixed profile. Warm witness + proof + native verification
took **4.344 seconds** on eight threads; an independent WASM reader accepted it.
It used a disposable software key, so it measures the pipeline rather than real
Touch ID or manufacturer attestation. Presence/origin additions are outside this
V3 compact profile. V4 includes them; the optimized V5 proof preserves the same
signed capture relation and is now selected for new Mac proofs.

Initial profile compilation and witness generation took about 35 seconds. A
product would distribute the precompiled artifact and key. Initial setup/downloads
are separate from the warm figures above.

These older V3 figures are not the current app's full-policy latency. The native
V5 measurement above covers the app's current service, including origin/presence.

Chrome checked the three valid compact exports in roughly 0.1–0.3 seconds each,
including local asset loading and all signatures. That is **verification**, not
proof generation. Both ordinary and shared-memory browser modes were exercised.

**New full writing-policy proof.** The `assurance256-v1` experiment proves replay,
authenticated origin metadata, presence accounting and all nine experimental
writing rules. A generated 250-character session had 500 key events, four
checkpoint signatures and two approved presence signatures. On two worker
threads, that fixture's proving took **8.690 seconds**; warm witness, proving and
independent native verification took **10.522 seconds**. Cold compilation/witness took
36.713 seconds and about 3.18 GB sampled RSS. Precompiled assets avoid that
compiler cost during ordinary use. These are single-run measurements, not a
five-second guarantee or live Touch ID acceptance.

A fresh capture from the Swift recorder now also completes the full proof path.
Its 250 characters, 750 capture records, seven checkpoint signatures and two
presence signatures survive save/reopen, independent full-session validation,
proving, browser verification and a local master/proof publication round trip.
The original signatures and challenge nonces are retained. Proving took
**8.093 seconds** on two threads; witness generation, proving and native
verification took **10.545 seconds**. Capture/signing took 360 ms. This uses a
disposable software key and simulated events/times, so it does not exercise
Touch ID. [The measured report](experiments/noir-compact/results/live-assurance-acceptance.json)
separates that harness test from the newer native app acceptance above.

The fixed circuit has 1,041,574 gates and the same 256-scalar/1,536-operation
limits. Twenty-two witness cases and two deliberately weakened controls check
timing, origin and presence bindings. Real passing and policy-failing proofs
verify under the same pinned key. A valid proof with a failed policy stays a
failed policy; requiring `huma-writing-rules-v1` rejects it. Every checkpoint
and approved presence signature is mandatory outside the SNARK. These are
software-key fixtures, including synthetic typing that satisfies the illustrative
rules. Detector accuracy has not been measured.

**New image, audio and video ZK foundation.** One fixed Noir circuit now produces
real proofs for generated PNG16, FLAC24/48 kHz and AV1/10-bit fixtures. Two-thread
proving took **7.060, 7.044 and 7.103 seconds**, respectively. It binds an exact
encoded-master commitment and signed seal to a decoded-data Merkle root, then
proves two challenge-derived private openings belong to that root. It uses
sampling with replacement and reports the unique selected leaf count. The
profile supports 256 leaves of at most 3,072 bytes; the reader's exact-master
input is limited to 32 MiB.

This media relation does **not yet prove decoding, physical scene response,
sensor origin, display-edit semantics or externally fresh sampling**. Its
encoded-to-decoded association is signed, not ZK-decoded. Fixtures use generic
decoded-byte chunks and local test challenges; they do not implement the final
tile/audio-block sampling geometry. The browser/Node SDK exposes these missing
layers explicitly. This is the first measured layer of the media design in
[MEDIA-PROVENANCE.md](MEDIA-PROVENANCE.md), with further policies still to build.

Independent entry points are `web/verify-core/node.mjs` and
`web/verify-core/browser.mjs`. Call `verify(source, readerPolicy, expectedContent)`
with displayed text for writing proofs or a `Uint8Array` of exact encoded master
bytes for media. `envelope(...)` exports the same checked statement contract.
Keys/programs are pinned by the reader. V4 and V5 writing exports also import into the
website and round-trip through local registry links. Hosted original links now
download an exact media master and proof into the same verifier. Native media
capture/proving and a general media file-picker remain to build.

### 24. Does the compact prototype check the same kinds of evidence?

It checks a newly versioned compact operation transcript, exact replay, final UTF-8
text and its canonical SHA-256 hash. Poseidon2 commits to private operations without
hashing a whole text snapshot after every edit.

Its signatures are checked **outside the ZK circuit** by a mandatory composite
verifier. Both the SNARK and every P-256 signature must pass. Accepting the SNARK
alone would be incomplete verification.

This fast profile discloses the public key and signatures. The app's existing
RISC Zero proof can instead verify signatures internally and expose a key
fingerprint. The privacy tradeoff is explicit. No old recordings have been
silently re-signed into the new format. Its adapter handles newly recorded
experimental sessions; controlled acceptance uses disposable software keys.
The V3 adapter refuses origin/presence fields it cannot authenticate. V4 has a
separate public format and pinned relation that binds those fields. The native
bridge now signs that complete new live transcript, including presence responses.
A fresh Swift software-key capture now proves and verifies without replacement
signatures through the bundled Mac proof service and sharing adapters.
Older signed recordings are never silently converted.

### 25. Can Noir handle 10,000 characters?

It can express a 10k-character statement. **Complete 10k-session support and a
five-second full proof are not demonstrated in Huma.**

A real proof of a private 10,000-byte ASCII input's SHA-256 hash took 3.050 seconds
on eight threads, or 6.681 seconds on two. That only proves the hash calculation.
It does not prove the edits, timing, signatures, text policy or physical origin.

The compact full-replay attempt at 1,024 individually recorded characters hit the
compiler's 6 GiB memory budget and stopped without attempting a proof. That is a
limit of this implementation and research budget, not a Noir language limit.

Text length alone is not enough to estimate cost: a 10k draft might have a much
longer revision history. Also, 10k Unicode characters can take more than 10k UTF-8
bytes, and visible characters can contain multiple Unicode scalars.

### 26. Why did the Mac get hot, and what has been improved?

The current Noir prover performs substantial cryptographic computation. Lower
thread counts reduce concurrent load but can lengthen the job.
The app currently limits proving to two lower-priority worker threads, admits one
local proof job at a time, supports elapsed time/cancellation, and stops on critical
thermal pressure. Cancellation terminates the owned worker/prover process group.

The Noir work targets a shorter complete proof, not just a progress indicator.
We have not measured a reliable temperature or energy improvement. We also do not
count hidden background computation as evidence that the entire proof costs under
five seconds.

### 27. Does a ZK proof hide everything?

It hides the private inputs of the specified relation, not whatever the public
outputs deliberately reveal. Public text, counts, commitments, key fingerprints
and reported session times can still be identifying or linkable.

The detailed draft history is private by default. Revealing it is a separate,
explicit export. A public key can link sessions that use that key. The compact
prototype adds a private random salt to its transcript commitment; that does
not hide the final text once the author publishes it.

### 28. What happens if somebody changes the text or supplies a fake proof?

A reader checks the proof and compares their text under its pinned character
policy. Changing meaningful characters produces a different commitment. Changed
proof bytes, a wrong program/key or mismatched evidence must fail verification.

The app's green verified state depends on successful verification, not the mere
presence of a proof file. Saved proofs are checked again, and raw edits invalidate
stale evidence.

The compact fixed profile rejects 23 private-input mutation cases and ten combined
native-reader tampering cases. Its new public reader has 29 automated checks,
including real proof-byte mutations, every signature, high/low-S DER signatures,
Unicode, large integers and cancellation. Chrome also passed 12 acceptance checks
in each of its two WASM modes. Separate tests recompute commitments around invalid replay
claims and reject overflow, mid-edit samples, surrogate splits, invalid Unicode
and a forged final hash. Tests support these particular checks; they are not an
independent audit of the whole system.

## Identity, time and independent verification

### 29. Does the public key prove who the writer is or which machine was used?

It proves which key signed the checked evidence. A fingerprint is a compact way
to recognize that key again. It is not a Mac serial number, a legal identity or
proof that the same person physically typed every session.

If a reader already trusts a fingerprint, they can require a match. Revealing
the corresponding public key lets them check its binding to the proof. A key
supplied only by an unknown producer does not establish that producer's real-world identity.

To link the key to an account or approved app/device, we need separately verified
account or manufacturer evidence bound to the same session. Even then, account
control and hardware presence are different claims from authorship of ideas.

### 30. What does hardware or app attestation add?

A manufacturer-backed attestation can authenticate supported facts about an app
and device. Merely saying “this is a Secure Enclave key” in a JSON file cannot do
that. An independent reader needs to verify the manufacturer's evidence and its
binding to this capture key and proof.

Huma has Apple enrollment/assertion clients, a verification service, portable
exports and independent CLI/browser checks. **No provisioned Huma Mac has yet
completed the required live enrollment and portable acceptance.** The ordinary
ad-hoc build must not be presented as an attested release.

Apple's Mac support requires macOS 27 or later, service availability and correct
provisioning. App identity/version/distribution and the supported Mac security
properties must be validated. See [Apple's App Attest explanation](https://developer.apple.com/videos/play/wwdc2026/201/).

The capture key is associated through an attested app assertion; Apple does not
supply this project with a direct manufacturer certificate for the capture key.
Attestation also does not certify that all keyboard input was physical human input.

### 31. Can anyone verify without our servers?

Yes, for the current base replay proof. A trusted verifier and its pinned program
can check a downloaded proof locally. Readers do not need a Huma account or the
private typing history. The existing browser reader runs verification through WASM.

A registry can host the files, but its response is not the reason a proof is valid.
A different host, an independent implementation or a local file can serve the same
purpose. Initial verifier assets must be obtained and trusted; prepared file checks
have been exercised with external networking denied.

The experimental compact format also has an independent browser and offline CLI
reader. Its verification key, public-field schema, WASM and small public CRS point
are pinned by the reader. A downloaded export cannot substitute them. The browser
uses a cancellable worker with a 20-second deadline and a 128 MiB WASM ceiling;
verification needs no proving-key download or external verification service.

The reader derives the displayed session facts directly from the proof's public
inputs and checks every checkpoint signature. Large time integers remain exact
decimal strings. Device attachments are not supported for compact proofs
yet; selecting those checks fails the result instead of silently skipping them.

Optional device evidence adds its own reader-selected trust policy. A file cannot
choose its own trusted app or manufacturer root. Retired account attachments and
policy options are rejected rather than silently ignored.

### 32. Can we prove “this was written from this time to this time” locally?

The current signatures cover **device-reported** start, end and elapsed readings.
They prevent those readings being changed afterward without invalidating evidence.
They do not establish that the original clock was honest.

A plausible fake timeline can still be signed. A monotonic clock helps normal
operation but is not an independently trusted clock to a remote reader. Backwards
UTC changes can be flagged; a consistent lie is harder to detect.

Fully local evidence therefore does not establish a fresh calendar interval or
prove that the displayed duration physically elapsed. The unsigned document
creation date must not be treated as a signing timestamp.

### 33. Would a Huma timestamp server make only Huma able to verify?

A signed Huma timestamp could be checked by anyone with its public key. The time
claim would still depend on trusting Huma's clock. We do not want that to become
a mandatory authority for the base proof.

Independent timestamp authorities, completed public-chain anchors or a reader's
own signed challenge are possible optional evidence. They introduce their own
trust assumptions and do not need to be operated by Huma.

An anchor on the final commitment can show that data existed by an anchored time.
It does not establish when typing started or continuous human attention. A bounded
interval would need appropriately bound start and finish evidence. These stronger
time attachments are not implemented today. See [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)
and [OpenTimestamps](https://opentimestamps.org/) for possible building blocks.

### 34. Can an old valid proof be replayed?

Yes. A valid old proof remains valid evidence about its original statement.
A session ID prevents mixing records from different sessions; it does not make
a copied proof fresh for a new request.

For a fresh interaction, a relying party could issue a new nonce and audience,
require the response to bind them to the current session, and track consumption.
An offline file alone cannot establish global non-reuse or that its counter was
not accepted elsewhere. The complete presence/freshness policy is future work.

## Saving and verifying proofs

### 35. Do I need an account or API key?

No. Write, record and create a proof locally. Save the `.huma` document to keep
formatting and private session history. Save a proof package to give someone
independently checkable evidence. No social account or provider key is needed.
Hosted sharing uses Coinbase uploader approval and server-side R2 configuration;
readers need neither an account nor API keys.

### 36. Where are proofs stored?

Your `.huma` document stores its proof alongside the writing and private history.
**Proof → Save Proof…** exports a public `Huma-evidence.json` package containing
text, proof and the statement derived from the verified proof. Advanced exports
can separately disclose a signing key or full session history. That disclosure
remains your choice. Reopening a document checks its saved proof again.

### 37. Can I share a verification link instead of a file?

Yes. **Share master & proof…** prepares the exact master text and public proof on
the sharing host configured in Settings. Browser approval authorizes storage.
The Mac checks the downloaded files and proof before saving the link. Private
edit history stays local. Changes to the text or session invalidate the saved link.
Question 47 explains the R2 and Coinbase flow and its current acceptance limits.

The included registry runs at `http://127.0.0.1:4318`. Its links work locally.
A public HTTPS host with R2 configuration is needed for the hosted delivery goal.
The older proof-only registry keeps saved links readable; new uploads use the
master-and-proof approval flow. Neither storage route is a chain or independent time authority. Local
proof files work without either host.

### 38. How does another person verify a saved package?

Open `/verify` in the included website, drop the package and compare the text
being checked. Verification runs locally in a bounded browser worker. The reader
checks the pinned proof program, content commitment and applicable signatures;
it rejects changed text, proof bytes, keys and invented policy claims. Readers
can supply a signing-key fingerprint they already trust.

Independent Node/browser SDKs use the same checks. Prepared verifier assets work
offline; the verifier does not ask the proof host whether a file is valid.
A signing key establishes continuity of that key, not a social or legal identity.

## Human assurance and the remaining work

### 39. How does Huma raise the cost of falsely attributed content?

By combining evidence that an attacker has to satisfy together: approved-app and
device evidence, signed capture, input provenance, unpredictable presence checks,
and a privately evaluated writing policy. All layers bind to the same session.

For text, that includes keyboard and edit history. Images, audio and video need
the equivalent evidence for their own capture paths and editing operations.
The overall goal is shared; the signals and policies are specific to each medium.

Each layer handles a different attack. Signatures protect the recorded history;
app evidence establishes its collector; source metadata exposes what the OS
reported; fresh biometric checks require interaction at particular moments;
behavioral rules test the recorded process. Layering them is the product strategy.

The attack benchmark needs physical HID injectors, adaptive timing generators,
replayed real traces and a person tapping while automation types. We will measure
accepted fakes, operator attention and honest-user friction. The local challenge
schedule is reported as local, without claiming an independent source of randomness.
[HUMAN-PRESENCE.md](HUMAN-PRESENCE.md) describes the design and build order.
[MEDIA-PROVENANCE.md](MEDIA-PROVENANCE.md) does the same for images, audio and
video: multi-sensor capture, physical challenges and policies that can later be
proved privately. Under the new plan, authenticated collector reports come first;
ZK upgrades the assurance about computation. Co-presence witnesses and an opt-in
track record are the longer-term network layer.

### 40. Can ZK prove human-like behavior privately?

It can prove that a private trace satisfies precisely defined behavioral rules.
To be meaningful, the feature extraction and policy checks must be linked to the
**same authenticated trace** that produces the final text.

The Noir circuit computes the experimental `huma-writing-rules-v1`
checks directly from the authenticated capture, including key pairing, dwell and
interval bounds, pauses, rate, duration and input labels. Its public result names
the policy and reports which rules passed. Raw timings remain private.

This is a concrete foundation for private behavioral verification. It is an
experimental ruleset, with attack evaluation and calibration ahead. A learned
classifier would require its own pinned model and validated inference path.
The existing compact Noir profile retains its earlier replay relation.

[ZK-PoP](https://arxiv.org/html/2603.00179v3) and
[zkSENSE](https://petsymposium.org/popets/2021/popets-2021-0058.php) are useful
architectural references, not Huma benchmarks. Reported accuracy or timing for
another workload cannot be transferred to Mac typing. ZK-PoP's reported M3 result
is 23.4 seconds; zkSENSE concerns mobile-motion evaluation. Their claims do not
establish Huma's five-second target or bot resistance.

### 41. Would a score out of 100 be better than yes/no?

It could summarize writing-process assurance after calibration. Cryptographic
validity remains a mandatory yes/no check: an invalid proof cannot be rescued by
a high behavioral score.

A useful score needs a named policy, evidence breakdown, supported platforms,
consented human baselines, held-out attacks, false-positive rates and uncertainty.
It must account for languages, IME, accessibility, keyboards and fluent writers
who make few corrections. Correlated signals cannot be counted as independent
proof of security.

We do not have a calibrated score today. “93/100” would not currently mean a
93% probability that a human wrote the text. Until calibration, show the verified
facts and missing evidence instead of inventing a number.

### 42. Can imperfect detection still make a valuable product?

Yes. A useful security product raises the cost of abuse and gives people better
evidence for decisions. It earns its value through measured protection, usable
workflows and a clear account of what a successful result establishes.

Huma already adds signed process evidence and independent cryptographic checking
to the Mac writing workflow. Its wider vision brings that value to images, audio
and video, using appropriate capture evidence for each. Stronger provenance and
behavioral layers can make automation more expensive while preserving privacy. They do not need to solve
thought attribution to be useful.

We should judge detection by held-out attacks, false positives, accepted fakes
per hour and operator cost. We should judge the proof by whether it correctly
verifies its precise statement. A synthetic trace that meets a behavioral policy
is a useful attack finding for improving that policy, rather than a break of ZK.

Cryptographic systems also have explicit assumptions, and quantum resistance
depends on the particular construction. Stating assumptions is good engineering;
it is not an argument that the product has no value. We will publish Huma's own
measurements rather than borrowing another detector's accuracy percentage.

### 43. Why open-source the clients? Does that prove the correct app ran?

Open source lets people inspect the capture code, proof program and verifier.
It should include licenses, dependency locks, build instructions and auditable
release artifacts. The public release process is not complete yet.

Public source alone does not establish which executable ran. We need a checked
chain from reviewed source to recorded build, signed distribution, supported
manufacturer app evidence and the particular session. A producer's self-reported
source hash is not manufacturer attestation.

The Mac is first. Future iOS/Android clients should use the same evidence contract,
but they do not exist in this checkout. Android app-integrity verdicts and hardware
key attestation are separate mechanisms; standard Play Integrity tokens require
Google's authenticated decoding flow, not merely trusting copied JSON. See
[Google's standard request flow](https://developer.android.com/google/play/integrity/standard).

### 44. Can attestations and scores be verified on-chain?

That is a future consumption path, not an implemented feature. A contract could
verify the required evidence directly or verify a proof of those checks under
approved roots, program IDs and policy versions.

Putting an attestation hash or release manifest hash on-chain is not the same as
checking it. Certificate policy, revocation, challenge freshness, session binding,
update authority and historical rules all need explicit treatment.

No attestation/proof contract, batch-root anchor or calibrated on-chain score is
deployed. The current local proof registry is a file host, not that on-chain system.
The original broader “salted vault” architecture is also not a shipped storage feature.

### 45. What remains before the current release is ready?

The current scope is the Mac editor, signed capture, proof creation, saved proof
packages, R2 delivery of the master and proof, and independent verification. The app now has
Writing and Proof pages. Coinbase uploader sign-in is being added for hosted sharing;
social posting and chain integration remain absent. Existing writing documents remain readable; retired posting
metadata is ignored when reopening and omitted on the next save.

The Mac now uses Noir V5 for new short recording proofs, with older V4 and RISC
Zero proofs still supported. Full-policy proofs verify in the native app service, shared
SDK, browser and sharing service. Original capture/presence signatures survive
proving, save/reopen and downloaded-master verification. Larger/10k histories
and a five-second full proof are
not yet demonstrated. Real fingerprint acceptance and provisioned Apple evidence
need device testing. R2 sharing needs bucket credentials, an HTTPS host and live
Coinbase approval acceptance; direct proof files work without them.

Images, audio, video, mobile clients, C2PA, witnesses, creator history, scores and
chain verification remain later work. The existing media ZK experiments are kept
as measured research and do not expand this release's scope.

### 46. What needs the owner's action?

Signed/notarized distribution and genuine manufacturer attestation need your
Apple Developer identity, app prefix, matching profile and approved device tests.
R2 delivery needs a private bucket, bucket-scoped S3 credentials and an HTTPS host.
Coinbase sign-in needs the chosen host allowed in the CDP project's origin settings.
Local proof-file creation, saving and
verification need no provider account or blockchain setup.

### 47. How will the master copy and proof be shared through R2?

Choose **Share master & proof…** after verifying a proof in the Mac app. Huma
prepares the exact UTF-8 text and public evidence package on the configured host,
checks that they match, then opens a browser approval page. Coinbase sign-in
identifies the uploader. Nothing is written to R2 until the user chooses
**Approve sharing**. Sign-in does not create a capture signature or prove authorship.

The host stores the master and public proof under their SHA-256 hashes in a
private R2 bucket, reads them back, and creates a manifest binding both hashes and
the verified evidence statement. The Mac downloads them again and checks the
proof before saving the link. A reader opens the link, downloads both files,
checks their exact hashes and runs the pinned verifier locally. A changed master,
proof or manifest fails. Files remain portable to another host.

The default is **link-only**: a random capability in the link grants download
access. The bucket is private; knowing an object hash alone does not grant access.
Anyone who receives the complete link can forward it. Public access is supported
by the transport; approved-viewer lists are not implemented yet. A failed upload
does not create a successful link. Prepared requests expire after ten minutes.

For text, the stored master preserves every UTF-8 byte, including final spaces.
The proof comparison still applies the defined trailing-ASCII-space/tab policy.
Editor formatting and private `.huma` documents, raw inputs and intermediate
drafts are not uploaded. The current Mac uploader handles text. The transport and
reader also accept existing experimental media proofs with their exact masters;
this does not add camera/microphone capture to the app.

**Current acceptance:** local staging/approval/transport and real proof verification
pass, including signed S3 requests to a local test server. R2 credentials are not
configured, and no real Coinbase sign-in or public R2 upload has been accepted.
No Base transaction is submitted by this sharing flow. Base anchoring remains the
separate milestone in [VISION §5](VISION.md#5-portable-proofs-stored-anywhere-public-record-on-base).

## Current issues and how you can help

Updated October 23, 2026, against the current code and saved acceptance results.
The working foundation is signed capture, saved proof packages, independent
browser/CLI verification and optional registry storage. The latest checks passed
47 Swift tests, 33 compact-native Rust tests, 50 Node tests and 46 browser checks.
Four fresh proofs passed the actual Mac service's save/reopen, tamper rejection
and local master/proof delivery tests. Automated tests use disposable software
keys; real fingerprint and live provider acceptance remain separate.

The issues below are concrete remaining work. Most are engineering tasks I can
continue; they do not all need something from you.

| Issue | Current state | Who can move it forward |
| --- | --- | --- |
| Five-second target for larger sessions | Short fixture: 3.08s complete service. The 120/250-character fixtures take 5.93s/10.81s | I can optimize and benchmark the complete relation and prover backend |
| 10k-character sessions are unsupported | Current app limit is 1,024 UTF-8 bytes; fast circuit has smaller history limits | I can build and measure a scalable session design |
| Real fingerprint flow needs acceptance | Software-key tests pass; the current start/finish fingerprint flow has not been accepted on your device | You can test a short recording when ready |
| Genuine app/device attestation is unvalidated | Portable verification exists; this preview has no demonstrated manufacturer enrollment | Your Apple provisioning setup and a real device test are needed |
| Typing policy needs adversarial evaluation | Nine rules are proved correctly; synthetic traces can also satisfy them | Your detection plan, research or consented test participants can help |
| R2 delivery needs live configuration and acceptance | Adapter, approval handoff and local read-back tests pass; live R2/Coinbase delivery is untested | You can configure the R2 bucket and choose the HTTPS host/CDP allowed origin |

### 1. The Mac now uses Noir; real hardware acceptance is still pending

The full V4 circuit proves edit replay, origin metadata, presence accounting and
the nine experimental writing rules. Its passing and policy-failing fixtures
verify independently. The native Rust/Swift bridge now records V4 source metadata
and presence records, signs approved responses while their fresh approval context
is active, and keeps cancellations and late responses. New-session/save/reopen
tests pass. The complete Swift-generated capture now produces a real proof
against the pinned V4 circuit. A native validator independently replays the full
original signed log and compares every projected operation, origin, presence
event and checkpoint before proving. No history is dropped or re-signed.

`ReplayProofService` now selects the bundled V5 Noir worker for new proofs.
The actual app service passed fresh proving, save/reopen, changed-proof rejection,
local master/proof publication and downloaded-proof verification. The Mac's
older replay-engine fallback has been removed. No fingerprint, owner key or real provider account
was used in this acceptance test. Your device's recording flow and a provisioned
Apple evidence adapter still need acceptance; Noir exports currently reject
unsupported manufacturer attachments rather than borrowing legacy evidence.

Evidence: [CaptureSigner.swift](Sources/Huma/CaptureSigner.swift),
[ExperimentalCompactRecorder.swift](Sources/HumaCore/ExperimentalCompactRecorder.swift),
[ReplayProofService.swift](Sources/Huma/ReplayProofService.swift).

### 2. Faster proofs and the remaining latency work

Automatic complete-history sizing brings the 40-character fixture to **2.35
seconds proving / 3.08 seconds complete service**. The 120-character fixture
measures **4.58 / 5.93 seconds**, and the largest 250-character fixture measures
**8.20 / 10.81 seconds**. Both the event history and every signature stay intact.
The 32-checkpoint boundary case also uses the faster 128-scalar profile.

Larger profiles still need work to meet the complete-service target. Circuit
compilation and verification-key setup happen during preparation; the app ships
those assets. Runtime witness generation and proving remain measured costs.
These software-fixture results are not a guarantee across Macs or workloads.

Evidence: [current Mac service measurements](integrations/noir/results/adaptive-app-acceptance.json).

### 3. A 10k draft needs more than a larger text buffer

The largest current profile permits at most 256 intermediate Unicode scalars
and 1,024 UTF-8 bytes. That full-policy profile has 1,536 operation slots,
516 key-event slots, 32 checkpoints and eight presence challenge/response pairs. A 10k-character
writing session, especially with revisions, exceeds these limits.

An earlier 10,000-byte hash-only proof succeeded, but that does not prove the
writing history. A larger full replay compilation also exceeded its 6 GiB budget.
The remaining work is a measured design for the whole history, potentially
chunking and proof composition, including boundary state, signatures and presence
coverage. No design is selected or benchmarked for complete 10k sessions yet.

A separate continuation prototype now carries the complete text buffer, cursor,
edit phase, elapsed time, counters and capture commitment between chunks. Its
synthetic 10,000-character typing trace has 50,003 operations across 417 chunks.
Every native boundary matches the reference counters and capture prefix, and
the final text matches the existing replay. Actual proofs of the first, middle
and last chunks pass native and independent WASM verification, taking **1.95–1.99
seconds proving per chunk** on two threads. These are per-chunk times, not a
complete 10k-session time.

All three chunks of a smaller Unicode revision trace are also proved and linked.
The tests reject changed state, forged starting state, ambiguous packed scalars,
altered proofs and altered public capture roots. Unicode and long starting-draft
cases pass witness checks too. This first component remains outside the app.
[Continuation measurements](integrations/noir/results/continuation-component-acceptance.json).

The next component carries the existing behavioral policy and input-origin chain
alongside replay. Held keys, the rate window, pauses and counters survive chunk
boundaries. On the same 10k trace, sampled combined proofs take **2.48–2.57 seconds
each**; native and independent WASM checks reject changed policy claims, origin
roots and proofs. Thirteen synthetic scenarios match the shared policy, including
rollover, repeats, unpaired keys, short holds, excessive rates and pasted edits.
All **17 chunks** of a passing rollover trace now have actual proofs, native
verification and independent WASM verification. The serial witness/prove/verify
path totals **11.08 seconds**, so generating many proofs at the end is still too
slow. A portable 348 KB bundle verifies in **180 ms in a fresh Chrome profile**,
including verifier setup. The reader rejects missing or reordered chunks,
state resets, changed proofs and substituted keys; sampled 10k chunks are rejected
as an incomplete chain. This supports testing incremental proving with a bundle
instead of adding an expensive recursive wrapper.

These are implementation tests, not a measured human-versus-bot accuracy rate.
Presence and original checkpoint signatures, the exact final-text commitment,
all-chunk 10k proving and native integration remain before this can replace the
app's current prover. The component reader explicitly reports that those broader
claims are unverified, and the current Huma SDK rejects this unfinished format.
[Combined-component measurements](integrations/noir/results/interaction-component-acceptance.json).

**Larger chunks and the final-text step (October 23).** A gate sweep at 10k
capacity shows each chunk costs about 217k fixed gates plus 574 per operation,
and proving time follows the real gate count. Raising chunks from 120 to 528
operations (520,299 gates) cuts the 10k trace from 417 to 95 chunks. Selected
chunks prove in **4.3–4.4 seconds** each, so whole-session proving drops from
about 17.6 to about 7 minutes. All 44 constraint checks behave as expected, and
tampered statements and proofs fail. A finalization proof now binds the terminal state to
raw and canonical text commitments: 10k characters prove in **7.6 seconds**,
and 30 altered statements plus empty/whitespace-only text are rejected. The
reader recomputes both commitments from the master bytes; only trailing ASCII
space/tab may differ. Still outside the app; signatures and incremental native
proving remain.
[Chunking and finalization measurements](integrations/noir/results/chunking-finalization-acceptance.json).

A recursive-verification experiment now verifies an existing proof inside a new
proof, with its verifier key fixed by the circuit. The valid case passes native
and WASM verification; altered inner proofs and statements fail the final check.
Wrapping one proof took **6.15 seconds**, and the two-proof wrapper has **1,475,818
gates**. This adds too much work for the current speed target, so it remains an
isolated component. It does not establish chunk continuity or complete 10k-session
support. [Measured results](integrations/noir/results/recursive-component-acceptance.json).

The test also confirms why witness generation alone cannot validate recursive
proofs: both altered cases produced witnesses and outer proof files, then failed
cryptographic verification. The current app verifies its generated proof before
exporting it. [Noir's recursion reference](https://noir-lang.org/docs/libraries/standard_library/recursion).
If you can describe a typical long session's length and amount of revision,
that will help choose realistic benchmarks. You do not need to share its content.

### 4. You can help test the real fingerprint flow

The capture key is designed for Secure Enclave signing with fingerprint approval.
The current recording path compiles and storage tests pass. Automated acceptance
uses disposable software keys; it does not establish that start/finish approval
feels right or works reliably with your actual Touch ID setup.

When convenient, open the proof-only preview, start a fresh recording, type a
short disposable sentence, then finish the session. Report whether start and
finish use Touch ID, whether a password appears, and the exact error if anything
fails. **You do not need to press Create Proof for this capture test.** A brief
description is enough; no private draft or raw timing history is needed.

### 5. Device signatures and manufacturer attestation are separate

Checkpoint signatures establish use of a signing key. Independently establishing
the approved app/device requires the supported manufacturer enrollment and
session binding. The verifier and optional Apple service components exist, but
real Huma Mac enrollment has not passed acceptance. The local preview is ad-hoc
signed. This Mac runs macOS 27.0.1; that alone does not establish App Attest support
for this particular app build and provisioning.

Your help: the Apple Developer team/app identity and matching provisioning setup,
followed by an owner-run enrollment test. Private signing keys or account passwords
do not belong in chat. Direct proof-file verification remains useful without
manufacturer attestation; its report must state which evidence was actually checked.

Evidence: [AppAttestClient.swift](Sources/Huma/AppAttestClient.swift),
[build script](scripts/build.sh).

### 6. Proving typing rules is implemented; validating the detector remains

The proof can establish that the committed private trace satisfied our rules.
The hard part is choosing rules that keep adaptive automation expensive while
accepting legitimate typing styles. The existing tests intentionally include
regular synthetic typing that passes. We have not measured a deployment accuracy,
false-positive rate or a calibrated 0–100 score.

Your help: the detection plan you mentioned, relevant research, and a consented
evaluation plan covering human typing, accessibility/IME use, macros, virtual HID
and varied hardware injectors. I can implement and prove a specified policy;
stronger empirical claims need measured attack and human data. Raw keystrokes
should not be uploaded just to make that evaluation easier.

### 7. R2 and Coinbase need real configuration and acceptance

The master/proof publication code now supports a private R2 bucket, explicit
Coinbase approval, immutable object writes and read-back verification. Local
tests use cached public proofs, dummy approval and a local S3 server. They do not
establish that the real bucket credentials or your CDP allowed origins work.
The included `127.0.0.1` registry is reachable on this Mac only. A registry
receipt is not independently trusted calendar time, and a host's verdict does
not replace local proof verification.

Your help: choose the host/domain and R2 bucket, and configure the R2 variables in
`.env.local` using the names in [the example](.env.example). CDP configuration is
already present locally; it has not been authenticated against a real user session.
Private API keys stay on the server. The current default is link-only, pending
your preference. Durable daily upload quotas now cover both each uploader and
the whole bucket. Seven moderate dependency findings remain for upstream fixes or
compatibility review; the earlier high-severity build findings have been removed.
No paid service, real wallet, transaction or public upload was
created during these checks.

### What is deliberately outside the current release

Social posting has been removed. Coinbase uploader sign-in is now part of the
R2 sharing goal; Base chain publication is a separate milestone. Creator history,
witness networking, mobile clients and full media capture are deferred under the
current limited scope. The media experiments prove signed master binding and
sample membership; decoding, physical scene response, edit semantics and external
freshness remain future relations. Those are not being treated as blockers for
the Mac master-and-proof workflow.

## Build, verify and inspect the implementation

<details>
<summary>Open the optional build and protocol reference</summary>

The sections below preserve the setup and protocol details in this same document.
They describe development tools, not steps an ordinary writer should need.

### A. Where is the code?

| Location | Responsibility |
| --- | --- |
| [Sources/Huma](Sources/Huma) | Native editor, signed capture, proof creation, saving and verification UI |
| [Sources/HumaCore](Sources/HumaCore) | Documents, sessions, text policy, signing/key storage and service clients |
| [zkvm](zkvm) | RISC Zero replay program, local worker and shared native/WASM verification |
| [web](web) | Website, browser reader, local registry and research deck |
| [web/verify-core](web/verify-core) | Shared statement contract, DOM-free verification API and bounded browser/Node workers |
| [integrations/attestation](integrations/attestation) | Apple checks, portable evidence and optional service |
| [experiments/noir-compact](experiments/noir-compact) | Compact-format and reusable-profile research |
| [experiments/noir-replay](experiments/noir-replay) | Small complete V2 circuit and scaling fixtures |
| [experiments/noir-prover](experiments/noir-prover) | Narrow signature/hash microbenchmarks |
| [PROVER-PERFORMANCE.md](PROVER-PERFORMANCE.md) | Prover profiling, right-sized profile measurements and thread scaling |

Source and machine-readable results are retained. Superseded standalone project
documents have been consolidated here. Third-party license notices are retained.

### B. Build the existing Mac app and reader

The current Mac app requires macOS 14+, Xcode command-line tools, Node 20+, Rust,
and the pinned Noir/Barretenberg tools prepared below. It does not require a RISC
Zero guest toolchain. The separate historical reader experiments use their own
Rust/WASM preparation scripts.

After preparing those tools:

```sh
npm ci --prefix integrations/attestation --ignore-scripts
npm ci --prefix experiments/noir-replay/runtime --ignore-scripts
python3 integrations/noir/prepare.py
python3 experiments/noir-prover/prepare.py
swift build --jobs 2
BIN_DIR="$(swift build --show-bin-path)"
swiftc -parse-as-library -I "$BIN_DIR" experiments/noir-replay/WorkerBench.swift \
  "$BIN_DIR/HumaCore.o" -o build/research/noir-tools/worker-bench
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  CARGO_TARGET_DIR="$PWD/build/research/noir-compact-native-target" \
  cargo build --release --manifest-path experiments/noir-compact/native/Cargo.toml --locked --jobs 2
if [ ! -f build/research/noir-assurance/assurance-typed250-v1/public.json ]; then
  python3 experiments/noir-compact/assurance_cases.py \
    --case typed250 --name assurance-typed250-v1 --profile cast256 --threads 2 --prove
fi
LIVE_DIR="$PWD/build/research/noir-assurance-native/live-v4-250-v2"
mkdir -p "$LIVE_DIR"
swiftc -parse-as-library -I "$BIN_DIR" experiments/noir-compact/live-assurance.swift \
  "$BIN_DIR/HumaCore.o" -o build/research/noir-tools/live-assurance
if [ ! -f "$LIVE_DIR/document.huma" ]; then
  build/research/noir-tools/live-assurance \
    "$PWD/build/research/noir-compact-native-target/release/libhuma_compact_experiment.dylib" "$LIVE_DIR"
fi
if [ ! -f build/research/noir-publictext/algebraic-v1/public.json ]; then
  python3 experiments/noir-compact/public_text_cases.py \
    --name algebraic-v1 --relation algebraic --prove
fi
if [ ! -f build/research/noir-capacity/cp32-pres8-v1/target/huma_compact_experiment.json ]; then
  python3 experiments/noir-compact/capacity_cases.py \
    --name cp32-pres8-v1 --checkpoints 32 --presence 8
fi
if [ ! -f build/research/noir-capacity/cp32-pres8-v1/target/setup/vk ]; then
  build/research/noir-tools/worker-bench /usr/bin/sandbox-exec \
    -p '(version 1)(allow default)(deny network-outbound)' \
    build/research/noir-tools/bb/bb write_vk \
    -b build/research/noir-capacity/cp32-pres8-v1/target/huma_compact_experiment.json \
    -o build/research/noir-capacity/cp32-pres8-v1/target/setup \
    -t noir-recursive -c build/research/noir-crs
fi
python3 integrations/noir/prepare-profiles.py
bash scripts/build.sh
open build/Huma.app
```

Use a new bundle path or quit the app before replacing its running bundle. The
script's default signing is ad-hoc; it does not provision App Attest or notarize
an app. Do not treat successful packaging as hardware acceptance.

The Mac bundle contains a precompiled Noir circuit, its pinned verifier key,
official Node 24.22.1 runtime and Barretenberg 5.2.1. Preparation verifies the
[official Node archive checksum](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt)
and the pinned prover archive. Cryptographic child processes cannot make outbound
connections. Private witness files live in a private temporary directory that the
Swift parent removes on success, failure or cancellation. Original signatures
stay in the saved draft and are never regenerated by proving.

If Xcode license selection prevents Rust linking on this development Mac, the
installed command-line SDK can be selected with
`DEVELOPER_DIR=/Library/Developer/CommandLineTools` for the relevant command.

For the website and local registry:

```sh
npm ci --prefix web --ignore-scripts
node web/registry.mjs
```

Open `http://127.0.0.1:4318`, `/verify` or `/download`. The loopback registry has no
account requirement for verification; hosting uses the installed storage SDK.
The optional React research deck has its own build:

```sh
npm ci --prefix web
npm run build --prefix web
npm run typecheck --prefix web
```

The deck is served at `/deck`; `web/dist` contains generated assets.

### C. Verify a downloaded proof independently

After building/preparing the trusted local verifier assets:

```sh
node zkvm/scripts/verify-file.mjs Huma-evidence.json
node zkvm/scripts/verify-file.mjs Huma-replay-proof.json --text received-text.txt
node zkvm/scripts/verify-file.mjs Huma-replay-proof.json \
  --expected-key <64-lowercase-hex-digits>
```

The CLI accepts saved evidence packages and legacy proof exports through the
same bounded SDK used by the browser. For experimental media, supply the exact
encoded master with `--media master-file`. Retired account options are rejected.

The expected fingerprint comes from a separately trusted source, not the receipt.
Text files must be valid UTF-8. The CLI loads its WASM and glue from disk; the base
check does not contact a proof service. Execution-only diagnostics return
`verified: false` and must not be presented as proofs. Fake receipts and development
mode are rejected.

The historical RISC Zero worker accepts `info`, `execute`, `prove` and `verify`
JSON commands on stdin with a 32 MiB request cap. It is absent from the current
Mac bundle. Its research guest pin is:

```text
83caafb5987a3c73d37ae9a5a31da1117c021f3818621a9f9911cb9d1fbf8bd4
```

This V3 program adds authenticated origin/presence records and the private writing
policy. The reader also keeps the previous V2 program pinned as
`dda9a53d84ded1b005a8bf45c193ccbaf52d9d7b62f5d83b54d197803c1a1295`.
Existing V2 receipts retain their original statement identity and have no V3
assurance fields. A proof cannot choose an arbitrary program ID.

Changing a program pin is a reviewed protocol release, not a proof-file option.
Supported old RISC Zero receipts retain their meaning. V1 checkpoints retain
signatures without a signed-time claim; V2 adds `device-clock-v1` readings under
`huma-signed-checkpoint-v2`.

The stable replay statement identity is:

```text
SHA256(UTF8("huma-replay-identity-v1\n" + imageID + "\n" + SHA256(journalBytes)))
```

Hashes are lowercase hex, with no final newline. `journalBytes` is the exact
receipt journal, not reserialized JSON. This identity matters only after verifying
the receipt. A registry content ID instead hashes exact serialized public-record
bytes; the two identifiers have different purposes.

### D. Sharing limits and optional evidence

For hosted originals, configure [`.env.example`](.env.example)'s server-only R2
and CDP variables in the existing `.env.local`; keep the R2 bucket private. From
`web/`, run `npm run build:share` and `npm run start:configured`. The server defaults
to localhost. An HTTPS deployment must preserve the API paths and allow its origin
in the CDP project. R2 uses the S3 endpoint and `auto` region described in
[Cloudflare's documentation](https://developers.cloudflare.com/r2/get-started/s3/).
Coinbase access tokens are checked server-side with
[CDP's validation API](https://docs.cdp.coinbase.com/api-reference/v2/rest-api/end-user-accounts/validate-end-user-access-token).

Before starting the live host, run from `web/`:

```sh
npm run check:publication -- --origin https://your-host.example
```

This offline check reports missing configuration by variable name, validates the
R2 endpoint and quota settings, checks the built approval page and pinned reader
assets, and requires an HTTPS origin. It never prints credential values, signs
in or uploads. A passing check means configured for live acceptance; bucket access,
the CDP allowed origin and a real approved download/verification still need testing.

A portable hosting bundle can be built from the current compiled reader and
approval assets. It uses an explicit runtime file list, includes a hash manifest,
and leaves out credentials, private drafts, witnesses and native proving tools:

```sh
node scripts/package-publication.mjs build/HumaPublicationHost-release
docker build -t huma-publication-host:release build/HumaPublicationHost-release
```

Use a new output directory for each bundle; packaging refuses to overwrite one.
Build the image on the target architecture. The current acceptance is **Linux
arm64, Node 24.22.1**, running as a non-root user with a read-only root filesystem
and no external network. Eight cached synthetic proof/master pairs passed the real
verification and publication routes against a loopback S3 fixture. This validates
the packaged runtime, not real R2 credentials or Coinbase sign-in.

On the chosen server, keep its configured environment file outside this bundle:

```sh
docker run -d --name huma-publications --restart unless-stopped \
  -p 127.0.0.1:4318:4318 --env-file /absolute/private/path/publication.env \
  -e HUMA_STORAGE_BACKEND=r2 -e HUMA_REGISTRY_HOST=0.0.0.0 -e HUMA_REGISTRY_PORT=4318 \
  --read-only --cap-drop ALL --security-opt no-new-privileges=true \
  --cpus 2 --memory 1g \
  --tmpfs /app/web/data:uid=1000,gid=1000,mode=0700 \
  --tmpfs /tmp:uid=1000,gid=1000,mode=0700 \
  huma-publication-host:release
```

Route the chosen HTTPS origin to that loopback port, register the origin with
Coinbase CDP, and set the same host in the Mac app. Run one publisher instance
while preparation state is process-local. Nothing has been deployed by these
local acceptance tests. The server-only lockfile has **zero npm advisories**;
the existing full website dependency tree still has seven moderate advisories.
Browser approval chunks are copied from Vite's complete import graph, including
lazy wallet assets; unknown files in its build directory are not packaged.

`POST /api/publications/prepare` stages a verified public upload. A ten-minute
capability protects its browser review/polling endpoint. Authenticated explicit
approval stores the objects; `/original/<manifest-hash>#<capability>` downloads and
checks them. Masters are capped at 32 MiB and public proof packages at 2 MiB;
the Mac text uploader has its existing smaller text/proof limits. At most two
preparations and two approvals run concurrently; staging holds at most 16 requests
and 64 MiB. Staging is process-local and expires on restart; run one publisher
instance until staging is distributed or routed consistently. The private bucket
stores content-addressed objects plus protected publication records.

Daily publication quotas persist alongside those records. Defaults are **1,000
publications / 1 GiB globally**, and **100 publications / 128 MiB per uploader**,
per server UTC day. `.env.example` names the four adjustable limits. Global count
is bounded at 2,000 to keep the daily ledger within its 512 KiB limit. This is an
upload allowance, not a cap on all provider charges.

Before uploading content, one conditional update reserves its declared master
and proof bytes against both allowances. R2 uses the object's ETag and atomic
conditional writes, so competing writers cannot spend the same remaining slot.
Retrying the same prepared publication reuses its reservation. A failed content
upload keeps its reservation; it is not rolled back into an allowance another
request might already be using. Unknown or corrupt quota state fails closed.
Quota accounting is a hosting policy, not a trusted timestamp in the proof.

Local preview uses a private file with a lock, atomic replacement and synced
contents. If the process is killed while holding its lock, approvals stop safely;
an operator must stop all local publisher processes before removing the abandoned
`.lock` file. R2 conditional writes do not use that filesystem lock. Real provider
acceptance and review of the remaining dependency findings still precede public launch.

The shipped server rejects the retired proof-only `POST /api/proofs` route.
New hosted uploads use the master-and-proof approval flow and its durable quotas.
Existing `/api/proofs/<hash>` records and `/verify/<hash>` links remain readable.
Isolated compatibility tests can explicitly enable the old writer; the server's
command-line entry point does not enable it. Public proof serialization strips
private history, including nested fields.

Portable Apple evidence can be checked separately:

```sh
node zkvm/scripts/verify-file.mjs Huma-replay-proof.json \
  --device-evidence Huma-device-evidence.json \
  --device-policy reader-app-policy.json
```

The reader policy specifies a trusted app ID, environment and approved bundle
versions; it is not obtained from the untrusted evidence file. The existing browser
can perform the same optional check. Selecting invalid optional evidence fails
the combined result rather than leaving an earlier success visible.

Archived enrollment checks use authenticated historical receipt data, not a claim
of current revocation status. Offline evidence does not establish global assertion
non-reuse or fresh human presence. V2 device bindings use the stable statement
identity and `huma-app-attest-assert-v2`; legacy bindings retain their byte-hash
semantics and V1 domain. No silent downgrade is permitted.

For provisioned testing, select the actual Apple account/profile and correct
`Resources/Huma.AppAttest.{development,production}.entitlements`. The local service
uses explicit configuration:

```sh
HUMA_APP_ID_PREFIX=YOURPREFIX \
HUMA_SIGNING_IDENTIFIER=dev.swayam.huma \
HUMA_ATTEST_ENVIRONMENT=development \
HUMA_BUNDLE_VERSIONS=1 \
node integrations/attestation/server.mjs
```

`YOURPREFIX` is a placeholder. The service defaults to loopback port 4319 and
stops if configuration is missing. It exposes `/v1/info`, `/v1/challenges`,
`/v1/enroll` and `/v1/assert`. Challenges use 32 random bytes and expire after 120
seconds. Enrollment/assertion checks cover the Apple chains, signed Mac properties,
app policy, session binding and increasing counters. Invalid attempts consume
challenges; identical accepted retries retrieve their original result.

Only public digests/device evidence go to this service, not raw text or typing
history. Its store uses private files, atomic durable writes and a single-writer
lock. Keep counters backed up and never run multiple replicas against it. Do not
remove a lock while its process is live. Production still needs HTTPS, transactional
shared storage, account/device binding, revocation and independent review.

### E. Reproduce the experimental Noir results

Preparation downloads pinned official binaries and immutable library sources:

```sh
python3 experiments/noir-prover/prepare.py
python3 experiments/noir-replay/typing_profile.py
python3 experiments/noir-compact/run.py \
  --fixture build/research/noir-typing-fixtures/typing-250-current.json \
  --name cast256 --candidate bounded-checkpoints --profile cast256 \
  --prove --threads 8
python3 experiments/noir-compact/bucket_cases.py --threads 8
python3 experiments/noir-compact/check.py cast256 --threads 8
python3 experiments/noir-compact/semantics.py --candidate bounded-checkpoints
```

Use `--overflow-control` only for its deliberately weakened constraint test; it
creates no proof or verification key and must never become a reader build.

The compact composite reader can be invoked directly:

```sh
python3 experiments/noir-compact/verify.py \
  --trusted-build build/research/noir-compact/cast256 \
  --proof-dir build/research/noir-compact/cast256/target/proof-8-threads \
  --capsule build/research/noir-compact/cast256/capsule.json
```

Optional `--text-file` and `--expected-key` compare reader text and an independently
known fingerprint. The trusted build chooses its own ABI/VK. It is never selected
by the capsule. Fixed-profile padding/counts are validated before the active
journal is compared and all signatures checked.

For an already captured and signed V4 session, the local acceptance runner is:

```sh
python3 experiments/noir-compact/live_assurance_cases.py \
  build/research/noir-assurance-native/live-v4-250-v2 --prove
```

This expects the existing synthetic Swift capture and frozen V4 build; it does
not create or replace signatures. It validates the complete original log, checks
two independent ABI adapters, pins program bytecode/public ABI/verifier key,
then generates and verifies a proof. Cryptographic child processes cannot make
outbound connections. The external monitor enforces witness memory/deadline
limits; the app's worker harness enforces proving cancellation/deadline/CPU limits.
An existing proof directory is never overwritten. Public fixture verification
can be repeated without proving using `npm test --prefix web`.

Build the browser reader without installing any Noir compiler or proving SRS:

```sh
npm ci --prefix experiments/noir-compact/browser --ignore-scripts
node experiments/noir-compact/browser/build.mjs --web
npm test --prefix experiments/noir-compact/browser
```

The build writes generated reader assets to `web/dist/compact`. Restart your own
local registry after server changes, then open `/verify`. Both supported proof
formats can be loaded from a local file or through Advanced → Paste proof JSON.
Compact proof files are capped at 512 KiB. The public software-key fixtures under
`browser/test/fixtures` are verification test material, not device evidence.

Export an already generated compact proof after native composite verification:

```sh
python3 experiments/noir-compact/export.py \
  --proof-dir build/research/noir-compact/cast256/target/Bucket250-8-threads \
  --capsule build/research/noir-compact/cast256/Bucket250-capsule.json \
  --output build/research/public-compact-proof.json
node experiments/noir-compact/browser/verify-file.mjs \
  build/research/public-compact-proof.json --text received-text.txt
```

Export refuses to overwrite an existing file. Add `--text-file` to the export
command to include the final text; registry sharing requires it. The offline
reader supports `--expected-key` too and disables network fetches. Its JSON report
keeps u64 times exact. The export contains `kind`, `profile`, base64 `proof`,
`publicInputs`, `publicKey`, DER `signatures`, and optional `text`. It contains no
private witness or producer-chosen verification key/journal. Its kind is
`huma-compact-public-proof-v1`, with profile `cast256-v1`; the signed V3 checkpoint
bytes and statement identity remain unchanged.

For a standalone loopback-only browser acceptance page:

```sh
node experiments/noir-compact/browser/build.mjs
python3 experiments/noir-compact/browser/prepare-fixtures.py
node experiments/noir-compact/browser/serve.mjs
```

Open `http://127.0.0.1:4324` and run the checks. Preparation requires the previously
generated synthetic proofs and native checker. The normal automated reader tests
use frozen public fixtures and do not require a private witness or prover.
`HUMA_NOIR_SHARED=1 HUMA_NOIR_PORT=4325` selects the isolated shared-memory mode.

The fixed profile's VK SHA-256 is
`149d13f114a80bc03df8966aa5b716ba86acc383c48c620e0bdb1afb09f4b600`.
Its public `checkpoint_count` determines the active prefix of the eight root
slots; all unused records and roots must be zero before the reader projects that
prefix into the signed capsule journal. Every active root needs its signature.
It uses 804,314 gates; proof bytes are 14,656 plus 1,824 public-input bytes and the
signature capsule. Source/VK/proof pairings are retained under
`build/research/noir-compact`; public timing and validation reports are in
[experiments/noir-compact/results](experiments/noir-compact/results).

Historical complete V2 experiments, narrow component benchmarks and their
machine-readable reports remain in the other experiment directories. The tiny
V2 fixture's 4.669-second result is proving-only on 16 threads; it is not a normal
session. The 10k hash-only result is in
[results-text10000-8-threads.json](experiments/noir-replay/results-text10000-8-threads.json).

Compiler/gate sizing uses a 90-second/6 GiB sampled-RSS budget. Proof jobs use
exclusive admission, lower priority, owned-process-group cancellation, thermal
stop and a deadline. The research driver refuses proofs above 2.1 million gates
without a budget review. Those are experiment limits, not language guarantees.

UltraHonk's universal CRS assumption differs from the current transparent RISC
Zero configuration. Barretenberg 5.2.1 includes the native-verifier security patch
for malformed recursive accumulators. Honest proof benchmarks do not establish
soundness against every malicious prover; independent review remains necessary.

### F. Compact experimental protocol details

This is `huma-compact-replay-experiment-v3`, not the app's existing V2 capture
format. Its implementation is in the compact experiment's Noir source/candidates
and `native/src/{commit,ops,protocol}.rs`.

An operation word is `code * 2^56 + argument`, below `2^62`. Four words pack into
one field as `w0 + w1*2^62 + w2*2^124 + w3*2^186`; the result is below `2^248`,
so it fits injectively in BN254. Twelve words form three packed fields.

| Code | Meaning | Argument |
| --- | --- | --- |
| 0 | Padding after the actual operation count only | Zero |
| 1 / 2 | Baseline scalar / end baseline | Unicode scalar / zero |
| 3 / 4 | Key down / up | 40-bit time delta, then 16-bit key code |
| 5 | Begin edit | 16-bit delta, 8-bit source, 16-bit removed UTF-16 width, 16-bit location |
| 6 / 7 | Move one scalar left / right | Zero |
| 8 / 9 / 10 | Delete / insert / end edit | Zero / Unicode scalar / zero |
| 11 | Advance elapsed time | Positive 56-bit delta |
| 12 / 13 | Modifier flags low / high | 32-bit half |

Source codes are 1 typing, 2 paste, 3 composition, 4 dictation, 5 replacement,
6 import and 255 unknown. Replay uses a bounded scalar gap buffer. Movement must
reach valid UTF-16 boundaries; deletion must finish before insertion; edits must
end correctly and key samples cannot occur mid-edit. Final text is encoded once
as UTF-8 and checked under the canonical policy.

Nonce and salt are each two big-endian 128-bit field halves; the salt is nonzero.
Poseidon2 uses BN254 width four, rate three, matching the pinned Noir beta.25
framing: initial capacity `N*2^64`, permute after each full block, absorb the
remainder, then always perform one final permutation. The native implementation
uses `taceo-poseidon2=0.2.1` and checks the pinned known vector.

The domain constants for seed/block/prefix/checkpoint are respectively
`0x48554d410301`, `0x48554d410302`, `0x48554d410303`, `0x48554d410304`:

```text
seed = H(seedDomain, nonce0, nonce1, salt0, salt1)
next = H(blockDomain, previousHead, packed0, packed1, packed2)
prefix = H(prefixDomain, fullBlockHead, wordCount, partial0, partial1, partial2)
```

Including the actual count prevents padding/length ambiguity. A checkpoint hashes
these twelve fields:

```text
checkpointDomain, prefixRoot, sequence, captures, edits, samples,
reportedUnixMillis, elapsedMillis, isFinal, previousCheckpointRoot,
finalTextSHA256High128OrZero, finalTextSHA256Low128OrZero
```

Offsets and elapsed readings are nondecreasing; checkpoints occur in idle phase.
The first covers exactly the baseline end at elapsed zero; the final one covers
all operations and the canonical text SHA. UTC is bounded to `253402300799999`;
backwards UTC sets a public flag. These checks still authenticate reported time,
not independently trusted time.

Elapsed accumulation is bounded below `2^72` by at most `2^16` nonnegative deltas
each below `2^56`. A final explicit 64-bit check prevents overflow; it must not be
removed. Counts are bounded by operations and initial bytes by scalar capacity.
The exact-profile research maximum is 65,536 operation slots, 65,535 scalar slots
and 2–1,024 checkpoints; the smaller fixed profile has the capacities stated above.

P-256/SHA-256 signs the following bytes, with `\0` denoting a NUL byte:

```text
HUMA_COMPACT_EXPERIMENT_CHECKPOINT_V3\0 || checkpointRoot32BE
```

The public key is 65-byte uncompressed SEC1; signatures are DER, at most 72 bytes.
The composite identity is:

```text
SHA256(HUMA_COMPACT_EXPERIMENT_ID_V3\0 || SHA256(trustedVK) || publicInputBytes || publicKey65)
```

It binds the trusted program, public statement and key. Both proof verification
and every signature are mandatory. Counts, byte lengths, reported start/end and
elapsed, nonce, commitments and checkpoint roots are public. Initial text,
intermediate edits, key details, individual timing, checkpoint offsets and salt
remain private unless separately disclosed.

V4 and V5 writing proofs use the richer capture journal in
[`assurance-abi.json`](experiments/noir-compact/browser/assets/assurance-abi.json).
The older eight-slot V5 profile keeps 94 public fields and the original V4 capture signatures. The
checkpoint domain is `HUMA_COMPACT_ASSURANCE_CHECKPOINT_V4\0`; approved presence
uses `HUMA_COMPACT_ASSURANCE_PRESENCE_V4\0`. V5's verifier-key SHA-256 is
`9faf09ad7af8b403cd8ea02cd1f896c96971f19bc03182660cc2008c8218f714`.
Its identity uses `HUMA_COMPACT_ASSURANCE_ID_V5\0`, that key hash, the public input
bytes and the 65-byte public key. The older V4 key and identity remain supported.

The current larger V5 profile is `assurance256-cp32-v1`, still using kind
`huma-compact-assurance-public-proof-v5`. Its pinned
[`assurance-cp32-abi.json`](experiments/noir-compact/browser/assets/assurance-cp32-abi.json)
has **142 public fields / 4,544 bytes**, with two 32-slot checkpoint-root arrays.
Its verifier-key SHA-256 is
`5b3a98abe325feca9d5187668fc3e97ab0486b0a0f1e5cb2f904de1c67621b11`.
The capture and signature domains remain V4; the identity still uses the V5
domain plus this profile's key hash, public inputs and public key. Each profile
has reader-owned key/ABI pins; changing only the profile label fails verification.

The optimized replay checks use field arithmetic with explicit bounds. Gap
indices fit 16 bits and UTF-16 counts fit 17 bits because the existing scalar
limit is at most 65,535. Gated range checks reject underflow; polynomial phase
checks enforce the same state transitions. This follows the numerical approach
described in Noir's [circuit guide](https://noir-lang.org/docs/guides/thinking_in_circuits);
the equivalence of this particular rewrite is checked by Huma's semantic and
counterfactual tests. No writing-rule thresholds changed.

### G. Validation and known dependency limits

October 23 current validation: **47 Swift, 33 compact-native Rust, 50 Node/registry
and 46 actual Chrome checks** passed. The latest Noir-only Mac service generated
fresh short, medium, 32-checkpoint and full-profile proofs. Save/reopen, altered
proof rejection, local dummy-approved master/proof delivery and downloaded-proof
verification passed for each. Crypto children cannot make outbound connections;
the parent test adapter uses a local server.

The current app has 103 verified prover-resource files and no old replay engine.
The host has 97 allowlisted files plus its manifest. Eight Linux cases passed
through the official S3 adapter and a loopback fixture, including the new small
profiles, the full profile and three media types. All 13 reader asset pins pass.
Real R2 and Coinbase acceptance still need the bucket configuration and HTTPS
origin. No automated test used an owner key or approved an authentication prompt.

Earlier, eight core Rust tests and two receipt verifier tests passed. The existing receipt also passed the updated native
adapter with external networking denied, and the old WASM/registry regressions
passed. The shared media contract typechecked for iOS.

The new writing-policy guest executed both typed and paste/missed-challenge
fixtures correctly. Its full RISC Zero proof attempt was stopped after exceeding
14 minutes and reaching about 8.4 GiB RSS on two threads. No completed V3 proof
is claimed. The Noir V4 and optimized V5 full-policy proofs complete through the native app
service, as described in question 23. The earlier RISC Zero attempt is in
[the presence/media report](zkvm/tests/results/presence-media-acceptance.json);
[the earlier compact native capture report](experiments/noir-compact/results/native-capture-acceptance.json)
records its separate successful 4.344-second short-session proof.

Useful existing checks include:

```sh
swift test
cargo test --manifest-path zkvm/Cargo.toml -p huma-replay-core -p huma-replay-verifier --locked
node zkvm/tests/browser-verifier.mjs
npm test --prefix web
npm test --prefix integrations/attestation
python3 -u zkvm/tests/native-worker.py
```

The native-worker test generates a real proof by default and can be expensive.
Do not confuse execution-only checks or narrow fixtures with full user acceptance.
The compact native crate has its own scoped checks:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  CARGO_TARGET_DIR="$PWD/build/research/noir-compact-native-target" \
  cargo test --all-targets --manifest-path experiments/noir-compact/native/Cargo.toml --jobs 2
```

Recorded audits are not a clean production approval. The RISC Zero host lockfile
reported two vulnerabilities/three unmaintained warnings; the guest lockfile one
vulnerability/two unmaintained warnings. The vulnerability IDs are
`RUSTSEC-2023-0071` (transitive RSA timing issue) and `RUSTSEC-2025-0055`
(transitive tracing-subscriber ANSI log injection). The app uses P-256 capture,
not RSA private signing, and installs no tracing subscriber, but the upstream
findings still need resolution or review before distribution.

The independent compact Rust lockfile reported zero known vulnerabilities and one
unmaintained `paste` warning (`RUSTSEC-2024-0436`). Its registry yanked-package check
timed out; it must not be described as completed. No advisory is suppressed.

The `web` lockfile pins S3 SDK 3.1156.0 and Coinbase SDK 1.60.0, with Coinbase
frontend packages 0.0.128. Vite is now 6.4.4 with React plugin 4.7.0, and compatible
transitive build packages were refreshed. Both pages build, and the existing
deck's TypeScript check passes. The saved npm audit comparison fell from **14 findings
(nine moderate, five high) to seven moderate findings, zero high or critical**.
The remaining affected packages are Coinbase/Solana and their `jayson`,
`stream-json` and `uuid` dependencies. Upstream Jayson 5 removes the latter two,
but the installed Solana SDK requires Jayson 4; no incompatible major override or
Coinbase SDK downgrade was forced. The remaining findings need an upstream patch
or compatibility/reachability review before public deployment. Passing local
tests is not a clean dependency audit.

The isolated compact browser lockfile pins `@aztec/bb.js` 5.2.1 and esbuild 0.28.2.
Its October 23 npm audit reported zero known vulnerabilities across 43 dependency
entries, including optional platform packages. This is dependency evidence, not a
cryptographic audit. The official public G2 point was retrieved from both Aztec
CDN hosts with matching SHA-256; verification then uses its pinned local copy.

The public Apple development fixture is from
[uebelack/node-app-attest](https://github.com/uebelack/node-app-attest/blob/main/test/fixtures/attestation-development.json),
retrieved October 21, 2026, under the MIT notice retained at
[integrations/attestation/test/fixtures/LICENSE](integrations/attestation/test/fixtures/LICENSE).
It contains public historical evidence, not a signing private key. The historical
assertion pair in the tests comes from that project's `test/verifyAssertion.test.js`.
Both are component-test material, must fail the current Mac admission policy, and
are not evidence of successful Huma Mac enrollment.

### H. Sources for further reading

- [Apple Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
- [Apple App Attest validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
- [Apple WWDC26 App Attest and Mac support](https://developer.apple.com/videos/play/wwdc2026/201/).
- [Google Play Integrity request flow](https://developer.android.com/google/play/integrity/standard).
- [Noir: thinking in circuits](https://noir-lang.org/docs/guides/thinking_in_circuits).
- [Barretenberg 5.2.1 release](https://github.com/AztecProtocol/aztec-packages/releases/tag/v5.2.1).
- [QUACK timing/injection study](https://arxiv.org/html/2604.15845v2); controlled research is not Huma deployment accuracy.
- [ZK-PoP behavioral process-attestation proposal](https://arxiv.org/html/2603.00179v3); benchmarks were not reproduced here.
- [zkSENSE mobile-motion work](https://petsymposium.org/popets/2021/popets-2021-0058.php); a different sensing task.
- [RFC 3161 timestamps](https://www.rfc-editor.org/rfc/rfc3161.html).
- [OpenTimestamps](https://opentimestamps.org/).

</details>
