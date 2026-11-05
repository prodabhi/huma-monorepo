# Huma: the human provenance network

Strategy note, October 23, 2026. This reframes the product around seven
decisions that were too small. Each section names the old decision, the bigger
one, why, and what is unproven. HUMAN-PRESENCE.md and MEDIA-PROVENANCE.md hold
the mechanisms; this note holds the shape.

## Current release scope

The active delivery goal is now creating proofs, saving portable packages, and
**shipping the exact master copy and its proof through Cloudflare R2**, with
independent verification after download. Sharing is explicit; private writing
histories, raw input streams and device keys stay local. The local file workflow
continues to work without a host or an account.

Coinbase CDP configuration is present locally. The next hosted publication flow
uses Coinbase sign-in for the uploader; it must never make a wallet or host's
approval a substitute for checking the proof. Base publication is retired (§5):
Huma sends no transaction and runs no on-chain verifier.
Social posting remains removed. Feed, witness networking and mobile clients stay
deferred. R2 hosting and Coinbase configuration are engineering work in progress,
not a claim of a live deployment. This scope supersedes the earlier file-only
release boundary and the broader build-order tables below.

New short Mac recordings now use the bundled Noir proof service. Native proving,
save/reopen and local master/proof delivery pass with an original signed software
fixture. Live R2/Coinbase and owner hardware acceptance remain pending; the
five-second and longer-session targets remain open.

## The one-line change

Old: *an app that proves you wrote or captured a thing.*

New: *a network in which people accumulate a verified human track record from
ordinary creation, and anything they publish inherits it, checked where it is
read.*

The product expands from individual documents to a creator's checkable history.
Each publication still needs its own content binding; an account's history adds
context rather than certifying every future item. The proposed moat is the
witness graph and its measured cost to forge.

## 1. From editor to trust layer in the feed

**Old.** Write in Huma, export a proof, hope readers open a verifier.

**New.** Verification happens at render time: a badge in supported readers, a
browser extension, a platform SDK that checks a manifest and shows one line.
Huma's own app is the reference capture client; the business is "verification
where content is read", which platforms integrate and pay for. Readers never do
anything.

**Why.** Every provenance product so far, ZCAM included, dies at "open our app
first". Under 1% of news images carry any provenance at all. The reader side
has no adoption cost if the client does it.

**Unproven.** That third-party clients will render a provenance badge; that
platforms pay. First test: an independent reader or an open-source client
patch, and one paying vertical from §7.

## 2. From documents to people

**Old.** One proof per document: heavy machinery for a weak claim.

**New.** Every verified capture appends to an identity's provenance log:
devices, presence challenges answered, witnesses, consistency across years.
The public claim becomes *"this account has N verified human captures over M
months across K devices, witnessed by J other people"*. A single session can
be faked; a coherent multi-year, multi-device, witnessed life is the expensive
thing. The score README q41 refuses to invent is replaced by facts a reader can
count.

**Why.** Readers do not ask "was this document typed"; they ask "is this a
person I can trust". Track record answers that; a proof file does not.

**Unproven.** Privacy design: the log must reveal counts and time spans
without revealing content, locations or exact times. Likely shape: per-capture
commitments in the public proof registry, ZK range proofs over the log ("≥ 50 captures in 2026,
≥ 3 enrolled device credentials") shown by the client. Distinct keys do not
establish distinct physical devices or people: keys can rotate, apps can be
reinstalled, and accounts can share an operator. Count keys as keys until a
privacy-preserving device-enrollment policy supports a stronger statement.

## 3. From attested devices to attested co-presence

**Old.** Device attestation plus probes, with witnesses as a footnote.

**New.** The witness graph is the product. When two Huma devices owned by
different accounts are near each other, each records the other's nonce-seeded
probe (light flash, inaudible chirp) and signs what it saw. Each capture then
can name a second signing device; each witness event is an edge. The intended
economic effect is to make a convincing forged history require sustained
collusion or control of more devices. Establishing independent people, resisting
relays and bounding Sybil attacks are research goals, not consequences of two
signatures. The aspiration is proof of personhood without a stored biometric.

**Research deliverable.** A formal "proof of physical capture" definition: an
adversary game with device, network and physical capabilities; a theorem
bounding the cost of k fake identities as a function of honest witness-graph
density and attestation cost; measured parameters from the attack bench. This
is a paper, and the basis for a standard.

**Unproven.** Witnessing without leaking who was with whom: witnesses should be
provable to the reader as "an independent account" without identifying it.
Blind signatures or group signatures over the witness edge are the candidates.
Also: incentive design so witnessing happens (defaults on, zero friction).

## 4. From our editor to the input layer

**Old.** Provenance only for text typed inside Huma.

**New.** A Huma keyboard on iOS and Android, and an input-monitoring agent on
Mac, observe typing in every app. Messages, posts, notes and emails all gain a
signed input history without the user changing tools. The editor stays as the
long-form home.

**Why.** Where people write is not in our app. Capture must go to them.

**Unproven.** Whether a keyboard extension can use a biometric-gated Secure
Enclave key and App Attest (extensions run with restrictions; not checked).
Whether users accept a keyboard that records timing. Raw timings and characters
must not be uploaded; persistence needs a separate consent and retention design.
Timing-only evidence cannot authenticate the text ultimately published by another
app. That needs a cooperating editor or an explicit content-binding handoff.
Apple's current guidance excludes keyboard extensions from App Attest; a host-app
assertion must not be presented as direct attestation of the extension (§8.6).

## 5. Portable proofs, stored anywhere

**October 30: Base retired.** Huma no longer records pages on Base. The
contracts, relayer, batch circuit and batch prover are archived in
`experiments/onchain/`. The Base decisions below are kept as history.

**Old.** Proof distribution depends on a social post and a chain anchor.

**New.** The proof is the product; no chain is required to *use* it. A Huma
proof is a self-contained file: anyone can verify it, from any storage (the
public registry, IPFS, a web server, an attachment). Emit C2PA-compatible
manifests carrying Huma's assertions (presence challenges, scene-response
checks, witnesses) so any C2PA reader shows something, and propose
"physical-response assertion" and "witness assertion" types to C2PA.
Distribution (a post, a link, a file) is independent of verification.

**Decision, October 24: Base is the public record, one proof per page, made on
the writer's Mac.** Huma's page proofs are Noir (UltraHonk), so RISC Zero's
router can't check them; Huma deploys its own verifiers. Server-side batching
and a Privy server wallet were built first and then dropped: with few writers,
one transaction per page costs about the same, and nothing private or costly
runs on a server.

- Long pages fold while the writer types (assurance-long-v2,
  `integrations/noir/long`). The first part is the `start` program; every later
  part is `fold`, which proves its own step and verifies the previous part's
  proof. Every part checks the capture key's P-256 signatures in-circuit, and
  the chain carries a commitment to that key. At Finish one `final` program per
  text tier (1,024 / 4,096 / 10,000 characters) verifies the last part and pins
  the start and fold keys, so a single 14.6 KB proof covers the whole session.
  Every program is a 2^21-gate circuit or smaller; the final step takes at most
  four signed events, and the planner moves earlier trailing events into a part
  with no keystrokes. For pages up to 1,024 characters the final step also
  proves the last part (an empty step if that part is already proved), so
  Finish is a single proof; the larger tiers would not fit 2^21 gates merged.
- Background parts run on two low-priority threads: about 10 s for the first
  part and about 15 s for each later one. At Finish, while the writer waits,
  proving uses the performance cores less one (11 on an M4 Max): the merged
  1,024-tier final step takes 5.4 s there (17.7 s on two threads), a later part
  4.5 s. Readers verify the one proof in about 50-90 ms.
- On-chain: after a page is published and signed by the writer's wallet, the
  Mac makes the same final step again as an EVM proof whose last public input
  is that wallet (about 10 s, reusing the last part's proof). Only a holder of
  the private session can choose the wallet, so a copied proof claims nothing.
  The host checks it carries the published page's statement and the signer's
  wallet, simulates the call, and sends it from a relayer wallet the host
  funds. `HumaPages` verifies it with the tier's verifier (each 17.8 KB) and
  records the wallet and block under keccak256 of the 45 statement fields; it
  records only pages that met the writing rules. Measured: about 1.06 M gas to
  execute plus about 0.2 M for 12 KB of calldata, roughly $0.02 per page at
  Oct 23 prices.
- A reader computes the record key from the page proof alone and reads
  `pages(key)` from a public Base RPC, so no Huma server is trusted. Every page
  proof still verifies off-chain without the chain.
- Never on chain: content, raw inputs, exact capture times, witness pairs.
  Only the statement (commitments and the summary the proof already exposes)
  and the owner wallet; publication is explicit, never automatic.
- Dormant, kept for higher volume: the 4-page batch circuit
  (`experiments/onchain/batch`) and the Rust prover (`prover/`), which can also
  prove pages for writers who opt in. Short single-proof pages still verify
  off-chain; pages proved before v2 are not recorded on-chain.

**Storage: masters and proofs on Huma's R2 bucket, so the original is always
reachable.** Social platforms re-encode every upload (recompressed JPEG,
transcoded video, stripped metadata), so the copy people see never hashes to
the master. The answer is a stable "original is here" link that travels with
every post:

- *What is stored:* for each published capture, the master (lossless AVIF
  photo, FLAC audio, AV1 video) and its full receipt (~590 KB), under their
  content hashes. Private witness data (keystroke timings, sensor streams,
  drafts) is never uploaded. The user also keeps everything locally; the
  bucket is a public copy, not the source of truth.
- *Where:* Cloudflare R2, chosen for zero egress fees, since verification
  means downloads. Roughly $15 per TB-month at list price (dated snapshot):
  a heavy creator at 1 GB/month is about $0.015/month; 10k such creators about
  $150/month. Setup is a bucket, signed URLs and a Worker; an afternoon.
- *Access:* the creator chooses per item: public, link-only, or approved
  viewers. A restricted master shows readers "proof verified; master not
  shared".
- *What the link means:* the badge or post says "verified original at
  huma.link/<hash>". A reader opens it, downloads the master and receipt,
  and the verifier checks them offline against the hash in the Base record.
  The platform copy is shown as "preview of a verified master", with a
  perceptual-match line ("matches, minor re-encoding" / "differs") that is
  labelled as similarity, not proof.
- *Trust and failure:* the content hash on Base is the commitment, so Huma
  cannot swap or edit a stored file without the hash breaking, and if the
  bucket is down or Huma is gone, any other copy of the file still verifies.
  For the record itself, the 1 KB wrapped proof on Base is permanent; the
  receipt may additionally be mirrored to Arweave for pennies if we want a
  copy that outlives us.
- *Media sizes to budget:* photo 15–30 MB, audio ~10 MB/min, video
  220–380 MB/min (§MEDIA-PROVENANCE 3b). Video at scale is the only line
  item that matters; cap and tier it before opening uploads.

**No wallet friction.** The user never sees a seed phrase, buys ETH, or
switches networks:
- *Account:* a non-custodial CDP embedded wallet created at sign-in with
  email, SMS or passkey, keys held in a TEE, exportable by the user; or Sign in
  with Base (passkey) for people who already have a Coinbase Wallet. Either
  way, Huma never holds keys. (Apple-side keys stay separate: the Secure
  Enclave capture key signs captures; the wallet signs publications.)
- *Gas:* CDP Paymaster sponsors every Huma transaction under a policy that
  allowlists only the Huma registry contract, with per-user and global caps.
  Billed to Huma monthly at gas plus 7%. Paymaster runs on Base mainnet and
  Base Sepolia only, which is one more reason the chain is Base.
- *Later, optional:* Base Verify for Sybil-resistant account checks as a
  second signal beside witnesses; USDC payments for customers in §7 via the
  same SDK.

**Why.** Standards outlive apps, so the proof file stays portable and
C2PA-shaped. A public record on a chain Coinbase sponsors gives readers an
independent timestamp and verification without asking users to learn crypto.

**Unproven.** Nothing in this section is built. The R2 bucket and
"original is here" links, the registry contract, the period composition, the
paymaster policy and the wallet sign-in are gates 6–8 in §9. C2PA's appetite for world-claims assertions remains slow; ship the
manifest first, lobby second. Fee figures are a dated snapshot.

## 6. From ZK-first to attested-policy-first, ZK second

**This does not remove ZK.** The existing RISC Zero replay proof (signed
history replays to the published text, private edits hidden) stays in v1: it
works today and verifies in about 0.2 s in the browser. Only the *new, heavier*
policy checks (writing rules, physical scene checks) start under attestation,
because the first full policy proof did not finish (stopped at 14 min,
8.4 GiB; README line 1223). They move into ZK as soon as proving is fast
enough. Against a forger who fakes the inputs, the two routes are equally
strong: both trust the device for where the streams came from. ZK's real gains
are that the policy computation is checked by the reader rather than trusted
to the app build, that a buggy or malicious build cannot sign a false verdict,
and that the computation can be checked in independent readers. Capture
provenance still needs its manufacturer evidence; all proofs retain their
cryptographic assumptions. On-chain verification needs a supported verifier.

**Old.** Every claim needs a RISC Zero proof: minutes of proving, 590 KB
receipts, before anything ships.

**New.** Version 1 evaluates the behavioral and physical policies on-device and
binds the policy report and session commitment to supported app/device evidence.
This route trusts the approved collector to evaluate the policy correctly. The
public record names that trust explicitly. ZK adds independently checked policy
computation over the committed private streams; it still relies on capture
provenance for where those streams came from. It does not remove Apple or Google
from that part of the trust model. Both routes should use portable evidence.

**Why.** The attestation is already in the trust base for everything else; it
costs nothing extra to lean on it for v1, and it cuts a year off the schedule.
ZK then becomes a measurable improvement rather than a blocker.

**Unproven.** Whether readers accept a policy report from an app authenticated
under Apple's or Google's supported checks. Apple authenticates app/key properties
and an assertion, not the truth of arbitrary policy results. Verify the exact
app/version/distribution and session binding, then name the trusted computation.

## 7. Name the customer

**Old.** Writers, who do not need proof, and readers, who do not pay.

**New, in order.**
1. Insurance and claims (photo/video provenance; ZCAM's own target).
2. Newsrooms and wire services (capture provenance; C2PA members already).
3. KYC and identity (injection-attack resistance: CEN/TS 18099 testing exists).
4. Courts and legal evidence.
5. Dating and marketplaces (co-presence and track record).
6. Consumer "human-made" badges and creator distribution, once the network
   exists.

Each of the first four pays for verification today and tolerates an app for
capture because the capture is the job.

## What stays the same

- Honesty rules: verified facts separate from self-reported claims; no score
  until calibrated; "Huma proves capture, not truth"; a staged real scene
  passes.
- Mac text as the first working surface, because it exists and its evidence
  contract (chain, checkpoints, Touch ID key) is the template for everything
  above.
- Raw inputs never leave the device. Keystroke timing is a biometric; sensor
  streams are private; the witness graph must be privacy-preserving by
  construction.

## First 90 days under the new frame

The experiments are feed verification, an opt-in provenance log, two-phone
witnessing, keyboard/host capability testing, and one customer workflow. Their
dependency order and measured completion criteria are in §9. Keyboard App Attest
is already excluded by Apple's availability guidance; the spike tests supported
alternatives rather than assuming that capability exists. The research output is
an adversary model and attack measurements before a security theorem or paper.

## 8. Engineering decisions under this vision

This section governs new implementation. The earlier sections state the product
ambition; HUMAN-PRESENCE.md and MEDIA-PROVENANCE.md contain mechanisms and
research hypotheses. README describes what the checkout actually does. A planned
component below is not a shipped feature.

### 8.1 Build the network around a shared evidence contract

Keep the existing Mac editor and signed capture. Extend them through adapters;
do not replace the working format or invalidate existing proofs to introduce the
network. Text and media keep their own capture records and verification rules.

The v1 `EvidenceEnvelope` data contract and existing-proof adapters are implemented.
The table describes the full contract direction; witnesses, external time and a
proof-free collector report are still future attachments.

| Piece | Binding and purpose |
| --- | --- |
| Statement | Version, session identity, content kind, exact content commitment, capture head and capture-key reference |
| Policy report | Policy identifier/version, results, coverage and evaluation method, bound to that statement |
| Capture/app evidence | Checkpoint signatures and supported manufacturer evidence bound to the same statement and key |
| Optional ZK evidence | Pinned relation/profile and proof of the named private computation |
| Optional witnesses | Challenge/response transcripts referencing this capture, with observer credentials and the applicable witness policy |
| Optional time evidence | Beacon rounds, publication/commitment receipts and their independently checked trust roots |

Canonical statement bytes and cross-language fixtures are frozen below. Keep
signed payloads separate from signatures/attachments to avoid a circular digest.
Unknown mandatory versions are rejected and attachment sizes bounded. An
attachment may add facts but cannot change the content or policy already bound.

`CaptureRecord` / `SignedCheckpoint` in `Sources/HumaCore/SignedCapture.swift`
and `MediaCapture.Manifest` in `Sources/HumaCore/MediaCapture.swift` remain the
capture foundations. `Sources/HumaCore/EvidenceEnvelope.swift` implements the
shared data types; `ReplayProofService.evidenceEnvelope` derives a statement only
after replay verification. The Mac Export menu offers an evidence package. Its
proof is projected through the shared typed Rust exporter to remove private
metadata; no re-signing, proof generation or device authentication is involved.

**Frozen v1 wire contract.** An envelope has exactly `kind`, `statement`, `proof`
and `attachments`. Kind is `huma-evidence-envelope-v1`. Proof is the public export
JSON as a string, preserving its integer values. Attachments accepts only optional
a `device` JSON string bounded to 256 KiB. Retired account attachments are rejected. The total envelope
limit is 32 MiB; the registry retains its smaller 2 MiB upload limit. New witness
and time attachments are rejected until their own versions/checks exist.

The statement contains exactly these fields, in this payload order:

```text
version, contentKind, contentPolicy, contentHash, byteLength, sessionBinding,
captureScheme, captureHead, checkpointBinding, captureKeyHash, policyID, policySatisfied
```

Its canonical payload is a compact UTF-8 JSON array starting with
`"huma-evidence-statement-v1"`, followed by those fields converted to strings.
Version is `"1"`; nullable fields use an empty-string slot; a present policy result
is `"true"` or `"false"`. Hashes are exactly 64 lowercase hexadecimal characters.
Length is a canonical unsigned 64-bit decimal string. Policy identifiers use
bounded lowercase ASCII, digits, dots and hyphens. Other values are enumerated;
every canonical payload character is ASCII. The statement identifier is SHA-256
of those bytes, distinct from the proof identity and registry content ID.

RISC Zero derives session binding from the proved session-ID hash, capture and
checkpoint bindings from the proved hashes, and content from the canonical text
hash/length. Compact V3 derives session binding from
`SHA256("huma-compact-session-binding-v3\\0" || nonce₀_BE16 || nonce₁_BE16)`;
capture/checkpoint fields encode the proven field elements as 32-byte hexadecimal
values. It retains the mandatory external P-256 signature checks.

The envelope is not independently signed. Its statement must equal the statement
derived by the verifier from the proof; the statement hash alone authenticates
nothing. Existing device attachments retain their checked proof bindings. Experimental Noir media membership now has a pinned verification
backend; its master bytes are supplied independently by the reader. This checks
signed master binding and sampled membership, not decoding or scene response.
The tests in `web/verify-core/fixtures/statements.json` remain encoding vectors;
the real media proofs live under `experiments/noir-media/reader/test/fixtures`.

### 8.2 Separate evidence verification from its presentation

`web/verify-core/` now provides a DOM-free entry point for text and experimental media proofs:

```text
verify(envelope, readerPolicy, expectedContent) → facts + missing + failures
```

It reuses the existing RISC Zero/compact readers, Apple evidence checks. It does not trust a registry's verdict, an envelope's
chosen trust roots or a producer-supplied verification key. Existing worker
isolation, cancellation and resource limits stay in place. Node and browser entry
points own a single cancellable worker; compact checks have a 20-second deadline,
RISC Zero 45 seconds. Expected displayed text or exact encoded master bytes are
mandatory; embedded text is also compared. Media master input is bounded to
32 MiB. Optional attachments require separate reader-owned policies. V4 and
media profiles currently reject device attachments until compatible
bindings exist.

Each fact records what was checked and the method that supports it. A policy
report signed by an authenticated collector and a policy result computed inside
a ZK proof are distinct facts. Missing optional evidence is unavailable; altered
or invalid evidence cannot receive a successful badge.

The website's replay worker and new envelope import consume this core. The Mac
export uses the same statement contract; feed/native report presentation and a
partner integration are next consumers.
Feed integrations first verify the exact displayed content and account binding;
a copied badge or a good account history cannot validate another item. No proof
attached means “no Huma evidence”, with no inference about AI use.

Start with an integration fixture and a small badge renderer, then test one
open-source reader. A browser extension is a distribution experiment;
its content permissions and platform compatibility need their own review.

### 8.3 Base replay ZK stays; add policy evidence over the same statement

The existing replay ZK proof remains in v1, as §6 specifies. The first new
policy route evaluates a named heavier policy locally, seals its report and
requests supported app/device evidence over that commitment. A reader trusts
the admitted collector for correct evaluation. The capture key alone does not
prove that a policy ran, and a copied JSON verdict is not attestation.

The current `AppAttestClient.seal` requires a replay proof and checks that the
capture key belongs to this Mac. Supporting a new policy report needs a **new
versioned binding and validation path** that retains that base proof requirement;
removing the proof check would violate §6. The collector must reject imported,
untrusted histories rather than certify them through a genuine app.

On supported Apple systems, independently check the app identity, allowed
version/distribution, enrollment and assertion. Mac App Attest requires macOS 27+
and service support; ordinary editor support remains macOS 14+. App Attest's key
and the biometric capture key are separate and need a checked association.
Android Play Integrity standard tokens require Google's authenticated decoding;
portable Android verification needs an explicit decoder/trust design.

ZK is an additional proof of computation over the same committed data. Retain
RISC Zero compatibility and the frozen Noir experiments; benchmark policies
before selecting a production backend. The experimental V4 assurance circuit now
has real passing and policy-failing proofs, constraint/tamper checks and a shared
Node/browser reader. A 250-character proof took 8.690 seconds on two threads;
warm witness/prove/native verification took 10.522 seconds. Its native live
capture and app backend integration remain. Do not automatically turn every
capture or track-record update into a heavy proof job.

Acceptance: an additional signed policy report verifies without launching a
separate policy prover; the base replay proof stays checked. Its method is
shown accurately, and swapping content, capture key, policy or report fails.
Only call it attested after real provisioned-device acceptance.

### 8.4 Account history is opt-in and contains countable facts

A published record references an account-endorsed capture commitment. Commit to
a canonical record with a fresh random salt, domain and version; keep the salt
private until an opening is disclosed. Publishing a deterministic hash of known
fields is not a hiding mechanism.

Do not post a cast automatically whenever someone seals a private draft. Separate
local capture, explicit publication, and consent to a public track record. Even
a content-free public commitment leaks account activity and timing.

Planned `TrackRecord` checks account authorization, evidence bindings and unique
session commitments before counting. Repeated casts, alternate proofs of the
same session and duplicate imports count once. Distinguish signed captures,
attested captures, ZK-checked policies and witnessed captures. An unavailable
envelope is a commitment seen, not a verified capture.

Initially show “N disclosed verified captures; active in M observed months;
K signing credentials.” Day/month claims need time evidence or must be labeled
self-reported. The report covers a disclosed subset, not a complete life or a
proof that an account has one human operator. Keep key rotations and revocation
status separate from cryptographic validity. A dispute does not automatically
invalidate every historical signature; revocation needs an issuer, reason,
effective time and historical policy.

Later range proofs can hide openings while proving counts against a specified
log root, account binding and deduplication policy. They do not establish omitted
history or unique devices on their own.

### 8.5 Witnesses are the central research track

Start with two consenting iPhones. Exchange fresh challenges in both directions,
bind each to both session heads, and retain signed observations of emitted
light/sound probes. A network delivery receipt is not a sensor observation.
Measure relay/replay, two phones owned by one person, colluding accounts,
prearranged scenes and compromised collectors before claiming co-presence.

A hash of an observer public key is still linkable. Publishing matching edges
on two account logs can reveal who met whom even without an FID in the edge.
Keep raw edges local in the prototype; disclose them only by consent. Anonymous
credentials or other privacy protocols need a design for credential admission,
distinctness, revocation and repeated-witness counting before public deployment.
Blind or group signatures alone do not establish independent people.

The initial reader may say “observation signed by another enrolled credential”
when verified. “Independent person” and a Sybil cost bound require additional
assumptions and measured results. The proposed physical-capture definition should
state adversary capabilities and those assumptions before proposing a theorem.

### 8.6 Input-layer capture follows a feasibility and privacy gate

Keep in-editor capture as the first text surface. Apple's current App Attest
availability excludes keyboard extensions. Test what a keyboard and its host app
can actually share, including biometric key access; report separate results for
each capability. Do not elevate host-app attestation into extension provenance.

A Mac monitoring experiment must be explicitly enabled and bounded to supported
surfaces; never silently monitor all apps. Exclude secure/password input, provide
an obvious recording indicator and stop control, and define retention first.
Timing-only collection cannot bind arbitrary text in another app. A cooperating
editor or a user-controlled publication handoff must establish that relation.
IME, dictation and accessibility input need explicit coverage, not silent loss.

### 8.7 Independent entropy and time, with precise claims

A future beacon client verifies drand signatures under a pinned chain identity
and records the round. A published round is public; deriving an entire future
schedule from one already known round makes it predictable. Combine fresh local
entropy with newly released rounds and state the trusted collector assumption.

A beacon-bound response supports a lower bound on creation of that response;
a verified external commitment receipt supports an upper bound on commitment
existence under the anchor's time/finality rules. Together they do not establish
when every keystroke or frame was captured. Registry receipts and cast
timestamps are not independent time-authority certificates; a chain anchor
is the Base record (§5), built at gates 6–7.

For post-seal frame selection, externally commit the sealed head **before** a
preselected future round is revealed. Merely writing the seal locally before
fetching a round permits backdating and grinding. Multiple candidate commitments
and selective publication still need a bound. Offline capture remains useful
signed evidence, with external freshness explicitly absent.

ENF matching is optional research evidence where a trustworthy reference and
signal exist. It does not by itself prove physical presence on a grid; reference
signals can be relayed or synthesized.

### 8.8 Media and portable manifests

Mac text remains the reference working surface; iPhone is the first physical
media prototype, then Android. Images use short bursts where supported. Evaluate
sensor availability, probe visibility/audibility, response deadlines, power and
accessibility per device. A universal 33 ms response is not yet established.

Run physical checks locally and report their coverage before building expensive
media circuits. Measure screen/speaker replay, injected streams and physical
staging. Separate sampled consistency checks from derivation of the entire
published asset; transcoded files need an explicitly verified edit relation.
An external manifest survives metadata removal but does not make altered pixels
or platform re-encoding match the original hash.

Use C2PA custom assertions as the interoperability target. A valid C2PA claim
also needs conforming asset binding, COSE signing and an acceptable signing
credential. An App Attest certificate is not automatically a C2PA signing
certificate, and a standard viewer need not understand Huma's custom assertions.
Test with an independent viewer; report “compatible”, “trusted signer” and
“Huma assertions verified” separately. Support detached envelopes meanwhile.

Social account integration is removed from the current release. Base is the chain adapter
(§5); no Huma-only server should be required to check already
portable evidence, which is why the proof file must verify offline.

## 9. Deferred network build order and acceptance gates

The current proof-file release scope above comes first. The later network gates
below replace calendar estimates that depend on
unvalidated hardware capabilities. Existing app behavior stays until its new
path passes the relevant gate.

| Order | Deliverable | Evidence that finishes it |
| --- | --- | --- |
| 1 | Evidence contract and reusable verifier | Current RISC Zero and compact fixtures retain their results; shared reports reject swapped content, keys and policy attachments |
| 2 | New signed policy evidence, with attestation on supported devices | Base replay ZK remains required; the extra report does not launch a heavy policy prover; actual manufacturer enrollment checked before an attested label |
| 3 | Feed-side verification | One client/fixture renders checked content/account facts; mismatched text, account and copied badges fail |
| 4 | Opt-in provenance history | Local log then approved publication; duplicate sessions do not inflate counts; missing evidence and key rotation are explicit |
| 5 | Mobile capability spikes | Documented keyboard/host capabilities; two-phone probe measurements; raw witness graph stays private |
| 6 | Beacon window and physical media pilot | Verified rounds/receipts with bounded claims; measured sensor checks and attack outcomes |
| 7 | Portable media manifests and optional ZK upgrades | Independent C2PA reader acceptance; real proofs for named policies with latency, memory and privacy measurements |
| 8 | Hosted originals and Base record | R2 bucket with per-item access; "original is here" link verifies a platform-altered post against the stored master and receipt; each page's single folded proof verified on Base by Huma's Noir verifiers, sent by a host-funded relayer for the wallet bound in the proof; a copied proof can't name another wallet, and a swapped proof fails the reader's own key lookup |

In parallel with implementation, test one customer workflow from §7. Insurance
is the first customer hypothesis, not a proven buyer; do not build insurance,
newsroom and KYC products simultaneously. No customer outreach or public posting
is implied by this plan.

Gate 1's shared contract, existing-proof adapters, Mac export, browser import and
registry transport pass software-fixture acceptance, including a native-export
registry link opened by the browser. Real device release acceptance is
separate. The user also explicitly requested ZK for every content type: build
text policy and image/audio/video relations alongside the report route. Media
§3c governs master commitments, signed display edits and sampled proofs; its
custom re-encoded-edit circuit is deferred. No attestation-only route substitutes
for completion of the requested ZK coverage.

### 9.1 Requirement-to-code coverage

This ledger distinguishes running code, measured experiments and work still
needed. “Experimental” means the named relation actually generated and verified
a proof; it does not imply native product integration or hardware acceptance.

| Requirement | Current implementation/evidence | Remaining work |
| --- | --- | --- |
| Formatted Mac writing with stable characters | `WritingView`, `WritingDocument`, `VerificationText`; native tests | Broader IME, undo and accessibility acceptance |
| Signed input, origin and presence history | `SignedCapture`, `HumanPresence`, `CaptureSigner`; native/Rust checks | Real fingerprint and physical-input attack measurements |
| Existing replay ZK | `zkvm`; old receipts and reader compatibility retained | Current heavier guest's full proof remains uncompleted; app still uses this backend |
| Faster full writing-policy ZK | `assurance-v4.nr`, `assurance.nr`, `assurance-core.mjs`; real 250-character and failed-policy proofs | V4 native capture/worker routing, larger histories, five-second target |
| Shared portable statement/export | `EvidenceEnvelope.swift`, `web/verify-core`; native export/browser registry acceptance | Additional versioned evidence bindings |
| New authenticated collector report | Existing app evidence requires base replay proof | New report contract and admitted app/version association; no weakening of the base proof |
| Media stream commitments | `MediaCapture.swift`; multi-stream signature/blob checks | Actual camera/microphone/motion recording and signed association to media seal |
| Media sampled ZK | `experiments/noir-media/src/main.nr`; PNG/FLAC/AV1 real proofs, shared SDK | Final sample geometry, meaningful scene policies, coverage/soundness analysis |
| Canonical master and decoded root | Experimental encoded hash + decoded Merkle root under a signed seal | Full asset sizes, bit-exact decoder conformance and ZK decoder relation |
| Display edits | Seal reserves edit commitment | Canonical signed edit instructions and verified-master viewer; baked-edit circuit deferred |
| Physical response/probes | Fresh probe nonces in media contract | Sensors/actuators, local feature extraction, calibrated checks, attack bench, ZK relations |
| Future beacon sampling/external time | Reader explicitly reports missing freshness/time | Pinned drand verification, pre-round external anchor, grinding bounds and receipt adapters |
| Media verification distribution | Node/browser SDK verifies exact master + experimental membership | Media file-picker, native proof flow, asset transport, lazy tile pyramid |
| Feed integration | Reusable content-bound facts/missing/failures SDK | Badge consumer and one real client integration with account checks |
| Opt-in history/count ZK | Plan and deduplication requirements defined | Local log, consent, account binding, dedup, time evidence and range/composition proofs |
| Witness/privacy network | Research protocol in docs | Two-phone measurements, signed observations, privacy/admission design and witness ZK |
| Input-layer/mobile clients | Shared core media contract typechecks for iOS | Keyboard/host capability spikes, consented Mac agent, iOS/Android apps |
| Portable C2PA/on-chain/wrappers | Existing detached envelopes verify independently | Conforming credentials/manifests, independent reader, public-proof wrapping/composition and chain verifier |
| Open-source release | Source available locally | License/release, reproducible distribution, signing/notarization and audit |

Acceptance reports: `web/verify-core/acceptance.json`,
`experiments/noir-media/results/acceptance.json` and
`experiments/noir-compact/results/assurance-v4-acceptance.json`. Measurements use
generated software-key fixtures; they do not certify hardware or production
readiness. No score, unique-person count or “everything complete” claim follows.

## 10. Primary references checked for these decisions

- [Apple, Secure your apps with App Attest (WWDC26)](https://developer.apple.com/videos/play/wwdc2026/201/): platform/extension support, app properties, key lifecycle and Mac ACL requirements.
- [Google, standard Play Integrity requests](https://developer.android.com/google/play/integrity/standard): request binding and authenticated verdict decoding.
- [drand cryptography](https://docs.drand.love/docs/cryptography/) and [security model](https://docs.drand.love/docs/security-model/): public randomness under threshold assumptions; the capture-time interpretation above is our protocol analysis.
- [C2PA 2.4 specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html): assertions, asset bindings, signing credentials and reader trust policy.

Nothing above is committed to git until Swayam says so.
