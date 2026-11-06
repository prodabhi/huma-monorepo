# Images, audio and video: proving a camera saw the world, not a screen

Research note for Huma, October 2026. Companion to HUMAN-PRESENCE.md (text).

> **Bigger frame (see VISION.md).** The scene-response proof is one capture's
> evidence. The product is the witness graph it enables: two devices near each
> other record each other's probes, so captures can add witnessed observations
> to a creator's track record. Independent people and relay resistance need
> additional evidence beyond distinct device keys. Version 1
> should ship the physical checks under device attestation and add ZK later
> (VISION §6); the manifest should be C2PA-compatible from day one (VISION §5).
> The paper to write is the "proof of physical capture" definition and an
> assumption-dependent witness-graph Sybil bound (VISION §3). VISION §8–9 governs
> implementation order. Physical-policy results and economic costs below are
> research hypotheses until Huma's own attack bench measures them.

## 1. The problem is not "was it signed". It is the analog hole.

Camera signing now exists: Pixel 10 signs every JPEG with Titan M2 keys at
C2PA Assurance Level 2 ([Google, Sep 2025](https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html));
the iPhone 18 Pro's opt-in Apple Reference Image signs sensor data and keeps an
unalterable reference copy, proprietary rather than C2PA
([Apple, Sep 2026](https://apple.com/newsroom/2026/09/apple-debuts-iphone-18-pro-and-iphone-18-pro-max/)).
Both answer "did a camera of this make sign these pixels". Neither answers the
attack that matters: point the signed camera at a screen showing an AI image,
or play AI audio into the microphone. The April 2026 S-RAHA preprint names it
the Screen-Recaptured Analog Hole Attack and shows moiré/illumination
detectors reach 98.9% on their own test set, which is self-reported and brittle
by the authors' own failure cases ([arXiv 2604.12178](https://arxiv.org/pdf/2604.12178),
[Computer Optics](https://www.computeroptics.ru/KO/PDF/KO47-4/470417.pdf)).
Content-side defences are weaker still: SynthID-Image falls to 100% removal under
advanced attacks in an unreviewed 2026 study ([MarkNull](https://arxiv.org/pdf/2608.10166)),
and the best ASVspoof 5 speech-deepfake detectors go from ~5% EER in-domain to
17–41% on in-the-wild and codec-compressed audio
([ASVspoof 5](https://arxiv.org/html/2601.03944v1), [survey](https://arxiv.org/pdf/2507.01750)).

Text had no physics, so HUMAN-PRESENCE.md had to fall back on biometric
challenges. Media has physics. That is the asset. A generator produces one
stream; a real capture produces many, from independent sensors, that agree with
each other and with the world, and that react when the device pokes the world.

> **Target claim after capture-path and policy validation:** these sensors observed a three-dimensional scene that
> responded to an unpredictable challenge, and the published file is a
> permitted edit of what they saw.
>
> **Claim Huma cannot make:** that the scene was not staged, or that what it
> shows is true.

## 2. Prior work, and the gap

| Work | What it shows | Gap for Huma |
| --- | --- | --- |
| Movee (ACSAC 2013, TMC 2016) and Vamos: accelerometer vs. motion inferred from video, 8% EER ([FIU](https://users.cs.fiu.edu/~carbunar/caspr.lab/liveness.html), [arXiv](https://arxiv.org/pdf/1704.02032)) | IMU–video consistency is a usable liveness signal | Verifier sees the raw IMU; no proof; one sensor pair |
| Face Flashing (NDSS 2018): random screen colours, reflections reveal 3D shape, 98.8% ([arXiv](https://arxiv.org/pdf/1801.01949)) | A nonce can be emitted as light and read back by the camera | Faces only; no provenance binding |
| VoiceGesture (CCS 2017): phone speaker as Doppler radar, ~1% EER against replay ([FSU](https://www.cs.trinity.edu/~stan/pdf/voicegesture.pdf)); EchoPrint (MobiCom 2018): inaudible chirps map 3D face geometry ([NSF PAR](https://par.nsf.gov/servlets/purl/10095814)) | A nonce can be emitted as sound and read back by the mic | Authentication, not recording provenance |
| Vronicle (MobiSys 2022), ProvCam (MobiCom 2024): TEE / camera-module TCB for video ([arXiv](https://arxiv.org/abs/2109.12712), [NSF PAR](https://par.nsf.gov/servlets/purl/10529016)) | The capture pipeline can be attested below the OS | Needs new hardware; phones today expose only App Attest / Play Integrity |
| VerITAS (ePrint 2024/1066), VIMz, zk-Cinema (ePrint 2026/1598), PPAAS for audio (ePrint 2026/1308) ([VerITAS](https://eprint.iacr.org/2024/1066), [zk-Cinema](https://eprint.iacr.org/2026/1598), [PPAAS](https://eprint.iacr.org/2026/1308)) | ZK proofs that a published file is a permitted edit of a signed original; 30 MP image in < 1 h at $2.42 (weak signer) | Prove edits of pixels; nothing about whether the pixels came from the world |
| ProofMode (Guardian Project): sensor metadata, PGP, OpenTimestamps, App Attest / Play Integrity, C2PA ([Guardian Project](https://guardianproject.info/code/c2pa)) | Practical capture-time evidence bundle | Metadata is self-reported and public; no physics checks, no ZK |

Huma's research direction combines attested multi-sensor capture, challenges
emitted into the physical world, and private verification of stream consistency
and published-file derivation. Novelty relative to the literature needs a
systematic review before presenting the combination as a new research result.

## 2a. How each shipped solution is broken, and how cheaply

"Broken" below means: a fake passes the system's own check. Costs are
estimates from the designs; we have not run these attacks ourselves. Where the
attack is a design limit rather than a bug, the row says so.

| System | Its claim | Cheapest attack that passes | Cost | Design limit or bug? |
| --- | --- | --- | --- | --- |
| **ZCAM** (Succinct, Apr 2026): hash raw pixels, sign in Secure Enclave, App Attest binds key to app, C2PA manifest ([Succinct](https://blog.succinct.xyz/introducing-zcam/)) | "Came from a real device, not altered or generated" | Open ZCAM, point the iPhone at a monitor or print showing an AI image, tap. The signature is genuine; the subject is fake | One phone, one screen, seconds | Design limit. ZCAM signs what the sensor saw; it never asks what the sensor was looking at. Second path: on a jailbroken iPhone, hook the camera API with a virtual camera and feed AI frames straight to the app; the enclave signs whatever it is handed, and App Attest is not a jailbreak detector. Succinct itself lists enclave breaks and capture-to-signing middleware tampering as open problems. No public break of ZCAM has been reported; both paths are reasoning from its published design |
| **Pixel 10 C2PA**, **Apple Reference Image** (hardware-signed stock cameras) | "Captured by this camera, this history of edits" | Same re-photograph attack. Second attack: strip the manifest on upload; most platforms do it for you, and under 1% of news images carry C2PA at all ([Reuters Institute via C2PA Viewer](https://c2paviewer.com/articles/apple-reference-image-vs-c2pa)) | Seconds | Design limit. Also: a missing manifest proves nothing, so absence can't be held against a fake |
| **C2PA generally** | A signed chain of custody | Any signer in the trust list vouches for whatever it is fed; software signers (editors, generators) sign AI output as "AI-generated", but a malicious or compromised signer can label anything | Compromise or register one signer | Trust-list policy, not cryptography |
| **Watermarks** (SynthID-Image, Stable Signature) | "Made by our generator" | Regenerate on-manifold or fine-tune the decoder; MarkNull reports 100% removal against SynthID-Image, UnMarker 79% (Google disputes) ([MarkNull](https://arxiv.org/pdf/2608.10166)) | GPU minutes | Bug class: post-hoc marks are removable; and nothing marks images from generators that don't opt in |
| **AI detectors** (image and speech) | "Looks generated" | Blur, compress, add noise: Succinct's own benchmark saw detection fall up to 96%; speech EER 5% → 17–41% in the wild ([ASVspoof 5](https://arxiv.org/html/2601.03944v1)) | Free | Arms race; each generator release resets it |
| **Recapture detectors** (moiré, illumination) | "This is a photo of a screen" | High-refresh OLED, matte print, defocus, or just a photo of a photo on paper; the authors' own failure cases include glare and background misalignment ([Computer Optics](https://www.computeroptics.ru/KO/PDF/KO47-4/470417.pdf)) | A printer | Classifier; evades with ordinary photography |
| **ProofMode** | Capture metadata, signed and notarized | Metadata (GPS, sensors) is written by the app from OS APIs; on a rooted device or with a mock-location provider it is whatever the attacker wants; the signature is honest about dishonest inputs | Rooted phone | Design limit; the signature covers self-reported data |
| **Movee / Vamos** (IMU vs. video) | "Video was shot live on this device" | Record the real IMU while filming a screen that plays the fake with matching camera motion, or stitch (Vamos names the stitch attack) | Camera on a rig, one afternoon | Partial: single sensor pair, no depth, no challenge |
| **Face Flashing, VoiceGesture, EchoPrint** (active probes) | Live 3-D face / live speaker | A 3-D mask or a second human. Not screens | Physical object | These are the strongest primitives; their limit is physical staging |
| **Vronicle / ProvCam** (TEE / camera-module TCB) | Pixels untouched from sensor to file | Same re-photograph attack; the hardware guarantees the pipeline, not the subject | Seconds | Design limit; solves the *other* half (pipeline tampering) that App Attest doesn't |
| **VerITAS / zk-Cinema / PPAAS** (ZK edit proofs) | Published file is a permitted edit of a signed original | Feed a fake signed original (re-photograph) and the proof is valid | Seconds | Design limit; they are correct about edits and silent about origin |

Read down the last column: every shipped product has the same hole, because
every one of them starts after the photons hit the sensor. The research
primitives that look at the world (depth, parallax, light and sound probes,
IMU) were built for face login, not for media provenance, and none of them is
bound to a proof or to a chain of custody in the examples above. Huma aims to
raise the cheapest accepted attack beyond a screen replay; that cost is a
benchmark target, not an established property of the current prototype.

## 3. Design: the scene-response proof

A Huma capture is never a single frame. It is a short, hash-chained,
multi-sensor record with the same clock and the same Secure Enclave key as the
text sessions. Fresh challenge nonces come from the operating system's secure
random generator and are bound to the current chain head and session. A chain
head alone is deterministic and should not be treated as unpredictable randomness.

**Streams** (whatever the device has, each hashed per sample into the chain):
camera frames (all cameras that are on), depth (LiDAR `ARFrame.sceneDepth` on
iPhone Pro, `AVCaptureDepthDataOutput` on TrueDepth, `ImageFormat.DEPTH16` on
Android), IMU (`CMDeviceMotion`: attitude, rotation rate, user acceleration),
microphones, and the probe log.

**Probes** (nonce → physical world → sensors):

1. *Light.* Flash the screen or torch in a nonce-derived colour/intensity
   sequence at random instants. The scene's reflectance change must match the
   sequence in timing and must vary with depth (Face Flashing). A screen being
   re-photographed shows the flash as a flat specular glare, not scene
   illumination.
2. *Sound.* Emit a nonce-coded chirp at 18–22 kHz. The mic must hear the direct
   path plus room echoes consistent with the depth map; a mouth in frame must
   produce Doppler from articulation (VoiceGesture). Played-back audio has no
   articulation Doppler and the wrong echo geometry.
3. *Motion.* Fire the haptic engine with a nonce-timed pattern. The IMU must show
   it; the camera must show the matching micro-shake (Movee's hand tremor,
   made deliberate).

**Consistency checks** (deterministic, published as a versioned policy P):
camera ego-motion ≈ IMU integration (Movee); depth is non-planar and parallax
across frames matches depth; stereo disparity between cameras matches depth;
each probe response arrives within its window and matches its nonce; audio and
video timing agree. Checks are rules, not a classifier, so they can run in the
RISC Zero guest.

**Evaluation and optional proof.** First evaluate the physical policy locally
and bind the report to supported app evidence, as VISION §8.3 specifies. For a
later ZK route, public inputs include the file commitment, the policy version, the device
attestation, and the chain head. Private witness: every stream, the depth maps,
the IMU, the probe timings. The guest proves (a) the chain is intact and signed
at start, at each probe, and at seal; (b) policy P passed; (c) the published
file is a permitted edit (crop, resize, encode, trim) of attested frames, after
VerITAS / zk-Cinema / PPAAS. Nothing but the final media leaves the device.

**Making it tractable.** Proving every frame of a video is far beyond current
budgets (VerITAS: ~1 h for one 90 MB image with a weak signer). So the guest
can check a frame subset committed to the sealed capture. This needs an explicit
sampling policy and soundness analysis: hashing a producer-chosen chain head
allows retries, so it does not by itself make the subset unpredictable to the
producer. An independent challenge or randomness beacon is one option; a local
construction needs a justified bound on grinding and a measured detection rate.
Sampling can reduce consistency-check cost. The permitted-edit proof still needs
to establish the claimed coverage of the entire published file.

## 3a. The rooted-device forger, and what makes it expensive

**How the attack works.** Root an Android phone or jailbreak an iPhone, hook the
camera, depth, motion and microphone APIs (virtual cameras and API hooks are
the standard KYC injection attack; MITRE ATLAS case AML.CS0033 documents a
deepfake fed through a virtual camera into a liveness check, and CEN/TS 18099
now standardises testing for it ([SecurityBrief](https://securitybrief.co.uk/story/mitre-flags-deepfake-kyc-threat-using-face-swap-tools),
[Signzy](https://www.signzy.com/blogs/injection-attack-detection))). Drive the
hooks from a real-time renderer: a game engine or Gaussian-splat scene gives
RGB, a depth buffer, a camera path from which IMU readings follow, and
relighting when the app asks for a flash. The Secure Enclave still signs; it
signs what it is handed.

**The hard truth.** An attacker with full control of the device *is* the
device. No amount of entropy fixes that, because whatever the app sees, the
attacker sees first. Only signing inside the sensor (ProvCam) removes the OS
from the trust base. Until phones ship that, the goal is cost, and four levers
compound.

**Lever 1: make "full control" cost an exploit chain, not a USB cable.**
Require hardware-attested locked state, not just app integrity: Android key
attestation carries a hardware-signed RootOfTrust (verified boot state, device
locked), and since May 2025 Play Integrity's device verdict requires a
hardware-backed verified-boot result on Android 13+ ([Google](https://developer.android.com/google/play/integrity/improvements)).
On iOS require App Attest on a current iOS release. Then an attacker needs one of:

- a leaked attestation keybox. These circulate and Google revokes them through a
  public status list ([Google, 2019](https://security.googleblog.com/2019/09/trust-but-verify-attestation-with.html));
  the cost is a key that dies on first detection, taking every capture it signed
  with it.
- a working exploit chain on a patched OS. Crowdfense's 2024 list priced an iOS
  zero-click full chain at $5–7M and Android at $5M ([SecurityWeek](https://www.securityweek.com/company-offering-30-million-for-android-ios-browser-zero-day-exploits/amp/)).
  Local chains are cheaper but still scarce on current patch levels, and each
  is burned when patched. Require a minimum patch level and raise it.

**Lever 2: public entropy turns offline forgery into live forgery.** Mix the
drand quicknet beacon, which publishes a BLS-signed random value every 3 s from
a federation of independent operators ([drand](https://drand.love/blog/2023/10/16/quicknet-is-live)),
into fresh challenges, and publish the sealed chain head to the proof registry
within a defined window, and to the Base registry per period (VISION §5). A checked
beacon response and registry receipt can bound creation of the response and
existence of the commitment under their trust assumptions;
they do not independently date every sensor frame. One already public round must
not seed a predictable future schedule. A live renderer also sees public entropy.
Probe deadlines, including whether one frame is feasible, need device measurements.
For sampling, externally commit the head before a preselected future round is
released. Multiple candidate commitments and selective publication still need a
grinding bound; a local seal followed by a beacon fetch does not close that gap.

**Lever 3: entropy from the world that independent infrastructure records.**
Mains electricity frequency (ENF) wanders unpredictably around 50/60 Hz, and the
wander is the same across a whole grid at a given moment. It is captured in
audio as hum and in video as light flicker, which a phone's rolling shutter
samples row by row ([Su et al., ICIP 2014](https://www.mast.umd.edu/files/paper_ENF/conf_paper11_ICIP14.pdf);
[Choi et al., IEEE TIFS 2023](https://par.nsf.gov/servlets/purl/10254058)).
Matching it against a grid reference timestamps media forensically
([UMD MAST](https://www.mast.umd.edu/research.php?t=enf)). For Huma, optional ENF
evidence could compare a usable indoor signal with a trusted grid reference.
A matching signal does not require a forger to be on that grid: a reference can
be relayed or synthesized. ENF is not secret (a cheap wall-plug sensor reads it,
and the UMD group's CCS 2012 paper studies forging it ([CCS 2012](https://www.mast.umd.edu/files/paper_ENF/conf_paper2_ACMCCS12.pdf))),
so it is supporting consistency evidence, not proof of location. Outdoors and on battery
lighting it is absent; the verifier says so. Reference databases are thin;
Huma would need its own grid probes or a partner feed.

**Lever 4: make every device key an asset that a single fake destroys.**
- One attested key per device, its public key and every capture's chain head
  appended to a public log (the proof registry now; the Base registry contract per period, VISION §5).
- Revocation should publish an issuer, reason and effective time. Readers flag
  affected captures under a historical policy. A report alone must not revoke
  an identity or erase the validity of every past signature.
- Optional bond: a credential with a separately verified history, or a
  small stake, so a forger loses reputation or money with the device.
- Witnesses can record another device's probe flash and chirp. Different accounts
  and keys alone do not establish independent owners; collusion, self-witnessing
  and remote relays belong in the attack bench.

**Attack-cost hypothesis to measure, when these checks apply:**
(exploit chain or revocable leaked keybox, amortised over captures until
detection) + a real-time multi-sensor renderer that answers unpredictable probes
within the measured deadline + matching available reference signals + loss of
the key's whole history and bond on detection. Compare ZCAM and Pixel/Apple
signing, where the same fake costs one screen and a few seconds. This is not
"impossible", and this note should never say it is. The benchmark should measure
whether the added checks change the cheapest accepted attack; projected exploit
prices are not a measured Huma security bound.

## 3b. Spot-check proofs: verify a few hundred pixels, not millions

Goal: a proof in 5–10 s on a phone that is still sound. Target, not measured.

**Commit, then sample.** At capture the app builds a Merkle tree over the full
original (pixel tiles for images, frames → tiles for video, 20 ms chunks for
audio) with native SHA-256, which takes milliseconds, and signs the root with
the capture key. After seal, the challenge positions come from the first drand
round published after the registry receipt (§3a), so the producer cannot pick
them or retry. The proof opens only those positions: Merkle path (~20 hashes), then the
local check. ~500 samples ≈ 10k SHA-256 compressions plus one P-256 signature,
roughly 1–3 M zkVM cycles, versus whole-image hashing in VerITAS's slow case.

**What sampling catches, and what it misses.** If a forger alters a fraction f
of positions, k samples catch it with probability 1 − (1 − f)^k:

| altered fraction f | k = 460 | k = 4,600 |
| --- | --- | --- |
| 1% (a face, an object) | 99% | ~100% |
| 0.1% | 37% | 99% |
| 0.01% (one digit on a receipt) | 4.5% | 37% |

So plain sampling is enough for the *scene-response* checks (a forger must fake
every frame, since any frame may be drawn) and for large edits, but it is
**not** enough to prove the published file is a faithful edit of the original:
one changed digit slips through. Two fixes, both standard in proof systems:

1. **Random linear check (Freivalds).** The verifier, who holds the published
   file, draws a random vector r after the commitment and computes ⟨r, P⟩
   itself: a single pass in JS, milliseconds for 12 MP. The prover shows
   ⟨Tᵀr, O⟩ equals it for the committed original O and the permitted edit T
   (crop, resize, colour matrix are linear). Any difference, even one pixel,
   is caught with probability ≈ 1 − 1/|field|. Proving an inner product
   against a committed vector is cheap with a polynomial commitment
   (sumcheck-style), not a pixel-by-pixel replay; this is the route efficient
   image-edit systems take. Building it means leaving the plain zkVM for a
   custom circuit; that is the research cost.
2. **Erasure-code amplification.** Commit to a Reed–Solomon extension of the
   original so any small change spreads across about half the coded positions;
   then ~30 samples give 1 − 2⁻³⁰. Same idea as data-availability sampling.
   Works directly on the exact samples of the canonical formats below.

**One accepted format per medium: deterministic, highest quality, made by Huma.**
Huma verifies exactly one format per medium. The app produces it by default,
and the verifier rejects everything else with a plain message. The requirement
is *deterministic decoding*, not losslessness: every conforming decoder must
produce bit-identical samples from the master, so exact equality, Merkle
openings and Reed–Solomon amplification work with no tolerance rule. Image and
audio masters are lossless because they are small enough. Video is the
exception: a lossless 1080p master is 5–7 GB per minute, so the video master is
a fixed high-quality AV1 bitstream, and the committed samples are its *decoded*
output, which the AV1 specification defines exactly in integer arithmetic.

| Medium | Huma canonical format v1 | Samples the proof covers |
| --- | --- | --- |
| Image | AVIF, lossless, 10-bit 4:4:4 (AV1 intra), colour space declared; PNG 16-bit is the fallback if lossless AVIF tooling proves worse | Decoded 10-bit samples |
| Audio | FLAC, 24-bit, 48 kHz, original channel count | Decoded 24-bit PCM samples |
| Video | AV1, 10-bit 4:2:0, fixed high-quality profile (constant quality, ~30–50 Mbit/s at 1080p30), film-grain synthesis off, keyframe every 1 s, in MP4; audio track as the FLAC profile | Decoded 10-bit Y′CbCr samples per frame |

One codec family (AV1 via dav1d) covers image and video, so the verifier ships
one WASM decoder plus FLAC. **Untested and required before shipping:** that
dav1d, libaom and the phone's hardware decoder give identical output for the
chosen profile. AV1 conformance is designed for this; prove it on our files.

Rules that make this explicit:

- **The master is what is verified.** A published Huma item always links its
  canonical master. The badge says "verified master" only for that file.
- **Lossy copies are labelled, never "verified".** JPEG, HEIC, H.264/HEVC,
  AAC and lossy AV1 copies for feeds and previews are allowed, and the badge
  shows them as "preview of a verified master" with a link. Nothing is claimed
  about a lossy copy's pixels; if a platform re-encodes, the claim still points
  at the master.
- **Decode with Huma's decoder, not the browser's.** Browsers colour-manage
  images on canvas and convert video to RGB on the GPU, so the values differ by
  device. The verifier decodes PNG, FLAC and AV1 with bundled WASM decoders and
  checks samples in the file's own colour space (Y′CbCr for video).
- **Edits stay in the format.** Permitted edits (crop, trim, resize, colour
  matrix) produce a new canonical master plus a proof that it derives from the
  captured one. Exporting to any other format leaves Huma's verified chain.
- **Versioned.** The format list is part of the policy version. Changing
  codec, bit depth or container is a new version, never a silent change.

Cost, stated plainly, unmeasured: a 12 MP lossless 10-bit AVIF is ~15–30 MB;
a minute of 24-bit FLAC ~10 MB; a minute of 1080p30 AV1 at 30–50 Mbit/s is
~220–380 MB, 15–25× smaller than the lossless master this note first proposed,
with no loss of verifiability. Masters are stored once (registry, IPFS) and
fetched only for full verification; the badge needs only the proof and the
preview.

**Cost estimates after the §3c pass.** Rough targets for GPU proving on the
user's phone or Mac. † marks a measured figure; everything else is unmeasured.

| | Text (1 session) | Photo (12 MP) | Audio (1 min) | Video (1 min, 1080p30) |
| --- | --- | --- | --- | --- |
| Prove on device | ~5–15 s (compact prototype: 4.3 s†) | ~5–15 s (~500 Merkle openings + ~64 sampled scene tiles; no linear check) | ~10–30 s (sampled chunks + chirp-window DSP) | ~30–60 s (sampled frames + probe windows + IMU match) |
| Wrap to ~1 KB (off-device, optional) | ~1–2 min on a Mac or service | same | same | same |
| Badge check in browser | ~0.2 s† (succinct) / ~10 ms (wrapped) | same | same | same |
| Full check of the master | same as badge | ~0.5 s: fetch and decode only the shown tiles | ~0.5 s: decode 10 MB FLAC | ~5–10 s: fetch keyframe-aligned sampled segments, decode, re-run sampled checks |
| Proof size | ~590 KB† today; ~1 KB wrapped | ~0.5 MB; ~1 KB wrapped | same | same |
| Master file | KBs | ~15–30 MB (lossless AVIF) | ~10 MB (24-bit FLAC) | ~220–380 MB (deterministic AV1 at 30–50 Mbit/s) |
| Capture overhead | none | ~0.2 s: encode, decode once, hash tiles | real-time chain; ~0.1 s post-capture Merkle | real-time chain over encoder output; post-capture decode + Merkle ~5–10 s for 1 min (hashing ~190 MB/s of decoded 4:2:0, far below the hardware SHA-256 rate) |
| Edits (crop, trim, resize, colour) | n/a | 0 s: signed edit list | 0 s | 0 s |

Basis: the text policy guest runs ~4.7 M cycles†
(`../backend/zkvm/tests/results/presence-media-acceptance.json`), the compact prototype
proved a short session in 4.344 s†, and the replay receipt verifies in the
browser in ~0.2 s† (`../backend/zkvm/tests/browser-verifier.mjs`). The 5–15 s text target
assumes GPU proving and a binary witness replace the stopped 14-minute CPU run.
Photo drops to the text range because §3c removes the linear check and the
whole-image hash: what remains is ~10k SHA-256 compressions and the sampled
tile checks. Audio and video stay highest because their sampled checks are
signal processing (chirp echo, Doppler, IMU-versus-motion), not hashing; those
are the least certain numbers. Full video verification no longer decodes the
master: it fetches only the keyframe-aligned segments that contain the sampled
frames (1 s keyframes, so ~500 samples touch at most ~500 of 60 segments) and
repeats the sampled checks. The 1 KB wrap time is RISC Zero's STARK-to-SNARK
step on x86, which we have not run on our receipts.

Consequences: all four media now verify in well under a second on the feed and
in seconds for a full check. Proving fits inside the time a user already spends
sealing a capture. The remaining large number is the video master's size, so
v1 keeps the 1080p, one-minute cap and stores masters once. Replace each
estimate with a measurement as the build order (§8) reaches it.

**Per medium.**
- *Image:* tiles of 16×16; scene checks on ~64 sampled tiles (depth
  non-planarity, light-probe response); edits carried as a signed edit list (§3c).
- *Video:* per-frame Merkle roots chained in time; sample frames, then tiles
  within frames; IMU-vs-motion on sampled frame pairs; every probe window is
  checked in full (they are few and short).
- *Audio:* 20 ms PCM chunks; sample chunks for echo/Doppler consistency; every
  chirp window in full; trims carried as a signed edit list (§3c).

**Verifier cost.** Unchanged in kind: one proof check plus, for the linear
check, one pass over the published file. Still well under a second on a phone.

## 3c. Second-pass audit: what got cheaper, what got safer

A re-read of §§3–3b and VISION §8 against each other. Each item names the
change, why, and what it costs.

**1. Edits as instructions, not re-encodes.** The hardest piece in §3b, the
random linear check in a custom circuit, exists to prove that a re-encoded
crop or resize matches the master. Drop the re-encode. Permitted edits (crop
rectangle, trim range, resize factor, colour matrix, rotation) are stored as a
signed *edit list* in the manifest, and viewers apply them to the master at
display time, the way raw-photo editors work. There is nothing to prove: the
master is verified, the edit list is public and signed, the viewer renders.
Lossy copies remain previews. Effect: removes the custom-circuit research from
v1 entirely, and removes a class of bugs with it. Keep the linear check for a
later "baked export" feature only.

**2. Two commitments at capture.** A live hash chain over the encoder's output
chunks (streams, costs nothing, signed at probes and seal) plus, after
recording stops, one Merkle tree over the *decoded* tiles of the finished
master, signed at seal. The chain binds time and probes; the tree is what the
spot-check proof opens. Decoding once after capture takes seconds and avoids
needing the hardware encoder's reconstruction, which VideoToolbox does not
expose. Both roots go in the envelope.

**3. Deterministic high-quality video instead of lossless.** §3b's table now
says this. The security property was never losslessness; it was that the
verifier and the prover see the same samples. 15–25× smaller masters, same
exactness, one decoder family. The cost is the conformance test in §3b.

**4. Spot-check sampling is sound for the threat it faces.** Small spliced
fakes evade sampling (§3b's table) only if the attacker can rewrite frames,
which on a stock, locked phone they cannot: the app signs the chain. The
attacker who can rewrite frames is the rooted-device renderer of §3a, and for
them every frame is rendered anyway, so sampling does not lower their cost.
For the stock-device case sampling only needs to make the *app's own* checks
honest, which attestation already covers. Conclusion: set k by budget, not by
splice size, and say in the verifier "N frames checked in proof; all frames
checked on device".

**5. Groth16 wrapping is privacy-safe off-device.** A 1 KB proof needs the
STARK-to-SNARK wrapper, which RISC Zero runs in an x86 container, not on a
phone. Sending the succinct receipt to a wrap service leaks nothing: the
receipt is already zero-knowledge and public. So: prove on the device, wrap on
a Mac or a service, publish 1 KB. The private witness never moves.

**6. Batch and compose.** A person's many captures do not need many proofs
on the feed. RISC Zero composition lets one proof attest N receipts, so the
track record (VISION §8.4) is one proof per period, not per capture. Cost per
capture falls with volume; nothing changes in security.

**7. Tiles double as lazy loading.** The Merkle tiles of an image master are
also a tile pyramid: a viewer applying a crop (item 1) fetches and verifies
only the tiles it shows, each against the signed root. Full verification of a
cropped region costs the region, not the master.

**8. Probe actuators, corrected.** The screen cannot light a scene behind the
phone. Rear captures use the torch LED for the light probe; selfie captures
use the screen. Chirps at 18–22 kHz sit where phone speakers roll off; measure
per device and fall back to 15–18 kHz with a note in the envelope. Haptic +
IMU is the cheapest probe and should fire most often.

**9. Where the proof money goes now.** With items 1–3, a photo proof is ~500
Merkle openings plus the sampled scene checks; the linear check and the
whole-image hash are gone. Target stays 5–10 s but with fewer unknowns. Video
remains dominated by DSP on sampled windows; audio by chirp analysis.

| | Before this pass | After |
| --- | --- | --- |
| Video master, 1 min 1080p | 5–7 GB lossless | 220–380 MB deterministic AV1 |
| Edit-fidelity proof | Custom sumcheck circuit (research) | None needed; signed edit list |
| Proof publication | 590 KB on device | 1 KB after off-device wrap, witness stays local |
| Per-capture proof cost on the feed | One proof each | One composed proof per period |
| Decoders in the verifier | PNG + FLAC + AV1 | dav1d (image and video) + FLAC |
| Open conformance risk | Browser colour management | Decoder bit-exactness test, once |


## 4. What each attack has to do now

| Attack | Why it fails, or what it costs |
| --- | --- |
| AI-generated image/video/audio | No sensor streams, no probe responses. Must be re-captured, which becomes the next row |
| Screen or speaker replay (analog hole) | Flat depth, no parallax, glare instead of illumination response, no articulation Doppler, echo geometry of the room not the scene. Each is a separate check; all must be fooled at once |
| Injected sensor data on a rooted/jailbroken device | Test evasion of enrollment, live rendering, deadline compliance and available reference checks. Cost depends on the accepted platform policy and measured attacks; the OS remains in the capture trust base |
| Physical rig: a 3D set, mannequin, or actor performing the fake | Passes. That is a staged real capture, which is exactly the claim's limit. Cost: a physical production per fake |
| Stripped metadata on upload | A detached envelope can remain available. Platform transcoding still changes bytes and requires a checked derivation relation or newly bound published asset |

## 5. Per-platform reality

| | Mac | iPhone | Android |
| --- | --- | --- | --- |
| Device/app attestation | App Attest on supported macOS 27+ systems; editor minimum remains macOS 14 | Supported App Attest app types; keyboard extensions excluded | Play Integrity + Keystore attestation (`userAuthType`, StrongBox) |
| Vendor camera signing | None | Apple Reference Image, iPhone 18 Pro Reference mode, opt-in; confirmed by Apple; Huma integration pending | Pixel 10 JPEG C2PA (confirmed); Pixel video C2PA is reported by one directory only, unconfirmed |
| Depth | None | LiDAR (Pro), TrueDepth (front) | `DEPTH16` on ToF-equipped devices; varies by OEM |
| IMU | None on laptops | Yes | Yes |
| Probes available | Light, sound | Light, sound, haptic | Light, sound, haptic |

The Mac can do light and sound probes with the FaceTime camera and mic but has
no IMU or depth, so its media claim is weaker; the phone is the primary media
device. Huma's text story stays Mac-first; media is phone-first.

## 6. Images are short videos

A Huma photo is a 1–2 s capture: a frame burst, depth, IMU and one light probe.
The user picks a frame; the proof shows that frame is a permitted derivation of
the attested burst and that the burst passed P. This costs nothing visible to
the user and turns the hardest medium (one frame has no motion to check) into
the easiest.

## 7. Honest limits

- A real recording of a staged scene passes. Huma proves capture, not truth.
- Accuracy numbers above are each lab's, on each lab's data; none are Huma's
  until measured with ISO/IEC 30107-3 metrics (APCER, BPCER at a stated
  threshold) against: screen replay, speaker replay, injected sensors on a
  rooted device, and a physical rig.
- Depth and probes assume the subject is within a few metres. Landscapes get
  only IMU–parallax and light-probe-on-nothing; the verifier must show which
  checks applied.
- Proving cost is unmeasured for Huma's guest. Expect minutes per short clip at
  first; sampling is the lever.

## 8. Build order

This is the media-specific research sequence under VISION §9, after the shared
evidence contract. Start with collector reports; ZK is an optional later upgrade.

1. iPhone capture prototype: camera + LiDAR + IMU + mic into the existing hash
   chain, with light, chirp and haptic probes at nonce-chosen instants. Record
   everything; no proof yet.
2. Attack bench: re-photograph a screen, replay audio through a speaker, and a
   jailbroken-device injection. Measure APCER/BPCER for each check alone and
   combined. Publish the numbers.
3. Local physical policy P v1 with coverage and an authenticated collector report.
   Then evaluate optional ZK over a specified sample set; measure proving time
   and sampling soundness before selecting a backend.
4. Permitted-edit proof for the published file (crop/resize/encode), starting
   from VIMz or zk-Cinema techniques.
5. Verifier page: per-check lines ("depth non-planar", "light probe answered
   3/3", "IMU matches camera motion") plus the fixed sentence "Huma proves this
   was captured, not that it is true".
6. Android port (DEPTH16 where present, Play Integrity server flow); Mac
   light/sound-only mode last.

## 9. Implementation status, October 23

`../extra/Sources/HumaCore/MediaCapture.swift` implements the shared Mac/iOS media session
contract: image/audio/video kinds; camera, depth, motion, microphone and probe
streams; bounded byte commitments; ordered elapsed readings; signed start/probe/
seal checkpoints; and fresh random probe nonces bound to the session head.
Verification requires the actual committed blobs and every signature. Optional
expected-key checking uses a key supplied independently by the reader.

The contract passes synthetic Mac tests for save/reopen, altered headers, stream
removal, altered blobs, wrong keys, time rollback, capacity, sealing and fresh
nonces. It also typechecks against the installed iOS SDK. These tests use
disposable software keys and generated bytes, without accessing cameras,
microphones, motion sensors or real device credentials.

`../extra/experiments/noir-media/` now adds a real **experimental ZK membership layer**.
One fixed 768,921-gate circuit proves two challenge-derived decoded-byte openings
under a signed master seal. PNG16, FLAC24/48 kHz and AV1/10-bit generated fixtures
all produce and independently verify real proofs with the same pinned key. Proof
generation took 7.060/7.044/7.103 seconds on two threads; native composite
verification, including signatures and master hashing, took about 53–58 ms.
These are tiny fixtures and single runs, not full-length capture benchmarks.

The fixed tree has 256 leaves, each at most 3,072 bytes. SHA-256 domains bind
kind/profile, session nonce, capture head, encoded hash/length, decoded root/
length, edit/layout roots and leaf count. Selection uses the complete 256-bit
hash reduced modulo leaf count. Sampling is with replacement; readers report
both opening count and unique selected leaves. Global decoded length is sealed
and range checked; this relation does not sum all private leaf lengths.
Every seal's P-256 signature is mandatory alongside the proof.

The shared `../frontend/verify-core` Node/browser SDK compares independently supplied
encoded master bytes and verifies these proofs locally. It rejects altered
files, public inputs, proofs, signatures, keys and unsupported claims. Public
exports contain no openings or private witness. Nineteen witness checks cover
changed paths, padding, challenge selection and unsupported bounds. The master
input limit in this reader is 32 MiB.

This first layer uses generic decoded-byte chunks rather than the final tile/
frame/audio-block geometry. Encoding/decoding happens outside the circuit; the
encoded-to-decoded association is signed. Capture heads are synthetic fixture
markers, the edit root denotes an empty fixture list, and challenges are local
test values. **Decoder correctness, live capture-chain association, signed
display edits, physical-response policies and externally anchored sampling are
still to build and are not claimed by these proofs.** A caller-specified matching
challenge is not itself verified beacon freshness.

The iPhone sensor recorder/probe actuators, Android client, C2PA, physical-policy
attack measurements, tile pyramid, period/witness composition and mobile/on-chain
proof acceptance remain subsequent work. The custom baked-edit circuit stays
deferred under §3c; signed display instructions remain the v1 edit direction.

## Sources

- Google Security Blog, Pixel 10 C2PA Content Credentials (2025). https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html
- Apple Newsroom, iPhone 18 Pro / Apple Reference Image (Sep 2026). https://apple.com/newsroom/2026/09/apple-debuts-iphone-18-pro-and-iphone-18-pro-max/
- S-RAHA, screen-recaptured analog hole (arXiv 2604.12178, 2026). https://arxiv.org/pdf/2604.12178
- Screen recapture detection, Computer Optics 47(4). https://www.computeroptics.ru/KO/PDF/KO47-4/470417.pdf
- MarkNull, SynthID-Image removal (arXiv 2608.10166, unreviewed). https://arxiv.org/pdf/2608.10166
- ASVspoof 5 overview (arXiv 2601.03944). https://arxiv.org/html/2601.03944v1
- Generalizable Detection of Audio Deepfakes (arXiv 2507.01750). https://arxiv.org/pdf/2507.01750
- Rahman, Topkara, Carbunar, Seeing is Not Believing / Movee (ACSAC 2013; IEEE TMC 2016). https://users.cs.fiu.edu/~carbunar/caspr.lab/liveness.html
- Video Liveness for Citizen Journalism (Vamos). https://arxiv.org/pdf/1704.02032
- Tang et al., Face Flashing (NDSS 2018). https://arxiv.org/pdf/1801.01949
- Zhang, Tan, Yang, VoiceGesture (CCS 2017). https://www.cs.trinity.edu/~stan/pdf/voicegesture.pdf
- Zhou et al., EchoPrint (MobiCom 2018). https://par.nsf.gov/servlets/purl/10095814
- Liu et al., Vronicle (MobiSys 2022). https://arxiv.org/abs/2109.12712
- Liu et al., ProvCam (MobiCom 2024). https://par.nsf.gov/servlets/purl/10529016
- Datta, Chen, Boneh, VerITAS (ePrint 2024/1066). https://eprint.iacr.org/2024/1066
- Frolov et al., zk-Cinema (ePrint 2026/1598). https://eprint.iacr.org/2026/1598
- PPAAS, privacy-preserving audio provenance (ePrint 2026/1308). https://eprint.iacr.org/2026/1308
- VIMz regional transformations (ePrint 2025/1024). https://eprint.iacr.org/2025/1024
- Guardian Project, ProofMode and C2PA. https://guardianproject.info/code/c2pa
- Apple, ARFrame.sceneDepth. https://developer.apple.com/documentation/arkit/arframe/scenedepth
- Apple, AVCaptureDepthDataOutput. https://developer.apple.com/documentation/avfoundation/avcapturedepthdataoutput
- Apple, CMDeviceMotion. https://developer.apple.com/documentation/coremotion/cmdevicemotion
- Android, ImageFormat.DEPTH16. https://developer.android.com/reference/android/graphics/ImageFormat#DEPTH16
- ISO/IEC 30107-3 PAD metrics (via vendor summaries; consult the standard). https://ppc.land/liveness-detection/
