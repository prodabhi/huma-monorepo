# Human presence: a design that bots cannot script, and what it still cannot prove

Research note for Huma, October 2026. Companion to README questions 39–42.

> **Bigger frame (see VISION.md).** The layers below are per-session
> mechanisms. Their value compounds only when every session appends to a
> person's provenance log and when presence challenges can be *witnessed* by
> another person's device. Read "presence challenge" below as the building
> block of a track record, not as the product. Capture should also move to the
> input layer (keyboard extension, input-monitoring agent) so these mechanisms
> cover typing in every app, not only Huma's editor.
>
> **Implementation order:** [VISION.md §8–9](VISION.md#8-engineering-decisions-under-this-vision)
> governs the current plan: shared evidence and authenticated collector reports
> first, optional ZK computation next. The RISC Zero design below describes the
> existing proof path; it is not a requirement to prove every future capture.

## 1. The claim we can make, and the claim we cannot

A zero-knowledge proof shows that a private trace satisfies a published rule set.
It never shows who produced the trace. If a script can produce a trace that
satisfies the rules, the script gets a valid proof. This is not a weakness of
ZK; it is what "proof" means. Three results fix the boundary:

- **Keystroke timing is a biometric.** TypeNet reaches a 2.2% equal error rate
  on physical keyboards and 9.2% on touchscreens, identifying people from 50
  keystrokes across 100,000 subjects ([Acien et al. 2021](https://arxiv.org/abs/2101.05570)).
  So raw timings must never leave the device. This is the privacy case for ZK,
  and the premise of ZK-PoP ([Condrey 2026](https://arxiv.org/abs/2603.00179)).
- **Synthetic keystrokes are realistic.** BeCAPTCHA-Type generates keystroke
  data that detectors catch only with large labeled sets; in few-shot settings
  detection "represents an important challenge" ([DeAlcala et al., CVPRW 2023](https://openaccess.thecvf.com/content/CVPRW2023/Biometrics/html/DeAlcala_BeCAPTCHA-Type_Biometric_Keystroke_Data_Generation_for_Improved_Bot_Detection_CVPRW_2023_paper.html)).
  A behavioral rule set is therefore a cost, not a wall.
- **Device attestation is not humanity.** Apple's Private Access Tokens attest a
  genuine device and account in good standing; the Privacy Pass architecture
  (RFC 9576) only transports "the client satisfied the attester". hCaptcha's own
  position: controlling hardware does not make you a person
  ([hCaptcha](https://hcaptcha.uth.edu/blog/announcing-support-for-private-access-tokens),
  [Educated Guesswork](https://educatedguesswork.org/posts/private-access-tokens/)).

So the design goal is not "prove a human typed every key". It is:

> Make an accepted fake require a real, enrolled human at a genuine device,
> answering unpredictable hardware challenges during the session, with every
> input event recorded with its origin. Then say exactly that, and no more.

That turns bot farms into human-attention farms, which is the economic result
README question 42 asks for.

## 2. Four layers, each with a named guarantee

| Layer | Mechanism | What it proves | What it does not prove |
| --- | --- | --- | --- |
| **A. Genuine device and app** | Supported App Attest (Mac/iOS); Play Integrity + hardware key attestation (Android) | Supported app/key properties and a checked binding to the capture; App Attest and biometric capture keys are separate | Human presence or the truth of a policy result; collector behavior and key association still matter |
| **B. Live human at unpredictable moments** | Biometric-gated signing key signs the hash-chain head at random times, each with a nonce and a response deadline | An enrolled finger/face was at the device at those instants and bound to this exact session | That the same person typed between challenges ("human taps while a script types") |
| **C. Input provenance** | Record available OS source metadata; calibrate its interpretation with physical and injected input | Which source fields the OS reported | A reliable physical-vs-injected verdict before testing, or resistance to virtual HID and USB injectors |
| **D. Private behavior evaluation** | Deterministic rules over the same trace; authenticated collector report first, optional ZK | Either what the trusted collector reported or what the proof independently checked, explicitly distinguished | That a matching pattern was not replayed or generated (BeCAPTCHA-Type) |

Layer B targets an unattended script when the key's biometric gating is trusted.
Layers A, C and D add provenance and policy evidence. All four must bind to the same
hash chain, or an attacker proves rules over one trace and submits another
(README question 40).

## 3. Layer B in detail: presence challenges

Huma already has the primitive: a Secure Enclave P-256 key created with
`.privateKeyUsage` and `.biometryCurrentSet` (`../extra/Sources/HumaCore/TouchIDCaptureKey.swift:80-84`).
Apple's rule for that flag: Touch ID or Face ID must be enrolled, and the key is
invalidated if the enrolment set changes ([Apple](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)).
Today it is used twice, at start and at seal (`../extra/Sources/Huma/WritingView.swift:479,493`).
Durability checkpoints every 256 records or 10 s are separate and unattended
(`../extra/Sources/HumaCore/CheckpointCadence.swift:6-7`).

Proposed protocol:

1. **Schedule.** Draw challenge times from a memoryless distribution (mean
   10–15 min, floor 3 min) so a script cannot predict them. Always challenge at
   seal.
2. **Challenge.** At time t, freeze the chain head H, draw a nonce n, show the
   Touch ID / Face ID sheet with the reason "Confirm you are still writing".
3. **Response.** The Secure Enclave key signs (H, n, t, session id). Record the
   wall-clock and elapsed time to answer. A fresh prompt is required: the
   `LAContext` reuse window defaults to 0 ([Apple](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration));
   keep it at 0 and create a new context per challenge. Whether Secure Enclave
   signing honors a non-zero reuse window is an open question on Apple's forums;
   do not rely on it either way.
4. **Policy.** Missed or slow (> 10 s) challenges are recorded, never hidden.
   The verifier shows "6 of 6 challenges answered, median 1.8 s" or "2 missed".
5. **Binding.** Each challenge signature goes into the chain as a record, so the
   replay proof covers it and App Attest's assertion covers the whole chain.

Android equivalent: a Keystore key with
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (fresh biometric per
use), used through `BiometricPrompt` with a `CryptoObject` so the result is
bound to the key operation rather than a callback that can be hooked
([OWASP MASTG](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/)).
Request StrongBox where available. The key attestation certificate's
authorization list carries `userAuthType [504]`, `authTimeout [505]` and
`noAuthRequired [503]` ([AOSP key attestation](https://source.android.com/docs/security/features/keystore/attestation)),
so a verifier can check that the key really demanded biometrics, not trust the
app's word.

Residual risk: an operator who presses the sensor while automation types. The
challenge cadence makes that cost one attentive human per device per session.
Measure it; do not claim it is impossible.

## 4. Layer C per platform: input provenance

**macOS.** Every `NSEvent` exposes its `CGEvent`. Two fields identify origin:
`CGEventField.eventSourceUnixProcessID` ("the event source Unix process ID") and
`eventSourceStateID` ("the event source state ID used to create this event")
([Apple](https://developer.apple.com/documentation/coregraphics/cgeventfield/eventsourceunixprocessid)).
Hardware events come through the HID system state table
(`CGEventSourceStateID.hidSystemState`, "all hardware event sources posting from
the HID system"). Software that posts events creates its own source: Zed, for
example, synthesizes keystrokes with a private source state
([Zed source](https://git.secluded.site/zed/blob/v0.156.1/crates/gpui/src/platform/mac/events.rs)).
Posting also needs the user-granted PostEvent privilege, shown as Accessibility
in System Settings ([Apple DTS](https://developer.apple.com/forums/thread/820594)).
Huma records both origin fields and the keyboard type with every key sample
(`../extra/Sources/Huma/RichTextEditor.swift:247-249`), and while recording it drops any key
whose event doesn't carry PID 0 and the HID state (`../extra/Sources/HumaCore/HumaTextView.swift:39-47`).

**Tested (29 Oct 2026, macOS 27, MacBook Pro M4 Max):**
- Real typing on the built-in keyboard passes: every page written on this Mac
  counts as typed.
- A program can write PID 0 and the HID state into an event in memory, but
  when it sends the event macOS replaces the PID with the sender's own. All four
  forgeries arrived refused. The test sends only to its own process:
  `testKeysSentByAProgramAreRefusedEvenWhenTheyClaimToBeTheKeyboard` in
  `../extra/Tests/HumaCoreTests/HumaTextViewTests.swift`.
- The state field alone can be forged, so the PID is what the check rests on.

**Untested:** events sent at the HID tap with `CGEventPost`, and AppleScript
`keystroke`. Both would type into the app in front, so they need a test Mac.
Also untested: a Karabiner virtual device and a USB injector. Virtual HID
drivers and USB injectors look like hardware. They are layer B's problem, not
layer C's.

**iOS.** There is no API to inject input into another app on a stock device.
Automation needs a jailbreak or an XCTest runner attached to a development
build, so App Attest plus a release build already excludes the cheap paths.
App Attest is not a jailbreak detector and about 0.2% of honest users fail it
([Apple forums](https://developer.apple.com/forums/thread/731968), [Swift Rocks](https://swiftrocks.com/app-attest-apple-protect-ios-jailbreak)).
Record `UITouch.majorRadius` and `force` per touch as soft signals
([Apple](https://developer.apple.com/documentation/uikit/uitouch/majorradius)); I found no
source on how test-injected touches differ, so treat this as data to collect,
not a rule.

**Android.** Three signals, none sufficient alone:

- `KeyEvent.getDeviceId() == KeyCharacterMap.VIRTUAL_KEYBOARD` (-1). CTS enforces
  that injected events carry -1 "to avoid misrepresentation of physical
  hardware" ([AOSP CTS](https://android.googlesource.com/platform/cts/+/faaa97629a6)).
  But soft keyboards (IMEs) also use the virtual keyboard, so on a phone this
  only separates physical keyboards from everything else. Record the IME
  package instead and whether it is a known keyboard.
- `MotionEvent.FLAG_IS_ACCESSIBILITY_EVENT` (Android 12+) marks touches injected
  by accessibility services ([AOSP](https://gerrit.omnirom.org/plugins/gitiles/android_frameworks_native/+/f00a4ec687e2bf9110106238c7738927fc3e87d7%5E%21)).
- Play Integrity's `appAccessRiskVerdict` reports KNOWN/UNKNOWN_CONTROLLING when
  an app that can control input is running
  ([Google](https://developer.android.com/google/play/integrity/app-access-risk)).
  Request it at session start and at seal; include the server-decoded verdict
  in the evidence.

## 5. Layer D: rules inside the proof, not a classifier outside it

Keep the first policy deterministic and small: inter-key interval bounds,
dwell bounds, a minimum pause count, a maximum sustained rate, and that the
text grew by insert/delete edits rather than one paste. Evaluate it in the
RISC Zero guest over the signed capture records already in the proof, so the
public output is "policy P v1 satisfied" and the timings stay private. This is
what ZK-PoP proposes with Groth16 and Pedersen commitments; Huma does not need
a second proof system for it. zkSENSE is the precedent that an on-device
classifier can be proved in ZK (92% accuracy on motion sensors, Android, code
marked not production-ready) ([PoPETs 2021](https://petsymposium.org/popets/2021/popets-2021-0058.php)).
A learned model in the circuit is a later step and must be benchmarked against
BeCAPTCHA-Type-style synthetic traces before it is called a detector.

**Measured** by `typing_checks_catch_machine_timing_but_not_imitation` in
`../extra/experiments/noir-compact/native/src/long.rs`, against the nine shipped rules:

| Fake typist | Result |
| --- | --- |
| Plain script (no key holds, 500 keys a second) | Fails four checks |
| Macro at a fixed 25 keys a second | Fails two checks |
| Steady bot at human speed | Fails only the pause check |
| About ten lines that copy human timing | Passes all nine |

The checks show the timing is one a person could type with. They don't show a
person typed.

## 6. Images, audio and video

For captured media, the hardware path already exists on one platform: Pixel 10
signs every photo with C2PA Content Credentials using Titan M2 keys and a
secure clock, at Conformance Assurance Level 2 ([Google](https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html)).
Apple's iPhone 18 Pro Reference mode now signs sensor data and provides a
reference image; its public announcement describes viewing APIs, not a ready-made
Huma verification integration ([Apple](https://www.apple.com/newsroom/2026/09/apple-debuts-iphone-18-pro-and-iphone-18-pro-max/)).
Huma should consume a C2PA manifest as capture evidence where one exists and
otherwise sign its own capture with the layer A/B keys, with the same honesty:
"captured in Huma on this device, human present at these times".

## 7. What the verifier should show

Four lines, each tied to the evidence actually checked:

1. Device: "Apple app identity, allowed version and bound assertion checked", when available (A).
2. Presence: "6 timely signed responses; longest reported gap 14 min"; name Touch ID only with trusted biometric-key provenance (B).
3. Input: "1,284 samples report HID system state"; classification remains experimental (C).
4. Behavior: "Policy v1 passed — collector report" or "Policy v1 passed — ZK checked", as supported (D).

Then one fixed sentence: "This does not prove that the person composed every
word." Keep README's rule: no score until calibrated.

## 8. Build order for Huma

The numbered list below is the original mechanism sequence. The shared
contract, fast report and network gates in VISION §9 now take precedence.

1. Record `eventSourceUnixProcessID`, `eventSourceStateID` and keyboard type per
   sample; run the four-source experiment (typing, `CGEventPost`, virtual HID,
   USB injector) and write down what each looks like. One day.
2. Presence challenges on the existing Touch ID key, with the schedule and
   deadline above, recorded in the chain and shown by the verifier. Two to three days.
3. Policy v1 in the RISC Zero guest, output as a public flag. Then measure proof
   time against the current 590 KB receipt.
4. Mobile: iOS first (same keys, App Attest), then Android (Keystore per-use
   biometric key, attestation parsing, Play Integrity server flow).
5. Attack bench: human-taps-while-script-types, replayed real traces,
   BeCAPTCHA-Type synthetic traces. Publish cost per accepted fake.

## 9. Mac implementation status, October 23

The Mac implementation now records source PID, source state, keyboard type and
repeat status in each available key sample. A versioned sample digest binds all
four values into the existing signed capture chain. The public report exposes
aggregate HID-state/other-state/missing coverage. These are OS-reported facts.
The physical-keyboard and posted-event (to a process) parts of the experiment
were run on 29 October (§4). The HID-tap, virtual-HID and USB parts are still
needed before treating these facts as physical-input classifications.

Presence uses append-only challenge and response records, a 32-byte random nonce,
the frozen capture head, session ID and device-reported elapsed readings. The
editor pauses while a challenge is pending. Fresh LAContexts explicitly set reuse
to zero. Cancelled/timed-out responses stay in history; an unresolved or late
seal cannot produce a completed presence session. The schedule has a three-minute
floor and a 12.5-minute mean. Local scheduling is not independently attested
randomness. Existing start approval remains separate from the reported interval
and seal challenge counts.

The V3 RISC Zero guest verifies every presence signature with the same capture
key and evaluates `huma-writing-rules-v1` from the authenticated private trace:

- Empty initial text and nonempty edits all labeled typing.
- At least 20 seconds of device-reported duration and 30 non-repeat key downs.
- No invalid key-pair sequence; at least 90% of downs paired with an up.
- At least 90% of paired dwell times between 10 and 2,000 ms.
- At least 90% of consecutive down intervals between 5 and 30,000 ms.
- At least one inter-key pause of 500 ms and no more than 20 non-repeat downs
  in a rolling half-open 1,000 ms window.

These illustrative rules are explicitly experimental. A regular synthetic trace
in the tests satisfies them; this is not a trained detector or a humanity score.
IMEs, accessibility input, lost key-up events and typing styles need evaluation
before stronger policies are selected. Median latency currently means the upper
middle approved response for an even number of responses.

The Mac and browser readers show source coverage, timely/missed responses and
policy results separately from cryptographic validity. The old V2 reader remains
supported. The original fast V3 Noir profile does not carry these new fields;
the native compact adapter refuses to omit them and retains the RISC Zero route.
The separate experimental V4 circuit now proves replay, origin commitments,
presence accounting and the nine writing rules. A real 250-character proof
(500 key events, four checkpoints, two approved responses) verifies in the shared
Node/browser SDK and through the browser registry reader. Every checkpoint and
approved response signature remains mandatory outside the SNARK. A second real
proof correctly reports a failed rate policy. Twenty-two witness checks and two
deliberately weakened controls exercise timing/origin/presence bindings.
Two-thread proving took 8.690 seconds; warm witness/prove/native verification took
10.522 seconds. Native live-capture integration and Mac backend switching remain;
the current app proof button is still RISC Zero. Software fixtures, including
synthetic traces that pass the illustrative policy, do not establish detector
accuracy or real biometric acceptance.
Live fingerprint acceptance, manufacturer enrollment, physical-source experiments,
consented human/attack datasets, mobile clients and media capture are the next
validation and product milestones.

## 10. What Huma tells people, and the evidence

Checked 29 October 2026. Every public claim about bots, scripts or agents should map to a row here. A claim with no row
needs a test or a source first.

| Claim | Where it appears | Evidence | Limit (say it, or don't claim more) |
| --- | --- | --- | --- |
| Keys sent by other apps, scripts or AI agents don't count | `../extra/Sources/Huma/WritingView.swift:169` | Refused unless PID 0 (`HumaTextView.swift:39-47`). macOS sets the sender's PID even when it writes 0 (§4 test). Sending keys needs the Accessibility privilege ([Apple DTS](https://developer.apple.com/forums/thread/789896)). Computer-use agents type by sending events or writing through Accessibility; both are refused (`testTextWrittenThroughAccessibilityIsRefused`). | A virtual keyboard driver (root) or a USB device that types produces real keyboard events |
| Text that doesn't come from a key press doesn't count | `../extra/Sources/Huma/RichTextEditor.swift:113-119` | Writing Tools, predictions and completions are off. Paste is labelled. Other inserted text is refused (`HumaTextView.swift:121`). One key press may add at most 16 UTF-16 units (`testOneKeyPressAddsAtMostAShortWord`). | An input method can still add up to 16 characters per key press |
| Another keyboard counts at 60% | `../frontend/pages/verify.mjs:695`, both reports | `KeyboardGuard.swift`. An Apple ID counts only with a connection type and no third-party driver, so Karabiner's virtual keyboard is caught even with Apple's ID (`KeyboardGuardTests`). | USB devices can claim any vendor ID, and Hak5's own example uses Apple's ([Hak5](https://docs.hak5.org/hak5-usb-rubber-ducky/attack-modes-constants-and-variables/attack-modes)) |
| The nine typing checks | Shared page, both reports | Bounds sit wide of human typing: mean key hold 116 ms (SD 24), mean gap 239 ms (SD 112), gaps rarely under 60 ms ([Dhakal et al., CHI 2018](https://doi.org/10.1145/3173574.3174220)). Machine timing fails (§5 table). | Imitated timing passes: "Speed- and regularity-based heuristics are easily evaded" ([Lotto et al. 2026](https://arxiv.org/abs/2604.15845)). Record bursts above 19 keys a second fail the speed check. |
| Touch ID at the start and at random times | Both reports, onboarding | Biometric-gated Secure Enclave key (§3) | Shows a fingerprint this Mac knows at those moments, not who typed in between |
| "Typed by a person" (was "Written by a human" until 29 Oct) | `../frontend/pages/verify.mjs:488`, `../frontend/registry.mjs:266` | Typed on a keyboard, with plausible timing and Touch ID present | Not who composed the words: retyping AI text gives "authentic motor signals" ([Condrey 2026](https://arxiv.org/abs/2601.17280)) |
| "Text from bots and scripts doesn’t count" (was "Bots get turned away at the door") | `../frontend/pages/foundation.html:122` | Keys sent by software are refused; pasted and inserted text counts 0 | A hardware typist with a person at Touch ID still counts |
| "53% of all web traffic now comes from bots" | `../frontend/pages/foundation.html:115` | "In 2025, bots made up more than 53% of all web traffic" ([Thales, 28 April 2026](https://www.thalesgroup.com/en/news-centre/press-releases/ai-driven-bot-attacks-surged-125x-according-thales-bad-bot-report)) | Includes good bots such as search crawlers. 40% was bad bots. The publisher sells bot defence. |

## Sources

- Condrey, ZK-PoP: Privacy-Preserving Proof of Human Authorship via Zero-Knowledge Process Attestation, arXiv 2603.00179 (2026). https://arxiv.org/abs/2603.00179
- Querejeta-Azurmendi et al., zkSENSE, PoPETs 2021(4). https://petsymposium.org/popets/2021/popets-2021-0058.php
- Acien et al., TypeNet: Deep Learning Keystroke Biometrics, arXiv 2101.05570 (2021). https://arxiv.org/abs/2101.05570
- DeAlcala et al., BeCAPTCHA-Type, CVPRW 2023. https://openaccess.thecvf.com/content/CVPRW2023/Biometrics/html/DeAlcala_BeCAPTCHA-Type_Biometric_Keystroke_Data_Generation_for_Improved_Bot_Detection_CVPRW_2023_paper.html
- Apple, `biometryCurrentSet`. https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset
- Apple, `touchIDAuthenticationAllowableReuseDuration`. https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration
- Apple, `CGEventField.eventSourceUnixProcessID`. https://developer.apple.com/documentation/coregraphics/cgeventfield/eventsourceunixprocessid
- Apple, `CGEventSourceStateID.hidSystemState`. https://developer.apple.com/documentation/coregraphics/cgeventsourcestateid/hidsystemstate
- Apple DTS on PostEvent/ListenEvent/Accessibility privileges. https://developer.apple.com/forums/thread/820594
- OWASP MASTG, biometric-bound Keystore keys. https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/
- AOSP, Key and ID attestation. https://source.android.com/docs/security/features/keystore/attestation
- AOSP CTS, "Ensure injected device has id = -1". https://android.googlesource.com/platform/cts/+/faaa97629a6
- AOSP, FLAG_IS_ACCESSIBILITY_EVENT. https://gerrit.omnirom.org/plugins/gitiles/android_frameworks_native/+/f00a4ec687e2bf9110106238c7738927fc3e87d7%5E%21
- Google, Play Integrity app access risk. https://developer.android.com/google/play/integrity/app-access-risk
- Google, Pixel 10 C2PA Content Credentials. https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html
- hCaptcha on Private Access Tokens. https://hcaptcha.uth.edu/blog/announcing-support-for-private-access-tokens
- Educated Guesswork on Private Access Tokens. https://educatedguesswork.org/posts/private-access-tokens/
- Approov on defeating DeviceCheck/App Attest (vendor view). https://approov.io/knowledge/how-to-defeat-apple-devicecheck-and-appattest
- Dhakal, Feit, Kristensson and Oulasvirta, Observations on Typing from 136 Million Keystrokes, CHI 2018. https://doi.org/10.1145/3173574.3174220
- Lotto, Marchiori and Conti, QUACK! A Systematic Study of Keystroke Dynamics for HID Injection Detection, arXiv 2604.15845 (2026). https://arxiv.org/abs/2604.15845
- Condrey, On the Insecurity of Keystroke-Based AI Authorship Detection, arXiv 2601.17280 (2026). https://arxiv.org/abs/2601.17280
- Apple DTS, posting events needs the PostEvent privilege, shown as Accessibility. https://developer.apple.com/forums/thread/789896
- pqrs.org, Karabiner-DriverKit-VirtualHIDDevice (virtual keyboard properties). https://github.com/pqrs-org/Karabiner-DriverKit-VirtualHIDDevice
- Hak5, USB Rubber Ducky attack modes (VID/PID). https://docs.hak5.org/hak5-usb-rubber-ducky/attack-modes-constants-and-variables/attack-modes
- Thales, 2026 Bad Bot Report press release. https://www.thalesgroup.com/en/news-centre/press-releases/ai-driven-bot-attacks-surged-125x-according-thales-bad-bot-report
