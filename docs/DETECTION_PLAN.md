# Detection plan: telling agent harnesses from writers on huma.social/write

Maps the agent/harness detection spec to this repo. Written after inspecting the code on 7 November 2026; each
section names the files it touches. Everything lands in `../frontend/` (the browser editor and its server); the Mac app's
path (its own recorder, Touch ID, no streamed events) is out of scope and keeps its score as it is.

## What is here today

| Piece | Where | What it does now |
| --- | --- | --- |
| Editor | `../frontend/write/editor.mjs` (ProseMirror, `../frontend/write/schema.mjs`) | `keydown`/`keyup` on `#pages` (trusted events only) go to the Rust recorder as Mac key codes (`../frontend/write/keys.mjs`, `../frontend/write/recorder.mjs`); every text change goes to the recorder as the whole text, which diffs it into a signed edit journal (`../extra/experiments/noir-compact/native/src/web.rs`). |
| Client typing checks | `../frontend/write/typing.mjs`, `../frontend/write/automation.mjs`, `../frontend/write/retype.mjs` | Blatant rhythms (instant releases, metronome, Shift in lockstep) stop the recording; `navigator.webdriver`, driver globals and DevTools are watched; a pointer that only teleports stops it; odd typing asks for a retype. All of it runs on the page, so a harness that types with human-ish random delays passes. |
| Transport | none live; `POST /api/sessions` at Start (`../frontend/sessions.mjs`, `../frontend/write/session.mjs`), `POST /api/publications/prepare` + `/pending/<id>/publish` at Finish (`../frontend/publications.mjs`, `../frontend/write/account.mjs`) | The server sees nothing between Start and Finish. At Finish it gets the proof, the text and the signed replay (edit journal) in one upload. |
| Server checks | `../frontend/publication-verifier.mjs` → `../frontend/replay-core.mjs` (`verifyReplay`), `../frontend/publication-contract.mjs` (`replayRhythm`, `humaScore`), `../frontend/sessions.mjs` (`confirm`: claimed time vs the nonce's issue time) | The replay is rebuilt and must end in the page's text; its typing rhythm (gaps between typed characters) is judged; an automated rhythm holds the score at 50 (`verifiedScore` in `publications.mjs`, mirrored by `pages/verify.mjs`). |
| Storage | `../frontend/object-store.mjs` (local folder or R2; `../frontend/arkiv-store.mjs` keeps `sessions/` and `quotas/` local), `../frontend/documents.mjs` (`readState`/`changeState`) | Records of shared pages (`records/<id>`), objects by hash, a writer's index. |
| Scoring | `humaScore` in `../frontend/publication-contract.mjs`: typed 70 + typing checks 20 + check-ins 10, capped at 50 when the typing can't be a person's | Readers (`pages/verify.mjs`) recompute it; the writer index keeps the server's. |

The bug: a Playwright/CDP/OS-level harness that sends key events with random delays is "100% typed", passes the 7
proof rules and the replay rhythm, and scores 100.

## Spec → files

### 1. Hard constraints

- Capture is listeners that push to an array; features are computed on the server only. Caret offsets come from
  ProseMirror's model (`view.state.selection`), never the DOM.
- The score is a clamped probability with reasons (`../frontend/detection/score.mjs`); no new challenge is shown while
  writing. The existing retype check and automation stop stay as they are.
- Modality (physical keyboard, touch, IME, mixed) is detected in `../frontend/detection/features.mjs` from the stream
  (`pointer: coarse`, keys without `code`/with `keyCode 229`, `isComposing`, composition events); key-physics and
  pointer features are marked unavailable where they don't apply, and the scoring skips them. Uncertain sessions get
  the `uncertain` band, which is never shown as "AI" to the writer.
- Only events inside `#pages` (the editor) are captured for keys and input; pointer, focus and visibility events on
  the document are positions and times only. Disclosure line in `pages/write.html` (Start card) and
  `pages/privacy.html`.

### 2. Client collector → `../frontend/write/collector.mjs`, wired in `../frontend/write/editor.mjs`

- Buffered listeners (passive, capture) for `keydown keyup beforeinput compositionstart compositionend` on the editor,
  `pointermove` (coalesced) and `pointerdown pointerup wheel selectionchange visibilitychange` on the document,
  `focus blur` on the window. Each event is a small object with a sequence number; nothing else happens in the handler.
- `beforeinput` records `caret` (= `view.state.selection.from`), `size` (= `view.state.doc.content.size`) and the
  input type and data, so the server can see where text goes and whether a key preceded it.
- Flush every 2–3 s via `requestIdleCallback` (fallback `setTimeout`) over a WebSocket to `/api/sessions/stream`
  (new; `../frontend/websocket.mjs` is a minimal RFC 6455 server on the existing `node:http` server, no new dependency).
  Batches are `{ session, index, sentAt, hmac, events }`, acked by index; unacked batches are resent in order after a
  reconnect, so the stream is contiguous.
- Once per session: user agent, `navigator.webdriver`, timer resolution (200 rapid `performance.now()` calls),
  modality guess, `crossOriginIsolated`, and the honeypot's value at each flush.
- Raw text never travels separately: the server has the signed replay and the final text at Finish.

### 3. Server features → `../frontend/detection/features.mjs`

`extractFeatures({ events, meta, frames, text })` returns `{ modality, features: { name: { value, confidence } },
windows }` over the whole session and 60 s windows. Tables 3.1–3.5 map one to one onto exported helpers:

- 3.1 key physics (physical keyboard only): `dwell_mean dwell_cv missing_keyup_rate rollover_rate shift_mismatch_rate
  code_key_mismatch orphan_input_rate untrusted_rate`.
- 3.2 timing: `iki_lag1_ac iki_hurst iki_exgauss_fit iki_lognorm_ks bigram_corr quantization_score drift_slope
  window_stationarity`. The seed bigram table (`../frontend/detection/bigrams.json`) is a hand-entered table of typical
  per-bigram latencies in the shape of the Aalto 136M keystrokes dataset's published medians; its origin is logged in
  the file and it is replaced by the human corpus from §7 once that exists.
- 3.3 content coupling, from the replay frames (signed edit journal, so the text and caret are exact) joined to the
  stream by time: `word_onset_ratio word_freq_corr boundary_pause_ratio linearity_ratio revision_depth
  typo_fix_latency typo_adjacency semantic_rewrite_rate`. Word frequency: a compact built-in list of the most common
  English words (`../frontend/detection/wordfreq.json`, Zipf-ranked), the long tail treated as rare.
- 3.4 agent-loop: `pause_periodicity burst_len_cv burst_speed_after_long_pause hidden_input_rate`.
- 3.5 pointer (mouse only): `teleport_click_rate path_straightness jerk_profile tremor_power overshoot_rate
  idle_pointer_ratio`.

Every feature has a unit test with a synthetic human series and a synthetic bot series from
`../frontend/detection/eval/synthetic.mjs` (shared with the evaluation harness) that asserts the direction.

### 4. Traps → `pages/write.html`, `../frontend/write/collector.mjs`, `../frontend/detection/traps.mjs`

- Canary: the server picks the word at Start (`POST /api/sessions` also returns `canary`); the page puts the
  instruction in a node beside the editor that is off-screen, `aria-hidden`, `inert`, `user-select: none`, outside
  the editor's content model and not in copy events. At Finish the server looks for the word at the start of a
  paragraph in the final text (`canaryHit`).
- Honeypot: `<input name="title_alt" tabindex="-1" autocomplete="off" aria-hidden="true">` in a hidden wrapper; its
  value is sent with each flush; any value is a hit.
- False-positive guard: the DOM attributes are asserted by a test; the VoiceOver/NVDA and autofill pass is a manual
  checklist in `../frontend/detection/eval/REPORT.md` (not run by the implementing agent; see the report).

### 5. Integrity → `../frontend/detection/stream.mjs` (receive) and `../frontend/detection/integrity.mjs` (judge)

1. Streaming only: `/api/sessions/stream` accepts batches for a live nonce (`sessions.live`), contiguous by index,
   within size caps; every batch is kept with its server receive time (in memory, appended to
   `data/streams/<hash>.ndjson`, pruned after 24 h). Burst check: share of the session that arrived live.
2. Signed batches: the session key is `HMAC(server secret, nonce)` (`HUMA_SESSION_SECRET`, else a per-process
   random secret), returned by `POST /api/sessions`; each batch's `hmac` is `HMAC(key, index || sha256(events))`.
   The collector is already minified into `dist/write/write.js` by `../frontend/write/build.mjs` (esbuild).
3. Replay verification: the signed replay is rebuilt and must end in the page text (already done by `verifyReplay`);
   the stream is bound to it: every typed frame needs a key press (or a composition) just before it, and the stream's
   inserted characters must match the replay's in order.
4. Clock consistency: event `timeStamp` deltas vs server receive deltas; the replay's elapsed time vs the stream's.
5. Plausibility: sustained WPM over the ceiling and no pauses over long text.

`integrity: 'fail'` means the page can't be verified as human: the score is held at 50 (as `rhythmAutomated` is
today) and the band is `likely_automated` or `uncertain` as the reason says.

### 6. Scoring → `../frontend/detection/score.mjs`, `../frontend/detection/thresholds.json`

Phase A: each available feature maps to a bounded logit contribution from the thresholds file, weighted by its
confidence; sigmoid; clamp to [0.01, 0.99]; bands at the thresholds file's cut points; the top reasons by |contribution|.
Trap hits and integrity failures are hard overrides. Output follows the spec's JSON exactly, `modelVersion` from the
thresholds file. `verifiedScore` (`publications.mjs`) and `pages/verify.mjs` take the verdict: only `likely_human` +
`integrity: pass` keeps the full score; the verdict and its reasons are kept in the page's record and shown on the
verify page's score row. `HUMA_DETECTION_MODE=shadow` computes and stores the verdict without changing the score.

Personal baseline (6.5): `../frontend/detection/baseline.mjs` keeps per-World-ID aggregates (means and variances of a few
features) after three high-scoring sessions under `baselines/<hash of owner>`; later sessions add a
`baseline_distance` feature (diagonal Mahalanobis). Raw events are never kept past 24 h.

Uncertain band at submit time: the web already asks for World ID at Finish for every page; an uncertain band keeps
that as the deferred step and never shows a behavioural "AI" label.

### 7. Evaluation → `../frontend/detection/eval/`

Generators drive a local registry (`node registry.mjs`) with Chrome through Playwright (`channel: 'chrome'`, no browser
download): `playwright_type`, `cdp_inserttext`, `cdp_dispatch_humanized`, `os_type` (xdotool on Linux, osascript on
macOS), `replay_human`, `computer_use_agent` (Claude computer use over Playwright; needs `ANTHROPIC_API_KEY`), and
`fabricated_post` (synthetic log over the WebSocket, must fail integrity). Each run saves a labelled session file;
`node detection/eval/report.mjs` scores them all and writes `REPORT.md` (detection rate at 1% FPR per generator,
FPR per modality, feature importances, reasons per generator). Human sessions: `node detection/eval/label.mjs` labels
a streamed session from the local store; until team sessions are collected the report says so and uses the synthetic
human model only for the threshold sanity check.

### 8. Order (one commit each, with tests)

1. This plan.
2. `../frontend/websocket.mjs` (server) + `../frontend/detection/stream.mjs` + the session key and canary in `../frontend/sessions.mjs`.
3. `../frontend/write/collector.mjs` and its wiring; honeypot and canary nodes.
4. `../frontend/detection/integrity.mjs`.
5. `../frontend/detection/features.mjs` 3.1–3.4, then 3.5, with `eval/synthetic.mjs`.
6. `../frontend/detection/traps.mjs`.
7. `../frontend/detection/score.mjs` + `thresholds.json`; wiring into `publications.mjs`, the receipt and `pages/verify.mjs`.
8. Evaluation harness and the first report; thresholds tuned from it.
9. Personal baseline; Phase B export and training script (`eval/train.py`, LightGBM + isotonic) with a Node
   tree evaluator, unshipped until data exists.
10. Disclosure copy.

### 9. Non-goals kept

No visible challenge while writing; no capture outside the editor; no text-only AI detector.

## Status (7 November 2026)

Done and tested: steps 1–7 and 9 of the order above, the personal baseline of step 8 (`../frontend/detection/baseline.mjs`,
applied at publish), and the Phase B scaffold (`../frontend/detection/eval/train.py` writes `model.json` from the report's
`features.csv`; `../frontend/detection/model.mjs` evaluates it; nothing is trained, as there are no recorded sessions yet).

### The Mac app, checked the same way

- Keys posted by other programs (pyautogui, osascript, CGEventPost with a forged source) are refused by their event
  source (`HumaTextView.fromKeyboard`: process ID 0 and HID state), and `../extra/Tests/HumaCoreTests/HumaTextViewTests.swift`
  proves the forged source is rewritten by macOS on delivery. That test needs Accessibility permission for the test
  host; it was skipped on the implementing machine (`swift test --filter HumaTextViewTests` ran 12 tests, 1 skipped).
- A keyboard-like device (a hardware injector, or a virtual keyboard driver, which `KeyboardGuard` only downgrades to
  "typing-external") with humanised timing passes the proof's nine rules: on the synthetic sessions, the rules hold at
  50 only the crude harnesses (zero dwell, no pauses); humanised CDP timing, a replayed human rhythm and an agent loop
  all pass them. So the host now judges a Mac page's replay with the same content and timing features
  (`judgeSession({ platform: 'mac' })`, no stream, no traps) and holds it at 50 only when the verdict is
  `likely_automated` (`holdsScore`); `humaScore` gained `automated` for that, `HumaScore.swift` `held`. The Mac app
  reads the verdict from the publish summary (`HostVerdict`), keeps it with the link and shows the held score with the
  host's reasons in the share sheet, so the app, the host and readers agree.
- World ID: the harness runs on a local registry without World ID keys, which is why its page skips the scan (the
  server says World ID is off). A production host without the keys now shares nothing (`WORLD_ID_UNCONFIGURED`,
  `/api/worldid` → `missing: true`; the write page refuses to start and the Mac app refuses to record), unless
  `HUMA_WORLD_OPTIONAL=true` says it means to.

### Where timing stops telling, and what stands behind it

Three fix-and-rerun cycles with the harness (`../frontend/detection/eval/REPORT.md`):

1. A humanised CDP typist that ran to the end scored "uncertain" because the person at the computer moved the mouse
   over the harness's window, because the harness's caret landed mid-text after a retype check (so its typing looked
   like revisions), and because easily faked key physics earned bonuses. Fixed: the harness owns no pointer unless
   it moves one, the caret goes to the end, physics bonuses are trimmed, and software that never backspaces is a
   feature (`correction_rate`). All three runs are now likely automated.
2. Reading before writing: an agent that reads the page (text, DOM, accessibility tree, screenshot, select-all copy)
   before each chunk is caught at 0.01 even without the console tell (`preface_activity`, `copy_rate`, word starts,
   boundary pauses, rollover, corrections).
3. The strongest attacker: a perfect model of a person (the synthetic `humanModel`) replayed key for key over CDP
   scored 0.93, then 0.87 once the replaced console carried −5. By construction it reproduces every timing pattern
   the features measure, which is the known boundary of behaviour alone (HUMAN-PRESENCE.md §1). What catches it is
   not timing: a replaced console or patched `Function.prototype.toString` (how a harness hides from the page's
   DevTools probe) is now an integrity failure on the server and a stop at Start on the page, and the run halts at
   Start. The residual: a driver speaking raw CDP without the Runtime domain, replaying a model trained on real
   typists, leaves neither tell. Against that stand World ID at Start and Finish (one unique human, at the
   keyboard twice), the writer's own profile (`baseline_distance`), the canary (an LLM that reads the page may follow
   it), and on the Mac the hardware origin of every key. That is the honest claim: the typing analysis makes an
   accepted fake cost a tuned human model driven through raw CDP by a verified human, and says exactly that.

### What the report says, and what it can't yet

`../frontend/detection/eval/REPORT.md` is regenerated by `node detection/eval/report.mjs`. Recorded sessions so far come from
the harness only; there are no consented human sessions, so the human false-positive rate and the 1% cut are not
measurable yet and the thresholds are tuned on the synthetic model. Collect sessions with `label.mjs` (team members,
physical keyboards, laptops, mobile and IME) before trusting any detection rate as a product number.
