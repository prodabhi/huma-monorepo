# Detection evaluation report

Generated 2026-11-07T00:09:48.629Z by `node detection/eval/report.mjs` with thresholds `rules-2026-11-07d`.

## Recorded sessions

19 sessions in `detection/eval/sessions/`: 0 human, 19 from generators.
Detection cut: human probability below 0.30, from the thresholds file (no human sessions yet); a session also counts as caught when its integrity fails.

| Generator | Sessions | Caught (page halt, band or integrity) | Caught at the cut | Halted by the page itself | Median p(human) | Outcome notes |
| --- | --- | --- | --- | --- | --- | --- |
| agent_read_type | 2 | 100% | 100% | 1 | 0.01 | |
| cdp_dispatch_humanized | 3 | 100% | 100% | 2 | 0.01 | |
| cdp_inserttext | 3 | 100% | 100% | 3 | 0.57 | |
| cdp_replay_model | 2 | 100% | 100% | 2 | 0.50 | |
| fabricated_post | 3 | 100% | 100% | 0 | 0.30 | |
| playwright_type | 3 | 100% | 100% | 3 | 0.01 | |
| replay_human | 3 | 100% | 100% | 3 | 0.01 | |
| os_type | 0 | n/a | n/a | 0 | | not run: 36:49: execution error: System Events got an error: osascript is not allowed to send keystrokes. (1002) |

### Human false positives by modality

No human sessions recorded yet. Record consented sessions on huma.social (or a local registry) and label them with `node detection/eval/label.mjs`; until then the human side of every number below comes from the synthetic model only, which is not evidence.

### Feature importance (mean |logit contribution| over recorded sessions)

| Feature | Sessions measured | Mean |contribution| |
| --- | --- | --- |
| console_wrapped | 6 | 5.00 |
| word_onset_ratio | 11 | 1.56 |
| boundary_pause_ratio | 9 | 1.33 |
| rollover_rate | 14 | 1.27 |
| copy_rate | 2 | 0.89 |
| preface_activity | 14 | 0.78 |
| typo_adjacency | 6 | 0.75 |
| linearity_ratio | 14 | 0.59 |
| iki_hurst | 11 | 0.57 |
| correction_rate | 11 | 0.53 |
| typo_fix_spread | 6 | 0.52 |
| revision_depth | 11 | 0.46 |
| bigram_corr | 11 | 0.44 |
| iki_lag1_ac | 11 | 0.43 |
| tremor_power | 4 | 0.42 |
| dwell_mean | 14 | 0.41 |
| path_straightness | 5 | 0.34 |
| shift_mismatch_rate | 14 | 0.34 |
| jerk_profile | 5 | 0.33 |
| word_onset_shift | 11 | 0.26 |
| teleport_click_rate | 3 | 0.25 |
| burst_len_cv | 9 | 0.24 |
| overshoot_rate | 3 | 0.20 |
| orphan_input_rate | 17 | 0.19 |
| semantic_rewrite_rate | 5 | 0.19 |
| pause_periodicity | 4 | 0.18 |
| dwell_cv | 14 | 0.17 |
| window_stationarity | 2 | 0.15 |
| word_freq_corr | 11 | 0.13 |
| burst_speed_after_long_pause | 4 | 0.12 |
| idle_pointer_ratio | 3 | 0.03 |
| missing_keyup_rate | 1 | 0.01 |

### Reasons per generator (how often each feature is among a session’s top reasons)

- **agent_read_type**: integrity:environment (2/2), console_wrapped (2/2), word_onset_ratio (2/2), rollover_rate (2/2), linearity_ratio (2/2), boundary_pause_ratio (1/2)
- **cdp_dispatch_humanized**: rollover_rate (3/3), word_onset_ratio (3/3), preface_activity (3/3), integrity:environment (2/3), console_wrapped (2/3), typo_fix_spread (2/3)
- **cdp_inserttext**: orphan_input_rate (3/3), path_straightness (1/3)
- **cdp_replay_model**: integrity:stream (2/2)
- **fabricated_post**: integrity:burst (3/3), integrity:clock (3/3), typo_adjacency (3/3), iki_hurst (2/3)
- **playwright_type**: dwell_mean (3/3), preface_activity (3/3), shift_mismatch_rate (3/3), rollover_rate (3/3), integrity:environment (2/3), console_wrapped (2/3)
- **replay_human**: boundary_pause_ratio (3/3), rollover_rate (3/3), word_onset_ratio (3/3), linearity_ratio (3/3), preface_activity (3/3)

## Synthetic sanity set

The generators of `detection/eval/synthetic.mjs` (a model of a person, and of each way software types), 6 seeds each on two texts, judged by the same code. This checks the code, not the world: the person here is a model.

| Generator (synthetic) | Sessions | Likely automated or integrity failed | Median p(human) | Web (stream + replay) | Mac (replay only) |
| --- | --- | --- | --- | --- | --- |
| human | 12 | 0% | 0.99 | 0% | 0% |
| human_touch | 12 | 0% | 0.99 | 0% | n/a |
| human_ime | 12 | 0% | 0.98 | 0% | n/a |
| playwright_type | 12 | 100% | 0.01 | 100% | 100% |
| cdp_inserttext | 12 | 100% | 0.30 | 100% | 0% |
| cdp_dispatch_humanized | 12 | 100% | 0.01 | 100% | 100% |
| os_type | 12 | 100% | 0.01 | 100% | 100% |
| replay_human | 12 | 100% | 0.01 | 100% | 100% |
| computer_use_agent | 12 | 100% | 0.01 | 100% | 100% |
| fabricated_post | 12 | 100% | 0.01 | 100% | n/a |

## Acceptance criteria

- agent_read_type: 100% caught, target 95%: met (2 recorded sessions; three runs is a smoke test, not a rate).
- cdp_dispatch_humanized: 100% caught, target 95%: met (3 recorded sessions; three runs is a smoke test, not a rate).
- cdp_inserttext: 100% caught, target 95%: met (3 recorded sessions; three runs is a smoke test, not a rate).
- cdp_replay_model: 100% caught, target 95%: met (2 recorded sessions; three runs is a smoke test, not a rate).
- fabricated_post: 100% caught, target 95%: met (3 recorded sessions; three runs is a smoke test, not a rate).
- playwright_type: 100% caught, target 95%: met (3 recorded sessions; three runs is a smoke test, not a rate).
- replay_human: 100% caught, target 80%: met (3 recorded sessions; three runs is a smoke test, not a rate).
- os_type: not run (36:49: execution error: System Events got an error: osascript is not allowed to send keystrokes. (1002)).
- The Mac app: scripted keys are refused at the event source (HumaTextViewTests); a keyboard-like device is judged on the replay alone, see the synthetic table’s Mac column. No live Mac harness ran here (recording needs Touch ID and World ID at the keyboard).
- Human false-positive rate: not measurable yet (no human sessions).
- Collector handler time and input lag: measured by hand with a Performance panel trace while typing at 100+ WPM; not automated here.
- Traps: the DOM is asserted by test/collector.test.mjs; the VoiceOver, NVDA and autofill pass is a manual checklist (see below) and has not been run by the implementing agent.

## Manual checklist (not run)

- VoiceOver (macOS) and NVDA (Windows): open /write, start recording, read through the page: the canary note and the “Alternate title” field must never be announced or reachable.
- Autofill: with a password manager and browser autofill on, open /write and sign in: the `title_alt` field must stay empty (the server would record a honeypot hit).
- Performance: Chrome DevTools Performance trace while typing fast; the collector’s listeners must stay under 1 ms each.
