import test from 'node:test';
import assert from 'node:assert/strict';
import { humaScore, pageSummary, percentLabel, scoreLine, checkTier, CHECK_TIERS } from '../publication-contract.mjs';
import { composition } from '../replay-core.mjs';

// The same cases as Tests/HumaCoreTests/HumaScoreTests.swift, so readers and the Mac agree on every page's score.
test('the score weighs typed text, typing checks and Touch ID like the Mac app', () => {
  const all = Array(9).fill(true), parts = p => ({ typed: 0, external: 0, pasted: 0, before: 0, other: 0, ...p, total: Object.values(p).reduce((a, b) => a + b, 0) });
  const score = (c, { typing = 0, edits = 0, rules = all, presence = 2, onTime = 2 } = {}) =>
    humaScore({ composition: c, typingEdits: typing, edits, rules, presenceCount: presence, onTime }).value;
  assert.equal(score(parts({ typed: 100 })), 100);
  assert.equal(score(parts({ external: 100 })), 72);
  assert.equal(score(parts({ typed: 80, pasted: 20 })), 86);
  assert.equal(score(null, { typing: 50, edits: 50 }), 72);
  const rules = [...all]; rules[2] = rules[5] = rules[8] = false;
  // Unusual holds and speed (typing no person makes) keep it at 50; a short or unpaused page isn't capped.
  assert.equal(score(parts({ typed: 100 }), { rules, onTime: 1 }), 50);
  const plain = [...all]; plain[2] = plain[7] = false;
  assert.equal(score(parts({ typed: 100 }), { rules: plain, onTime: 1 }), 89);
  assert.equal(humaScore({ composition: parts({ typed: 100 }), rules, presenceCount: 2, onTime: 1 }).capped, true);
  assert.equal(score(parts({ typed: 100 }), { presence: 0, onTime: 0 }), 100);
  assert.equal(score(parts({ pasted: 100 }), { rules: Array(9).fill(false), presence: 3, onTime: 0 }), 0);
});
test('the page summary reads the proof statement the score uses', () => {
  const raw = new Uint8Array(46 * 32), set = (i, v) => { raw[i * 32 + 31] = v; };
  set(16, 40); set(18, 38); set(19, 2); set(25, 3); set(27, 2);
  for (let rule = 0; rule < 9; rule++) if (rule !== 1) set(33 + rule, 1);
  const summary = pageSummary(btoa(String.fromCharCode(...raw)));
  assert.deepEqual(summary, { edits: 40, samples: 0, typingEdits: 38, pasteEdits: 2, presenceCount: 3, onTime: 2, rules: [true, false, true, true, true, true, true, true, true] });
  assert.equal(humaScore({ ...summary, composition: { typed: 90, external: 0, pasted: 10, before: 0, other: 0, total: 100 } }).value, 90);
});
test('typing on another keyboard has its own share of the text', () => {
  assert.deepEqual(composition('ttkkpi'), { typed: 2, external: 2, pasted: 1, before: 1, other: 0, total: 6 });
});
test('the score splits into whole points that add up to it, and one plain line', () => {
  const all = Array(9).fill(true), some = [...all]; some[3] = some[6] = false;
  const cases = [[{ typed: 97, pasted: 3, total: 100 }, all, 3, 2], [{ typed: 50, external: 50, total: 100 }, some, 2, 1], [null, some, 0, 0]];
  for (const [composition, rules, presenceCount, onTime] of cases) {
    const score = humaScore({ composition, typingEdits: 40, edits: 41, rules, presenceCount, onTime });
    assert.equal(score.points.typed + score.points.checks + score.points.touch, score.value);
    assert.ok(score.points.typed <= 70 && score.points.checks <= 20 && score.points.touch <= 10);
  }
  const line = (composition, rules = all) => scoreLine(humaScore({ composition, typingEdits: 9, edits: 10, rules, presenceCount: 2, onTime: 1 }));
  assert.equal(line({ typed: 100, external: 0, pasted: 0, before: 0, other: 0, total: 100 }), 'Mac app \u00b7 strong check \u00b7 100% typed \u00b7 7 of 7 typing checks \u00b7 Touch ID 1 of 2');
  assert.equal(line({ typed: 995, external: 0, pasted: 5, before: 0, other: 0, total: 1000 }), 'Mac app \u00b7 strong check \u00b7 99% typed \u00b7 7 of 7 typing checks \u00b7 Touch ID 1 of 2');
  assert.equal(line({ typed: 60, external: 40, pasted: 0, before: 0, other: 0, total: 100 }, some), 'Mac app \u00b7 strong check \u00b7 100% typed (40% on another keyboard) \u00b7 5 of 7 typing checks \u00b7 Touch ID 1 of 2');
  assert.equal(line(null), 'Mac app \u00b7 strong check \u00b7 Replay not shared, so typing counts at 60% \u00b7 7 of 7 typing checks \u00b7 Touch ID 1 of 2');
  // A web page scores out of 100 too, and always says it's the basic check.
  const web = humaScore({ composition: { typed: 100, external: 0, pasted: 0, total: 100 }, typingEdits: 9, edits: 10, rules: all, presenceCount: 0, onTime: 0, browser: true });
  assert.equal(web.value, 100);
  assert.equal(scoreLine(web), 'Web browser \u00b7 basic check \u00b7 100% typed \u00b7 7 of 7 typing checks');
  // A passkey that approved every check-in raises the tier, never the score; a Mac page has no passkey tier.
  const inputs = { composition: { typed: 80, external: 0, pasted: 20, total: 100 }, typingEdits: 9, edits: 10, rules: some, presenceCount: 3, onTime: 2, browser: true };
  const basic = humaScore(inputs), passkey = humaScore({ ...inputs, passkey: true });
  assert.equal(passkey.value, basic.value); assert.deepEqual(passkey.points, basic.points); assert.equal(passkey.passkey, true); assert.equal(basic.passkey, false);
  assert.equal(scoreLine(passkey), 'Web browser \u00b7 passkey check \u00b7 80% typed \u00b7 5 of 7 typing checks \u00b7 Check-ins 2 of 3');
  assert.equal(scoreLine(basic), 'Web browser \u00b7 basic check \u00b7 80% typed \u00b7 5 of 7 typing checks \u00b7 Check-ins 2 of 3');
  const macInputs = { ...inputs, browser: false }, mac = humaScore({ ...macInputs, passkey: true });
  assert.equal(mac.value, humaScore(macInputs).value); assert.equal(mac.passkey, false);
  assert.match(scoreLine(mac), /^Mac app \u00b7 strong check \u00b7 /);
  assert.equal(checkTier(true, true), CHECK_TIERS.passkey); assert.equal(checkTier(true), CHECK_TIERS.web); assert.equal(checkTier(false, true), CHECK_TIERS.mac);
  assert.deepEqual([0, 0.004, 0.5, 0.996, 1].map(percentLabel), ['0%', '<1%', '50%', '99%', '100%']);
});
