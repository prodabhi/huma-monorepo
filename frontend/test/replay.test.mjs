import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReplay, parseReplay } from '../replay-core.mjs';

// Made by the Mac (extra/Tests/HumaCoreTests/ReplayExportTests.swift with HUMA_REPLAY_FIXTURE set).
const source = readFileSync(new URL('./fixtures/replay-swift.json', import.meta.url), 'utf8');
const text = readFileSync(new URL('./fixtures/replay-swift.json.txt', import.meta.url), 'utf8');
const publicKey = JSON.parse(source).checkpoint.publicKey;

test('a replay made on the Mac verifies here, edit by edit', async () => {
  const replay = await verifyReplay(source, { publicKey, text });
  assert.equal(replay.finalText, text);
  assert.equal(replay.frames.length, 6);
  assert.deepEqual(replay.frames.map(f => f.kind), ['typing', 'typing', 'paste', 'typing', 'undo-redo', 'typing']);
  // The undo brought the pasted text back, so it still counts as pasted; "Intro/\n" was there before.
  const c = replay.composition;
  assert.equal(c.before, 7); assert.equal(c.typed, 2 + 3); assert.equal(c.pasted, ' "a/b"\t😀'.length); assert.equal(c.other, 0);
  assert.equal(c.total, text.length);
});

test('a replay that was changed, cut or moved to another page fails', async () => {
  const edit = change => { const r = JSON.parse(source); change(r); return JSON.stringify(r); };
  const bad = [
    edit(r => { r.events[1][4] = 'X'; }),                         // a different edit
    edit(r => { r.events.pop(); }),                                // the last edit cut
    edit(r => { r.events[2][1] = 'typing'; }),                     // a paste relabelled as typing
    edit(r => { r.events[3][0] = 0; }),                            // time going backwards
    edit(r => { r.initialText = 'Intro\n'; }),                     // a different start
    edit(r => { r.checkpoint.reportedTime.elapsedMilliseconds++; }), // signed fields changed
  ];
  for (const replay of bad) await assert.rejects(verifyReplay(replay, { publicKey, text }));
  await assert.rejects(verifyReplay(source, { publicKey, text: text + '.' }), /page’s text/);
  const other = Buffer.from(Uint8Array.from({ length: 65 }, (_, i) => i ? i : 4)).toString('base64');
  await assert.rejects(verifyReplay(source, { publicKey: other, text }), /different key/);
  assert.throws(() => parseReplay(edit(r => { r.extra = 1; })));
  assert.throws(() => parseReplay(edit(r => { r.events[0].push('x'); })));
});
