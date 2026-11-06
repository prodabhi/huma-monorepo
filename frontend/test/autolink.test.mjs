import test from 'node:test';
import assert from 'node:assert/strict';
import { EditorState, TextSelection } from 'prosemirror-state';
import { schema, plainText } from '../write/schema.mjs';
import { autolink } from '../write/autolink.mjs';

const link = schema.marks.link;
const start = text => EditorState.create({ schema, doc: schema.node('doc', null, [schema.node('paragraph', null, text ? schema.text(text) : null)]),
  plugins: [autolink(link, () => true)] });
const links = state => { const out = []; state.doc.descendants(n => { const m = link.isInSet(n.marks); if (m) out.push([n.text, m.attrs.href]); }); return out; };
const at = (state, pos) => state.apply(state.tr.setSelection(TextSelection.create(state.doc, pos)));
const typed = (state, text) => state.applyTransaction(state.tr.insertText(text)).state;

test('a pasted address becomes a link; the text stays the same', () => {
  const state = start('');
  const pasted = state.applyTransaction(state.tr.insertText('Read https://huma.social/write. And www.example.com too').setMeta('uiEvent', 'paste')).state;
  assert.deepEqual(links(pasted), [['https://huma.social/write', 'https://huma.social/write'], ['www.example.com', 'https://www.example.com']]);
  assert.equal(plainText(pasted.doc), 'Read https://huma.social/write. And www.example.com too');
});

test('a typed address becomes a link when a space follows, not while it is typed', () => {
  let state = at(start('see https://huma.social'), 24);
  assert.deepEqual(links(state), []);
  state = typed(state, ' ');
  assert.deepEqual(links(state), [['https://huma.social', 'https://huma.social']]);
  // Not a web address: no link.
  assert.deepEqual(links(typed(at(start('version 1.2'), 12), ' ')), []);
});

test('Enter after an address links it', () => {
  let state = at(start('go to www.huma.social'), 22);
  state = state.applyTransaction(state.tr.split(state.selection.from)).state;
  assert.deepEqual(links(state), [['www.huma.social', 'https://www.huma.social']]);
});
