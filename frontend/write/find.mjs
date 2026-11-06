// Find in the document (⌘F): every match highlighted, the current one stronger. Finding never changes the text.
import { Plugin, PluginKey, TextSelection } from 'prosemirror-state';
import { Decoration, DecorationSet } from 'prosemirror-view';

const key = new PluginKey('find');
const empty = { query: '', matches: [], current: -1, deco: DecorationSet.empty };

function search(doc, query, caseSensitive = false) {
  if (!query) return [];
  const needle = caseSensitive ? query : query.toLowerCase(), matches = [];
  doc.descendants((node, pos) => {
    if (!node.isTextblock) return true;
    // Each text block's characters, with their positions (a line break or other leaf counts as one position).
    let text = '', map = [];
    node.forEach((child, offset) => {
      const start = pos + 1 + offset;
      if (child.isText) { for (let i = 0; i < child.text.length; i++) map.push(start + i); text += child.text; }
      else { map.push(start); text += '\n'; }
    });
    const hay = caseSensitive ? text : text.toLowerCase();
    for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length))
      matches.push({ from: map[i], to: map[i + needle.length - 1] + 1 });
    return false;
  });
  return matches;
}
const decorate = (doc, matches, current) => DecorationSet.create(doc,
  matches.map((m, i) => Decoration.inline(m.from, m.to, { class: i === current ? 'find-match current' : 'find-match' })));

export const findPlugin = new Plugin({
  key,
  state: {
    init: () => empty,
    apply(tr, value) {
      const set = tr.getMeta(key);
      if (set) {
        const matches = search(tr.doc, set.query), current = matches.length ? Math.min(Math.max(set.current ?? 0, 0), matches.length - 1) : -1;
        return { query: set.query, matches, current, deco: decorate(tr.doc, matches, current) };
      }
      if (!tr.docChanged || !value.query) return value;
      const matches = search(tr.doc, value.query), current = matches.length ? Math.min(Math.max(value.current, 0), matches.length - 1) : -1;
      return { ...value, matches, current, deco: decorate(tr.doc, matches, current) };
    },
  },
  props: { decorations: state => key.getState(state).deco },
});

export const findState = state => key.getState(state);
/** Search for `query`, starting from the match at or after the caret. */
export function find(view, query) {
  const from = view.state.selection.from, matches = search(view.state.doc, query);
  const current = Math.max(0, matches.findIndex(m => m.to >= from));
  view.dispatch(view.state.tr.setMeta(key, { query, current }));
  reveal(view);
}
/** The next (1) or previous (-1) match, selected and scrolled into view. */
export function step(view, by) {
  const { query, matches, current } = findState(view.state);
  if (!matches.length) return;
  view.dispatch(view.state.tr.setMeta(key, { query, current: (current + by + matches.length) % matches.length }));
  reveal(view, true);
}
function reveal(view, select = false) {
  const { matches, current } = findState(view.state);
  const match = matches[current];
  if (!match) return;
  if (select) view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, match.from, match.to)));
  const scroller = view.dom.closest('.canvas'), at = view.coordsAtPos(match.from);
  if (scroller) scroller.scrollTop += at.top - scroller.getBoundingClientRect().top - scroller.clientHeight / 2;
}
export const clearFind = view => view.dispatch(view.state.tr.setMeta(key, { query: '' }));
