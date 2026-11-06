// Links as in Docs: a web address pasted, or typed and followed by a space or a new line, becomes a link, and a link
// pasted onto selected words links them. Only formatting changes: the characters the proof covers stay the same.
import { Plugin } from 'prosemirror-state';

const URLS = /(?:https?:\/\/|www\.)[^\s￼]+/gi;
const AT_END = /(?:https?:\/\/|www\.)[^\s￼]+$/i;
// Punctuation after an address belongs to the sentence ("see huma.social." or "(https://huma.social)").
const TRAILING = /[.,;:!?)\]}'"”’]+$/;
const href = url => (/^https?:\/\//i.test(url) ? url : 'https://' + url);
const address = text => {
  const url = text.replace(TRAILING, '');
  return url.length >= 8 && /\.[a-z]{2,}/i.test(url) ? url : null;
};
const blockText = node => node.textBetween(0, node.content.size, undefined, '￼');

/** Links the addresses in `from`…`to` of `tr`'s document that aren't links yet. */
export function linkAddresses(tr, link, from, to) {
  tr.doc.nodesBetween(from, to, (node, pos) => {
    if (!node.isTextblock) return true;
    for (const match of blockText(node).matchAll(URLS)) {
      const url = address(match[0]);
      if (!url) continue;
      const start = pos + 1 + match.index, end = start + url.length;
      if (end < from || start > to || tr.doc.rangeHasMark(start, end, link)) continue;
      tr.addMark(start, end, link.create({ href: href(url) }));
    }
    return false;
  });
  return tr;
}

/** Where `trs` changed the document, as a range of the final one, or null. */
function changed(trs) {
  let from = Infinity, to = -Infinity;
  trs.forEach((tr, k) => tr.steps.forEach((step, i) => step.getMap().forEach((_a, _b, start, end) => {
    let a = tr.mapping.slice(i + 1).map(start, -1), b = tr.mapping.slice(i + 1).map(end, 1);
    for (const later of trs.slice(k + 1)) { a = later.mapping.map(a, -1); b = later.mapping.map(b, 1); }
    from = Math.min(from, a); to = Math.max(to, b);
  })));
  return from <= to ? { from, to } : null;
}

/** The plugin; `link` is the schema's link mark, `editable()` whether the page is open for writing. */
export function autolink(link, editable) {
  return new Plugin({
    appendTransaction(trs, _old, state) {
      if (!editable() || !trs.some(tr => tr.docChanged)) return null;
      const pasted = trs.some(tr => ['paste', 'drop'].includes(tr.getMeta('uiEvent')));
      if (pasted) {
        const range = changed(trs);
        const tr = range && linkAddresses(state.tr, link, range.from, range.to);
        return tr?.docChanged ? tr : null;
      }
      // Typed: the word before a space, or the end of the paragraph just left with Enter.
      const { $from, empty } = state.selection;
      if (!empty) return null;
      let node = $from.parent, end = $from.parentOffset, start = $from.start();
      if (end === 0) {
        const before = state.doc.resolve($from.before()).nodeBefore;
        if (!before?.isTextblock) return null;
        node = before; end = before.content.size; start = $from.before() - before.nodeSize + 1;
      } else if (!/\s/.test(blockText(node)[end - 1])) return null;
      else end -= 1;
      const word = blockText(node).slice(0, end).match(AT_END), url = word && address(word[0]);
      if (!url) return null;
      const from = start + word.index, to = from + url.length;
      if (state.doc.rangeHasMark(from, to, link)) return null;
      return state.tr.addMark(from, to, link.create({ href: href(url) }));
    },
    props: {
      // A link pasted onto selected words links them, without changing the words.
      handlePaste(view, event) {
        const text = event.clipboardData?.getData('text/plain')?.trim() ?? '', { from, to, empty } = view.state.selection;
        if (empty || !editable() || !/^https?:\/\/\S+$/i.test(text)) return false;
        view.dispatch(view.state.tr.removeMark(from, to, link).addMark(from, to, link.create({ href: text })));
        return true;
      },
    },
  });
}
