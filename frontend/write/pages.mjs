// Lays the document out on pages, as Google Docs does: US Letter with 1-inch margins, the text moving to the next page
// line by line. The text flows as one column; before the first line of each new page goes a gap as tall as the rest
// of the page, its bottom margin, the space between pages and the next page's top margin. Gaps are decorations, so
// the document itself never changes. Positions are measured without the gaps ("natural"), so one pass settles.
import { Plugin, PluginKey } from 'prosemirror-state';
import { Decoration, DecorationSet } from 'prosemirror-view';

export const PAGE = { width: 816, height: 1056, margin: 96, gap: 12 };
const key = new PluginKey('pages');
const LIST_ITEMS = new Set(['list_item', 'check_item']);

function gap(height) {
  const el = document.createElement('span');
  el.className = 'page-gap'; el.contentEditable = 'false'; el.setAttribute('aria-hidden', 'true');
  el.style.height = `calc(var(--z, 1) * ${height.toFixed(2)}px)`;
  return el;
}
const decorate = (doc, breaks) => DecorationSet.create(doc, breaks.map(({ pos, height }) =>
  Decoration.widget(pos, () => gap(height), { side: -1, key: `gap:${height.toFixed(2)}`, ignoreSelection: true, height })));

/** Where a block's first line moves to a new page: before the block, or before its list item. */
function blockStart(doc, pos) {
  const $pos = doc.resolve(pos);
  return $pos.index() === 0 && LIST_ITEMS.has($pos.parent.type.name) ? $pos.before() : pos;
}

/** The lines of a text block, each as its top and bottom on the screen, and the first character on it. */
function lines(el) {
  const texts = [], walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) if (node.length) texts.push(node);
  const range = document.createRange(), rects = [];
  for (const node of texts) { range.selectNodeContents(node); for (const r of range.getClientRects()) if (r.height) rects.push(r); }
  rects.sort((a, b) => a.top - b.top);
  const found = [];
  for (const r of rects) {
    const line = found[found.length - 1];
    if (line && r.top < line.bottom - 1) { line.top = Math.min(line.top, r.top); line.bottom = Math.max(line.bottom, r.bottom); }
    else found.push({ top: r.top, bottom: r.bottom });
  }
  // The first character of each line: where a character's middle passes the boundary between this line and the last.
  const middle = (node, offset) => { range.setStart(node, offset); range.setEnd(node, offset + 1); const r = range.getBoundingClientRect(); return (r.top + r.bottom) / 2; };
  const total = texts.reduce((sum, n) => sum + n.length, 0);
  const at = index => { for (const node of texts) { if (index < node.length) return [node, index]; index -= node.length; } return null; };
  for (let i = 1; i < found.length; i++) {
    const boundary = (found[i - 1].bottom + found[i].top) / 2;
    let low = 0, high = total - 1;
    while (low < high) { const mid = (low + high) >> 1, [node, offset] = at(mid); if (middle(node, offset) > boundary) high = mid; else low = mid + 1; }
    let [node, offset] = at(low);
    if (offset > 0 && /[\udc00-\udfff]/.test(node.data[offset])) offset--;
    found[i].node = node; found[i].offset = offset;
  }
  return found;
}

function measure(view, zoom) {
  const { height: H, margin: M, gap: G } = PAGE, z = zoom();
  const origin = view.dom.getBoundingClientRect().top;
  const gaps = [...view.dom.querySelectorAll('.page-gap')].map(el => { const r = el.getBoundingClientRect(); return [r.top, r.height]; });
  const natural = y => { let s = 0; for (const [top, h] of gaps) if (top < y - 0.5) s += h; return (y - origin - s) / z; };
  const breaks = [];
  let pageTop = M, end = H - M;
  const newPage = (pos, top) => { breaks.push({ pos, height: end - top + 2 * M + G }); pageTop = top; end = top + H - 2 * M; };
  view.state.doc.descendants((node, pos) => {
    if (!node.isTextblock && !node.isLeaf) return true;
    const el = view.nodeDOM(pos);
    if (!(el instanceof HTMLElement)) return false;
    const box = el.getBoundingClientRect(), top = natural(box.top), bottom = natural(box.bottom);
    if (node.type.name === 'page_break') {
      breaks.push({ pos: pos + node.nodeSize, height: Math.max(0, end - bottom) + 2 * M + G });
      pageTop = bottom; end = bottom + H - 2 * M;
      return false;
    }
    if (bottom <= end + 0.5) return false;
    if (!node.isTextblock) { if (top > pageTop + 0.5) newPage(blockStart(view.state.doc, pos), top); return false; }
    const found = lines(el), style = getComputedStyle(el);
    const contentTop = top + parseFloat(style.paddingTop) / z, contentBottom = bottom - parseFloat(style.paddingBottom) / z;
    if (found.length < 2) { if (top > pageTop + 0.5) newPage(blockStart(view.state.doc, pos), top); return false; }
    for (let i = 0; i < found.length; i++) {
      // Between two lines, halfway: each side measured on its own, as a gap may lie between them.
      const lineTop = i === 0 ? contentTop : (natural(found[i - 1].bottom) + natural(found[i].top)) / 2;
      const lineBottom = i === found.length - 1 ? contentBottom : (natural(found[i].bottom) + natural(found[i + 1].top)) / 2;
      if (lineBottom <= end + 0.5 || lineTop <= pageTop + 0.5) continue;
      if (i === 0) newPage(blockStart(view.state.doc, pos), top);
      else newPage(view.posAtDOM(found[i].node, found[i].offset), lineTop);
    }
    return false;
  });
  return breaks;
}

const same = (a, b) => a.length === b.length && a.every((x, i) => x.pos === b[i].pos && Math.abs(x.height - b[i].height) < 0.5);

/**
 * The pagination plugin. `zoom()` is the page's zoom; `paged()` is false for one continuous sheet (pageless);
 * `onLayout(pages)` hears the page count after each layout.
 */
export function pages({ zoom, paged, onLayout }) {
  return new Plugin({
    key,
    state: {
      init: (_, state) => ({ breaks: [], deco: DecorationSet.empty, doc: state.doc }),
      apply(tr, value) {
        const next = tr.getMeta(key);
        if (next) return next;
        if (!tr.docChanged) return value;
        const deco = value.deco.map(tr.mapping, tr.doc);
        return { breaks: deco.find().map(d => ({ pos: d.from, height: d.spec.height })), deco, doc: tr.doc };
      },
    },
    props: { decorations: state => key.getState(state).deco },
    view(view) {
      let frame = 0, count = 0;
      const layout = () => {
        frame = 0;
        if (!view.dom.isConnected) return;
        const breaks = paged() ? measure(view, zoom) : [], current = key.getState(view.state);
        if (!same(breaks, current.breaks))
          view.dispatch(view.state.tr.setMeta(key, { breaks, deco: decorate(view.state.doc, breaks), doc: view.state.doc }).setMeta('addToHistory', false));
        const pages = breaks.length + 1;
        if (pages !== count || !paged()) { count = pages; onLayout(pages); }
      };
      const schedule = () => { if (!frame) frame = requestAnimationFrame(layout); };
      const observer = new ResizeObserver(schedule);
      observer.observe(view.dom);
      document.fonts?.ready.then(schedule);
      schedule();
      view.dom.addEventListener('huma-relayout', schedule);
      return {
        update: (v, previous) => { if (v.state.doc !== previous.doc) schedule(); },
        destroy: () => { cancelAnimationFrame(frame); observer.disconnect(); },
      };
    },
  });
}
/** Lay the pages out again (after a zoom change). */
export const relayout = view => view.dom.dispatchEvent(new Event('huma-relayout'));
