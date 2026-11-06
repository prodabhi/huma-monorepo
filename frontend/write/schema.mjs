// The page's document, with Google Docs' text styles. Formatting is kept apart from the characters: the proof covers
// the plain text (`plainText`), and styles, fonts, colours, lists and links change only how it looks.
import { Schema } from 'prosemirror-model';

// Docs' paragraph styles: size in points, space before and after in points, and colour.
export const STYLES = {
  paragraph: { label: 'Normal text', size: 11, before: 0, after: 0 },
  title: { label: 'Title', size: 26, before: 0, after: 3 },
  subtitle: { label: 'Subtitle', size: 15, before: 0, after: 16, color: '#666666' },
  1: { label: 'Heading 1', size: 20, before: 20, after: 6 },
  2: { label: 'Heading 2', size: 16, before: 18, after: 6 },
  3: { label: 'Heading 3', size: 14, before: 16, after: 4, color: '#434343' },
  4: { label: 'Heading 4', size: 12, before: 14, after: 4, color: '#666666' },
  5: { label: 'Heading 5', size: 11, before: 12, after: 4, color: '#666666' },
  6: { label: 'Heading 6', size: 11, before: 12, after: 4, color: '#666666', italic: true },
};
// Their order in menus (number-like keys would otherwise come first).
export const STYLE_ORDER = ['paragraph', 'title', 'subtitle', '1', '2', '3', '4', '5', '6'];
export const FONTS = ['Arial', 'Comic Sans MS', 'Courier New', 'Georgia', 'Impact', 'Times New Roman', 'Trebuchet MS', 'Verdana'];
export const DEFAULT_FONT = 'Arial', DEFAULT_SIZE = 11, DEFAULT_LINE = 1.15;
// Sizes on the page scale with the zoom (--z), so the page lays out the same at every zoom.
const z = (value, unit) => `calc(var(--z, 1) * ${value}${unit})`;

// Every paragraph-like block: alignment, indents (in pixels at 100%), line spacing, and space before and after.
const blockAttrs = { align: { default: null }, indent: { default: 0 }, firstLine: { default: 0 }, right: { default: 0 },
  line: { default: null }, before: { default: null }, after: { default: null } };
const number = (value, fallback = 0) => { const n = parseFloat(value); return Number.isFinite(n) ? n : fallback; };
// Points from a CSS length: '14pt', '20px', or this page's own 'calc(var(--z, 1) * 14pt)'.
const points = value => {
  const m = /(-?\d+(?:\.\d+)?)(pt|px)\)?\s*$/.exec(value ?? '');
  return !m ? null : m[2] === 'pt' ? Number(m[1]) : Number(m[1]) * 0.75;
};
function readBlock(dom) {
  const s = dom.style, align = /^(center|right|justify)$/.test(s.textAlign) ? s.textAlign : null;
  const line = /^\d+(\.\d+)?$/.test(s.lineHeight) ? Math.min(3, Math.max(1, number(s.lineHeight))) : null;
  const before = points(s.marginTop || s.paddingTop), after = points(s.marginBottom || s.paddingBottom);
  const indent = Math.max(0, Math.round((points(s.marginLeft) ?? 0) / 0.75));
  return { align, line, before: before || null, after: after || null, indent };
}
function blockStyle(attrs) {
  const parts = [];
  if (attrs.align) parts.push(`text-align:${attrs.align}`);
  if (attrs.indent) parts.push(`margin-left:${z(attrs.indent, 'px')}`);
  if (attrs.right) parts.push(`margin-right:${z(attrs.right, 'px')}`);
  if (attrs.firstLine) parts.push(`text-indent:${z(attrs.firstLine, 'px')}`);
  if (attrs.line) parts.push(`line-height:${attrs.line}`);
  if (attrs.before !== null) parts.push(`padding-top:${z(attrs.before, 'pt')}`);
  if (attrs.after !== null) parts.push(`padding-bottom:${z(attrs.after, 'pt')}`);
  return parts.join(';');
}
const textblock = (tag, extra = {}) => node => {
  const style = blockStyle(node.attrs);
  return [tag, { ...extra, ...(style ? { style } : {}) }, 0];
};

const colour = value => {
  if (!value) return null;
  const rgb = value.match(/^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)$/);
  if (rgb) return rgb[4] === '0' ? null : '#' + rgb.slice(1, 4).map(n => Number(n).toString(16).padStart(2, '0')).join('');
  return /^#[0-9a-f]{6}$/i.test(value) ? value.toLowerCase() : null;
};

export const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'inline*', attrs: blockAttrs,
      parseDOM: [{ tag: 'p', getAttrs: readBlock }], toDOM: textblock('p') },
    title: { group: 'block', content: 'inline*', attrs: blockAttrs, defining: true,
      parseDOM: [{ tag: 'p.title', getAttrs: readBlock, priority: 60 }], toDOM: textblock('p', { class: 'title' }) },
    subtitle: { group: 'block', content: 'inline*', attrs: blockAttrs, defining: true,
      parseDOM: [{ tag: 'p.subtitle', getAttrs: readBlock, priority: 60 }], toDOM: textblock('p', { class: 'subtitle' }) },
    heading: { group: 'block', content: 'inline*', attrs: { ...blockAttrs, level: { default: 1 } }, defining: true,
      parseDOM: [1, 2, 3, 4, 5, 6].map(level => ({ tag: 'h' + level, getAttrs: dom => ({ ...readBlock(dom), level }) })),
      toDOM: node => textblock('h' + node.attrs.level)(node) },
    code_block: { group: 'block', content: 'text*', marks: '', code: true, defining: true,
      parseDOM: [{ tag: 'pre', preserveWhitespace: 'full' }], toDOM: () => ['pre', ['code', 0]] },
    blockquote: { group: 'block', content: 'block+', defining: true, parseDOM: [{ tag: 'blockquote' }], toDOM: () => ['blockquote', 0] },
    horizontal_rule: { group: 'block', parseDOM: [{ tag: 'hr:not([style*="page-break"])' }], toDOM: () => ['hr'] },
    // A page break carries no characters: the text either side of it is unchanged.
    page_break: { group: 'block', selectable: true,
      parseDOM: [{ tag: 'div.page-break', priority: 60 }, { tag: 'hr[style*="page-break"]', priority: 60 }],
      toDOM: () => ['div', { class: 'page-break', contenteditable: 'false' }] },
    bullet_list: { group: 'block', content: 'list_item+', parseDOM: [{ tag: 'ul:not([data-check])' }], toDOM: () => ['ul', 0] },
    ordered_list: { group: 'block', content: 'list_item+', parseDOM: [{ tag: 'ol' }], toDOM: () => ['ol', 0] },
    check_list: { group: 'block', content: 'check_item+', parseDOM: [{ tag: 'ul[data-check]' }], toDOM: () => ['ul', { 'data-check': '' }, 0] },
    list_item: { content: 'paragraph block*', defining: true, parseDOM: [{ tag: 'li:not([data-done])' }], toDOM: () => ['li', 0] },
    check_item: { content: 'paragraph block*', defining: true, attrs: { done: { default: false } },
      parseDOM: [{ tag: 'li[data-done]', getAttrs: dom => ({ done: dom.getAttribute('data-done') === 'true' }) }],
      toDOM: node => ['li', { 'data-done': String(node.attrs.done) }, 0] },
    text: { group: 'inline' },
    hard_break: { group: 'inline', inline: true, selectable: false, parseDOM: [{ tag: 'br' }], toDOM: () => ['br'] },
  },
  marks: {
    link: { attrs: { href: {} }, inclusive: false,
      parseDOM: [{ tag: 'a[href]', getAttrs: dom => (/^https?:\/\//i.test(dom.getAttribute('href') ?? '') ? { href: dom.getAttribute('href') } : false) }],
      toDOM: node => ['a', { href: node.attrs.href, rel: 'noopener noreferrer nofollow', target: '_blank' }, 0] },
    strong: { parseDOM: [{ tag: 'strong' }, { tag: 'b', getAttrs: n => n.style.fontWeight !== 'normal' && null },
      { style: 'font-weight', getAttrs: v => /^(bold(er)?|[6-9]\d{2})$/.test(v) && null }], toDOM: () => ['strong', 0] },
    em: { parseDOM: [{ tag: 'i' }, { tag: 'em' }, { style: 'font-style=italic' }], toDOM: () => ['em', 0] },
    underline: { parseDOM: [{ tag: 'u' }, { style: 'text-decoration=underline' }, { style: 'text-decoration-line=underline' }], toDOM: () => ['u', 0] },
    strike: { parseDOM: [{ tag: 's' }, { tag: 'del' }, { style: 'text-decoration=line-through' }, { style: 'text-decoration-line=line-through' }],
      toDOM: () => ['s', 0] },
    sup: { excludes: 'sup sub', parseDOM: [{ tag: 'sup' }, { style: 'vertical-align=super' }], toDOM: () => ['sup', 0] },
    sub: { excludes: 'sup sub', parseDOM: [{ tag: 'sub' }, { style: 'vertical-align=sub' }], toDOM: () => ['sub', 0] },
    font: { attrs: { family: {} },
      parseDOM: [{ style: 'font-family', getAttrs: v => {
        const family = FONTS.find(f => f.toLowerCase() === v.split(',')[0].replace(/["']/g, '').trim().toLowerCase());
        return family && family !== DEFAULT_FONT ? { family } : false;
      } }],
      toDOM: node => ['span', { style: `font-family:"${node.attrs.family}"` }, 0] },
    size: { attrs: { pt: {} },
      parseDOM: [{ style: 'font-size', getAttrs: v => {
        const pt = points(v); return pt && pt !== DEFAULT_SIZE && pt >= 1 && pt <= 400 ? { pt: Math.round(pt * 2) / 2 } : false;
      } }],
      toDOM: node => ['span', { style: `font-size:${z(node.attrs.pt, 'pt')}` }, 0] },
    color: { attrs: { value: {} },
      parseDOM: [{ style: 'color', getAttrs: v => { const value = colour(v); return value && value !== '#000000' ? { value } : false; } }],
      toDOM: node => ['span', { style: `color:${node.attrs.value}` }, 0] },
    highlight: { attrs: { value: {} },
      parseDOM: [{ style: 'background-color', getAttrs: v => { const value = colour(v); return value && value !== '#ffffff' ? { value } : false; } }],
      toDOM: node => ['span', { style: `background-color:${node.attrs.value}` }, 0] },
  },
});

/** Blocks that hold a line of text and take the paragraph styles. */
export const TEXT_BLOCKS = new Set(['paragraph', 'title', 'subtitle', 'heading']);
/** A text block's paragraph style: 'paragraph', 'title', 'subtitle' or a heading level. */
export const styleOf = node => (node.type.name === 'heading' ? node.attrs.level : node.type.name);

/** The characters the proof covers: blocks one line each, a line break as a newline. */
export const plainText = doc => doc.textBetween(0, doc.content.size, '\n', leaf => leaf.type.name === 'hard_break' ? '\n' : '');
