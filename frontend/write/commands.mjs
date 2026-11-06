// What the toolbar and menus do to the document, as ProseMirror commands. None of them add characters, except an
// inserted line or page break, which may start a new paragraph after it; that's labelled the way the Mac labels a
// format command that inserts text ('format-insert').
import { TextSelection } from 'prosemirror-state';
import { wrapInList, liftListItem, sinkListItem } from 'prosemirror-schema-list';
import { schema, STYLES, TEXT_BLOCKS, styleOf } from './schema.mjs';

const { nodes, marks } = schema;
export const BLOCK_DEFAULTS = { align: null, indent: 0, firstLine: 0, right: 0, line: null, before: null, after: null };
export const INDENT_STEP = 48, MAX_INDENT = 576;

/** Whether the selection is inside a node of this type. */
export function inside(state, type) {
  const { $from } = state.selection;
  for (let d = $from.depth; d > 0; d--) if ($from.node(d).type === type) return true;
  return false;
}
/** The text blocks the selection touches, with their positions. */
export function textBlocks(state) {
  const { from, to } = state.selection, found = [];
  state.doc.nodesBetween(from, to, (node, pos) => {
    if (TEXT_BLOCKS.has(node.type.name)) { found.push({ node, pos }); return false; }
    return true;
  });
  if (!found.length && TEXT_BLOCKS.has(state.selection.$from.parent.type.name))
    found.push({ node: state.selection.$from.parent, pos: state.selection.$from.before() });
  return found;
}
const changeBlocks = change => (state, dispatch) => {
  const blocks = textBlocks(state);
  if (!blocks.length) return false;
  if (dispatch) {
    const tr = state.tr;
    for (const { node, pos } of blocks) tr.setNodeMarkup(pos, null, { ...node.attrs, ...change(node) });
    dispatch(tr.scrollIntoView());
  }
  return true;
};

// Marks: a toggled style, or one with a value (font, size, colour). The default value removes the mark.
export const toggle = type => (state, dispatch) => {
  const { from, to, empty, $from } = state.selection;
  if (empty) {
    const on = type.isInSet(state.storedMarks || $from.marks());
    dispatch?.(on ? state.tr.removeStoredMark(type) : state.tr.addStoredMark(type.create()));
    return true;
  }
  const on = state.doc.rangeHasMark(from, to, type) && everyHas(state, type);
  if (dispatch) {
    const tr = state.tr;
    for (const range of state.selection.ranges) {
      if (on) tr.removeMark(range.$from.pos, range.$to.pos, type);
      else tr.addMark(range.$from.pos, range.$to.pos, type.create());
    }
    dispatch(tr.scrollIntoView());
  }
  return true;
};
/** Whether every character selected has the mark, as Docs shows it. */
export function everyHas(state, type) {
  let all = true;
  state.doc.nodesBetween(state.selection.from, state.selection.to, node => {
    if (node.isText && !type.isInSet(node.marks)) all = false;
  });
  return all;
}
export const setMark = (type, attrs) => (state, dispatch) => {
  const { empty } = state.selection;
  if (dispatch) {
    const tr = state.tr;
    if (empty) {
      tr.removeStoredMark(type);
      if (attrs) tr.addStoredMark(type.create(attrs));
    } else for (const range of state.selection.ranges) {
      tr.removeMark(range.$from.pos, range.$to.pos, type);
      if (attrs) tr.addMark(range.$from.pos, range.$to.pos, type.create(attrs));
    }
    dispatch(tr.scrollIntoView());
  }
  return true;
};
/** A mark's value where the selection starts: what the toolbar shows. */
export function markValue(state, type) {
  const { $from, empty, from, to } = state.selection;
  let set = empty ? state.storedMarks || $from.marks() : null;
  if (!set) {
    let found = null;
    state.doc.nodesBetween(from, to, node => { if (!found && node.isText) found = node.marks; });
    set = found ?? $from.marks();
  }
  return type.isInSet(set)?.attrs ?? null;
}

// Paragraph styles, as Docs names them. Lists hold only normal text, so they're skipped.
export const setStyle = style => (state, dispatch) => {
  const type = style === 'paragraph' ? nodes.paragraph : style === 'title' ? nodes.title : style === 'subtitle' ? nodes.subtitle : nodes.heading;
  const tr = state.tr;
  for (const { node, pos } of textBlocks(state)) {
    const $pos = state.doc.resolve(pos), index = $pos.index();
    if (!$pos.parent.canReplaceWith(index, index + 1, type)) continue;
    const attrs = { ...Object.fromEntries(Object.keys(BLOCK_DEFAULTS).map(k => [k, node.attrs[k]])), ...(type === nodes.heading ? { level: style } : {}) };
    if (node.type !== type || node.attrs.level !== attrs.level) tr.setNodeMarkup(pos, type, attrs);
  }
  if (!tr.docChanged) return false;
  dispatch?.(tr.scrollIntoView());
  return true;
};
export const currentStyle = state => styleOf(state.selection.$from.parent);

export const align = value => changeBlocks(() => ({ align: value === 'left' ? null : value }));
export const lineSpacing = value => changeBlocks(() => ({ line: value }));
export const spacing = (side, add) => changeBlocks(() => ({ [side]: add ? 10 : 0 }));
/** Space before or after the selected paragraph, with its style's own as the default. */
export function spaceOf(state, side) {
  const node = state.selection.$from.parent;
  return node.attrs[side] ?? STYLES[styleOf(node)]?.[side] ?? 0;
}

const listItemOf = state => (inside(state, nodes.check_list) ? nodes.check_item : nodes.list_item);
const LISTS = [nodes.bullet_list, nodes.ordered_list, nodes.check_list];
export const toggleList = (listType, itemType) => (state, dispatch, view) => {
  if (inside(state, listType)) return liftListItem(itemType)(state, dispatch, view);
  // In another kind of list: the nearest list changes kind, its items and their text as they are.
  const { $from, $to } = state.selection;
  for (let d = $from.depth; d > 0; d--) {
    const list = $from.node(d);
    if (!LISTS.includes(list.type)) continue;
    if (dispatch) {
      const items = [];
      list.forEach(item => items.push(itemType.create(itemType === nodes.check_item ? { done: false } : null, item.content)));
      const tr = state.tr.replaceWith($from.before(d), $from.after(d), listType.create(null, items));
      dispatch(tr.setSelection(TextSelection.create(tr.doc, $from.pos, $to.pos)).scrollIntoView());
    }
    return true;
  }
  return wrapInList(listType)(state, dispatch, view);
};
export const indent = (state, dispatch, view) => {
  if (inside(state, nodes.bullet_list) || inside(state, nodes.ordered_list) || inside(state, nodes.check_list))
    return sinkListItem(listItemOf(state))(state, dispatch, view);
  return changeBlocks(node => ({ indent: Math.min(MAX_INDENT, (Math.floor(node.attrs.indent / INDENT_STEP) + 1) * INDENT_STEP) }))(state, dispatch);
};
export const outdent = (state, dispatch, view) => {
  if (inside(state, nodes.bullet_list) || inside(state, nodes.ordered_list) || inside(state, nodes.check_list))
    return liftListItem(listItemOf(state))(state, dispatch, view);
  return changeBlocks(node => ({ indent: Math.max(0, (Math.ceil(node.attrs.indent / INDENT_STEP) - 1) * INDENT_STEP) }))(state, dispatch);
};
export const setIndents = values => changeBlocks(() => values);

/** Clear formatting: every text style but links, and the paragraph's own alignment, indents and spacing. */
export const clearFormatting = (state, dispatch) => {
  const { from, to, empty } = state.selection, tr = state.tr;
  for (const mark of Object.values(marks)) if (mark !== marks.link) tr.removeMark(from, to, mark);
  if (empty) tr.setStoredMarks([]);
  for (const { node, pos } of textBlocks(state)) tr.setNodeMarkup(pos, null, { ...node.attrs, ...BLOCK_DEFAULTS });
  dispatch?.(tr.scrollIntoView());
  return true;
};

/** A horizontal line or page break at the caret, splitting the paragraph if needed, with the caret after it. */
export const insertBlock = type => (state, dispatch) => {
  const { $to } = state.selection;
  if (!$to.parent.isTextblock) return false;
  if (!dispatch) return true;
  const tr = state.tr;
  let at;
  if ($to.parentOffset === 0) at = $to.before();
  else if ($to.parentOffset === $to.parent.content.size) at = $to.after();
  else { tr.split($to.pos); at = tr.mapping.map($to.pos) - 1; }
  tr.insert(at, type.create());
  const after = at + 1, $after = tr.doc.resolve(after);
  if (!$after.nodeAfter?.isTextblock) tr.insert(after, nodes.paragraph.create());
  tr.setSelection(TextSelection.create(tr.doc, after + 1));
  dispatch(tr.setMeta('source', 'format-insert').scrollIntoView());
  return true;
};
