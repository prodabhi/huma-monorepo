// huma.social/write: a document editor laid out like Google Docs whose typing is recorded and proved on this computer.
// The same rules as the Mac app (HumaTextView): typed text counts, paste goes in marked as pasted, text that arrives
// without a key press is refused, and one key press adds at most a short word. Formatting never changes the characters
// the proof covers.
import { EditorState, Plugin, Selection, TextSelection } from 'prosemirror-state';
import { EditorView, Decoration, DecorationSet } from 'prosemirror-view';
import { DOMSerializer } from 'prosemirror-model';
import { history, undo, redo, undoDepth, redoDepth } from 'prosemirror-history';
import { keymap } from 'prosemirror-keymap';
import { baseKeymap, chainCommands, exitCode } from 'prosemirror-commands';
import { splitListItem, liftListItem, sinkListItem } from 'prosemirror-schema-list';
import { inputRules, wrappingInputRule } from 'prosemirror-inputrules';
import { schema, plainText, STYLES, STYLE_ORDER, FONTS, DEFAULT_FONT } from './schema.mjs';
import * as edit from './commands.mjs';
import { pages, relayout, PAGE } from './pages.mjs';
import { findPlugin, find, step, clearFind, findState } from './find.mjs';
import { grammarPlugin, issueAt, refreshGrammar } from './grammar.mjs';
import { autolink } from './autolink.mjs';
import { menu, popup, closeAll, icon, whenAllClosed } from './menus.mjs';
import { loadRecorder, Recording, writingKey } from './recorder.mjs';
import { keyCode, modifiers } from './keys.mjs';
import { PageProver } from './prove.mjs';
import { analyse, robotic } from './typing.mjs';
import { watchAutomation, automation } from './automation.mjs';
import { odd, retypeCheck } from './retype.mjs';
import { confirmHuman } from './turnstile.mjs';
import { worldIDOn, worldIDRequired, verifiedAuthor, signInWithWorldID, scanAtStart, confirmStart, finishWithWorldID, prepareWorldID } from './worldid.mjs';
import { sessionNonce } from './session.mjs';
import { createCollector } from './collector.mjs';
import { canaryInstruction } from './canary.mjs';
import { provedPage, provedReport, stoppedReport, pdfTools, replayOf } from './report.mjs';
import { account, signOut, accountDocuments, accountDocument, saveToAccount, deleteFromAccount, publish, shorten, setReplay, setTitle, setListed, removeShared, pageShown, shortTarget,
  profile, loadProfile, saveProfile, handleTaken, newFace, faceURL, addPasskey, loadPasskeys, sitePasskeys, passkeysWork, passkeyAssertion, linkedWorldID } from './account.mjs';
import { pagePDF, pageDocx, pageMarkdown } from './export.mjs';
import { track } from '../pages/track.mjs';
import { pages as keptPages, page, putPage, removePage, proof, putProof, newId, isId } from './library.mjs';
import { percentLabel, checkTier, FULL_LINK, HANDLE, RESERVED_HANDLES, shortTitle, cleanTitle } from '../publication-contract.mjs';

const $ = id => document.getElementById(id);
const assets = new URL('./', import.meta.url);
// The page this tab shows (/write?page=…); without one, the list of pages.
const pageId = (id => (isId(id) ? id : null))(new URLSearchParams(location.search).get('page'));
let pageRecord = null;
// Whether this browser keeps any other page: until it does, nothing offers Your Pages.
let hasPages = false;
const SAVED = 'huma-write-page', PREFS = 'huma-write-view', KEY_PRESS_LIMIT = 16, CHECK_DEADLINE = 10_000, TEXT_LIMIT = 10_000;
// Like the Mac app (PresenceSchedule): the first check-in at least 3 minutes in, then about every 12.5 minutes.
const nextCheckIn = after => after + 180_000 + Math.floor(-Math.log1p(-crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * 570_000);
const { nodes, marks } = schema;
const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
/** A shortcut as this computer writes it: ⌘B on a Mac, Ctrl+B elsewhere. */
const keys = (text = '') => (mac ? text : text.replace(/⇧/g, 'Shift+').replace(/⌥/g, 'Alt+').replace(/⌃/g, 'Ctrl+').replace(/⌘/g, 'Ctrl+'));

let view, recording = null, prover = null, started = 0, latest = 0, nextCheck = Infinity, proved = null, stopReason = null;
let ready = false, paused = false, finished = false, lastText = '', initialText = '', pageCount = 1, viewing = false;
// Paused by the writer (not by a check-in): since when, on the recording's clock.
let pausedByWriter = false, pausedAt = 0, sealing = false;
// What the change being made comes from: a key press (and how much it has added), undo or redo, or nothing.
let pending = 'other', addedThisKey = 0, historyAction = false;
// Input-method keys (Chinese, Japanese, accents) since the composition began, and what the composition has added.
let imeKeys = 0, imeAdded = 0, imeReset = 0;
const held = new Set();
const now = () => Math.max(latest, Math.floor(performance.now() - started));
const canEdit = () => ready && !paused && !finished && !viewing;

// The view's settings, kept in this browser.
const prefs = (() => { try { return JSON.parse(localStorage.getItem(PREFS) ?? '{}') ?? {}; } catch { return {}; } })();
prefs.zoom ??= innerWidth < 860 ? 'fit' : 1; prefs.ruler ??= true; prefs.spell ??= true; prefs.grammar ??= true; prefs.theme ??= 'system';
// Pages, as Docs' print layout; a phone gets one continuous sheet unless asked for pages.
let printLayout = prefs.printLayout ?? innerWidth >= 700;
const savePrefs = () => { try { localStorage.setItem(PREFS, JSON.stringify(prefs)); } catch {} };

let messageTimer;
function say(text) {
  const message = $('message');
  clearTimeout(messageTimer); message.textContent = text;
  // A popover, shown again each time, so it sits over any open dialog rather than behind it.
  if (message.showPopover) try { message.hidePopover(); if (text) message.showPopover(); } catch {}
  if (text) messageTimer = setTimeout(() => say(''), 5000);
}
/** A control that doesn't take the focus from the page's text when pressed. */
const keepFocus = el => el.addEventListener('mousedown', e => e.preventDefault());
function show(state, label) { document.body.dataset.state = state; if (label !== undefined) $('state').textContent = label; }
/** A failure the recording can't continue past: stop and keep the page (`title`: the card's heading). */
function stop(reason, title = 'Recording stopped') {
  track('recording_stopped', { reason });
  stopReason = reason; recording = null; ready = false; pausedByWriter = false; view?.setProps({});
  collector?.stop().catch(() => {}); collector = null;
  if ($('pausedCard').open) $('pausedCard').close();
  $('proving').close(); $('finish').disabled = true; $('pause').disabled = true; $('pausedBar').hidden = true; show('stopped', 'Stopped');
  closeAll(); for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  $('haltTitle').textContent = title; $('haltBarText').textContent = title + '.';
  $('haltText').textContent = reason;
  $('halt').oncancel = e => e.preventDefault();
  $('halt').showModal(); document.activeElement?.blur();
}
// After a stop: read the page, keep it as a report or as text, or start again.
/** A stopped page to read, with every option in the bar across the top. */
function viewStopped() { setMode(true); document.body.classList.add('barred'); $('haltBar').hidden = false; }
$('haltNew').onclick = $('haltBarNew').onclick = () => newPage();
// A card closed without a choice (a second Escape, Android Back) leaves its bar, so every option stays.
$('halt').onclose = () => { if ($('haltBar').hidden) viewStopped(); };
$('haltDownload').onclick = $('haltBarDownload').onclick = () => openFormats();
/** Runs `then` for a click on the dimmed page around a dialog: pressed and released outside its box. (A click on the
 *  dialog's own padding, or a text selection dragged past a field's edge, also lands on the dialog itself.) */
function onClickOutside(dialog, then) {
  const outside = e => { const r = dialog.getBoundingClientRect(); return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom; };
  let pressedOutside = false;
  dialog.addEventListener('mousedown', e => { pressedOutside = e.target === dialog && outside(e); });
  dialog.addEventListener('click', e => { if (pressedOutside && e.target === dialog && outside(e)) then(); pressedOutside = false; });
}
// Each card offers its main action and one other; a click outside it shows the page with every option in its bar.
for (const id of ['startCard', 'pausedCard', 'halt']) onClickOutside($(id), () => $(id).close());
/** Pause: no input reaches the page, and the next check-in waits by as long as the pause lasts. */
function pauseRecording(viewOnly = false) {
  if (!recording || paused || finished) return;
  releaseHeld();
  pausedByWriter = paused = true; pausedAt = now(); view.setProps({});
  closeAll(); show('paused', 'Paused');
  $('pauseIcon').setAttribute('href', '#i-play_arrow'); $('pauseLabel').textContent = 'Resume'; $('pause').title = 'Resume recording';
  if (viewOnly) { document.body.classList.add('barred'); $('pausedBar').hidden = false; }
  else { $('pausedCard').oncancel = e => { e.preventDefault(); resumeRecording(); }; $('pausedCard').showModal(); document.activeElement?.blur(); }
}
function resumeRecording() {
  if (!pausedByWriter) return;
  if (devtools) { say('Close developer tools to keep recording.'); return; }
  nextCheck += now() - pausedAt; pausedByWriter = paused = false; view.setProps({});
  $('pausedCard').close(); $('pausedBar').hidden = true; document.body.classList.remove('barred');
  $('pauseIcon').setAttribute('href', '#i-pause'); $('pauseLabel').textContent = 'Pause'; $('pause').title = 'Pause recording';
  show('writing', 'Recording'); view.focus();
}
keepFocus($('pause'));
$('pause').onclick = () => (pausedByWriter ? resumeRecording() : pauseRecording());
$('resume').onclick = $('pausedBarResume').onclick = resumeRecording;
$('pausedFinish').onclick = () => finishNow();
$('pausedCard').onclose = () => { if (pausedByWriter) { document.body.classList.add('barred'); $('pausedBar').hidden = false; } };
// The status opens the recording's own menu: pause or resume, finish, or start again.
keepFocus($('status'));
$('status').onclick = () => {
  // While a page proves behind it, the status brings the progress back.
  if (sealing && !$('proving').open) { $('proving').showModal(); return; }
  if ($('status').getAttribute('aria-expanded') === 'true') { closeAll(); return; }
  menu($('status'), [
    idle() ? { label: 'Start recording', icon: 'radio_button_checked', run: begin }
      : pausedByWriter ? { label: 'Resume recording', icon: 'play_arrow', disabled: !recording, run: resumeRecording }
      : { label: 'Pause recording', icon: 'pause', disabled: !recording || paused || finished, run: () => pauseRecording() },
    { label: 'Finish', icon: 'task_alt', disabled: !recording || finished, run: () => finishNow() },
    'separator',
    { label: 'Download report', icon: 'article', disabled: !proved && !stopReason, run: saveReport },
    ...(replayOn === null ? [] : [{ label: replayOn ? 'Stop showing how you wrote it' : 'Let readers watch you write', icon: 'play_arrow', run: () => toggleReplay(!replayOn) }]),
    ...(listedOn === null ? [] : [{ label: listedOn ? 'Hide from Your Page' : 'Show on Your Page', icon: 'visibility', run: () => toggleListed(!listedOn) }]),
    { label: 'Start a new document', icon: 'description', run: confirmNew },
  ]);
};
async function guarded(work) {
  try { return await work(); } catch (e) { if (recording) stop(`Recording stopped: ${e?.message ?? 'unknown error'}. Your text is saved.`); }
}

/** Where a change's characters came from, as the Mac labels them. */
function labelFor(tr) {
  if (historyAction) return 'undo-redo';
  const source = tr.getMeta('source');
  if (source) return source;
  const ui = tr.getMeta('uiEvent');
  if (ui === 'paste' || ui === 'drop') return 'paste';
  // An input method's text counts as typed only while its own key presses drive it, as on the Mac; dictation has none.
  if (view?.composing || tr.getMeta('composition') !== undefined) return imeKeys ? 'input-method' : 'other';
  return pending;
}
function diff(a, b) {
  let start = 0; while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let end = 0; while (end < a.length - start && end < b.length - start && a[a.length - 1 - end] === b[b.length - 1 - end]) end++;
  return { inserted: b.slice(start, b.length - end), removed: a.length - start - end };
}
// Every change to the characters is checked before it applies; formatting goes through as it is.
const rules = new Plugin({
  filterTransaction(tr, state) {
    if (!tr.docChanged) return true;
    if (!ready || paused || finished || viewing) return false;
    const before = plainText(state.doc), after = plainText(tr.doc);
    if (before === after) return true;
    // The proof holds a page of up to 10,000 characters.
    if ([...after].length > Math.max(TEXT_LIMIT, [...before].length)) { say('A document holds up to 10,000 characters.'); return false; }
    const label = labelFor(tr), { inserted, removed } = diff(before, after);
    if (label === 'typing-external') {
      const added = Math.max(0, inserted.length - removed);
      if (addedThisKey + added > KEY_PRESS_LIMIT) { say('One key press can add at most a short word.'); return false; }
      addedThisKey += added;
    } else if (label === 'input-method') {
      const added = Math.max(0, inserted.length - removed);
      if (imeAdded + added > imeKeys * KEY_PRESS_LIMIT) { say('One key press can add at most a short word.'); return false; }
      imeAdded += added;
    } else if (label === 'format-insert') return inserted === '\n' && removed === 0;
    else if (label === 'other' && inserted !== '') { refuseUntyped(); return false; }
    return true;
  },
});
// Once proved, the pasted parts are shaded on the page, as in the report: `origin` marks each character of the
// plain text (p = pasted), and each maps to its place in the document.
let pastedShade = DecorationSet.empty;
function shadePasted(doc, origin) {
  const at = [];
  let first = true;
  doc.descendants((node, pos) => {
    if (!node.isTextblock) return true;
    if (!first) at.push(null); // the newline between blocks
    first = false;
    node.forEach((child, offset) => {
      const start = pos + 1 + offset;
      if (child.isText) for (let i = 0; i < child.text.length; i++) at.push(start + i);
      else if (child.type === nodes.hard_break) at.push(start);
    });
    return false;
  });
  const marks = [];
  for (let i = 0; i < origin.length; i++) {
    if (origin[i] !== 'p' || at[i] === null || at[i] === undefined) continue;
    let j = i; while (j + 1 < origin.length && origin[j + 1] === 'p' && at[j + 1] === at[j] + 1) j++;
    marks.push(Decoration.inline(at[i], at[j] + 1, { class: 'pasted-mark' }));
    i = j;
  }
  pastedShade = DecorationSet.create(doc, marks);
}
const shading = new Plugin({ props: { decorations: () => pastedShade } });
// "Start typing…" on an empty page, and spelling suggestions on or off.
const attributes = new Plugin({
  props: { attributes: state => ({
    // Spelling comes from Huma's own checker (grammar.mjs), so the browser's underlines don't double it.
    spellcheck: 'false',
    ...(state.doc.childCount === 1 && state.doc.firstChild.type === nodes.paragraph && state.doc.firstChild.content.size === 0 ? { class: 'empty' } : {}),
  }) },
});

const historyCommand = command => (state, dispatch, v) => {
  historyAction = true;
  try { return command(state, dispatch, v); } finally { historyAction = false; }
};
const { listItemOf: listItem, inList } = edit;
const fontSize = state => edit.markValue(state, marks.size)?.pt ?? STYLES[edit.currentStyle(state)]?.size ?? 11;
const resize = by => (state, dispatch) => {
  const next = Math.max(1, Math.min(400, Math.round(fontSize(state)) + by));
  return edit.setMark(marks.size, next === STYLES[edit.currentStyle(state)]?.size ? null : { pt: next })(state, dispatch);
};

// Everything the menus, toolbar, shortcuts and menu search can do. `edit: true` needs the page open for writing.
const A = {
  newPage: { label: 'New document', icon: 'description', run: () => confirmNew() },
  yourPages: { label: 'Your documents', icon: 'toc', run: () => openPages(), enabled: () => hasPages },
  pause: { label: 'Pause recording', icon: 'pause', run: () => pauseRecording(), enabled: () => Boolean(recording) && !paused && !finished },
  resume: { label: 'Resume recording', icon: 'play_arrow', run: () => resumeRecording(), enabled: () => pausedByWriter },
  finish: { label: 'Finish', icon: 'task_alt', run: () => finish(), enabled: () => Boolean(recording) && !paused && !finished },
  downloadPDF: { label: 'PDF (.pdf)', run: () => download('pdf') },
  downloadWord: { label: 'Word (.docx)', run: () => download('docx') },
  downloadMarkdown: { label: 'Markdown (.md)', run: () => download('md') },
  downloadHTML: { label: 'Web page (.html)', run: () => download('html') },
  downloadText: { label: 'Plain text (.txt)', run: () => download('txt') },
  downloadReport: { label: 'Report (.pdf)', icon: 'article', run: () => saveReport(), enabled: () => Boolean(proved || stopReason) },
  rename: { label: 'Rename', icon: 'edit', run: () => { $('title').focus(); $('title').select(); } },
  print: { label: 'Print', icon: 'print', keys: '⌘P', run: () => print() },
  undo: { label: 'Undo', icon: 'undo', keys: '⌘Z', edit: true, command: historyCommand(undo), enabled: () => undoDepth(view.state) > 0 },
  redo: { label: 'Redo', icon: 'redo', keys: '⌘Y', edit: true, command: historyCommand(redo), enabled: () => redoDepth(view.state) > 0 },
  cut: { label: 'Cut', icon: 'content_cut', keys: '⌘X', edit: true, run: () => document.execCommand('cut') },
  copy: { label: 'Copy', icon: 'content_copy', keys: '⌘C', run: () => document.execCommand('copy') },
  paste: { label: 'Paste', icon: 'content_paste', keys: '⌘V', edit: true, run: () => say(`Use ${keys('⌘V')} to paste.`) },
  pastePlain: { label: 'Paste without formatting', keys: '⇧⌘V', edit: true, run: () => say(`Use ${keys('⇧⌘V')} to paste without formatting.`) },
  selectAll: { label: 'Select all', icon: 'select_all', keys: '⌘A', run: () => view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 0, view.state.doc.content.size)).scrollIntoView()) },
  delete: { label: 'Delete', icon: 'delete', edit: true, command: (state, dispatch) => { if (state.selection.empty) return false; dispatch?.(state.tr.deleteSelection().scrollIntoView()); return true; } },
  find: { label: 'Find', icon: 'search', keys: '⌘F', run: () => openFind() },
  // A finished or stopped page can't change, so it stays in view only.
  editing: { label: 'Editing', icon: 'edit', run: () => setMode(false), checked: () => !viewing, enabled: () => !finished && !stopReason },
  viewing: { label: 'Viewing', icon: 'visibility', run: () => setMode(true), checked: () => viewing },
  printLayout: { label: 'Show print layout', run: () => { printLayout = prefs.printLayout = !printLayout; savePrefs(); applyView(); applyZoom(); view.focus(); }, checked: () => printLayout },
  ruler: { label: 'Show ruler', run: () => toggleView('ruler'), checked: () => prefs.ruler },
  'theme-system': { label: 'System default', run: () => setTheme('system'), checked: () => prefs.theme === 'system' },
  'theme-light': { label: 'Light', run: () => setTheme('light'), checked: () => prefs.theme === 'light' },
  'theme-dark': { label: 'Dark', run: () => setTheme('dark'), checked: () => prefs.theme === 'dark' },
  outline: { label: 'Show outline', run: () => toggleView('outline'), checked: () => Boolean(prefs.outline) },
  compact: { label: 'Hide the menus', icon: 'keyboard_arrow_up', keys: '⌃⇧F', run: () => toggleView('compact') },
  hr: { label: 'Horizontal line', icon: 'horizontal_rule', edit: true, command: edit.insertBlock(nodes.horizontal_rule) },
  pageBreak: { label: 'Page break', icon: 'insert_page_break', keys: '⌘↵', edit: true, command: edit.insertBlock(nodes.page_break) },
  link: { label: 'Link', icon: 'link', keys: '⌘K', edit: true, run: () => openLink() },
  strong: { label: 'Bold', icon: 'format_bold', keys: '⌘B', edit: true, command: edit.toggle(marks.strong) },
  em: { label: 'Italic', icon: 'format_italic', keys: '⌘I', edit: true, command: edit.toggle(marks.em) },
  underline: { label: 'Underline', icon: 'format_underlined', keys: '⌘U', edit: true, command: edit.toggle(marks.underline) },
  strike: { label: 'Strikethrough', icon: 'strikethrough_s', keys: '⇧⌘X', edit: true, command: edit.toggle(marks.strike) },
  sup: { label: 'Superscript', icon: 'superscript', keys: '⌘.', edit: true, command: edit.toggle(marks.sup) },
  sub: { label: 'Subscript', icon: 'subscript', keys: '⌘,', edit: true, command: edit.toggle(marks.sub) },
  bigger: { label: 'Increase font size', icon: 'add', keys: '⇧⌘.', edit: true, command: resize(1) },
  smaller: { label: 'Decrease font size', icon: 'remove', keys: '⇧⌘,', edit: true, command: resize(-1) },
  left: { label: 'Left', icon: 'format_align_left', keys: '⇧⌘L', edit: true, command: edit.align('left') },
  center: { label: 'Center', icon: 'format_align_center', keys: '⇧⌘E', edit: true, command: edit.align('center') },
  // No ⇧⌘R, as in Google Docs: in a browser that's a hard reload, and people press it for that.
  right: { label: 'Right', icon: 'format_align_right', edit: true, command: edit.align('right') },
  justify: { label: 'Justified', icon: 'format_align_justify', keys: '⇧⌘J', edit: true, command: edit.align('justify') },
  indent: { label: 'Increase indent', icon: 'format_indent_increase', keys: '⌘]', edit: true, command: edit.indent },
  outdent: { label: 'Decrease indent', icon: 'format_indent_decrease', keys: '⌘[', edit: true, command: edit.outdent },
  bullet: { label: 'Bulleted list', icon: 'format_list_bulleted', keys: '⇧⌘8', edit: true, command: edit.toggleList(nodes.bullet_list, nodes.list_item) },
  number: { label: 'Numbered list', icon: 'format_list_numbered', keys: '⇧⌘7', edit: true, command: edit.toggleList(nodes.ordered_list, nodes.list_item) },
  check: { label: 'Checklist', icon: 'checklist', keys: '⇧⌘9', edit: true, command: edit.toggleList(nodes.check_list, nodes.check_item) },
  clear: { label: 'Clear formatting', icon: 'format_clear', keys: '⌘\\', edit: true, command: edit.clearFormatting },
  spellcheck: { label: 'Show spelling suggestions', run: () => toggleView('spell'), checked: () => prefs.spell },
  grammar: { label: 'Show grammar suggestions', run: () => toggleView('grammar'), checked: () => prefs.grammar },
  paint: { label: 'Paint format', icon: 'format_paint', edit: true, run: () => togglePaint(false) },
  wordCount: { label: 'Word count', icon: 'text_fields', keys: '⇧⌘C', run: () => openWordCount() },
  searchMenus: { label: 'Search the menus', icon: 'search', keys: '⌥/', run: () => openMenuSearch() },
  shortcuts: { label: 'Keyboard shortcuts', icon: 'keyboard', keys: '⌘/', run: () => openShortcuts() },
};
for (const [style, s] of Object.entries(STYLES)) {
  const shortcut = style === 'paragraph' ? '⌘⌥0' : /^\d$/.test(style) ? `⌘⌥${style}` : undefined;
  A['style-' + style] = { label: s.label, keys: shortcut, edit: true, command: edit.setStyle(/^\d$/.test(style) ? Number(style) : style),
    checked: () => String(edit.currentStyle(view.state)) === style };
}
for (const [value, label] of [[1, 'Single'], [1.15, '1.15'], [1.5, '1.5'], [2, 'Double']])
  A['line-' + value] = { label, edit: true, command: edit.lineSpacing(value === 1.15 ? null : value),
    checked: () => (view.state.selection.$from.parent.attrs.line ?? 1.15) === value };

const enabled = id => (!A[id].edit || canEdit()) && (A[id].enabled?.() ?? true);
/** Run an action: its command on the page, or its own function. Formatting keeps the page focused. */
function act(id) {
  const action = A[id];
  if (!action || !enabled(id)) return false;
  closeAll();
  if (action.command) { action.command(view.state, view.dispatch, view); view.focus(); }
  else action.run();
  return true;
}
const item = (id, extra = {}) => ({ label: A[id].label, icon: A[id].icon, keys: A[id].keys && keys(A[id].keys), disabled: !enabled(id),
  ...(A[id].checked ? { checked: A[id].checked() } : {}), run: () => act(id), ...extra });
const command = id => (state, dispatch, v) => { if (!enabled(id)) return true; return act(id); };

// The menu bar's menus.
const MENUS = {
  file: () => [item('newPage'), ...(hasPages ? [item('yourPages')] : []), 'separator', pausedByWriter ? item('resume') : item('pause'), item('finish'), 'separator',
    { label: 'Download', icon: 'download', submenu: () => [item('downloadReport'), 'separator', { heading: 'This page' }, item('downloadPDF'), item('downloadWord'), item('downloadMarkdown'), item('downloadHTML'), item('downloadText')] },
    item('rename'), 'separator', item('print')],
  edit: () => [item('undo'), item('redo'), 'separator', item('cut'), item('copy'), item('paste'), item('pastePlain'), 'separator',
    item('selectAll'), item('delete'), 'separator', item('find')],
  view: () => [{ label: 'Mode', icon: viewing ? 'visibility' : 'edit', submenu: () => [item('editing'), item('viewing')] }, 'separator',
    item('printLayout'), item('ruler'), item('outline'), 'separator',
    { label: 'Theme', icon: 'visibility', submenu: () => [item('theme-system'), item('theme-light'), item('theme-dark')] }, 'separator', item('compact', { label: document.body.classList.contains('compact') ? 'Show the menus' : 'Hide the menus' })],
  insert: () => [item('hr'), { label: 'Break', icon: 'insert_page_break', submenu: () => [item('pageBreak')] }, 'separator', item('link')],
  format: () => [
    { label: 'Text', icon: 'format_bold', submenu: () => [item('strong'), item('em'), item('underline'), item('strike'), item('sup'), item('sub'),
      'separator', { label: 'Size', icon: 'format_size', submenu: () => [item('bigger'), item('smaller')] }] },
    { label: 'Paragraph styles', icon: 'notes', submenu: () => STYLE_ORDER.map(s => item('style-' + s)) },
    { label: 'Align & indent', icon: 'format_align_left', submenu: () => [item('left'), item('center'), item('right'), item('justify'), 'separator', item('indent'), item('outdent')] },
    { label: 'Line & paragraph spacing', icon: 'format_line_spacing', submenu: spacingItems },
    { label: 'Bullets & numbering', icon: 'format_list_bulleted', submenu: () => [item('bullet'), item('number'), item('check')] },
    'separator', item('clear')],
  tools: () => [{ label: 'Spelling and grammar', icon: 'spellcheck', submenu: () => [item('spellcheck'), item('grammar')] }, item('wordCount')],
  help: () => [item('searchMenus'), item('shortcuts')],
};
function spacingItems() {
  const before = edit.spaceOf(view.state, 'before') > 0, after = edit.spaceOf(view.state, 'after') > 0, on = canEdit();
  return [item('line-1'), item('line-1.15'), item('line-1.5'), item('line-2'), 'separator',
    { label: before ? 'Remove space before paragraph' : 'Add space before paragraph', disabled: !on, run: () => { edit.spacing('before', !before)(view.state, view.dispatch); view.focus(); } },
    { label: after ? 'Remove space after paragraph' : 'Add space after paragraph', disabled: !on, run: () => { edit.spacing('after', !after)(view.state, view.dispatch); view.focus(); } }];
}
let menubarOpen = null;
function openMenubar(button) {
  menubarOpen = button;
  menu(button, MENUS[button.dataset.menu](), { onClose: () => { if (menubarOpen === button) menubarOpen = null; } });
}
for (const button of document.querySelectorAll('#menubar button')) {
  keepFocus(button);
  button.addEventListener('click', () => { if (menubarOpen === button) closeAll(); else openMenubar(button); });
  button.addEventListener('mouseenter', () => { if (menubarOpen && menubarOpen !== button) openMenubar(button); });
}

// The toolbar's drop-downs and palettes.
const PALETTE = [
  ['#000000', '#434343', '#666666', '#999999', '#b7b7b7', '#cccccc', '#d9d9d9', '#efefef', '#f3f3f3', '#ffffff'],
  ['#980000', '#ff0000', '#ff9900', '#ffff00', '#00ff00', '#00ffff', '#4a86e8', '#0000ff', '#9900ff', '#ff00ff'],
  ['#e6b8af', '#f4cccc', '#fce5cd', '#fff2cc', '#d9ead3', '#d0e0e3', '#c9daf8', '#cfe2f3', '#d9d2e9', '#ead1dc'],
  ['#dd7e6b', '#ea9999', '#f9cb9c', '#ffe599', '#b6d7a8', '#a2c4c9', '#a4c2f4', '#9fc5e8', '#b4a7d6', '#d5a6bd'],
  ['#cc4125', '#e06666', '#f6b26b', '#ffd966', '#93c47d', '#76a5af', '#6d9eeb', '#6fa8dc', '#8e7cc3', '#c27ba0'],
  ['#a61c00', '#cc0000', '#e69138', '#f1c232', '#6aa84f', '#45818e', '#3c78d8', '#3d85c6', '#674ea7', '#a64d79'],
  ['#85200c', '#990000', '#b45f06', '#bf9000', '#38761d', '#134f5c', '#1155cc', '#0b5394', '#351c75', '#741b47'],
  ['#5b0f00', '#660000', '#783f04', '#7f6000', '#274e13', '#0c343d', '#1c4587', '#073763', '#20124d', '#4c1130'],
];
function palette(anchor, type, level) {
  const el = document.createElement('div'), current = edit.markValue(view.state, type)?.value;
  el.className = 'palette';
  el.innerHTML = `<button class="none" type="button">${icon(type === marks.highlight ? 'format_color_reset' : 'format_color_text')}${type === marks.highlight ? 'None' : 'Reset'}</button>`
    + PALETTE.map((row, i) => `<div class="grid${i < 2 ? ' first' : ''}">${row.map(c => `<button type="button" style="--c:${c}" data-c="${c}" title="${c}" aria-label="${c}" aria-pressed="${c === current}"></button>`).join('')}</div>`).join('');
  el.addEventListener('click', e => {
    const button = e.target.closest('button');
    if (!button || !canEdit()) return;
    const c = button.dataset.c, value = !c || (type === marks.color && c === '#000000') ? null : { value: c };
    closeAll(); edit.setMark(type, value)(view.state, view.dispatch); view.focus();
  });
  popup(anchor, el, { level });
}
const styleColor = s => (s?.color === '#434343' ? 'var(--doc-ink-2)' : s?.color ? 'var(--doc-ink-3)' : null);
const POPS = {
  zoom: (button, level) => menu(button, ['fit', 0.5, 0.75, 0.9, 1, 1.25, 1.5, 2].map(z => ({
    label: z === 'fit' ? 'Fit' : Math.round(z * 100) + '%', checked: prefs.zoom === z, run: () => { prefs.zoom = z; savePrefs(); applyZoom(); view.focus(); },
  })), { className: 'compact-list', level }),
  style: (button, level) => menu(button, STYLE_ORDER.slice(0, 6).map(style => [style, STYLES[style]]).map(([style, s]) => ({
    ...item('style-' + style), keys: undefined,
    style: `font-family:Arial,sans-serif;font-size:${Math.min(26, Math.round(s.size * 1.333))}px;${s.color ? `color:${styleColor(s)};` : ''}`,
  })), { className: 'styles', level }),
  font: (button, level) => {
    const current = edit.markValue(view.state, marks.font)?.family ?? DEFAULT_FONT;
    menu(button, FONTS.map(family => ({ label: family, checked: family === current, style: `font-family:"${family}"`, disabled: !canEdit(),
      run: () => { edit.setMark(marks.font, family === DEFAULT_FONT ? null : { family })(view.state, view.dispatch); view.focus(); } })), { level });
  },
  color: (button, level) => palette(button, marks.color, level),
  highlight: (button, level) => palette(button, marks.highlight, level),
  align: (button, level) => {
    const el = document.createElement('div'), current = view.state.selection.$from.parent.attrs.align ?? 'left';
    el.className = 'align-pop';
    for (const id of ['left', 'center', 'right', 'justify']) {
      const b = document.createElement('button');
      b.className = 'tb'; b.type = 'button'; b.title = A[id].keys ? `${A[id].label} (${keys(A[id].keys)})` : A[id].label; b.setAttribute('aria-pressed', String(current === id));
      b.innerHTML = icon(A[id].icon); b.onclick = () => act(id); el.append(b);
    }
    popup(button, el, { level });
  },
  spacing: (button, level) => menu(button, spacingItems(), { level }),
  mode: (button, level) => menu(button, [item('editing'), item('viewing')], { alignRight: true, level }),
};
for (const button of document.querySelectorAll('#toolbar [data-pop]')) {
  keepFocus(button);
  button.addEventListener('click', () => {
    if (!view) return;
    const level = button.closest('.toolbar-more') ? 1 : 0;
    if (button.getAttribute('aria-expanded') === 'true') closeAll(level); else POPS[button.dataset.pop](button, level);
  });
}
// A narrow window: the toolbar items that don't fit go in the ⋮ panel, as in Docs.
const toolbar = $('toolbar'), more = $('moreButton');
const flowing = [...toolbar.children].slice(0, [...toolbar.children].indexOf(more));
let overflowed = [], moreOpen = false;
function fitToolbar() {
  if (moreOpen) return;
  for (const el of flowing) el.hidden = false;
  more.hidden = true; overflowed = [];
  if (toolbar.scrollWidth <= toolbar.clientWidth) return;
  more.hidden = false;
  for (let i = flowing.length - 1; i >= 0 && toolbar.scrollWidth > toolbar.clientWidth; i--) { flowing[i].hidden = true; overflowed.unshift(flowing[i]); }
  const last = flowing.filter(el => !el.hidden).at(-1);
  if (last?.classList.contains('sep')) { last.hidden = true; overflowed.unshift(last); }
}
keepFocus(more);
more.addEventListener('click', () => {
  if (moreOpen) { closeAll(); return; }
  const panel = document.createElement('div'), moved = [...overflowed];
  panel.className = 'toolbar-more';
  for (const el of moved) { el.hidden = false; panel.append(el); }
  moreOpen = true;
  popup(more, panel, { alignRight: true, onClose: () => {
    for (const el of moved) toolbar.insertBefore(el, more);
    moreOpen = false; fitToolbar();
  } });
});
new ResizeObserver(() => fitToolbar()).observe(toolbar);
// With the menus hidden, Pause and Finish sit at the end of the toolbar's row: the toolbar leaves room for exactly as
// much as they take (more once signed in, less on a narrow window).
const headActions = document.querySelector('.head-actions');
new ResizeObserver(() => document.body.style.setProperty('--actions-width', headActions.offsetWidth + 'px')).observe(headActions);
for (const button of document.querySelectorAll('#toolbar [data-cmd]')) {
  keepFocus(button);
  button.addEventListener('click', () => { if (view) act(button.dataset.cmd); });
}
document.querySelector('[data-cmd="paint"]').addEventListener('dblclick', () => togglePaint(true));
const size = $('size');
size.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); applySize(); view.focus(); }
  if (e.key === 'Escape') { e.preventDefault(); size.value = String(fontSize(view.state)); view.focus(); }
});
size.addEventListener('change', applySize);
function applySize() {
  const pt = Math.round(parseFloat(size.value) * 2) / 2;
  if (!Number.isFinite(pt) || pt < 1 || pt > 400 || !canEdit()) { size.value = String(fontSize(view.state)); return; }
  edit.setMark(marks.size, pt === STYLES[edit.currentStyle(view.state)]?.size ? null : { pt })(view.state, view.dispatch);
}

// Keys: Docs' shortcuts, then list editing, then the editor's own.
const shortcuts = keymap({
  'Mod-z': command('undo'), 'Shift-Mod-z': command('redo'), 'Mod-y': command('redo'),
  'Mod-b': command('strong'), 'Mod-i': command('em'), 'Mod-u': command('underline'), 'Shift-Mod-x': command('strike'),
  'Mod-.': command('sup'), 'Mod-,': command('sub'), 'Shift-Mod-.': command('bigger'), 'Mod->': command('bigger'), 'Shift-Mod-,': command('smaller'), 'Mod-<': command('smaller'),
  'Mod-k': command('link'), 'Mod-Alt-0': command('style-paragraph'),
  ...Object.fromEntries([1, 2, 3, 4, 5, 6].map(n => ['Mod-Alt-' + n, command('style-' + n)])),
  'Shift-Mod-l': command('left'), 'Shift-Mod-e': command('center'), 'Shift-Mod-j': command('justify'),
  'Shift-Mod-7': command('number'), 'Shift-Mod-8': command('bullet'), 'Shift-Mod-9': command('check'),
  'Mod-]': command('indent'), 'Mod-[': command('outdent'), 'Mod-\\': command('clear'), 'Mod-Enter': command('pageBreak'),
  Enter: (state, dispatch, v) => splitListItem(listItem(state))(state, dispatch, v),
  // Tab nests a list item; in a paragraph it types a tab, as in Docs.
  Tab: (state, dispatch, v) => (inList(state) ? sinkListItem(listItem(state))(state, dispatch, v) : (dispatch?.(state.tr.insertText('\t')), true)) || true,
  'Shift-Tab': (state, dispatch, v) => (inList(state) ? liftListItem(listItem(state))(state, dispatch, v) : edit.outdent(state, dispatch, v)) || true,
  'Shift-Enter': chainCommands(exitCode, (state, dispatch) => { dispatch?.(state.tr.replaceSelectionWith(nodes.hard_break.create()).scrollIntoView()); return true; }),
  Escape: () => { if (painting) { stopPaint(); return true; } return false; },
});
// Lists as you type them: "* " or "- ", "1. " and "[] ".
const autoformat = inputRules({ rules: [
  wrappingInputRule(/^\s*([-*])\s$/, nodes.bullet_list),
  wrappingInputRule(/^(\d+)\.\s$/, nodes.ordered_list),
  wrappingInputRule(/^\[\s?\]\s$/, nodes.check_list),
] });
// Shortcuts that work wherever the focus is.
addEventListener('keydown', e => {
  if (e.defaultPrevented || !view) return;
  const mod = mac ? e.metaKey : e.ctrlKey, code = e.code;
  const global = mod && !e.altKey && !e.shiftKey && code === 'KeyF' ? 'find'
    : mod && !e.altKey && !e.shiftKey && code === 'KeyP' ? 'print'
    : mod && !e.altKey && code === 'Slash' ? 'shortcuts'
    : e.altKey && !mod && !e.ctrlKey && code === 'Slash' ? 'searchMenus'
    : e.ctrlKey && e.shiftKey && code === 'KeyF' ? 'compact'
    : mod && e.shiftKey && !e.altKey && code === 'KeyC' ? 'wordCount' : null;
  if (global) { e.preventDefault(); act(global); return; }
  if (mod && code === 'KeyG' && findState(view.state).query) { e.preventDefault(); step(view, e.shiftKey ? -1 : 1); }
});

// The toolbar and ruler follow the selection.
const FORMAT_MARKS = [marks.strong, marks.em, marks.underline, marks.strike, marks.sup, marks.sub, marks.font, marks.size, marks.color, marks.highlight];
function updateToolbar(state) {
  const { from, $from, to, empty } = state.selection;
  const active = mark => (empty ? Boolean(mark.isInSet(state.storedMarks || $from.marks())) : state.doc.rangeHasMark(from, to, mark) && edit.everyHas(state, mark));
  const pressed = { strong: active(marks.strong), em: active(marks.em), underline: active(marks.underline), link: active(marks.link),
    bullet: edit.inside(state, nodes.bullet_list), number: edit.inside(state, nodes.ordered_list), check: edit.inside(state, nodes.check_list),
    spellcheck: prefs.spell, paint: Boolean(painting) };
  for (const button of document.querySelectorAll('#toolbar [data-cmd]')) {
    const id = button.dataset.cmd;
    if (id in pressed) button.setAttribute('aria-pressed', String(pressed[id]));
    if (id === 'undo' || id === 'redo') button.disabled = !enabled(id);
  }
  const style = edit.currentStyle(state);
  $('styleLabel').textContent = STYLES[style]?.label ?? 'Normal text';
  $('fontLabel').textContent = edit.markValue(state, marks.font)?.family ?? DEFAULT_FONT;
  if (document.activeElement !== size) size.value = String(fontSize(state));
  $('colorButton').style.setProperty('--swatch', edit.markValue(state, marks.color)?.value ?? styleColor(STYLES[style]) ?? 'var(--doc-ink)');
  $('highlightButton').style.setProperty('--swatch', edit.markValue(state, marks.highlight)?.value ?? 'transparent');
  $('alignIcon').setAttribute('href', '#i-format_align_' + ($from.parent.attrs.align ?? 'left'));
  updateRuler(); updateOutlineHere(state);
}

// Word counts: on the toolbar's dialog and, if asked for, while typing.
const words = text => (text.trim() ? text.trim().split(/\s+/).length : 0);
function counts(state) {
  const text = plainText(state.doc), { from, to, empty } = state.selection;
  const selected = empty ? null : state.doc.textBetween(from, to, '\n', leaf => leaf.type === nodes.hard_break ? '\n' : '');
  const measure = t => ({ words: words(t), characters: [...t.replace(/\n/g, '')].length, letters: [...t.replace(/\s/g, '')].length });
  return { all: measure(text), selected: selected === null ? null : measure(selected) };
}
function updateCounts() {
  if (prefs.words) {
    const { all, selected } = counts(view.state);
    $('wordPill').innerHTML = (selected ? `${selected.words.toLocaleString()} of ${all.words.toLocaleString()} words` : `${all.words.toLocaleString()} ${all.words === 1 ? 'word' : 'words'}`) + icon('arrow_drop_down');
  }
  $('wordPill').hidden = !prefs.words;
  if (prover) {
    const { done, total, working } = prover.progress;
    $('parts').textContent = !total ? '' : `${done} of ${total} parts proved` + (working ? '…' : '');
  }
}
function openWordCount() {
  const { all, selected } = counts(view.state), n = v => v.toLocaleString();
  const row = (label, key) => `<tr><td>${label}</td><td>${selected ? `${n(selected[key])} of ${n(all[key])}` : n(all[key])}</td></tr>`;
  $('countRows').innerHTML = `<tr><td>Pages</td><td>${n(pageCount)}</td></tr>` + row('Words', 'words') + row('Characters', 'characters') + row('Characters excluding spaces', 'letters');
  $('showWords').checked = Boolean(prefs.words);
  $('wordCount').showModal();
}
$('wordCountOK').onclick = () => { prefs.words = $('showWords').checked; savePrefs(); updateCounts(); $('wordCount').close(); view.focus(); };
$('wordPill').onclick = openWordCount;

// Keyboard shortcuts.
function openShortcuts() {
  const groups = { Text: ['strong', 'em', 'underline', 'strike', 'sup', 'sub', 'bigger', 'smaller', 'clear'],
    Paragraph: ['style-paragraph', 'style-1', 'style-2', 'style-3', 'left', 'center', 'right', 'justify', 'indent', 'outdent', 'bullet', 'number', 'check'],
    Page: ['undo', 'redo', 'link', 'pageBreak', 'find', 'wordCount', 'print', 'searchMenus', 'compact'] };
  const escape = t => t.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);
  $('keysTable').innerHTML = Object.entries(groups).map(([group, ids]) => `<span class="group">${group}</span>`
    + ids.filter(id => A[id].keys).map(id => `<span>${escape(id.startsWith('style-') ? 'Apply ' + A[id].label : A[id].label)}</span><span>${escape(keys(A[id].keys))}</span>`).join('')).join('');
  $('shortcuts').showModal();
}
$('shortcutsOK').onclick = () => { $('shortcuts').close(); view.focus(); };

// Search the menus (⌥/): every action by name.
function openMenuSearch() {
  const el = document.createElement('div');
  el.className = 'search-pop';
  el.innerHTML = '<input type="text" placeholder="Search the menus" aria-label="Search the menus" autocomplete="off" spellcheck="false"><div class="results"></div>';
  const input = el.querySelector('input'), results = el.querySelector('.results');
  const ids = Object.keys(A).filter(id => id !== 'searchMenus');
  let shown = [], active = 0;
  const render = () => {
    const q = input.value.trim().toLowerCase();
    shown = q ? ids.filter(id => A[id].label.toLowerCase().includes(q)).slice(0, 12) : [];
    active = 0;
    results.innerHTML = '';
    if (q && !shown.length) { results.innerHTML = '<div class="empty">No results</div>'; return; }
    if (!shown.length) return;
    const list = document.createElement('div');
    list.className = 'menu';
    shown.forEach((id, i) => {
      const row = document.createElement('div');
      row.className = 'menu-item' + (i === active ? ' active' : '');
      if (!enabled(id)) row.setAttribute('aria-disabled', 'true');
      row.innerHTML = (A[id].icon ? icon(A[id].icon) : '<span class="i"></span>') + '<span class="menu-label"></span>' + (A[id].keys ? `<span class="menu-keys"></span>` : '');
      row.querySelector('.menu-label').textContent = A[id].label;
      if (A[id].keys) row.querySelector('.menu-keys').textContent = keys(A[id].keys);
      keepFocus(row);
      row.addEventListener('click', () => act(id));
      list.append(row);
    });
    results.append(list);
  };
  input.addEventListener('input', render);
  input.addEventListener('keydown', e => {
    const rows = results.querySelectorAll('.menu-item');
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); if (!rows.length) return;
      active = (active + (e.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
      rows.forEach((r, i) => r.classList.toggle('active', i === active));
    } else if (e.key === 'Enter') { e.preventDefault(); if (shown[active]) act(shown[active]); }
  });
  popup(document.querySelector('[data-cmd="searchMenus"]'), el, { onClose: () => view.focus() });
  input.focus();
}

// Paint format: the text style where the caret is, on the next text selected (twice-clicked, until Escape).
let painting = null;
function togglePaint(sticky) {
  if (painting && !sticky) { stopPaint(); return; }
  const { $from, empty, from } = view.state.selection;
  const source = empty ? view.state.storedMarks || $from.marks() : view.state.doc.resolve(from + 1).marks();
  painting = { marks: source.filter(m => FORMAT_MARKS.includes(m.type)), sticky };
  document.body.classList.add('painting'); updateToolbar(view.state);
}
function stopPaint() { painting = null; document.body.classList.remove('painting'); if (view) updateToolbar(view.state); }
function paint() {
  const { from, to, empty } = view.state.selection;
  if (!painting || empty || !canEdit()) return;
  const tr = view.state.tr;
  for (const type of FORMAT_MARKS) tr.removeMark(from, to, type);
  for (const mark of painting.marks) tr.addMark(from, to, mark);
  view.dispatch(tr);
  if (!painting.sticky) stopPaint();
}

// Grammar: underlines from grammar.mjs, checked on this computer while writing (and turned on), and a card for the
// one under the caret. Choosing its fix selects the words and says what to type, so the page stays typed.
const grammar = grammarPlugin({ active: () => Boolean(prefs.grammar || prefs.spell) && canEdit(), show: kind => Boolean(kind === 'spelling' ? prefs.spell : prefs.grammar),
  worker: () => new Worker(new URL('grammar.js', assets), { type: 'module' }) });
function grammarCard() {
  const issue = view.state.selection.empty && canEdit() ? issueAt(view.state, view.state.selection.from) : null;
  if (!issue) { if (cardFor) { cardFor = null; closeAll(); } return; }
  if (cardFor && cardFor.from === issue.from && cardFor.fixes === issue.fixes) return;
  const shown = cardFor = issue;
  const el = document.createElement('div');
  el.className = 'grammar-card';
  el.innerHTML = '<p class="reason"></p><div class="row"></div>';
  el.querySelector('.reason').textContent = issue.reason;
  // Each fix as a button, the best first; then Ignore.
  issue.fixes.forEach((fix, i) => el.querySelector('.row').append(Object.assign(document.createElement('button'),
    { type: 'button', className: i ? 'fix other' : 'fix', textContent: fix || 'Delete these words', onclick: () => choose(fix) })));
  el.querySelector('.row').append(Object.assign(document.createElement('button'), { type: 'button', className: 'text-button', textContent: 'Ignore', onclick: () => choose(null) }));
  function choose(fix) {
    const what = fix === null ? 'ignore' : 'fix';
    cardFor = null; closeAll();
    if (what === 'ignore') { grammar.spec.ignore(issue); refreshGrammar(view); view.focus(); return; }
    // The words are still the ones the suggestion was for: select them, and the writer types the fix over them.
    if (view.state.doc.textBetween(issue.from, issue.to, undefined, '\ufffc') !== issue.original) return;
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, issue.from, issue.to)));
    view.focus();
    say(fix ? `Type “${fix}”.` : 'Press Delete to remove them.');
  }
  popup(virtualAnchor(issue.from, issue.to), el, { onClose: () => { if (cardFor === shown) cardFor = null; } });
}
/** The card for what's under the caret: a link's, else a grammar suggestion's. */
function showCard() {
  if (view.state.selection.empty && !finished && linkRange(view.state)) linkCard(); else grammarCard();
}

// Links: a card under a link with the caret in it, and a box to add or change one.
const virtualAnchor = (from, to) => {
  const a = view.coordsAtPos(from), b = view.coordsAtPos(to);
  const rect = { left: Math.min(a.left, b.left), right: Math.max(a.right, b.right), top: Math.min(a.top, b.top), bottom: Math.max(a.bottom, b.bottom) };
  return { getBoundingClientRect: () => rect, contains: () => false };
};
function linkRange(state) {
  const { $from } = state.selection, mark = marks.link.isInSet($from.marks()) ?? marks.link.isInSet($from.nodeAfter?.marks ?? []);
  if (!mark) return null;
  // The run of text carrying this link that holds the caret.
  let run = null, found = null;
  $from.parent.forEach((child, offset) => {
    const a = $from.start() + offset, b = a + child.nodeSize;
    run = mark.isInSet(child.marks) ? (run && run.to === a ? { from: run.from, to: b } : { from: a, to: b }) : null;
    if (run && run.from <= $from.pos && $from.pos <= run.to) found = { ...run, href: mark.attrs.href };
  });
  return found;
}
function openLink() {
  let { from, to, empty } = view.state.selection;
  const existing = linkRange(view.state);
  if (empty && existing) ({ from, to } = existing);
  else if (empty) {
    // The word at the caret.
    const { $from } = view.state.selection, text = $from.parent.textBetween(0, $from.parent.content.size, '\0', '\0'), at = $from.parentOffset;
    let s = at, e = at;
    while (s > 0 && /[\p{L}\p{N}_'-]/u.test(text[s - 1])) s--;
    while (e < text.length && /[\p{L}\p{N}_'-]/u.test(text[e])) e++;
    if (s === e) { say('Select the words to link first.'); return; }
    from = $from.start() + s; to = $from.start() + e;
  }
  view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, from, to)));
  const el = document.createElement('form');
  el.className = 'link-form';
  el.innerHTML = `<label class="link-field">${icon('link')}<input type="url" placeholder="Paste a link" aria-label="Link" autocomplete="off" spellcheck="false"></label><button class="text-button" type="submit">Apply</button>`;
  const input = el.querySelector('input');
  input.value = existing && view.state.selection.from === existing.from ? existing.href : '';
  el.addEventListener('submit', e => {
    e.preventDefault();
    const href = input.value.trim();
    if (!/^https?:\/\/\S+$/i.test(href)) { say('Links start with https://'); return; }
    closeAll();
    const tr = view.state.tr.removeMark(from, to, marks.link).addMark(from, to, marks.link.create({ href }));
    view.dispatch(tr.setSelection(TextSelection.create(tr.doc, to)));
    view.focus();
  });
  popup(virtualAnchor(from, to), el, { onClose: () => view.focus() });
  input.focus(); input.select();
}
let cardFor = null;
function linkCard() {
  const range = view.state.selection.empty && !finished ? linkRange(view.state) : null;
  if (!range) { if (cardFor) { cardFor = null; closeAll(); } return; }
  if (cardFor && cardFor.from === range.from && cardFor.href === range.href) return;
  cardFor = range;
  const el = document.createElement('div');
  el.className = 'link-card';
  el.innerHTML = `<a target="_blank" rel="noopener noreferrer nofollow"></a>`
    + `<button class="tb" type="button" data-do="copy" title="Copy link" aria-label="Copy link">${icon('content_copy')}</button>`
    + (canEdit() ? `<button class="tb" type="button" data-do="edit" title="Edit link" aria-label="Edit link">${icon('edit')}</button>`
      + `<button class="tb" type="button" data-do="remove" title="Remove link" aria-label="Remove link">${icon('link_off')}</button>` : '');
  const a = el.querySelector('a'); a.href = range.href; a.textContent = range.href.replace(/^https?:\/\//, '');
  el.addEventListener('click', e => {
    const what = e.target.closest('button')?.dataset.do;
    if (what === 'copy') { navigator.clipboard?.writeText(range.href).then(() => say('Link copied.'), () => {}); }
    if (what === 'edit') { cardFor = null; openLink(); }
    if (what === 'remove') { cardFor = null; closeAll(); view.dispatch(view.state.tr.removeMark(range.from, range.to, marks.link)); view.focus(); }
  });
  popup(virtualAnchor(range.from, range.to), el, { onClose: () => { if (cardFor === range) cardFor = null; } });
}

// Find (⌘F).
function openFind() {
  const box = $('find'), toolbar = $('toolbar').getBoundingClientRect();
  box.hidden = false; box.style.top = toolbar.bottom + 8 + 'px'; box.style.right = '24px';
  const { from, to, empty } = view.state.selection;
  if (!empty && to - from < 100) $('findInput').value = view.state.doc.textBetween(from, to, ' ');
  $('findInput').focus(); $('findInput').select();
  if ($('findInput').value) find(view, $('findInput').value);
  updateFind();
}
function updateFind() {
  const { matches, current, query } = findState(view.state);
  $('findCount').textContent = query ? (matches.length ? `${current + 1} of ${matches.length}` : '0 of 0') : '';
}
function closeFind() { $('find').hidden = true; clearFind(view); view.focus(); }
$('findInput').addEventListener('input', e => { find(view, e.target.value); updateFind(); });
$('findInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); step(view, e.shiftKey ? -1 : 1); updateFind(); }
  if (e.key === 'Escape') { e.preventDefault(); closeFind(); }
});
$('findNext').onclick = () => { step(view, 1); updateFind(); };
$('findPrev').onclick = () => { step(view, -1); updateFind(); };
$('findClose').onclick = closeFind;

// View settings: ruler, outline, spelling, hidden menus, mode and zoom.
function toggleView(name) {
  if (name === 'compact') document.body.classList.toggle('compact');
  else { prefs[name] = !prefs[name]; savePrefs(); }
  applyView(); view.focus();
}
function setTheme(theme) { prefs.theme = theme; savePrefs(); applyView(); view?.focus(); }
// Light or dark: the writer's choice, or the system's; the button beside Sign In switches to the other one.
const systemDark = matchMedia('(prefers-color-scheme: dark)');
const isDark = () => prefs.theme === 'dark' || (prefs.theme === 'system' && systemDark.matches);
function applyTheme() {
  if (prefs.theme === 'system') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = prefs.theme;
  const label = isDark() ? 'Light Mode' : 'Dark Mode';
  for (const button of document.querySelectorAll('.theme-toggle')) {
    button.title = label; button.setAttribute('aria-label', label);
    button.querySelector('use').setAttribute('href', isDark() ? '#i-light_mode' : '#i-dark_mode');
  }
}
for (const button of document.querySelectorAll('.theme-toggle')) {
  keepFocus(button);
  button.onclick = () => setTheme(isDark() ? 'light' : 'dark');
}
systemDark.addEventListener('change', applyTheme);
applyTheme();
function applyView() {
  applyTheme();
  if (view) refreshGrammar(view);
  document.body.classList.toggle('pageless', !printLayout);
  document.body.classList.toggle('no-ruler', !prefs.ruler);
  document.body.classList.toggle('outline-open', Boolean(prefs.outline));
  $('compactIcon').setAttribute('href', document.body.classList.contains('compact') ? '#i-keyboard_arrow_down' : '#i-keyboard_arrow_up');
  if (view) { view.setProps({}); relayout(view); updateToolbar(view.state); renderOutline(); }
  fitToolbar();
}
function setMode(read) {
  viewing = read;
  $('modeLabel').textContent = read ? (finished || stopReason ? 'View Only' : 'Viewing') : 'Editing';
  $('modeIcon').setAttribute('href', read ? '#i-visibility' : '#i-edit');
  view.setProps({}); updateToolbar(view.state); view.focus();
}
const zoom = () => (prefs.zoom !== 'fit' ? prefs.zoom : !printLayout ? 1 : Math.max(0.25, Math.min(2, ($('canvas').clientWidth - 32) / PAGE.width)));
function applyZoom() {
  const z = zoom();
  document.documentElement.style.setProperty('--z', String(z));
  $('zoomLabel').textContent = prefs.zoom === 'fit' ? 'Fit' : Math.round(z * 100) + '%';
  drawRuler();
  if (view) { relayout(view); updateRuler(); }
}
addEventListener('resize', () => { if (prefs.zoom === 'fit') applyZoom(); });
$('outlineOpen').onclick = () => toggleView('outline');
$('outlineClose').onclick = () => toggleView('outline');

// Ruler: inches from the left margin, the page's margins, and the paragraph's indents, which drag in eighths of an inch.
function drawRuler() {
  const z = zoom(), W = PAGE.width * z, M = PAGE.margin * z, parts = [];
  parts.push(`<rect class="r-margin" x="0" y="4" width="${M}" height="16"/><rect class="r-margin" x="${W - M}" y="4" width="${M}" height="16"/><rect class="r-page" x="${M}" y="4" width="${W - 2 * M}" height="16"/>`);
  for (let k = 0; k <= 68; k++) {
    const x = k * 12 * z, eighths = k - 8;
    if (eighths % 8 === 0) { if (eighths !== 0 && k > 0 && k < 68) parts.push(`<text x="${x}" y="15.5" class="r-text" text-anchor="middle" font-size="10" font-family="Arial, sans-serif">${Math.abs(eighths / 8)}</text>`); continue; }
    // Half inches longest, then quarters, then eighths (left out when zoomed far out).
    const h = eighths % 4 === 0 ? 6 : eighths % 2 === 0 ? 4 : 2;
    if (h > 2 || z >= 0.75) parts.push(`<line x1="${x + 0.5}" x2="${x + 0.5}" y1="${20 - h}" y2="20" class="r-tick" stroke-width="1"/>`);
  }
  $('rulerMarks').innerHTML = parts.join('');
}
function blockDOM(state) {
  const { $from } = state.selection;
  if (!$from.parent.isTextblock) return null;
  const el = view.nodeDOM($from.before());
  return el instanceof HTMLElement ? el : null;
}
function updateRuler() {
  if (!view || !prefs.ruler) return;
  const el = blockDOM(view.state), z = zoom(), base = $('scale').getBoundingClientRect().left;
  const attrs = view.state.selection.$from.parent.attrs, list = inList(view.state);
  let left = PAGE.margin, right = PAGE.width - PAGE.margin;
  if (el) { const r = el.getBoundingClientRect(); left = (r.left - base) / z; right = (r.right - base) / z; }
  $('markLeft').style.left = left * z + 'px';
  $('markFirst').style.left = (left + (attrs.firstLine ?? 0)) * z + 'px';
  $('markRight').style.left = right * z + 'px';
  for (const id of ['markLeft', 'markFirst', 'markRight']) $(id).disabled = list || !canEdit() || !attrs || attrs.indent === undefined;
}
for (const [id, which] of [['markLeft', 'left'], ['markFirst', 'first'], ['markRight', 'right']]) {
  const marker = $(id);
  keepFocus(marker);
  marker.addEventListener('pointerdown', e => {
    if (marker.disabled) return;
    e.preventDefault(); marker.setPointerCapture(e.pointerId);
    const z = zoom(), base = $('scale').getBoundingClientRect().left, attrs = view.state.selection.$from.parent.attrs;
    const M = PAGE.margin, end = PAGE.width - M, guide = document.createElement('div');
    guide.className = 'guide'; document.body.append(guide);
    let x = 0;
    const move = ev => {
      const raw = Math.round((ev.clientX - base) / z / 12) * 12;
      const leftEdge = M + attrs.indent, rightEdge = end - attrs.right;
      x = which === 'left' ? Math.max(M, Math.min(rightEdge - 48, raw))
        : which === 'first' ? Math.max(M, Math.min(rightEdge - 48, raw))
        : Math.max(Math.max(leftEdge, leftEdge + attrs.firstLine) + 48, Math.min(end, raw));
      marker.style.left = x * z + 'px'; guide.style.left = base + x * z + 'px';
      if (which === 'left') $('markFirst').style.left = (x + attrs.firstLine) * z + 'px';
    };
    move(e);
    marker.onpointermove = move;
    marker.onpointerup = marker.onpointercancel = () => {
      marker.onpointermove = marker.onpointerup = marker.onpointercancel = null; guide.remove();
      const values = which === 'left' ? { indent: x - M, firstLine: Math.max(-(x - M), attrs.firstLine) }
        : which === 'first' ? { firstLine: x - (M + attrs.indent) } : { right: end - x };
      edit.setIndents(values)(view.state, view.dispatch); view.focus();
    };
  });
}

// Outline: the title and headings; a click goes to one.
let outlineTimer;
function renderOutline() {
  clearTimeout(outlineTimer);
  if (!prefs.outline || !view) return;
  outlineTimer = setTimeout(() => {
    const list = $('outlineList'); list.textContent = '';
    view.state.doc.forEach((node, offset) => {
      if ((node.type !== nodes.heading && node.type !== nodes.title) || !node.textContent.trim()) return;
      const li = document.createElement('li'), button = document.createElement('button');
      li.dataset.level = node.type === nodes.title ? '1' : String(node.attrs.level); li.dataset.pos = String(offset);
      button.type = 'button'; button.textContent = node.textContent;
      button.onclick = () => {
        view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, offset + 1)));
        const at = view.coordsAtPos(offset + 1), canvas = $('canvas');
        canvas.scrollTop += at.top - canvas.getBoundingClientRect().top - 80;
        view.focus();
      };
      li.append(button); list.append(li);
    });
    $('outlineNone').hidden = list.childElementCount > 0;
    updateOutlineHere(view.state);
  }, 150);
}
function updateOutlineHere(state) {
  if (!prefs.outline) return;
  const at = state.selection.from;
  let here = null;
  for (const li of $('outlineList').children) if (Number(li.dataset.pos) < at) here = li;
  for (const li of $('outlineList').children) li.classList.toggle('here', li === here);
}

// Title: sized to its text, and the tab's name. Until one is given, the page is named by its first line, as in Docs.
const title = $('title');
function firstLine() {
  // A Title or heading near the top names the page; otherwise its first line does.
  let line = '', heading = '', seen = 0;
  view?.state.doc.descendants(node => {
    if (heading || seen >= 4) return false;
    if (!node.isTextblock) return true;
    const text = node.textContent.trim();
    if (text) { seen++; if (node.type === nodes.title || node.type === nodes.heading) heading = text; else line ||= text; }
    return false;
  });
  return shortName(heading || line);
}
const shortName = shortTitle;
const pageName = () => title.value.trim() || firstLine() || 'Untitled document';
function updateTitle() {
  title.placeholder = firstLine() || 'Untitled document';
  $('titleWrap').dataset.value = title.value || title.placeholder;
  document.title = pageName() + ' · Huma';
}
title.addEventListener('input', () => { updateTitle(); save(); renameShared(); });
// Named while it proves (the proving runs on when hidden: Hide or Escape), and again over the result.
$('provingName').addEventListener('input', () => { title.value = $('provingName').value; updateTitle(); save(); });
$('provingName').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); $('provingName').blur(); } });
$('provingHide').onclick = () => $('proving').close();
$('proving').addEventListener('close', () => { if (sealing) drawProgress(); });
// Named again when it's finished, over the result.
$('doneName').addEventListener('input', () => { title.value = $('doneName').value; updateTitle(); save(); renameShared(); });
$('doneName').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); $('doneName').blur(); } });
// A finished page's name, kept where it's shared too (its writer page), a moment after it changes.
let renameTimer;
function renameShared() {
  clearTimeout(renameTimer);
  const id = proved && publicationOf(pageRecord), name = cleanTitle(pageName());
  if (!id || !name) return;
  renameTimer = setTimeout(() => setTitle(id, name).catch(e => say(e.message)), 800);
}
title.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === 'Escape') { e.preventDefault(); view.focus(); } });

let saveTimer;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(persist, 400);
}
/** Keeps the page in Your Pages; a new page is kept once it has a name or some text. */
async function persist(changes = {}) {
  clearTimeout(saveTimer);
  if (!pageId || !view) return;
  const text = plainText(view.state.doc);
  if (!pageRecord && !text.trim() && !title.value.trim() && !changes.status) return;
  pageRecord = { id: pageId, created: Date.now(), status: 'draft', score: null, ...pageRecord, title: title.value, doc: view.state.doc.toJSON(),
    text: text.slice(0, 300), words: words(text), updated: Date.now(), ...changes };
  $('saved').textContent = 'Saving…';
  try { await putPage(pageRecord); $('saved').textContent = 'Saved'; } catch { $('saved').textContent = 'Not saved'; }
  syncSoon();
}

// The account: with someone signed in, each document is kept in their account too, a moment after it changes, so it
// opens on any device. A finished one goes with what it proved (never the keystroke recording).
async function accountRecord(record) {
  const { id, title: name, doc, text, words: count, status, score, created, updated, shared, publication } = record;
  const out = { id, title: name, doc, text, words: count, status, score, created, updated, ...(shared ? { shared } : {}), ...(publication ? { publication } : {}) };
  if (status === 'proved') {
    const result = await proof(id).catch(() => null);
    if (!result) return null;
    out.proof = { envelope: result.envelope, report: result.report, text: result.text, replay: result.replay ?? replayOf(result.recording) };
  }
  return out;
}
let syncTimer;
function syncSoon(delay = 2000) {
  clearTimeout(syncTimer);
  if (!account() || !pageRecord) return;
  syncTimer = setTimeout(() => syncPage(pageRecord), delay);
}
async function syncPage(record) {
  if (record === pageRecord) clearTimeout(syncTimer);
  if (!account() || !record) return;
  try { const value = await accountRecord(record); if (value) await saveToAccount(value); }
  catch (e) { if (e.status === 401) updateAccount(); else if (e.status === 413) say(e.message); }
}
// Privy sign-in, off for now (write/account.mjs keeps its code): it signed in on Huma's sign-in page, in this tab or a
// small window opened by the click.
// const signInHereNow = () => persist().finally(() => signInHere(location.pathname + location.search));
// const signInWindow = () => window.open('', 'huma-signin', 'popup,width=480,height=720');
/** Signing in, with World ID (worldid.mjs): its QR shows over this page, so a recording here waits behind it. */
let signingIn = null;
function startSignIn() {
  signingIn ??= signInWithWorldID()
    .then(me => {
      if (!me?.wallet) { if (me?.reason) say(me.reason); return null; }
      return signedIn(me);
    })
    .catch(e => { say(e.message); return null; })
    .finally(() => { signingIn = null; });
  return signingIn;
}
/** Signed in, with World ID (at Sign In, or at Start Recording): the account shows here, and everything already in
 *  this browser joins it, unless the account already has it as new. */
async function signedIn(me) {
  updateAccount(); say('Signed in with World ID.');
  ensureProfile({ ask: false });
  const kept = new Map((await accountDocuments().catch(() => [])).map(d => [d.id, d.updated]));
  const pending = (await keptPages().catch(() => [])).filter(record => !(kept.get(record.id) >= record.updated));
  await Promise.all(Array.from({ length: 3 }, async () => { while (pending.length) await syncPage(pending.shift()); }));
  return me;
}
$('signinCancel').onclick = () => { $('signinWait').hidden = true; };
function updateAccount() {
  const me = account(), mine = me ? profile() : null;
  for (const id of ['accountButton', 'homeAccount']) {
    const button = $(id);
    if (mine) { const face = document.createElement('img'); face.src = faceURL(mine.avatar); face.alt = ''; button.replaceChildren(face); }
    else button.textContent = me ? (me.name?.[0] ?? '•').toUpperCase() : 'Sign In';
    button.classList.toggle('signed-in', Boolean(me));
    button.classList.toggle('has-face', Boolean(mine));
    button.title = me ? `Signed in as ${mine?.name ?? me.name ?? 'your account'}` : 'Sign In';
  }
}
/** Your Profile: the name and face on pages you share, kept in your account (as the Mac app sets them). */
let faceChoice = null;
const shuffleFaces = () => drawFaces([faceChoice, ...Array.from({ length: 7 }, newFace)]);
function drawFaces(choices) {
  $('profileFaces').replaceChildren(...choices.map(seed => {
    const button = document.createElement('button'), face = document.createElement('img');
    button.type = 'button'; button.setAttribute('role', 'radio'); button.setAttribute('aria-label', 'Face');
    button.setAttribute('aria-checked', String(seed === faceChoice));
    face.src = faceURL(seed); face.alt = ''; button.append(face);
    button.onclick = () => { faceChoice = seed; $('profileFace').src = faceURL(seed); for (const b of $('profileFaces').children) b.setAttribute('aria-checked', String(b === button)); };
    return button;
  }));
}
// The handle is the writer's page address, huma.social/@handle: picked here, suggested from the name the first time,
// and checked as they type (the account's own handle counts as free).
let handleTyped = false, handleCheck = 0, handleTimer = null;
const handleFrom = name => name.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 20).replace(/_+$/, '');
const handleState = (text = '', state = '') => { $('profileHandleStatus').textContent = text; $('profileHandleStatus').dataset.state = state; };
function checkHandle() {
  const handle = $('profileHandle').value, check = ++handleCheck;
  clearTimeout(handleTimer);
  updateProfileSave();
  if (!handle || handle === profile()?.handle) { handleState(); return; }
  if (!HANDLE.test(handle)) { handleState('3 to 20 letters, numbers or _.'); return; }
  if (RESERVED_HANDLES.has(handle)) { handleState('Taken', 'taken'); updateProfileSave(); return; }
  handleState('Checking…');
  handleTimer = setTimeout(async () => {
    let taken = await handleTaken(handle);
    if (check !== handleCheck) return;
    // A suggestion someone has already: a free one with a number, or none (a handle isn't needed to save).
    if (taken && !handleTyped) {
      for (let i = 0; i < 3 && taken; i++) {
        const other = handle.slice(0, 17) + (10 + Math.floor(Math.random() * 990));
        taken = await handleTaken(other);
        if (check !== handleCheck) return;
        if (taken === false) $('profileHandle').value = other;
      }
      if (taken !== false) { $('profileHandle').value = ''; handleState(); updateProfileSave(); return; }
    }
    if (taken === null) handleState(); else handleState(taken ? 'Taken' : 'Available', taken ? 'taken' : 'free');
    updateProfileSave();
  }, 350);
}
function updateProfileSave() {
  const handle = $('profileHandle').value;
  $('profileSave').disabled = !$('profileName').value.trim() || (handle && !HANDLE.test(handle)) || $('profileHandleStatus').dataset.state === 'taken';
}
function openProfile() {
  const mine = profile(), me = account();
  faceChoice = mine?.avatar ?? newFace();
  // A new profile starts from the account's name, unless that's an email address, which stays private.
  $('profileName').value = mine?.name ?? (me?.name && !me.name.includes('@') ? me.name.slice(0, 40) : '');
  handleTyped = Boolean(mine?.handle);
  $('profileHandle').value = mine?.handle ?? handleFrom($('profileName').value);
  if ($('profileHandle').value.length < 3) $('profileHandle').value = '';
  $('profileFace').src = faceURL(faceChoice);
  shuffleFaces();
  checkHandle();
  $('profile').showModal(); $('profileName').focus();
}
$('profileName').oninput = () => {
  // Until the writer types a handle, it follows the name.
  if (!handleTyped) { const suggested = handleFrom($('profileName').value); $('profileHandle').value = suggested.length >= 3 ? suggested : ''; checkHandle(); }
  else updateProfileSave();
};
$('profileHandle').oninput = () => {
  const input = $('profileHandle'), cleaned = input.value.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
  if (cleaned !== input.value) input.value = cleaned;
  handleTyped = true; checkHandle();
};
$('profileHandle').onkeydown = e => { if (e.key === 'Enter' && !$('profileSave').disabled) { e.preventDefault(); $('profileSave').click(); } };
$('profileName').onkeydown = e => { if (e.key === 'Enter' && !$('profileSave').disabled) { e.preventDefault(); $('profileSave').click(); } };
$('profileShuffle').onclick = () => shuffleFaces();
$('profileCancel').onclick = () => $('profile').close();
$('profileSave').onclick = async () => {
  const handle = $('profileHandle').value;
  $('profileSave').disabled = true;
  try {
    await saveProfile({ name: $('profileName').value.trim(), avatar: faceChoice, ...(handle ? { handle } : {}) });
    $('profile').close(); updateAccount(); showListedHint(); say('Saved. Pages you share show your name and face.');
  } catch (e) {
    if (e.status === 409) handleState('That handle is taken.', 'taken');
    else if (e.status === 400) handleState(e.message);
    else say(e.message || 'Couldn’t save your profile. Try again.');
  } finally { updateProfileSave(); }
};
/** Adds a passkey (called from a click: the browser asks for one). Writing already recording keeps its own mode. */
async function newPasskey() {
  try {
    await addPasskey();
    $('passkeyOffer').hidden = true;
    say(recording && !finished ? 'Passkey added. It starts with your next document.' : 'Passkey added.');
  } catch (e) {
    if (e?.name !== 'NotAllowedError' && e?.name !== 'AbortError') say(e?.message || 'Couldn’t add a passkey. Try again.');
  }
}
/** Before recording, signed in, with no passkey for this site yet and one this computer can make: offered once. */
const PASSKEY_OFFER = 'huma-passkey-offer';
async function offerPasskey() {
  if (!account() || !passkeysWork()) return;
  // The account's passkeys come down first, so one added on another computer is used here too.
  await loadPasskeys().catch(() => null);
  try { if (localStorage.getItem(PASSKEY_OFFER) === 'declined') return; } catch {}
  if (sitePasskeys().length || !(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().catch(() => false))) return;
  if (idle() && $('startCard').open) $('passkeyOffer').hidden = false;
}
$('passkeyAdd').onclick = () => newPasskey();
$('passkeyLater').onclick = () => { try { localStorage.setItem(PASSKEY_OFFER, 'declined'); } catch {} $('passkeyOffer').hidden = true; };
/** After signing in: the account's profile comes down, or, the first time, the writer picks one. */
async function ensureProfile({ ask = true } = {}) {
  if (!account()) return;
  const mine = await loadProfile().catch(() => profile());
  updateAccount();
  if (!mine && ask && !recording) openProfile();
}
for (const id of ['accountButton', 'homeAccount']) $(id).onclick = () => {
  const me = account(), button = $(id);
  if (!me) { startSignIn(); return; }
  const handle = profile()?.handle;
  menu(button, [{ heading: profile()?.name ?? me.name ?? 'Signed in' }, ...(handle ? [{ label: 'Your Page', run: () => window.open('/@' + handle, '_blank', 'noopener') }] : []),
    { label: 'Your Profile', run: openProfile }, ...(passkeysWork() ? [{ label: 'Add Passkey', run: () => newPasskey() }] : []),
    { label: 'Sign out', run: () => { signOut(); updateAccount(); say('Signed out. Documents stay in this browser and in your account.'); } }], { alignRight: true });
};
const fileName = () => pageName().replace(/[\\/:*?"<>|]+/g, ' ').trim().slice(0, 80) || 'Untitled document';
function downloadBlob(blob, name) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob); link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}
/** The page itself, as PDF, Word, Markdown, a web page or plain text. */
async function download(kind) {
  track('document_downloaded', { format: kind });
  if (kind === 'txt') { downloadBlob(new Blob([plainText(view.state.doc)], { type: 'text/plain;charset=utf-8' }), fileName() + '.txt'); return; }
  if (kind === 'md') { downloadBlob(new Blob([pageMarkdown(view.state.doc)], { type: 'text/markdown;charset=utf-8' }), fileName() + '.md'); return; }
  if (kind === 'docx') {
    downloadBlob(new Blob([pageDocx(view.state.doc, pageName())], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }), fileName() + '.docx');
    return;
  }
  if (kind === 'pdf') {
    say('Preparing the PDF…');
    try { downloadBlob(new Blob([await pagePDF(view.state.doc, pageName(), await pdfTools())], { type: 'application/pdf' }), fileName() + '.pdf'); say(''); }
    catch { say('Couldn’t make the PDF. Try again.'); }
    return;
  }
  const body = document.createElement('div');
  body.append(DOMSerializer.fromSchema(schema).serializeFragment(view.state.doc.content));
  const name = fileName().replace(/[&<>]/g, '');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${name}</title><style>body{max-width:6.5in;margin:1in auto;font:11pt/1.15 Arial,sans-serif}`
    + `p,h1,h2,h3,h4,h5,h6{margin:0;font-weight:400}.title{font-size:26pt}.subtitle{font-size:15pt;color:#666}h1{font-size:20pt;padding:20pt 0 6pt}`
    + `h2{font-size:16pt;padding:18pt 0 6pt}h3{font-size:14pt;padding:16pt 0 4pt;color:#434343}a{color:#1155cc}</style></head><body>`
    + body.innerHTML.replace(/calc\(var\(--z, 1\) \* ([\d.]+)(pt|px)\)/g, '$1$2') + '</body></html>';
  downloadBlob(new Blob([html], { type: 'text/html;charset=utf-8' }), fileName() + '.html');
}
/** The report: for a proved page, the PDF with its proof and replay attached; for a stopped one, why it stopped. */
let reportBusy = false;
async function saveReport() {
  if (reportBusy || (!proved && !stopReason)) return;
  reportBusy = true; say('Preparing the report…');
  try {
    const pdf = proved ? await provedReport(proved, title.value.trim(), shareLink() ?? undefined)
      : await stoppedReport({ title: title.value.trim(), text: plainText(view.state.doc), reason: stopReason,
        measures: analyse(typingLog).measures, started: new Date(performance.timeOrigin + started), elapsed: now() });
    downloadBlob(new Blob([pdf], { type: 'application/pdf' }), fileName() + ' – Huma report.pdf'); say('');
    track('report_downloaded');
  } catch { say('Couldn’t make the report. Try again.'); }
  finally { reportBusy = false; }
}

function dispatch(tr) {
  const label = labelFor(tr), before = view.state;
  view.updateState(before.apply(tr));
  if (view.state.doc !== before.doc) {
    const text = plainText(view.state.doc);
    if (text !== lastText && recording) {
      if (evalLog) evalLog.push(editFrame(lastText, text, label, now()));
      lastText = text; const t = latest = now();
      guarded(async () => { await recording.edit(text, label, t); await recording.checkpoint(t); });
    }
    save(); renderOutline(); if (!title.value.trim()) updateTitle();
  }
  if (view.state.doc !== before.doc || !view.state.selection.eq(before.selection)) {
    updateCounts();
    if (findState(view.state).query) updateFind();
  }
  updateToolbar(view.state);
}

function layoutPages(count) {
  pageCount = count;
  const backs = $('backs');
  while (backs.children.length < count) backs.append(Object.assign(document.createElement('div'), { className: 'page' }));
  while (backs.children.length > count) backs.lastChild.remove();
  [...backs.children].forEach((page, i) => { page.style.top = `calc(var(--z) * ${i * (PAGE.height + PAGE.gap)}px)`; });
  view.dom.style.minHeight = printLayout ? `calc(var(--z) * ${count * PAGE.height + (count - 1) * PAGE.gap}px)` : '';
  // The page is laid out: the loading screen goes.
  if (document.body.dataset.state === 'loading') requestAnimationFrame(() => { if (document.body.dataset.state === 'loading') show('starting', 'Getting ready'); });
}

/** Pages kept from before this version: the old Title style was a heading of level 0. */
function migrate(json) {
  if (!json || typeof json !== 'object') return json;
  if (json.type === 'heading' && json.attrs?.level === 0) return { ...json, type: 'title', attrs: {}, content: json.content?.map(migrate) };
  return json.content ? { ...json, content: json.content.map(migrate) } : json;
}
function restore() {
  try { if (pageRecord?.doc) { title.value = pageRecord.title ?? ''; return schema.nodeFromJSON(migrate(pageRecord.doc)); } } catch {}
  return undefined;
}
function createView(doc) {
  view = new EditorView($('editor'), {
    state: EditorState.create({ doc, schema, plugins: [rules, attributes, shading, grammar, autolink(marks.link, canEdit), autoformat, shortcuts, keymap(baseKeymap), history(), findPlugin,
      pages({ zoom, paged: () => printLayout, onLayout: layoutPages })] }),
    dispatchTransaction: dispatch,
    editable: () => canEdit(),
    handleDOMEvents: {
      beforeinput: (v, e) => {
        // The browser's own undo (from its Edit menu) runs through the page's history, so it's labelled undo.
        if (e.inputType === 'historyUndo' || e.inputType === 'historyRedo') {
          e.preventDefault(); act(e.inputType === 'historyUndo' ? 'undo' : 'redo'); return true;
        }
        // The browser's spelling suggestion isn't typed, so it isn't put in: its words are selected and the writer is told
        // what to type, as on the Mac.
        if (e.inputType === 'insertReplacementText' && pending === 'other' && !v.composing) {
          e.preventDefault();
          const range = e.getTargetRanges?.()[0], text = e.data ?? e.dataTransfer?.getData('text/plain') ?? '';
          if (range) { try { v.dispatch(v.state.tr.setSelection(TextSelection.create(v.state.doc, v.posAtDOM(range.startContainer, range.startOffset), v.posAtDOM(range.endContainer, range.endOffset)))); } catch {} }
          say(text ? `To fix it, type “${text}”.` : 'Only typed or pasted text can be added.'); return true;
        }
        // Text that arrives without a key press (dictation, autofill, another program) never reaches the page.
        if (pending === 'other' && !v.composing && /^insert(Text|ReplacementText|FromYank)$/.test(e.inputType) && (e.data ?? '') !== '') {
          e.preventDefault(); refuseUntyped(); return true;
        }
        return false;
      },
      // A checklist item's box: clicking it ticks the item.
      mousedown: (v, e) => {
        const item = e.target.closest?.('li[data-done]');
        if (!item || e.clientX >= item.getBoundingClientRect().left || !canEdit()) return false;
        const pos = v.posAtDOM(item, 0) - 1, node = v.state.doc.nodeAt(pos);
        if (node?.type !== nodes.check_item) return false;
        e.preventDefault(); v.dispatch(v.state.tr.setNodeMarkup(pos, null, { done: !node.attrs.done })); return true;
      },
      mouseup: () => { setTimeout(() => { if (painting) paint(); else showCard(); }); return false; },
      keyup: () => { if (cardFor) showCard(); return false; },
    },
  });
  lastText = plainText(view.state.doc);
  applyView(); updateTitle(); updateToolbar(view.state); updateCounts(); drawRuler();
}
whenAllClosed(() => { cardFor = null; });

// Keys, recorded the way the Mac records them, before the editor handles them. Shortcuts (⌘ or Ctrl) aren't typing,
// and macOS browsers drop their key-ups.
const sheet = $('pages');
// Typing that no person can produce stops the recording (typing.mjs): checked as keys arrive, from their own times.
// Touch keyboards send keys without a key code and release them at once, so they aren't judged this way.
const typingLog = [];
let touchKeyboard = false, typingChecked = 0;
function watchTyping(e, kind) {
  if (!e.code || e.key === 'Unidentified') { touchKeyboard = true; return; }
  typingLog.push([e.timeStamp - started, keyCode(e.code), kind]);
  if (kind !== 'down' || touchKeyboard || ++typingChecked % 5 || typingLog.length < 40) return;
  const result = analyse(typingLog.slice(-800));
  if (result.blatant.length) { automated(result.blatant[0]); return; }
  if (!retypePassed && !retyping && odd(result)) { retype(); return; }
  // With enough typing: a rhythm that ignores words and hands, or is spread flat with no rollover, as random delays are.
  if (typingChecked >= 250 && typingChecked % 25 === 0 && robotic(analyse(typingLog.slice(-4000)).signals)) automated('its rhythm had none of a hand’s shape');
}
const AUTOMATED = 'Automated typing detected';
function automated(reason) {
  if (!recording || finished) return;
  stop(`Huma detected typing a person didn’t do: ${reason}. This document can’t be proved. Start a new one to keep writing.`, AUTOMATED);
}
// Text that arrives with no key press is refused. Once can be dictation or the emoji picker; three times in one
// recording is software putting text in, so the recording stops.
let untyped = 0;
function refuseUntyped() {
  say('Only typed or pasted text can be added.');
  if (++untyped >= 3) automated('text kept appearing without any key presses');
}
// Software driving this browser: watched from the moment the page opens, so it can't even start. Developer tools
// (which can drive a page too) only pause the recording while they're open.
let controlled = null, devtools = false, pausedForTools = false;
watchAutomation((kind, reason) => {
  if (kind === 'controlled') { controlled = reason; if (recording && !finished) stop('This browser is run by software, so it can’t record. Start a new document in a browser you use yourself.', AUTOMATED); return; }
  devtools = kind === 'devtools';
  if (devtools && recording && !paused && !finished) { pausedForTools = true; pauseRecording(true); say('Close developer tools to keep recording.'); }
  else if (!devtools && pausedForTools) { pausedForTools = false; resumeRecording(); }
});
/** Software in charge, or developer tools open: why recording can't start or finish now, or null. */
function automationBlock() {
  const sign = automation();
  return controlled || sign?.kind === 'controlled' ? 'This browser is run by software, so it can’t record.' : sign ? 'Close developer tools to keep recording.' : null;
}
// Typing that looks odd but not plainly automated: the writer retypes a few words, once per recording.
let retypePassed = false, retyping = false;
async function retype() {
  if (retyping) return 'cancelled';
  retyping = true; releaseHeld(); paused = true; view.setProps({});
  try {
    const outcome = await retypeCheck({ dialog: $('retype'), phraseEl: $('retypePhrase'), input: $('retypeInput'), go: $('retypeGo'), cancel: $('retypeCancel'), note: $('retypeNote') });
    if (outcome === 'passed') retypePassed = true; else if (outcome === 'failed') automated('it failed the typing check');
    return outcome;
  } finally { retyping = false; if (recording && !finished && !pausedByWriter) { paused = false; view.setProps({}); view.focus(); } }
}
/** Cloudflare Turnstile at Start, alongside writing: it never holds anyone up or stops a recording. The check that
 *  counts is the one when the page is shared (the server's), which can be tried again; this one gets Cloudflare to know
 *  the browser first, so that one is usually unseen. */
const confirmAlongside = action => confirmHuman(action).catch(() => false);
sheet.addEventListener('keydown', e => {
  if (!recording || !e.isTrusted || !canEdit() || !e.target.closest('.ProseMirror')) return;
  // AltGr (Ctrl+Alt on Windows) types characters such as @ € ą; ⌘ or Ctrl with a deleting key deletes as typing does.
  const shortcut = (e.metaKey || e.ctrlKey) && !e.getModifierState?.('AltGraph');
  if (shortcut) {
    const deleting = e.key === 'Backspace' || e.key === 'Delete' || (e.ctrlKey && !e.metaKey && /^[hdk]$/i.test(e.key) && /Mac/.test(navigator.platform));
    if (deleting) { pending = 'typing-external'; addedThisKey = KEY_PRESS_LIMIT; setTimeout(() => { pending = 'other'; }); }
    return;
  }
  if (e.isComposing || e.keyCode === 229) imeKeys++;
  if (!e.repeat) {
    held.add(e.code); const t = latest = now();
    guarded(() => recording.key('down', keyCode(e.code), modifiers(e), t));
    watchTyping(e, 'down');
  }
  // Everything this key press changes, autocorrect included, is typing; a held key's repeats too.
  pending = 'typing-external'; addedThisKey = 0;
  setTimeout(() => { pending = 'other'; });
}, true);
// A composition's budget ends with it, once its last change is in.
sheet.addEventListener('compositionend', () => {
  clearTimeout(imeReset); imeReset = setTimeout(() => { if (!view?.composing) imeKeys = imeAdded = 0; }, 100);
}, true);
/** Keys still down when input stops (a check-in, a pause, leaving the window) are let go now, so none stays held. */
function releaseHeld() {
  if (!recording || !held.size) { held.clear(); return; }
  const t = latest = now();
  for (const code of held) {
    guarded(() => recording.key('up', keyCode(code), 0, t));
    typingLog.push([t, keyCode(code), 'up']);
  }
  held.clear();
}
addEventListener('blur', () => { if (!paused && !finished) releaseHeld(); });
sheet.addEventListener('keyup', e => {
  if (!recording || !e.isTrusted || !held.delete(e.code) || paused) return;
  const t = latest = now();
  guarded(() => recording.key('up', keyCode(e.code), modifiers(e), t));
  watchTyping(e, 'up');
}, true);
// Software driving the browser: a test browser says so; and a pointer that jumps to every click, never moving between,
// isn't a hand on a mouse or trackpad.
let pointer = null, trail = 0, trails = 0, jumps = 0;
addEventListener('pointermove', e => {
  if (e.pointerType !== 'mouse' || !e.isTrusted) return;
  const far = pointer && Math.hypot(e.clientX - pointer.x, e.clientY - pointer.y) > 160 && e.timeStamp - pointer.t < 1000;
  trail = far ? 0 : trail + 1;
  if (trail === 6) trails++;
  if (far) jumps++;
  pointer = { x: e.clientX, y: e.clientY, t: e.timeStamp };
}, true);
addEventListener('pointerdown', e => {
  if (e.pointerType !== 'mouse' || !e.isTrusted) return;
  if (pointer && Math.hypot(e.clientX - pointer.x, e.clientY - pointer.y) > 160) jumps++;
  pointer = { x: e.clientX, y: e.clientY, t: e.timeStamp };
  if (jumps >= 4 && trails === 0) automated('the pointer jumped to every click without moving');
}, true);
// Leaving the window and coming back is a jump no hand made.
document.addEventListener('mouseout', e => { if (!e.relatedTarget) pointer = null; });
addEventListener('blur', () => { pointer = null; });
// A click on the grey around the pages puts the caret in the text, as in a document editor.
$('canvas').addEventListener('mousedown', e => {
  if (!view || e.button !== 0 || e.target.closest('.ProseMirror, .ruler, button')) return;
  e.preventDefault(); view.focus();
});

/** A check-in: input pauses until it's answered; within 10 seconds counts as on time. */
function checkIn(reason) {
  return new Promise(resolve => {
    const dialog = $('check'), issued = now();
    // Signing in comes before this, with World ID (humanBeforeFinish).
    $('checkTitle').textContent = reason === 'seal' ? 'Finish this document?' : 'Still writing?';
    $('checkNote').hidden = true;
    $('checkGo').textContent = reason === 'seal' ? 'Finish' : 'Continue';
    $('checkCancel').hidden = reason !== 'seal';
    const tick = () => { const left = Math.ceil((issued + CHECK_DEADLINE - now()) / 1000); $('checkTime').textContent = left > 0 ? `${left} s left` : 'Time’s up'; };
    tick(); const timer = setInterval(tick, 250);
    let settled = false;
    const done = (outcome, answered = null) => { if (settled) return; settled = true; clearInterval(timer); dialog.onclose = null; if (dialog.open) dialog.close(); resolve({ outcome, answered }); };
    // Closed without an answer (a second Escape, Android Back, or a stop): Finish is cancelled, a check-in shows again.
    dialog.onclose = () => { if (reason === 'seal' || !recording) done('cancelled'); else dialog.showModal(); };
    // With a passkey, the recorder's challenge and the passkey prompt both start within this click (Safari needs that).
    $('checkGo').onclick = () => {
      if (!recording?.passkey || settled) { done('approved'); return; }
      const at = latest = now();
      done('approved', { at, result: recording.approve(at, challenge => {
        const asked = passkeyAssertion(challenge);
        if (sitePasskeys().length) say('Use your passkey.');
        return asked;
      }) });
    };
    $('checkCancel').onclick = () => done('cancelled');
    dialog.oncancel = e => { e.preventDefault(); };
    closeAll(); dialog.showModal(); $('checkGo').focus();
  });
}
async function presence(reason) {
  releaseHeld();
  paused = true; view.setProps({});
  try {
    const { issued } = await recording.presenceIssue(reason, now());
    latest = Math.max(latest, issued);
    const { outcome, answered } = await checkIn(reason);
    if (!recording) return false;
    if (answered) {
      // Writing waits for the passkey; without it, the check-in still counts and the page keeps the basic check.
      const skipped = recording.passkeySkipped;
      await answered.result;
      if (recording?.passkeySkipped && !skipped) say('No passkey used. This document gets the basic check.');
      latest = Math.max(latest, answered.at);
      return answered.at - issued <= CHECK_DEADLINE;
    }
    latest = now();
    await recording.presenceRespond(outcome, latest);
    return outcome === 'approved' && latest - issued <= CHECK_DEADLINE;
  } finally { paused = false; view.setProps({}); view.focus(); }
}

// Once a second: a check-in when one is due, and after a 3-second pause, the open part closes once it holds 450 of its
// 600 operations, so it proves while the writer thinks (CaptureSigner.idle).
setInterval(() => guarded(async () => {
  if (!recording || paused || finished || sealing) return;
  const t = now();
  if (t >= nextCheck) { await presence('interval'); nextCheck = nextCheckIn(now()); return; }
  const info = await recording.info();
  // A part closes by itself once it's full: it proves now, while the writer keeps typing.
  if (info.closedChunks > prover.closed) prover.offer(recording, info.closedChunks);
  if (t >= info.latestElapsed + 3000 && info.characters >= 50 && (await recording.cut(450)).closed)
    prover.offer(recording, (await recording.info()).closedChunks);
}), 1000);

// Proving's progress: the bar fills over the time this computer is expected to take, never going back, with the step
// and about how long is left; each step corrects the estimate.
let plan = null;
function planProgress(step, remainingMs) {
  const at = performance.now();
  plan ??= { start: at, shown: 0, timer: setInterval(drawProgress, 250) };
  plan.step = step; plan.end = at + Math.max(1000, remainingMs);
  drawProgress();
}
function drawProgress() {
  if (!plan) return;
  const at = performance.now(), left = Math.ceil((plan.end - at) / 1000);
  plan.shown = Math.max(plan.shown, Math.min(0.97, (at - plan.start) / (plan.end - plan.start)));
  $('provingBar').classList.remove('busy');
  $('provingBar').querySelector('i').style.width = `${(plan.shown * 100).toFixed(1)}%`;
  $('provingText').textContent = plan.step + ' · ' + (left <= 0 ? 'almost done' : left >= 90 ? `about ${Math.round(left / 60)} min left` : `about ${left} s left`);
  // Hidden, the proving goes on behind the page, and the status shows how far it is.
  if (!$('proving').open) $('state').textContent = `Proving ${Math.round(plan.shown * 100)}%`;
}
function endProgress() {
  if (!plan) return;
  clearInterval(plan.timer); plan = null;
  $('provingBar').querySelector('i').style.width = '100%';
}
/** Before Finish where World ID is on: only a verified human finishes a document. Signed out, the writer signs in with
 *  World ID now, once for this browser; an account without a World ID yet links one (worldid.mjs). Resolves whether
 *  Finish may go on: always where World ID is only a badge. */
async function humanBeforeFinish() {
  // The Start scan, if the host is still confirming it.
  if (startConfirmed && !(await startConfirmed)) return false;
  if (!(await worldIDOn())) return true;
  const required = await worldIDRequired();
  if (!account() && !(await startSignIn())) return !required;
  const { ok, reason, worldId, linkedNow } = await verifiedAuthor();
  if (ok && linkedNow) say(`Verified human. Your World ID ${worldId.fingerprint} now shows on every page you share.`);
  if (!ok && reason) say(reason);
  return ok || !required;
}
let finishStarted = 0;
/** Finish, from a button or menu: a paused recording resumes first. */
function finishNow() { resumeRecording(); finish(); }
async function finish() {
  if (!recording || paused || finished || sealing) return;
  if (!plainText(view.state.doc).trim()) { say('Write something first.'); return; }
  // Too little typing to tell a person from software, so it can't be proved yet; then the whole recording is checked
  // once more for typing no person makes (while writing, only the last stretch is).
  const downs = typingLog.filter(([, , kind]) => kind === 'down').length, span = typingLog.length ? typingLog.at(-1)[0] - typingLog[0][0] : 0;
  if (downs < 30 || span < 20000) { say('Type a little more first: at least 30 keys over 20 seconds.'); return; }
  const blocked = automationBlock();
  if (blocked) { say(blocked); return; }
  const whole = analyse(typingLog);
  if (whole.blatant.length) { automated(whole.blatant[0]); return; }
  if (!retypePassed && odd(whole) && (await retype()) !== 'passed') return;
  $('finish').disabled = true; sealing = true;
  try {
    // The open part closes now, so it proves while the check-in shows.
    await recording.cut(1); prover.offer(recording, (await recording.info()).closedChunks);
    if (!(await humanBeforeFinish())) return;
    if (!(await presence('seal'))) { say('Press Finish within 10 seconds.'); return; }
    finished = true; $('pause').disabled = true; view.setProps({}); updateToolbar(view.state);
    try { await recording.finish(now()); } catch (e) { throw Object.assign(new Error(`The recording couldn’t be sealed (${e?.message ?? 'unknown error'})`), { cause: e }); }
    // The last of the editor's events go to the server now, well before the page is shared; a stream that never got
    // through is said, since the page can't then be checked as a person's.
    if (collector) {
      const streamed = collector; collector = null;
      streamed.stop().then(sent => { if (!sent && !streamed.state.connected) say('The live typing check couldn’t reach huma.social. This page may show as unverified.'); }).catch(() => {});
    }
    show('proving', 'Proving'); finishStarted = performance.now();
    planProgress('Getting ready', prover.remainingMs());
    $('provingName').value = title.value;
    $('provingName').placeholder = title.placeholder;
    $('proving').showModal(); $('provingName').focus();
    const result = await prover.finish(recording, ({ done, total, checking, finishing }) => {
      const t = prover.times();
      if (finishing) planProgress('Finishing up', prover.remainingMs());
      else if (checking) planProgress('Checking the proof', t.check);
      else if (done + 1 === total) planProgress('Sealing the page', t.final + t.check);
      else planProgress(`Part ${done + 1} of ${total - 1}`, prover.estimate(total - 1 - done));
    }).finally(endProgress);
    // done() closes the progress itself, after noting whether the writer was naming the page in it.
    done(result);
  } catch (e) {
    if ($('proving').open) $('proving').close();
    // Named with the step that failed (prove.mjs), and in the console with its cause, for a report.
    console.error('Finish stopped:', e);
    if (finished) stop(`Proving stopped: ${e?.message ?? 'unknown error'}. Your text is saved.`); else say(e?.message ?? 'Couldn’t finish.');
  } finally { sealing = false; $('finish').disabled = finished; }
}
// After Finish: the result over the page. A finished page can't change, so closing the result (a click outside it, or
// Escape) goes to Your Documents, where the page opens again in view only, with its link and downloads in the bar.
/** Leaves for Your Documents; a link still being made is waited for first, as leaving would stop it. */
async function leaveProved() {
  if (publishing) { say('Finishing your link…'); await publishing.catch(() => null); }
  openPages();
}
onClickOutside($('done'), () => $('done').close());
/** Download: the report (how it was written, with its proof) or the document itself, in the format chosen. */
function openFormats() {
  $('formatReport').hidden = !proved && !stopReason;
  $('formats').showModal(); $('formats').querySelector('button:not([hidden])').focus();
}
$('doneDownload').onclick = $('doneBarDownload').onclick = openFormats;
for (const button of $('formats').querySelectorAll('[data-format]')) button.onclick = () => {
  $('formats').close();
  if (button.dataset.format === 'report') saveReport(); else download(button.dataset.format);
};
$('formatsCancel').onclick = () => $('formats').close();
$('done').onclose = () => { if ($('doneBar').hidden) leaveProved(); };
// The view link: anyone with it can read the page and check it was written in Huma. At Finish the server checks the
// proof and keeps the page under the writer's account; Share copies the link, or makes it if that didn't happen yet.
let publishing = null, saving = false, copiedTimer;
const shareLink = () => pageRecord?.shared ? new URL(pageRecord.shared, location.origin).href : null;
// While the page is saved, its buttons wait, and Share says so; a copied link says so on the button itself, as the
// snackbar sits behind the open result.
function updateShare(copied = false) {
  clearTimeout(copiedTimer);
  for (const id of ['doneShare', 'doneBarShare']) {
    $(id).textContent = saving ? 'Saving…' : copied ? 'Copied' : shareLink() ? 'Copy Link' : 'Share';
    $(id).disabled = saving || !proved;
  }
  for (const id of ['doneDownload', 'doneBarDownload']) $(id).disabled = saving;
  for (const id of ['postX', 'postLinkedIn']) $(id).disabled = saving || !proved;
  if (copied) copiedTimer = setTimeout(updateShare, 2000);
}
function linkStatus(text) { $('doneLink').hidden = !text; $('doneLink').textContent = text; }
// Readers can watch the writing replay unless the writer turns it off (as on the Mac, on unless they've said no):
// before the link is made, the choice is remembered for it; after, the browser that shared the page changes it.
// The page shows on the writer's page (huma.social/@handle) the same way: on unless they've said no.
const SHARE_REPLAY = 'huma-share-replay', SHOW_ON_PAGE = 'huma-show-on-page';
const wantsReplay = () => { try { return localStorage.getItem(SHARE_REPLAY) !== 'off'; } catch { return true; } };
const wantsListed = () => { try { return localStorage.getItem(SHOW_ON_PAGE) !== 'off'; } catch { return true; } };
let replayOn = null, listedOn = null;
const publicationOf = record => record?.publication ?? record?.shared?.match(FULL_LINK)?.[1] ?? null;
/** A shared page's id as the server keeps it, found from its short link (pages shared before the id was kept right, or
 *  opened in another browser, may hold none or a wrong one); else the one the record holds. */
const sharedId = async record => (await shortTarget(record?.shared)) ?? publicationOf(record);
async function showShareChoices() {
  const id = proved && pageRecord?.shared ? await sharedId(pageRecord) : null;
  // A page kept with no id or a wrong one (shared before it was kept right) is put right, so its options work.
  if (id && id !== pageRecord.publication) await persist({ shared: pageRecord.shared, publication: id, updated: pageRecord.updated }).catch(() => {});
  const shown = id ? await pageShown(id, new URL(pageRecord.shared, location.origin).hash.slice(1)) : null;
  replayOn = proved?.replay ? shown?.replay ?? null : null; listedOn = shown?.listed ?? null;
  $('replayRow').hidden = !proved?.replay || (id && replayOn === null);
  $('replayToggle').checked = id ? replayOn === true : wantsReplay();
  $('listedRow').hidden = !proved || (id && listedOn === null);
  $('listedToggle').checked = id ? listedOn === true : wantsListed();
  showListedHint();
  // Once the page is shared, it carries the writer's World ID from its Start and Finish scans: said here, after, never
  // before the Finish scan has been made and confirmed.
  const human = proved && pageRecord?.shared && account() && (await worldIDOn()) ? await linkedWorldID().catch(() => null) : null;
  $('worldidRow').hidden = !human;
  if (human) $('worldidLabel').textContent = `✓ Started and finished with World ID ${human.fingerprint}`;
}
/** Shown on Your Page, signed in without a handle yet: the way to pick one, so the page has an address. */
function showListedHint() { $('listedHandle').hidden = !account() || Boolean(profile()?.handle) || !$('listedToggle').checked || $('listedRow').hidden; }
$('listedHandle').onclick = () => openProfile();
async function toggleListed(on) {
  $('listedToggle').disabled = true;
  try { listedOn = await setListed(publicationOf(pageRecord), on); say(listedOn ? 'Shown on Your Page.' : 'Hidden from Your Page.'); }
  catch (e) { say(e.message); }
  finally { $('listedToggle').checked = listedOn === true; $('listedToggle').disabled = false; showListedHint(); }
}
$('listedToggle').onchange = () => {
  const on = $('listedToggle').checked;
  try { localStorage.setItem(SHOW_ON_PAGE, on ? 'on' : 'off'); } catch {}
  showListedHint();
  if (publicationOf(pageRecord)) toggleListed(on);
};
async function toggleReplay(on) {
  $('replayToggle').disabled = true;
  try { replayOn = await setReplay(publicationOf(pageRecord), on ? proved.replay : null); say(replayOn ? 'Readers can watch you write.' : 'Replay removed.'); }
  catch (e) { say(e.message); }
  finally { $('replayToggle').checked = replayOn === true; $('replayToggle').disabled = false; }
}
$('replayToggle').onchange = () => {
  const on = $('replayToggle').checked;
  try { localStorage.setItem(SHARE_REPLAY, on ? 'on' : 'off'); } catch {}
  if (publicationOf(pageRecord)) toggleReplay(on);
};
/** Keeps the proved page in the account with its link; signs in first when needed (`ask`: the writer pressed Share). */
function publishPage(ask) {
  publishing ??= (async () => {
    if (!proved || shareLink()) return shareLink();
    if (!account()) {
      linkStatus('Sign in to get a link.');
      // Signing in is asked for only from a click (Share), never by itself.
      if (!signingIn && !ask) return null;
      if (!(await (signingIn ?? startSignIn()))) return null;
    }
    linkStatus(''); saving = true; updateShare();
    const saveStarted = performance.now();
    // Finished by the same human who started it: World ID again, for this page's text and proof (worldid.mjs).
    const replay = wantsReplay(), listed = wantsListed(), named = cleanTitle(pageName()),
      { path, id } = await publish(proved, { replay, listed, title: named, humanProof: finishWithWorldID });
    await persist({ shared: path, publication: id });
    track('page_shared', { ms: Math.round(performance.now() - saveStarted) });
    await syncPage(pageRecord);
    // Changed while the link was being made: the page follows the latest choice.
    if (wantsReplay() !== replay) await setReplay(id, wantsReplay() ? proved.replay : null).catch(() => {});
    if (wantsListed() !== listed) await setListed(id, wantsListed()).catch(() => {});
    if (cleanTitle(pageName()) && cleanTitle(pageName()) !== named) await setTitle(id, cleanTitle(pageName())).catch(() => {});
    showShareChoices();
    return shareLink();
  })().catch(e => { linkStatus(e.message || 'Couldn’t save. Press Share to try again.'); return null; })
    .finally(() => { publishing = null; saving = false; updateShare(); });
  return publishing;
}
/** The page's link; a page shared before short links keeps its full link until it's copied or posted, then gets its short one. */
async function shortLink() {
  if (pageRecord.shared.startsWith('/original/')) {
    const short = await shorten(pageRecord.shared);
    if (short !== pageRecord.shared) { await persist({ shared: short, publication: publicationOf(pageRecord) }); syncPage(pageRecord).catch(() => {}); }
  }
  return shareLink();
}
async function share() {
  if (!proved) return;
  if (!(shareLink() ?? await publishPage(true))) return;
  const link = await shortLink();
  try { await navigator.clipboard.writeText(link); updateShare(true); say('Link copied.'); track('link_copied'); }
  catch { if ($('done').open) linkStatus('Press Copy Link to copy it.'); else say(link); }
}
$('doneShare').onclick = $('doneBarShare').onclick = () => share();
// Posting the link: X gets a ready-made line with it, LinkedIn shows the page's card. The post opens in a new tab with
// the click and goes to X or LinkedIn once the link exists; signed out, the click signs in first (World ID, on this
// page), and a second posts.
const POSTS = {
  x: { name: 'X', event: 'posted_on_x', url: link => 'https://x.com/intent/post?text=' + encodeURIComponent('I wrote this myself, not AI. Huma shows how I typed it:') + '&url=' + encodeURIComponent(link) },
  linkedin: { name: 'LinkedIn', event: 'posted_on_linkedin', url: link => 'https://www.linkedin.com/sharing/share-offsite/?url=' + encodeURIComponent(link) },
};
async function post(where) {
  if (!proved) return;
  const { name, event, url } = POSTS[where];
  const tab = shareLink() || account() || signingIn ? window.open('', '_blank') : null;
  const made = shareLink() ?? await publishPage(true);
  if (!made) { tab?.close(); return; }
  const link = await shortLink();
  if (!tab) { linkStatus(`Your link is ready. Press Post on ${name} again.`); return; }
  tab.opener = null; tab.location.href = url(link);
  track(event);
}
$('postX').onclick = () => post('x');
$('postLinkedIn').onclick = () => post('linkedin');
// How the score could be higher: the writing checks this page missed.
const TIPS = { 'it started from imported text': 'start from a blank page', 'some text wasn’t typed': 'type the text rather than pasting it', 'it was typed for less than 20 seconds': 'write for 20 seconds or more',
  'it has fewer than 30 key presses': 'type 30 keys or more', 'there was no natural pause': 'pause as you think' };
function scoreWhy({ score, unmet }) {
  const tips = [...new Set(unmet.map(rule => TIPS[rule] ?? 'type as you usually do'))];
  if (score.presenceOnTime < score.presenceCount) tips.push('answer check-ins within 10 seconds');
  const about = score.browser && score.passkey ? 'Your passkey approved every check-in. The Mac app gives the strong check.' : checkTier(score.browser, score.passkey).about;
  return [...(score.capped ? ['Held at 50: the typing didn’t look like a person’s.'] : []), about,
    tips.length ? `To score more, ${tips.join(', ')}.` : ''].filter(Boolean).join(' ');
}
async function done(result, { reopened = false } = {}) {
  recording = null; show('done', 'Proved'); $('parts').textContent = '';
  try { proved = await provedPage(result); } catch { proved = null; }
  if (!reopened) {
    try { await putProof(pageId, result); } catch {}
    await persist({ status: 'proved', score: proved?.score.value ?? null });
    track('page_proved', { score: proved ? Math.round(proved.score.value) : undefined, ms: Math.round(performance.now() - finishStarted), cores: navigator.hardwareConcurrency });
    // Checked and kept in the account, with its link, without waiting for a click.
    if (proved) publishPage();
  } else linkStatus(shareLink() || account() ? '' : 'Sign in to get a link.');
  if (proved?.origin?.length === plainText(view.state.doc).length) { shadePasted(view.state.doc, proved.origin); view.setProps({}); }
  const n = words(result.text), c = proved?.composition, pasted = c?.total ? c.pasted / c.total : 0;
  // How much was typed and how much pasted, as readers will see it.
  $('doneName').value = pageName();
  // How long the writing took, from the first key to the last (known only right after writing it here).
  const minutes = !reopened && typingLog.length > 1 ? Math.max(1, Math.round((typingLog.at(-1)[0] - typingLog[0][0]) / 60000)) : 0;
  $('doneText').textContent = [n.toLocaleString() + (n === 1 ? ' word' : ' words'), ...(minutes ? [`written over ${minutes} min`] : []),
    ...(c ? [percentLabel(c.total ? (c.typed + c.external) / c.total : 0) + ' typed'] : []), ...(pasted ? [percentLabel(pasted) + ' pasted'] : [])].join(' · ');
  updateShare(); replayOn = listedOn = null; $('replayRow').hidden = $('listedRow').hidden = true; showShareChoices();
  if (proved) { $('doneScoreValue').textContent = String(proved.score.value); $('doneTier').textContent = checkTier(proved.score.browser, proved.score.passkey).label; $('doneScore').hidden = false; }
  const why = proved ? scoreWhy(proved) : '';
  $('doneWhy').hidden = !why; $('doneWhy').textContent = why;
  if (proved?.score.browser) $('doneWhy').append(' ', Object.assign(document.createElement('a'), { href: '/download#mac', target: '_blank', rel: 'noopener', textContent: 'Get Huma' }));
  $('doneBarText').textContent = 'Proved' + (proved ? ` · Huma Score ${proved.score.value} of 100 (${checkTier(proved.score.browser, proved.score.passkey).label})` : '') + ' · ' + $('doneText').textContent;
  // A proved page opened from Your Pages shows its result in the bar; just proved, over the page.
  if (reopened) { setMode(true); document.body.classList.add('barred'); $('doneBar').hidden = false; return; }
  // Proved while the writer was naming it: the result opens with their name and caret where they left them; while
  // they type anywhere else on the page (its title, a dialog), it waits in the bar, so nothing closes under them.
  const naming = document.activeElement === $('provingName') ? [$('provingName').selectionStart, $('provingName').selectionEnd] : null;
  if ($('proving').open) $('proving').close();
  const typing = !naming && document.activeElement?.matches?.('input, textarea, [contenteditable="true"]') && !view.hasFocus();
  if (typing) { setMode(true); document.body.classList.add('barred'); $('doneBar').hidden = false; say('Proved.'); return; }
  $('done').showModal();
  // Opened by the prover, not a click: no button starts out ringed.
  if (naming) { $('doneName').focus(); $('doneName').setSelectionRange(...naming); } else document.activeElement?.blur();
}
// A new page was already confirmed: the browser doesn't ask again on the way out.
let leaving = false;
function newPage() { leaving = true; persist().finally(() => { location.href = '/write?page=' + newId(); }); }
function confirmNew() {
  if (finished || !recording || plainText(view.state.doc) === initialText) { newPage(); return; }
  $('confirmNew').showModal();
}
$('confirmNewGo').onclick = newPage;
$('confirmNewCancel').onclick = () => { $('confirmNew').close(); view.focus(); };
$('finish').onclick = () => finishNow();
window.addEventListener('beforeunload', e => { if (!leaving && recording && !finished && plainText(view.state.doc) !== initialText) e.preventDefault(); });

// The recorder and the writing key, loaded with the page; recording waits for the writer.
let recorderCall = null, writerPair = null, beginning = false;
// The editor's raw events, streamed to huma.social for its typing analysis while the recording runs (collector.mjs).
let collector = null;
// The evaluation harness (frontend/detection/eval/harness.mjs), on this computer's own server only: it reads the recording's
// session, text and edits (as the recorder's replay has them, diffed the same way) through window.__humaEval, so a
// session can be judged without Finish. Never on huma.social.
const evalLog = ['localhost', '127.0.0.1'].includes(location.hostname) ? [] : null;
let evalNonce = null;
/** One replay frame for a text change, as the recorder diffs it (web.rs edit: UTF-16 offsets, surrogate pairs kept whole). */
function editFrame(before, after, kind, time) {
  let prefix = 0; while (prefix < Math.min(before.length, after.length) && before.charCodeAt(prefix) === after.charCodeAt(prefix)) prefix++;
  if (prefix > 0 && prefix < before.length && (before.charCodeAt(prefix) & 0xfc00) === 0xdc00) prefix--;
  let suffix = 0; while (suffix < Math.min(before.length, after.length) - prefix && before.charCodeAt(before.length - 1 - suffix) === after.charCodeAt(after.length - 1 - suffix)) suffix++;
  if (suffix > 0 && (before.charCodeAt(before.length - suffix) & 0xfc00) === 0xdc00) suffix--;
  return { time, kind, location: prefix, length: before.length - prefix - suffix, inserted: after.slice(prefix, after.length - suffix) };
}
if (evalLog) window.__humaEval = { session: () => ({ nonce: evalNonce, text: view ? plainText(view.state.doc) : '', frames: evalLog.slice(), state: document.body.dataset.state,
  halted: $('halt').open ? $('haltText').textContent : null, retyping: $('retype').open ? $('retypePhrase').textContent : null, stream: collector?.state ?? null }) };
// The host's confirmation of this recording's Start World ID: resolves true once it's kept, false if refused (null:
// none was asked). Writing doesn't wait for it; Finish does.
let startConfirmed = null;
/** The prover, made and warmed once per page, from Start Recording: its start-up (programs, bb.js and the proving
 *  points, about 8 s) runs while World ID is scanned, not while the writer types. */
function warmProver() {
  if (prover) return;
  prover = new PageProver(new URL('prover.js', assets), assets);
  prover.onchange = updateCounts;
  prover.warm();
}
let unsupported = false;
// Writing on the web is for computers only, until phones and tablets have a check as strong (an iPad says it's a Mac,
// but has a touch screen).
const phoneOrTablet = navigator.userAgentData?.mobile === true || /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent)
  || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
const idle = () => Boolean(recorderCall) && !recording && !beginning && !unsupported && !stopReason && !finished;
/** From the writer's own page (/@handle): one of a shared page's options, done here, where this browser signs it;
 *  then back to that page. */
async function fromWriterPage() {
  const params = new URLSearchParams(location.search), code = params.get('shared'), act = params.get('do');
  if (!/^[A-Za-z0-9_-]{4,32}$/.test(code ?? '') || !['rename', 'download', 'hide', 'delete'].includes(act)) return false;
  const back = () => location.replace(profile()?.handle ? '/@' + profile().handle : '/write?pages');
  if (!account()) { failed('Sign in to change this page.', back); return true; }
  // A page whose document was deleted (or never kept in the account) is still on the writer page: it's renamed,
  // hidden or deleted there by its link.
  const kept = (await allPages().catch(() => [])).find(p => p.shared?.split('#')[0] === '/p/' + code);
  const record = kept ?? { orphan: true, status: 'proved', title: '', shared: '/p/' + code }, id = await sharedId(record);
  if (!id) { failed('Couldn’t find this page. It may be deleted already.', back); return true; }
  if (act === 'hide') { await setListed(id, false).then(back, e => failed(e.message, back)); return true; }
  if (act === 'download') {
    if (kept) location.replace('/write?page=' + kept.id + '&download'); else failed('This page’s document was deleted, so it can’t be downloaded.', back);
    return true;
  }
  await home();
  (act === 'rename' ? renamePage : deletePage)(record, back);
  return true;
}
async function start() {
  // Privy sign-in came back to this page to finish (off for now: World ID signs in on this page).
  // await finishSignIn().catch(() => null);
  if (!pageId && await fromWriterPage()) return;
  if (!pageId) { await home(); return; }
  track('$pageview');
  try { pageRecord = (await page(pageId)) ?? null; hasPages = Boolean(account()) || (await keptPages()).some(p => p.id !== pageId); } catch {}
  // A document kept in the account but not yet in this browser comes down first, with what it proved.
  if (!pageRecord && account()) {
    try {
      const { proof: proven, ...record } = await accountDocument(pageId);
      if (proven) await putProof(pageId, proven);
      pageRecord = { ...record, ...(proven ? {} : { status: 'draft' }) };
      await putPage(pageRecord);
    } catch {}
  }
  updateAccount();
  // With no other pages, the Huma icon goes to Huma's home page instead.
  if (!hasPages) $('pagesLink').href = '/';
  applyZoom();
  createView(restore());
  // A proved page opens as it was proved, to read and download; it can't be written in again.
  if (pageRecord?.status === 'proved') {
    const result = await proof(pageId).catch(() => null);
    if (result) { finished = true; $('finish').disabled = true; $('pause').disabled = true; await done(result, { reopened: true }); downloadAsked(); return; }
  }
  if (phoneOrTablet) {
    $('unsupportedText').textContent = 'Huma needs a computer for now. Send yourself the link, then open it in Chrome, Edge, Firefox or Safari there.';
    $('sendLink').hidden = false;
    $('sendLink').onclick = async () => {
      const url = location.origin + '/write';
      try { if (navigator.share) { await navigator.share({ title: 'Huma', text: 'Write on Huma on my computer', url }); return; } } catch (e) { if (e?.name === 'AbortError') return; }
      try { await navigator.clipboard.writeText(url); say('Link copied. Send it to yourself.'); } catch { say(url); }
    };
    show('unsupported', ''); return;
  }
  if (!window.crossOriginIsolated || typeof WebAssembly !== 'object' || !window.indexedDB) { show('unsupported', ''); return; }
  if (navigator.webdriver) { stop('This browser is run by software, so it can’t record. Start a new document in a browser you use yourself.', AUTOMATED); return; }
  try {
    [recorderCall, writerPair] = await Promise.all([fetch(new URL('recorder.wasm', assets)).then(r => r.arrayBuffer()).then(loadRecorder), writingKey()]);
  } catch { show('unsupported', ''); return; }
  show('ready', 'Not recording');
  const kept = Boolean(plainText(view.state.doc).trim());
  // A new, empty document starts recording as it opens, so the writer just types. One with text kept from before
  // asks first, since that text won't count as typed; so does any start that didn't go through (offline).
  if (!kept && !new URLSearchParams(location.search).has('download')) {
    const go = () => begin().then(() => { if (idle()) showStartCard(false); });
    if (document.visibilityState === 'visible') go(); else document.addEventListener('visibilitychange', go, { once: true });
    ensureProfile();
    return;
  }
  showStartCard(kept);
  if (downloadAsked()) return;
  // Signed in without a name and face yet (the first time): chosen before writing, over the start card, as in the
  // Mac's setup.
  ensureProfile();
  offerPasskey();
}
/** Start Recording, as a card over the page: for a document with text from before, or when starting by itself failed. */
function showStartCard(kept) {
  if (kept) {
    $('startTitle').textContent = 'Pick up where you left off';
    $('startText').textContent = 'Text already here won’t count as typed.';
  }
  // Beside Start Recording, one other choice: the other documents, or for a kept page with none, a fresh one.
  showStartAlt(hasPages ? 'pages' : kept ? 'new' : null);
  $('startCard').oncancel = e => e.preventDefault();
  if (!$('startCard').open) $('startCard').showModal();
  document.activeElement?.blur();
}
/** Opened by Download in Your Documents (?download): the Download choices show over the page, once. */
function downloadAsked() {
  const url = new URL(location.href);
  if (!url.searchParams.has('download')) return false;
  url.searchParams.delete('download'); window.history.replaceState(window.history.state, '', url);
  openFormats(); return true;
}
// Your Pages: every page kept in this browser, newest first, as Docs lists documents.
async function home() {
  let list = [];
  try {
    // The one page kept before there was a list joins it.
    const old = JSON.parse(localStorage.getItem(SAVED) ?? 'null');
    if (old?.doc) {
      const doc = schema.nodeFromJSON(migrate(old.doc)), text = plainText(doc), at = Date.now();
      if (text.trim() || old.title?.trim()) await putPage({ id: newId(), title: old.title ?? '', doc: doc.toJSON(), text: text.slice(0, 300), words: words(text), status: 'draft', score: null, created: at, updated: at });
      localStorage.removeItem(SAVED);
    }
    list = await allPages();
  } catch {}
  // With nothing kept yet, writing starts straight away, unless the list was asked for (the Huma icon, File menu).
  if (!list.length && !new URLSearchParams(location.search).has('pages')) { location.replace('/write?page=' + newId()); return; }
  document.title = 'Your Documents · Huma';
  track('$pageview');
  document.body.classList.add('home-mode'); show('home', '');
  $('home').hidden = false; updateAccount();
  renderPages(list);
  ensureProfile();
}
/** This browser's documents and, when signed in, the account's: one entry each, the most recently changed version. */
async function allPages() {
  const local = await keptPages();
  if (!account()) return local;
  const remote = await accountDocuments().catch(() => []), byId = new Map(local.map(p => [p.id, p]));
  for (const entry of remote) if (!byId.has(entry.id) || (byId.get(entry.id).updated ?? 0) < entry.updated) byId.set(entry.id, { ...byId.get(entry.id), ...entry, remote: true });
  return [...byId.values()].sort((a, b) => b.updated - a.updated);
}
const nameOf = record => record.title?.trim() || shortName(record.text?.split('\n').find(line => line.trim()) ?? '') || 'Untitled document';
function when(time) {
  const date = new Date(time), today = new Date();
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', ...(date.getFullYear() !== today.getFullYear() ? { year: 'numeric' } : {}) });
}
// Search and order: shown once there are a few documents; the list keeps the last one loaded.
let listed = [];
$('homeSearch').oninput = () => renderPages(listed);
// The order, from Huma's own menu (a check by the current one), as in Docs.
const SORTS = [['updated', 'Last edited'], ['name', 'Name'], ['score', 'Huma Score']];
$('homeSort').onclick = () => {
  const button = $('homeSort');
  menu(button, SORTS.map(([value, label]) => ({ label, checked: button.value === value,
    run: () => { button.value = value; button.textContent = label; renderPages(listed); } })), { className: 'sort-menu', alignRight: true });
};
function renderPages(all) {
  listed = all;
  $('homeTools').hidden = all.length < 4;
  const query = $('homeSearch').value.trim().toLowerCase(), order = $('homeSort').value;
  const list = all.filter(r => !query || nameOf(r).toLowerCase().includes(query) || (r.text ?? '').toLowerCase().includes(query))
    .sort(order === 'name' ? (a, b) => nameOf(a).localeCompare(nameOf(b)) : order === 'score' ? (a, b) => (b.score ?? -1) - (a.score ?? -1) : () => 0);
  const ul = $('pageList');
  $('pagesEmpty').hidden = list.length > 0;
  $('pagesEmpty').textContent = all.length ? 'No documents match.' : 'No documents yet.';
  ul.replaceChildren(...list.map(record => {
    const li = document.createElement('li'), link = document.createElement('a');
    link.href = '/write?page=' + record.id;
    link.innerHTML = icon(record.status === 'proved' ? 'task_alt' : 'description', record.status === 'proved' ? 'proved' : '');
    const name = Object.assign(document.createElement('span'), { className: 'name', textContent: nameOf(record) });
    const status = Object.assign(document.createElement('span'), { className: 'meta',
      textContent: record.status === 'proved' ? `Proved${record.score === null || record.score === undefined ? '' : ` · Score ${record.score}`}` : `Draft · ${(record.words ?? 0).toLocaleString()} ${record.words === 1 ? 'word' : 'words'}` });
    const date = Object.assign(document.createElement('span'), { className: 'date', textContent: when(record.updated) });
    link.append(name, status, date);
    const more = Object.assign(document.createElement('button'), { type: 'button', className: 'tb', title: 'More', innerHTML: icon('more_vert') });
    more.setAttribute('aria-label', 'More for ' + nameOf(record));
    more.onclick = () => menu(more, [
      { label: 'Open', icon: 'open_in_new', run: () => { location.href = link.href; } },
      { label: 'Download', icon: 'download', run: () => { location.href = link.href + '&download'; } },
      { label: 'Rename', icon: 'edit', run: () => renamePage(record) },
      { label: 'Delete', icon: 'delete', run: () => deletePage(record) }], { alignRight: true });
    li.append(link, more);
    return li;
  }));
}
async function refreshPages() { try { renderPages(await allPages()); } catch {} }
/** A document kept only in the account, brought into this browser (with its proof) so it can change here. */
async function localCopy(record) {
  if (record.doc) return record;
  const { proof: proven, ...full } = await accountDocument(record.id);
  if (proven) await putProof(record.id, proven);
  await putPage(full);
  return full;
}
/** Renames a document, in the account too, and where it's shared. `after` runs once it's done or cancelled. */
/** A change that didn't go through says why, and what follows (often leaving for the writer page) waits until it's read. */
function failed(message, after) { say(message); setTimeout(after, 3000); }
function renamePage(record, after = refreshPages) {
  $('renameInput').value = record.orphan ? '' : record.title || nameOf(record);
  $('rename').onclose = () => after();
  $('renameGo').onclick = async () => {
    const name = cleanTitle($('renameInput').value);
    $('rename').onclose = null; $('rename').close();
    try {
      // A page only on the writer page (its document deleted) is renamed there alone.
      if (!record.orphan) {
        const renamed = { ...(await localCopy(record)), title: name, updated: Date.now() };
        await putPage(renamed);
        if (account()) await syncPage(renamed);
      }
      const shared = record.status === 'proved' && name && await sharedId(record);
      if (shared) await setTitle(shared, name);
    } catch (e) { failed(e?.message || 'Couldn’t rename it. Try again.', after); return; }
    after();
  };
  $('rename').showModal(); $('renameInput').select();
}
$('renameInput').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); $('renameGo').click(); } };
$('renameCancel').onclick = () => $('rename').close();
/** Deletes a document, from the account too; a shared one's link stops working first. */
function deletePage(record, after = refreshPages) {
  const shared = Boolean(record.shared || publicationOf(record));
  $('deleteTitle').textContent = record.orphan ? 'Delete this page?' : `Delete “${nameOf(record)}”?`;
  $('deleteText').textContent = shared ? 'Its link stops working too. This can’t be undone.' : 'This can’t be undone. Download it first to keep a copy.';
  $('deletePage').onclose = () => after();
  $('deleteGo').onclick = async () => {
    $('deletePage').onclose = null; $('deletePage').close();
    // The link comes down first, so the page leaves the writer page too, then the document.
    try { const id = shared && await sharedId(record); if (id) await removeShared(id); } catch (e) { failed(e.message, after); return; }
    if (record.orphan) { after(); return; }
    try { await removePage(record.id); } catch {}
    if (account()) try { await deleteFromAccount(record.id); } catch (e) { failed(e.message, after); return; }
    after();
  };
  $('deletePage').showModal(); $('deleteCancel').focus();
}
$('deleteCancel').onclick = () => $('deletePage').close();
$('homeNew').onclick = () => { location.href = '/write?page=' + newId(); };
/** Your Pages, with this page saved first. */
function openPages() { persist().finally(() => { location.href = '/write?pages'; }); }
$('pagesLink').onclick = e => { if (!hasPages) return; e.preventDefault(); openPages(); };
// Leaving the page some other way still keeps its last changes.
addEventListener('pagehide', () => { if (pageId && view) persist(); });
// Another tab may have changed the list.
addEventListener('pageshow', e => { if (e.persisted && !pageId) refreshPages(); });

const FIRST_TIP = 'huma-write-tip';
/** Start Recording: from here on, every change to the page is recorded. */
async function begin() {
  if (!idle()) return;
  const blocked = automationBlock();
  if (blocked) { say(blocked); return; }
  if ([...plainText(view.state.doc)].length > TEXT_LIMIT) {
    $('startText').textContent = 'This document is over 10,000 characters. Start a new one to record.';
    showStartAlt('new'); $('startGo').hidden = true; return;
  }
  beginning = true;
  warmProver();
  // The session's number comes from huma.social with its start time, so sharing can check the writing took real time.
  const issued = await sessionNonce(), nonce = issued?.nonce;
  if (!nonce) { beginning = false; say('Couldn’t reach huma.social to start. Check your connection and try again.'); return; }
  // Every document is started by a verified human: World ID for this writing session (worldid.mjs). Writing begins as
  // soon as World App answers; the host confirms the scan meanwhile (and signs in a writer who isn't yet), and one it
  // refuses stops the recording. Cancelled or declined, nothing starts, and Start Recording can be pressed again.
  const wasSignedIn = Boolean(account()), scan = await scanAtStart(nonce);
  if (!scan.ok) { beginning = false; if (scan.reason) say(scan.reason); return; }
  $('startCard').close(); $('startBar').hidden = true; $('passkeyOffer').hidden = true; document.body.classList.remove('barred');
  // Writing picks up at the end of a kept page.
  view.dispatch(view.state.tr.setSelection(Selection.atEnd(view.state.doc)).scrollIntoView());
  try {
    initialText = plainText(view.state.doc);
    started = performance.now(); latest = 0;
    // Text already on the page (kept from before a reload) stays as it was, never counted as typed.
    // Signed in with a passkey for this site: every check-in asks for it too, and the page shows the passkey check.
    const passkey = account() && passkeysWork() && sitePasskeys().length ? { rp_id: location.hostname, origin: location.origin } : null;
    recording = await Recording.start(recorderCall, writerPair, { initialText, passkey, nonce });
    warmProver();
    // From here on the editor's events stream to huma.social (collector.mjs), and the page hides its canary (canary.mjs).
    if (issued.key) {
      collector = createCollector({ editor: sheet, caret: () => (view ? { caret: view.state.selection.from, size: view.state.doc.content.size } : null), trap: () => $('title_alt').value });
      collector.start(nonce, issued.key).catch(() => {});
    }
    if (issued.canary) $('canary').textContent = canaryInstruction(issued.canary);
    evalNonce = nonce; if (evalLog) evalLog.length = 0;
    startConfirmed = scan.proof ? confirmStart(nonce, scan.proof).then(me => { if (!wasSignedIn) signedIn(me); return true; }, e => {
      if (recording && !finished) stop((e?.message || 'World ID couldn’t be confirmed.') + ' This document can’t be shared; start a new one.', 'World ID not confirmed');
      return false;
    }) : null;
    nextCheck = nextCheckIn(0); ready = true;
    view.setProps({}); updateToolbar(view.state); refreshGrammar(view);
    $('finish').disabled = false; $('pause').disabled = false; show('writing', 'Recording'); view.focus();
    // The first time: what's recorded, in one line.
    try { if (!localStorage.getItem(FIRST_TIP)) { say('Recording. Type as usual. You can paste, but pasted text is marked.'); localStorage.setItem(FIRST_TIP, '1'); } } catch {}
    track('recording_started');
    confirmAlongside('start');
  } catch {
    unsupported = true; show('unsupported', '');
  } finally { beginning = false; }
}
// Anyone can start writing; signing in waits until Finish, when the page gets its link.
$('startGo').onclick = $('startBarGo').onclick = () => begin();
$('startCard').onclose = () => { if (idle()) { document.body.classList.add('barred'); $('startBar').hidden = false; } };
function showStartAlt(kind) {
  $('startAlt').hidden = !kind;
  $('startAlt').textContent = kind === 'new' ? 'Start a New Document' : 'Your Documents';
  $('startAlt').onclick = kind === 'new' ? () => newPage() : () => openPages();
}
start();
// World ID's config and code, ahead of the first scan (Start Recording).
prepareWorldID();
// Session replays (pages/replay.mjs), every word hidden, once the page has settled.
(window.requestIdleCallback ?? setTimeout)(() => import('/write/replay.js').catch(() => {}), { timeout: 4000 });
