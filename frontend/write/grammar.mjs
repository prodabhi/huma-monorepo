// Spelling and grammar suggestions as you write, as on the Mac (extra/Sources/Huma/GrammarChecker.swift): a few exact rules
// (the Mac's GrammarRules), then Harper (backend/integrations/grammar, built into grammar.wasm), which reads each paragraph in
// its own worker on this computer, spelling included (red, as in Docs; grammar is blue). Nothing is sent anywhere. A fix is never put in for you: choosing one selects the words
// and says what to type, so the page stays typed.
import { Plugin, PluginKey } from 'prosemirror-state';
import { Decoration, DecorationSet } from 'prosemirror-view';

const LOWERCASE_I = /(?<![\p{L}\p{N}'’.])i(?![\p{L}\p{N}])(?!\.[eE])/gu;
const REPEATED = /(?<![\p{L}\p{N}])(\p{L}+)\s+\1(?![\p{L}\p{N}])/giu;
const SENTENCE_START = /(?:^|(?<=[.!?])["”’)\]]?[ \t]+)["“‘(\[]?(\p{L}[\p{L}'’]*)/gmud;
const ABBREVIATIONS = new Set(['mr', 'mrs', 'ms', 'dr', 'st', 'vs', 'etc', 'jr', 'sr', 'no', 'fig', 'approx']);

/** A lowercase "i" on its own, a word typed twice in a row, and a sentence that starts with a lowercase letter. */
export function ruleIssues(text) {
  const found = [];
  for (const m of text.matchAll(LOWERCASE_I)) found.push({ start: m.index, end: m.index + 1, fixes: ['I'], reason: 'Write “I” as a capital letter' });
  for (const m of text.matchAll(REPEATED)) {
    if (['had', 'that'].includes(m[1].toLowerCase())) continue;
    found.push({ start: m.index, end: m.index + m[0].length, fixes: [m[1]], reason: 'The same word twice' });
  }
  // A sentence starts the paragraph, or follows ". ", "! " or "? " (not after "e.g." or "Dr.").
  for (const m of text.matchAll(SENTENCE_START)) {
    const [start, end] = m.indices[1], before = text.slice(0, start), stop = before.search(/[.!?]["”’)\]]?\s+$/);
    if (stop !== -1) {
      const previous = before.slice(0, stop).split(/\s+/).at(-1) ?? '';
      if (previous.length === 1 || previous.includes('.') || ABBREVIATIONS.has(previous.toLowerCase())) continue;
    }
    const word = m[1];
    // Lowercase words only: not "i" (above), "iPhone", "e.g." or a web address.
    if (word === 'i' || word[0] === word[0].toUpperCase() || /\p{Lu}/u.test(word.slice(1)) || ['http', 'https', 'www'].includes(word.toLowerCase())) continue;
    if (['.', '/', ':', '@'].includes(text[end])) continue;
    found.push({ start, end, fixes: [word[0].toUpperCase() + word.slice(1)], reason: 'Start a sentence with a capital letter' });
  }
  return found;
}

/** Harper's message, kept short for the card: its first sentence, without Markdown. */
const short = message => (message.replaceAll('`', '').split('.')[0] ?? '').trim().slice(0, 80);

export const grammarKey = new PluginKey('grammar');
const ignoredKey = issue => issue.original + '\u001f' + issue.fixes.join('\u001e');

/**
 * The underlines, and the checks behind them. `active()`: whether to check now (writing, and spelling or grammar
 * turned on); `show(kind)`: whether to show 'spelling' or 'grammar'; `worker()`: makes Harper's worker
 * (grammar-worker.mjs), started the first time there's something to read.
 */
export function grammarPlugin({ active, show = () => true, worker: makeWorker }) {
  const harper = new Map(), ignored = new Set(), waiting = new Map();
  let worker = null, failed = false, nextId = 0, timer = null;
  const read = texts => new Promise(resolve => {
    if (failed) { resolve(null); return; }
    if (!worker) {
      worker = makeWorker();
      worker.onmessage = ({ data }) => { waiting.get(data.id)?.(data.results ?? null); waiting.delete(data.id); };
      worker.onerror = () => { failed = true; for (const done of waiting.values()) done(null); waiting.clear(); };
    }
    const id = ++nextId; waiting.set(id, resolve); worker.postMessage({ id, texts });
  });
  // Each paragraph's text as positions count it: one character per position, a line break as one.
  const blocks = doc => {
    const list = [];
    doc.descendants((node, pos) => {
      if (!node.isTextblock) return true;
      list.push({ from: pos + 1, text: node.textBetween(0, node.content.size, undefined, '￼') });
      return false;
    });
    return list;
  };
  function decorations(state, typing) {
    if (!active()) return DecorationSet.empty;
    const caret = state.selection.empty ? state.selection.from : -1, found = [];
    for (const { from, text } of blocks(state.doc)) {
      if (!text.trim()) continue;
      const issues = [...(show('grammar') ? ruleIssues(text) : []), ...(harper.get(text) ?? []).filter(issue => show(issue.spelling ? 'spelling' : 'grammar'))];
      for (const issue of issues) {
        const at = from + issue.start, to = from + issue.end, original = text.slice(issue.start, issue.end);
        // The word just typed is still being written, so it isn't judged until the writer moves on.
        if (typing && to === caret) continue;
        const spec = { ...issue, original, from: at, to };
        if (issue.fixes.includes(original) || ignored.has(ignoredKey(spec)) || found.some(d => d.from < to && at < d.to)) continue;
        found.push(spec);
      }
    }
    return DecorationSet.create(state.doc, found.map(issue => Decoration.inline(issue.from, issue.to, { class: issue.spelling ? 'spelling-mark' : 'grammar-mark' }, { issue })));
  }
  // Harper reads each paragraph once, a moment after typing stops; what it finds is kept by the paragraph's text.
  function schedule(view) {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!active()) return;
      const texts = [...new Set(blocks(view.state.doc).map(b => b.text))].filter(t => t.trim() && t.length <= 5000 && !harper.has(t));
      if (!texts.length) return;
      const results = await read(texts);
      if (!results) return;
      if (harper.size > 2000) harper.clear();
      // A misspelling shows Harper's first three guesses; its guesses that split a word in two ("Typo") are left out.
      texts.forEach((text, i) => harper.set(text, (results[i] ?? []).filter(p => p.kind !== 'Typo' && typeof p.fix === 'string')
        .map(p => p.kind === 'Spelling'
          ? { start: p.start, end: p.end, spelling: true, fixes: (p.fixes ?? [p.fix]).filter(Boolean).slice(0, 3), reason: 'Check the spelling' }
          : { start: p.start, end: p.end, fixes: [p.fix], reason: short(p.message) })
        .filter(p => p.fixes.length)));
      if (!view.isDestroyed) view.dispatch(view.state.tr.setMeta(grammarKey, 'found'));
    }, 600);
  }
  return new Plugin({
    key: grammarKey,
    state: {
      init: (_, state) => ({ typing: false, set: decorations(state, false) }),
      apply(tr, old, _, state) {
        const typing = tr.docChanged ? true : tr.selectionSet ? false : old.typing;
        if (tr.docChanged || tr.getMeta(grammarKey) || typing !== old.typing) return { typing, set: decorations(state, typing) };
        return old;
      },
    },
    props: { decorations: state => grammarKey.getState(state).set },
    view: view => {
      schedule(view);
      return { update: (v, previous) => { if (v.state.doc !== previous.doc || v.state.plugins !== previous.plugins) schedule(v); }, destroy: () => { clearTimeout(timer); worker?.terminate(); } };
    },
    /** Hides a suggestion the writer chose to ignore (its words with that fix, anywhere on the page). */
    ignore: issue => ignored.add(ignoredKey(issue)),
  });
}

/** The suggestion under `pos` (inside its words or at either end), or null. */
export function issueAt(state, pos) {
  const set = grammarKey.getState(state)?.set;
  return set?.find(pos, pos).map(d => d.spec.issue).find(Boolean) ?? null;
}
/** Re-reads the page's underlines (after turning suggestions on or off, or ignoring one). */
export const refreshGrammar = view => view.dispatch(view.state.tr.setMeta(grammarKey, 'refresh'));
