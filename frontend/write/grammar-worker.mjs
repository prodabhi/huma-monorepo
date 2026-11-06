// Harper's grammar checks (backend/integrations/grammar, built into grammar.wasm by write/build.mjs), off the page's thread:
// paragraphs in, problems out ({ start, end, kind, message, fix, fixes }, offsets as JavaScript counts them), spelling
// included: the page has no other spell checker it can count on.
let ready = null;
function load() {
  ready ??= (async () => {
    const response = await fetch(new URL('./grammar.wasm', self.location.href), { credentials: 'omit', redirect: 'error' });
    const module = await WebAssembly.compileStreaming(response);
    let exports;
    // Harper's random numbers come from here. Its other imports (left by a dependency's JavaScript bindings) are never
    // called while checking, and fail loudly if one is.
    const imports = { huma: { random: (pointer, length) => {
      for (let at = 0; at < length; at += 65536) crypto.getRandomValues(new Uint8Array(exports.memory.buffer, pointer + at, Math.min(65536, length - at)));
    } } };
    for (const { module: name, name: field } of WebAssembly.Module.imports(module)) {
      if (name !== 'huma') (imports[name] ??= {})[field] = () => { throw new Error('Not available here.'); };
    }
    exports = (await WebAssembly.instantiate(module, imports)).exports;
    return exports;
  })();
  return ready;
}
const encoder = new TextEncoder(), decoder = new TextDecoder();
function lint(x, text) {
  const bytes = encoder.encode(text), pointer = x.huma_grammar_alloc(bytes.length + 1);
  const memory = new Uint8Array(x.memory.buffer);
  memory.set(bytes, pointer); memory[pointer + bytes.length] = 0;
  const reply = (x.huma_grammar_lint_spelling ?? x.huma_grammar_lint)(pointer);
  x.huma_grammar_dealloc(pointer, bytes.length + 1);
  if (!reply) return [];
  const after = new Uint8Array(x.memory.buffer);
  let end = reply; while (after[end]) end++;
  const json = decoder.decode(after.slice(reply, end));
  x.huma_grammar_free(reply);
  return JSON.parse(json);
}
self.onmessage = async ({ data }) => {
  try {
    const results = [];
    for (const text of data.texts) {
      // A check that stops partway (a bug in a rule) can leave Harper half-way through its own state: a fresh copy reads the rest.
      try { results.push(lint(await load(), text)); } catch { ready = null; results.push([]); }
    }
    self.postMessage({ id: data.id, results });
  } catch {
    self.postMessage({ id: data.id, results: null });
  }
};
