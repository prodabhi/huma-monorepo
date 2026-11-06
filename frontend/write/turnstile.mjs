// Cloudflare Turnstile on the write page: a check, usually unseen, that a person uses this browser, at Start, Finish
// and when a page is shared (the server checks the token: turnstile-verify.mjs, publications.mjs). Off, and nothing is
// loaded, when the server has no Turnstile keys (GET /api/turnstile says siteKey: null).
//
// Cloudflare's script loads only when it's on. Its widget is drawn into the dialog open at the time (a modal dialog
// makes the rest of the page inert, so a challenge outside it couldn't be clicked), or else into #turnstile.
export const NOT_CONFIRMED = 'Couldn’t confirm this browser. Try again.';
export const TURNSTILE_ACTIONS = Object.freeze(['start', 'finish', 'publish']);
const SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const WAIT = 120000;

let config = null, script = null;
/** The site key, or null when Turnstile is off (or the server can't be asked, which the server then decides). */
export function turnstileSiteKey() {
  config ??= fetch('/api/turnstile').then(r => (r.ok ? r.json() : null)).then(value => (typeof value?.siteKey === 'string' && value.siteKey ? value.siteKey : null), () => null);
  return config;
}
/** Whether Turnstile is on here. */
export const turnstileOn = async () => (await turnstileSiteKey()) !== null;

// The page's <div id="turnstile"> is also window.turnstile until Cloudflare's script replaces it, so look for render.
const loaded = () => (typeof window.turnstile?.render === 'function' ? window.turnstile : null);
function loadScript() {
  if (loaded()) return Promise.resolve(loaded());
  script ??= new Promise((resolve, reject) => {
    const tag = document.createElement('script');
    tag.src = SCRIPT;
    tag.onload = () => (loaded() ? resolve(loaded()) : reject(new Error(NOT_CONFIRMED)));
    tag.onerror = () => { script = null; tag.remove(); reject(new Error(NOT_CONFIRMED)); };
    document.head.append(tag);
  });
  return script;
}

// Where the widget goes: the top dialog that's open (modal or not), or #turnstile, or the end of the page.
function host() {
  const open = [...document.querySelectorAll('dialog[open]')].pop();
  const box = document.createElement('div');
  box.className = 'turnstile-widget';
  (open ?? document.getElementById('turnstile') ?? document.body).append(box);
  return box;
}

/**
 * A fresh Turnstile token for `action` ('start' | 'finish' | 'publish'): usually no one sees anything; when Cloudflare
 * wants a click, its box shows where host() put it. Resolves the token, or null when Turnstile is off. Rejects with
 * NOT_CONFIRMED when the browser isn't confirmed (failed, expired, timed out or blocked). Each token works once,
 * for about five minutes, so get it just before it's used.
 */
export async function humanToken(action) {
  if (!TURNSTILE_ACTIONS.includes(action)) throw new Error('Unknown Turnstile action.');
  const siteKey = await turnstileSiteKey();
  if (!siteKey) return null;
  const turnstile = await loadScript();
  const box = host();
  let widget;
  try {
    return await new Promise((resolve, reject) => {
      const fail = () => reject(new Error(NOT_CONFIRMED));
      const timer = setTimeout(fail, WAIT);
      const done = token => { clearTimeout(timer); typeof token === 'string' && token ? resolve(token) : fail(); };
      try {
        widget = turnstile.render(box, { sitekey: siteKey, action, appearance: 'interaction-only', theme: 'auto', size: 'flexible',
          'response-field': false, 'refresh-expired': 'never', retry: 'never',
          callback: done, 'error-callback': () => { clearTimeout(timer); fail(); return true; },
          'expired-callback': () => { clearTimeout(timer); fail(); }, 'timeout-callback': () => { clearTimeout(timer); fail(); },
          'unsupported-callback': () => { clearTimeout(timer); fail(); } });
      } catch { clearTimeout(timer); fail(); }
    });
  } finally {
    try { if (widget !== undefined) turnstile.remove(widget); } catch {}
    box.remove();
  }
}

/**
 * The page's own check at Start and Finish: true when Turnstile is off or the server confirms a fresh token for
 * `action`; false when it doesn't (show NOT_CONFIRMED). Never rejects.
 */
export async function confirmHuman(action) {
  let token;
  try { token = await humanToken(action); } catch { return false; }
  if (token === null) return true;
  const reply = await fetch('/api/turnstile/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, action }) }).then(r => r.json().catch(() => null), () => null);
  return reply?.ok === true;
}
