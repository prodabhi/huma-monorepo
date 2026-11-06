// Software driving the browser, told from what it leaves behind: 'controlled' when a driver says so or leaves its own
// globals (webdriver, ChromeDriver, Playwright, Puppeteer, Selenium, PhantomJS, Nightmare), 'devtools' when something
// is listening to the page's JavaScript through the DevTools protocol, as Puppeteer and Playwright do by default, but
// as DevTools does too, open in front of a person. Each check is cheap and synchronous, and none of them fires in a
// plain Chrome, Edge, Firefox or Safari. A careful driver hides all of them; the typing checks are what remain then.

// Globals drivers have been seen to leave on the page (window or document): Playwright's binding and init scripts,
// PhantomJS, Nightmare, Chrome's DOM automation, and the Selenium and old WebDriver bridges.
const GLOBALS = ['__playwright__binding__', '__pwInitScripts', 'callPhantom', '_phantom', '__nightmare', 'domAutomation',
  'domAutomationController', '_selenium', 'callSelenium', '_Selenium_IDE_Recorder', '__webdriver_evaluate', '__selenium_evaluate',
  '__webdriver_script_function', '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate', '__driver_unwrapped',
  '__webdriver_unwrapped', '__driver_evaluate', '__selenium_unwrapped', '__fxdriver_unwrapped'];
// ChromeDriver's helpers (window.cdc_…_Array, document.$cdc_…), and an old WebDriver's.
const DRIVER_KEY = /^\$?cdc_|^\$wdc_/;
// Scripts a driver evaluates are named so in stacks (Puppeteer, older and newer; Playwright).
const EVALUATED = /__puppeteer_evaluation_script__|pptr:|__playwright_evaluation_script__/;

const own = target => { try { return target ? Object.keys(target) : []; } catch { return []; } };
const has = (target, name) => { try { return !!target && name in target; } catch { return false; } };
const native = f => { try { return typeof f === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(f)); } catch { return false; } };

/** Why this browser looks driven by software (empty when it doesn't): definite signs only, never DevTools alone. */
export function automationSigns(win = globalThis) {
  const nav = win.navigator, doc = win.document, signs = [];
  // Set by --enable-automation, --headless and ChromeDriver; by Marionette in Firefox, and safaridriver in Safari.
  if (nav?.webdriver === true) signs.push('the browser says it is automated');
  // Chromium has had navigator.webdriver since 63 and userAgentData since 90: one without the other was removed, as
  // stealth plugins do; and only a driver puts its own on the navigator.
  else if (nav && (nav.userAgentData && !has(nav, 'webdriver') || Object.hasOwn(nav, 'webdriver'))) signs.push('the browser hides that it is automated');
  if (/HeadlessChrome/.test(nav?.userAgent ?? '') || nav?.userAgentData?.brands?.some(b => /Headless/.test(b.brand))) signs.push('the browser runs headless');
  const left = GLOBALS.find(name => has(win, name) || has(doc, name))
    ?? [...own(win), ...own(doc)].find(key => DRIVER_KEY.test(key))
    ?? ['webdriver', 'selenium', 'driver'].find(name => { try { return doc?.documentElement?.hasAttribute(name); } catch { return false; } });
  if (left) signs.push(`a driver left ${left} on the page`);
  return signs;
}

/** Whether a stack (by default, the caller's) runs through a script a driver evaluated in the page. */
export const scriptedStack = (stack = new Error().stack) => EVALUATED.test(stack ?? '');

/**
 * Whether something listens to this page through the DevTools protocol's Runtime domain: DevTools, open, or a driver
 * on CDP. With the domain on, every console call is turned into a preview, which reads the arguments; otherwise
 * nothing reads them. console.groupEnd shows nothing, open or closed. Three baits, since V8 has closed one already:
 * an error's own `stack` getter (V8 before mid-2025 only), one it inherits, and a Proxy behind an object, whose keys
 * the preview lists. Skipped (false) when console.groupEnd isn't the browser's own, so a wrapper can't set it off.
 */
export function runtimeProbe(con = globalThis.console) {
  const end = con?.groupEnd;
  if (!native(end)) return false;
  let read = false;
  const bait = () => { read = true; return ''; };
  try {
    const ownStack = new Error();
    Object.defineProperty(ownStack, 'stack', { configurable: true, get: bait });
    const inherited = new Error();
    delete inherited.stack;
    Object.setPrototypeOf(inherited, Object.create(Error.prototype, { stack: { get: bait } }));
    const behind = Object.create(new Proxy({}, { ownKeys: () => (bait(), []) }));
    end.call(con, ownStack, inherited, behind);
  } catch { /* a browser that refuses one of the baits */ }
  return read;
}

/** What the browser looks like right now: 'controlled' with a reason, 'devtools', or null. */
export function automation(win = globalThis, con = win.console) {
  const [sign] = automationSigns(win);
  return sign ? { kind: 'controlled', reason: sign } : runtimeProbe(con) ? { kind: 'devtools', reason: 'developer tools are open' } : null;
}

/**
 * Checks now, every `every` ms and when the window gets focus. `on(kind, reason)`: 'controlled' once (watching then
 * ends), 'devtools' when DevTools opens and 'clear' when it closes. Returns a function that stops watching.
 */
export function watchAutomation(on, { every = 2000, win = globalThis, con = win.console } = {}) {
  let open = false, done = false, timer = 0;
  const stop = () => { done = true; clearInterval(timer); win.removeEventListener?.('focus', check); };
  function check() {
    if (done) return;
    const [sign] = automationSigns(win);
    if (sign) { stop(); on('controlled', sign); return; }
    if (runtimeProbe(con) === open) return;
    open = !open; on(open ? 'devtools' : 'clear', open ? 'developer tools are open' : '');
  }
  timer = setInterval(check, every);
  win.addEventListener?.('focus', check);
  check();
  return stop;
}
