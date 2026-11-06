import test from 'node:test';
import assert from 'node:assert/strict';
import inspector from 'node:inspector';
import { automationSigns, automation, runtimeProbe, scriptedStack, watchAutomation, consoleReplaced } from '../write/automation.mjs';

// A browser's globals, as plain objects: navigator's attributes live on its prototype, as in browsers.
function browser({ nav = {}, chromium = true, win = {}, doc = {}, attributes = [] } = {}) {
  class Navigator {}
  Object.assign(Navigator.prototype, { webdriver: false, userAgent: 'Mozilla/5.0 Chrome/141.0.0.0 Safari/537.36' }, chromium ? { userAgentData: { brands: [{ brand: 'Google Chrome' }] } } : {}, nav);
  const document = Object.assign({ documentElement: { hasAttribute: name => attributes.includes(name) } }, doc);
  return Object.assign({ navigator: new Navigator(), document }, win);
}

test('a plain browser, and node itself, show no signs', () => {
  assert.deepEqual(automationSigns(browser()), []);
  assert.deepEqual(automationSigns(browser({ chromium: false, nav: { userAgent: 'Mozilla/5.0 Firefox/144.0' } })), []);
  assert.deepEqual(automationSigns(), []);
  assert.equal(automation(browser(), {}), null);
});

test('drivers are told by what they leave', () => {
  const sign = options => automationSigns(browser(options))[0];
  assert.equal(sign({ nav: { webdriver: true } }), 'the browser says it is automated');
  assert.equal(sign({ nav: { userAgent: 'Mozilla/5.0 HeadlessChrome/141.0.0.0' } }), 'the browser runs headless');
  assert.equal(sign({ win: { cdc_adoQpoasnfa76pfcZLmcfl_Array: Array } }), 'a driver left cdc_adoQpoasnfa76pfcZLmcfl_Array on the page');
  assert.equal(sign({ doc: { $cdc_asdjflasutopfhvcZLmcfl_: {} } }), 'a driver left $cdc_asdjflasutopfhvcZLmcfl_ on the page');
  assert.equal(sign({ win: { __playwright__binding__: () => {} } }), 'a driver left __playwright__binding__ on the page');
  assert.equal(sign({ win: { __pwInitScripts: {} } }), 'a driver left __pwInitScripts on the page');
  assert.equal(sign({ win: { callPhantom: () => {} } }), 'a driver left callPhantom on the page');
  assert.equal(sign({ doc: { __webdriver_evaluate: 1 } }), 'a driver left __webdriver_evaluate on the page');
  assert.equal(sign({ attributes: ['webdriver'] }), 'a driver left webdriver on the page');
  // Stealth plugins: navigator.webdriver deleted from a Chromium, or shadowed on the navigator itself.
  const deleted = browser(); delete Object.getPrototypeOf(deleted.navigator).webdriver;
  assert.equal(automationSigns(deleted)[0], 'the browser hides that it is automated');
  const shadowed = browser(); Object.defineProperty(shadowed.navigator, 'webdriver', { get: () => false });
  assert.equal(automationSigns(shadowed)[0], 'the browser hides that it is automated');
  // Firefox and Safari have no userAgentData, so a missing webdriver says nothing there.
  const old = browser({ chromium: false }); delete Object.getPrototypeOf(old.navigator).webdriver;
  assert.deepEqual(automationSigns(old), []);
  assert.deepEqual(automation(browser({ nav: { webdriver: true } }), {}), { kind: 'controlled', reason: 'the browser says it is automated' });
});

test('a console whose methods were replaced is a sign, as it hides the DevTools probe', () => {
  assert.equal(consoleReplaced({ console }), false);
  const original = console.groupEnd;
  const wrapped = { console: Object.assign(Object.create(console), { groupEnd: (...a) => original.apply(console, a) }) };
  assert.equal(consoleReplaced(wrapped), true);
  assert.equal(automationSigns(browser({ win: wrapped })).at(-1), 'the browser’s console was replaced (turn off extensions that change it)');
  assert.deepEqual(automationSigns(browser({ win: { console } })), []);
});

test('stacks through a driver’s evaluated scripts', () => {
  assert.ok(scriptedStack('Error\n    at check (https://huma.social/write/editor.js:1:2)\n    at pptr:evaluate;foo:3:5'));
  assert.ok(scriptedStack('Error\n    at __puppeteer_evaluation_script__:3:5'));
  assert.ok(scriptedStack('Error\n    at eval (__playwright_evaluation_script__:1:1)'));
  assert.equal(scriptedStack(), false);
});

// The probe against this V8's own inspector: nothing reads the baits until a session enables the Runtime domain.
test('the Runtime probe fires only while a DevTools session listens', () => {
  const con = inspector.console;
  assert.equal(runtimeProbe(con), false);
  const session = new inspector.Session(); session.connect();
  try {
    session.post('Runtime.enable');
    assert.equal(runtimeProbe(con), true);
    assert.deepEqual(automation(browser(), con), { kind: 'devtools', reason: 'developer tools are open' });
    session.post('Runtime.disable');
    assert.equal(runtimeProbe(con), false);
  } finally { session.disconnect(); }
  // A console someone wrapped can't set it off.
  assert.equal(runtimeProbe({ groupEnd: (...args) => args.forEach(a => a.stack) }), false);
});

test('watching reports DevTools opening and closing, and a driver once', async () => {
  const win = browser(), calls = [], session = new inspector.Session(); session.connect();
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const stop = watchAutomation((kind, reason) => calls.push([kind, reason]), { every: 5, win, con: inspector.console });
  try {
    await wait(20); assert.deepEqual(calls, []);
    session.post('Runtime.enable'); await wait(20);
    session.post('Runtime.disable'); await wait(20);
    assert.deepEqual(calls, [['devtools', 'developer tools are open'], ['clear', '']]);
    Object.getPrototypeOf(win.navigator).webdriver = true; await wait(20);
    win.cdc_x = 1; await wait(20);
    assert.deepEqual(calls.at(-1), ['controlled', 'the browser says it is automated']);
    assert.equal(calls.length, 3);
  } finally { stop(); session.disconnect(); }
});
