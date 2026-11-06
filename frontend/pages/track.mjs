// Counting where visitors stop: a few named steps go to huma.social/api/events (events.mjs), which passes them on to
// PostHog. Never any text, title or link: the step's name, the page's path, where the visitor came from (the site's
// name only) and a random number this browser keeps. Nothing is sent with Global Privacy Control or Do Not Track on.
const KEY = 'huma.visitor';
const off = navigator.globalPrivacyControl === true || navigator.doNotTrack === '1';
export const trackingOff = off;
let visitor = null;
/** This browser's random number, made the first time it's asked for. */
export function visitorId() {
  if (visitor) return visitor;
  try { visitor = localStorage.getItem(KEY); } catch {}
  if (!/^[a-f0-9]{32}$/.test(visitor ?? '')) {
    visitor = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    try { localStorage.setItem(KEY, visitor); } catch {}
  }
  return visitor;
}
function from() {
  try { const host = new URL(document.referrer).hostname; return host && host !== location.hostname ? host : undefined; } catch { return undefined; }
}
/** Sends one step, with what it allows (reason, score, format, ms, cores); never waits and never fails. */
export function track(event, details = {}) {
  if (off) return;
  try {
    const body = JSON.stringify({ ...details, event, id: visitorId(), path: location.pathname, referrer: from() });
    if (!navigator.sendBeacon?.('/api/events', new Blob([body], { type: 'application/json' })))
      fetch('/api/events', { method: 'POST', body, headers: { 'Content-Type': 'application/json' }, keepalive: true }).catch(() => {});
  } catch {}
}
