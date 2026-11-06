// A page's visit, and its links marked data-track="<step>" when they're followed (pages/track.mjs).
import { track } from '/track.js';

track('$pageview');
addEventListener('click', e => { const step = e.target.closest?.('[data-track]')?.dataset.track; if (step) track(step); });
// Session replays (pages/replay.mjs), once the page has settled.
(window.requestIdleCallback ?? setTimeout)(() => import('/write/replay.js').catch(() => {}), { timeout: 4000 });
