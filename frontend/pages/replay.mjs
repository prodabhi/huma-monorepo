// Session replays, to see where visitors get stuck: clicks, scrolling and the screens they open, with every word on the
// page and in its fields hidden (shown as stars). Sent through this site (/ph/, events.mjs), so PostHog never sees a
// visitor's address, under the same random number as the visitor's steps (pages/track.mjs). Nothing is recorded with
// Global Privacy Control or Do Not Track on, on a shared page (its link holds the key that opens it), or when the site
// has no PostHog key. Built into /write/replay.js (write/build.mjs) and loaded once the page is idle.
import posthog from 'posthog-js/dist/module.no-external';
// The recorder and the part that starts it (PostHog 1.2xx+ needs both; dist/recorder alone only loads rrweb, so nothing
// was ever recorded).
import 'posthog-js/dist/posthog-recorder';
import { visitorId, trackingOff } from './track.mjs';

async function start() {
  if (trackingOff || location.hash || /^\/(p|original)\//.test(location.pathname)) return;
  const config = await fetch('/api/replay').then(r => (r.ok ? r.json() : null)).catch(() => null);
  if (!/^phc_[A-Za-z0-9_-]{20,80}$/.test(config?.key ?? '')) return;
  posthog.init(config.key, {
    api_host: location.origin + '/ph', persistence: 'localStorage', person_profiles: 'identified_only',
    bootstrap: { distinctID: visitorId() }, disable_external_dependency_loading: true, respect_dnt: true,
    // Replays only: PostHog's own page views, clicks, timings, surveys and error reports stay off (pages/track.mjs counts steps).
    autocapture: false, capture_pageview: false, capture_pageleave: false, capture_dead_clicks: false, capture_performance: false,
    capture_exceptions: false, disable_surveys: true, enable_heatmaps: false, advanced_disable_toolbar_metrics: true,
    enable_recording_console_log: false,
    session_recording: { maskAllInputs: true, maskTextSelector: '*', recordHeaders: false, recordBody: false, recordCrossOriginIframes: false },
  });
}
start().catch(() => {});
