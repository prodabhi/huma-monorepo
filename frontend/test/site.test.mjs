import test from 'node:test';
import assert from 'node:assert/strict';
import { siteURL, DEFAULT_SITE_URL } from '../site.mjs';
import { configuredEvents, eventFrom } from '../events.mjs';

test('HUMA_SITE_URL sets the site, as a bare origin; unset, it is huma.social', () => {
  assert.equal(siteURL({}), DEFAULT_SITE_URL);
  assert.equal(siteURL({ HUMA_SITE_URL: '  ' }), DEFAULT_SITE_URL);
  assert.equal(siteURL({ HUMA_SITE_URL: 'https://staging.example' }), 'https://staging.example');
  assert.equal(siteURL({ HUMA_SITE_URL: 'https://staging.example/' }), 'https://staging.example');
  assert.equal(siteURL({ HUMA_SITE_URL: 'http://127.0.0.1:4318' }), 'http://127.0.0.1:4318');
  for (const bad of ['staging.example', 'ftp://staging.example', 'https://staging.example/app', 'https://u:p@staging.example', 'https://staging.example/?x=1', 'https://staging.example/#x'])
    assert.throws(() => siteURL({ HUMA_SITE_URL: bad }), /HUMA_SITE_URL/, bad);
});

test('events carry the configured site in their URL', async () => {
  const id = 'a'.repeat(32);
  assert.equal(eventFrom({ event: 'page_proved', id, path: '/write' }, '').properties.$current_url, 'https://huma.social/write');
  assert.equal(eventFrom({ event: 'page_proved', id, path: '/write' }, '', 'https://staging.example').properties.$current_url, 'https://staging.example/write');
  const sent = [], events = configuredEvents({ POSTHOG_KEY: 'phc_' + 'k'.repeat(40), HUMA_SITE_URL: 'https://staging.example' }, { fetch: async (_, init) => { sent.push(...JSON.parse(init.body).batch); }, now: () => 0 });
  events.add({ headers: {}, socket: { remoteAddress: '1.2.3.4' } }, { event: 'page_proved', id, path: '/write' });
  await events.flush();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].properties.$current_url, 'https://staging.example/write');
});
