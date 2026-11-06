import test from 'node:test';
import assert from 'node:assert/strict';
import { configuredEvents, eventFrom, eventPath, eventRoutes } from '../events.mjs';

const id = 'a'.repeat(32), mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
const req = (ip = '203.0.113.9') => ({ headers: { 'user-agent': mac }, socket: { remoteAddress: ip } });

test('paths keep no handle, code or page id', () => {
  assert.equal(eventPath('/write'), '/write');
  assert.equal(eventPath('/@swayam'), '/@writer');
  assert.equal(eventPath('/p/Ab3xY'), '/p/page');
  assert.equal(eventPath('/original/' + 'f'.repeat(64)), '/original/page');
  assert.equal(eventPath('/write/secret'), '/other');
});

test('an event keeps only what it is allowed to', () => {
  const event = eventFrom({ event: 'page_proved', id, path: '/write', score: 87, title: 'My letter', text: 'Dear…', referrer: 'x.com', $ip: '1.2.3.4' }, mac);
  assert.deepEqual(Object.keys(event.properties).sort(), ['$browser', '$current_url', '$geoip_disable', '$lib', '$os', '$pathname', '$process_person_profile', '$referring_domain', 'score'].sort());
  assert.equal(event.properties.$os, 'Mac OS X'); assert.equal(event.properties.$browser, 'Safari');
  assert.equal(eventFrom({ event: 'anything', id, path: '/' }, mac), null);
  assert.equal(eventFrom({ event: '$pageview', id: 'short', path: '/' }, mac), null);
  assert.equal(eventFrom({ event: 'document_downloaded', id, format: 'exe' }, mac).properties.format, undefined);
  assert.deepEqual([eventFrom({ event: 'page_proved', id, ms: 7300, cores: 16 }, mac).properties.ms, eventFrom({ event: 'page_proved', id, ms: -1, cores: 1.5 }, mac).properties.cores], [7300, undefined]);
});

test('events go to PostHog in a batch, with the key, only when one is set', async () => {
  const sent = [], send = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response(''); };
  const off = configuredEvents({}, { fetch: send });
  assert.equal(off.enabled, false);
  assert.equal(off.add(req(), { event: '$pageview', id, path: '/' }), true);
  await off.flush(); assert.equal(sent.length, 0);
  const on = configuredEvents({ POSTHOG_KEY: 'phc_' + 'k'.repeat(40), POSTHOG_HOST: 'https://eu.i.posthog.com/' }, { fetch: send });
  on.add(req(), { event: '$pageview', id, path: '/' }); on.add(req(), { event: 'recording_started', id, path: '/write' });
  await on.flush();
  assert.equal(sent.length, 1); assert.equal(sent[0].url, 'https://eu.i.posthog.com/batch/');
  assert.equal(sent[0].body.api_key, 'phc_' + 'k'.repeat(40));
  assert.deepEqual(sent[0].body.batch.map(e => e.event), ['$pageview', 'recording_started']);
});

test('one client may send 120 events a minute', async () => {
  const sent = [], on = configuredEvents({ POSTHOG_KEY: 'phc_' + 'k'.repeat(40) }, { fetch: async (_, init) => { sent.push(...JSON.parse(init.body).batch); }, now: () => 0 });
  for (let i = 0; i < 130; i++) on.add(req(), { event: '$pageview', id, path: '/' });
  on.add(req('203.0.113.10'), { event: '$pageview', id, path: '/' });
  await on.flush();
  assert.equal(sent.length, 121);
});

test('/api/events answers 204, and 400 for anything else', async () => {
  const route = eventRoutes(configuredEvents({}));
  const call = async (method, body) => {
    const request = Object.assign((async function* () { if (body) yield Buffer.from(body); })(), { method, ...req() });
    let status; const res = { writeHead: s => { status = s; }, end() {} };
    const handled = await route(request, res, '/api/events', { json: (_, s) => { status = s; } });
    return handled && status;
  };
  assert.equal(await call('POST', JSON.stringify({ event: '$pageview', id, path: '/' })), 204);
  assert.equal(await call('POST', JSON.stringify({ event: 'nope', id })), 400);
  assert.equal(await call('POST', 'x'.repeat(3000)), 413);
  assert.equal(await call('GET'), 405);
  assert.equal(await route({}, {}, '/api/other', {}), false);
});

test('replays go to PostHog through /ph/, without the visitor’s address or cookies', async () => {
  const key = 'phc_' + 'k'.repeat(40), sent = [];
  const send = async (url, init) => { sent.push({ url, init }); return new Response('{"ok":1}', { status: 200, headers: { 'Content-Type': 'application/json' } }); };
  const route = eventRoutes(configuredEvents({ POSTHOG_KEY: key }, { fetch: send }));
  const call = async (method, pathname, body, url = pathname) => {
    const request = Object.assign((async function* () { if (body) yield Buffer.from(body); })(), { method, url,
      headers: { 'user-agent': mac, 'content-type': 'text/plain', cookie: 'secret=1', 'x-forwarded-for': '198.51.100.7' }, socket: { remoteAddress: '203.0.113.9' } });
    let status, sentBody; const res = { writeHead: s => { status = s; }, end: b => { sentBody = b; } };
    await route(request, res, pathname, { json: (_, s, b) => { status = s; sentBody = b; } });
    return { status, body: sentBody };
  };
  assert.deepEqual((await call('GET', '/api/replay')).body, { key });
  assert.equal((await call('POST', '/ph/s/', 'snapshot', '/ph/s/?compression=gzip-js')).status, 200);
  assert.equal(sent[0].url, 'https://us.i.posthog.com/s/?compression=gzip-js');
  assert.deepEqual(Object.keys(sent[0].init.headers).sort(), ['Content-Type', 'User-Agent']);
  assert.equal((await call('GET', `/ph/array/${key}/config`)).status, 200);
  assert.equal(sent[1].url, `https://us-assets.i.posthog.com/array/${key}/config`);
  assert.equal((await call('GET', '/ph/api/projects/')).status, 404);
  assert.equal((await call('PUT', '/ph/s/')).status, 405);
  assert.equal(sent.length, 2);
  const off = eventRoutes(configuredEvents({}, { fetch: send }));
  let status; await off({ method: 'GET', headers: {} }, {}, '/api/replay', { json: (_, s) => { status = s; } });
  assert.equal(status, 404);
});
