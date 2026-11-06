import React, { useEffect, useRef, useState } from 'react';
import { accountSignal, deviceCode } from '../../publication-contract.mjs';
import Skeleton from './Skeleton.jsx';

// Signing in the Mac app with World ID, in place of Privy (Approval.jsx, off for now). Huma opens this page with a
// secret code and this Mac's publishing key. The person checks the code here matches the one Huma shows, then proves
// with World App that one real, unique person is signing in. The proof is made for this Mac's key, so it can link no
// other; the server checks it with World and links the key to that World ID's account (publications.mjs), which Huma
// reads back with the code. Readers then see the same anonymous World ID on every page the account shares.
const WAIT = 5 * 60 * 1000;
const DECLINED = new Set(['user_rejected', 'verification_rejected', 'user_presence_failed']);
const Check = () => <div className="done"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.2"
  strokeLinecap="round" strokeLinejoin="round"><path d="M4.5 10.5l3.5 3.5 7.5-8" /></svg></div>;

/** The QR for `uri` as one SVG path (qr.mjs is the site's own copy, loaded when it's wanted). */
async function qrPath(uri) {
  const { default: encodeQR } = await import(/* @vite-ignore */ new URL('/vendor/qr/qr.mjs', location.origin).href);
  const rows = encodeQR(uri, 'raw', { ecc: 'medium', border: 0 });
  let path = '';
  rows.forEach((row, y) => row.forEach((on, x) => { if (on) path += `M${x} ${y}h1v1h-1z`; }));
  return { size: rows.length, path };
}

export default function WorldSignIn({ secret, world }) {
  const [code, publicKey] = secret.split('.');
  const fromApp = /^[a-f0-9]{64}$/.test(code), device = /^04[0-9a-f]{128}$/.test(publicKey ?? '') ? publicKey : null;
  const [shortCode, setShortCode] = useState(''), [state, setState] = useState(''), [error, setError] = useState('');
  const [qr, setQR] = useState(null), [link, setLink] = useState('');
  const cancel = useRef(null);
  useEffect(() => { if (device) deviceCode(device).then(setShortCode); }, [device]);
  useEffect(() => () => cancel.current?.abort(), []);

  async function verify() {
    const controller = new AbortController(), { signal } = controller;
    cancel.current = controller; setState('waiting'); setError(''); setQR(null); setLink('');
    const timer = setTimeout(() => controller.abort(), WAIT);
    try {
      const { rp_context } = await fetch('/api/worldid/context', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal })
        .then(r => (r.ok ? r.json() : Promise.reject(new Error('World ID couldn’t be reached.'))));
      const { IDKit, proofOfHuman } = await import('@worldcoin/idkit-core');
      const request = await IDKit.request({ app_id: world.appId, action: world.action, rp_context, allow_legacy_proofs: true,
        environment: world.environment }).preset(proofOfHuman({ signal: accountSignal(device) }));
      setQR(await qrPath(request.connectorURI)); setLink(request.connectorURI);
      const done = await request.pollUntilCompletion({ signal, timeout: WAIT });
      if (!done.success) throw new Error(DECLINED.has(done.error) ? 'World ID was declined.' : done.error === 'timed_out' ? 'World ID ran out of time.' : 'World ID couldn’t be confirmed.');
      setState('checking');
      const response = await fetch('/api/publications/signin', { method: 'POST', redirect: 'error', signal,
        headers: { 'X-Huma-Signin': code, 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: device, worldId: done.result }) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error ?? 'Signing in didn’t finish. Start again from Huma.');
      setState('sent');
      location.href = 'huma://signed-in'; // Back to the app; the first time, the browser asks whether to open Huma.
    } catch (e) {
      setState(''); setQR(null);
      setError(signal.aborted ? 'World ID wasn’t completed. Try again.' : e.message || 'World ID couldn’t be confirmed.');
    } finally { clearTimeout(timer); }
  }

  if (!fromApp || !device) return <>
    <h1>Sign in to Huma.</h1>
    <p role="alert">Press Sign In in the Huma app to open this page. On the web, sign in from the page you’re writing on.</p>
  </>;
  if (state === 'sent') return <>
    <Check />
    <h1>You're signed in.</h1>
    <p>Huma is open again. You can close this tab.</p>
    <a className="button secondary" href="huma://signed-in">Open Huma</a>
  </>;
  if (!shortCode) return <Skeleton label="Loading sign-in…" />;
  return <>
    <h1>Sign in with World ID.</h1>
    <p>Huma is for real people. Check that Huma shows this code:</p>
    <p className="code" aria-label="Mac code">{shortCode}</p>
    <p className="small">If Huma shows a different code, or you didn't just press Sign In in Huma, close this tab.</p>
    {qr ? <>
      <p>Scan this with World App. It shows one real, unique person is signing in, never who you are.</p>
      <div className="worldid-qr" role="img" aria-label="World ID QR code">
        <svg viewBox={`0 0 ${qr.size} ${qr.size}`} shapeRendering="crispEdges" aria-hidden="true"><path fill="currentColor" d={qr.path} /></svg>
      </div>
      <p role="status" className="small">{state === 'checking' ? 'Checking your World ID…' : 'Waiting for World App…'}</p>
      {link ? <p><a href={link} target="_blank" rel="noopener noreferrer">Open World App →</a></p> : null}
      <button className="button secondary" onClick={() => cancel.current?.abort()}>Cancel</button>
    </> : <button className="button" disabled={state !== ''} onClick={verify}>{state ? 'Getting a request ready…' : 'Sign In with World ID'}</button>}
    {error ? <p role="alert">{error}</p> : null}
    <p className="small">Every page you share will show the same anonymous World ID, so you can show they’re yours.</p>
  </>;
}
