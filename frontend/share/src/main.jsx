import React, { lazy, Suspense, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './share.css';
import Skeleton from './Skeleton.jsx';
// Privy sign-in and sharing (Approval.jsx), off for now: World ID signs in instead.
// const Approval = lazy(() => import('./Approval.jsx'));
const WorldSignIn = lazy(() => import('./WorldSignIn.jsx'));
const id = location.pathname.match(/^\/share\/([a-f0-9]{64})$/)?.[1];
const signIn = location.pathname === '/share/signin';
// Google and Apple sign-in leave the page and come back without the #fragment, so keep it for this tab.
const secret = (() => {
  const key = 'huma-share:' + (id ?? 'signin'), fromLink = location.hash.slice(1);
  try { if (fromLink) sessionStorage.setItem(key, fromLink); return fromLink || sessionStorage.getItem(key) || ''; }
  catch { return fromLink; }
})();
document.title = signIn ? 'Sign in · Huma' : 'Share · Huma';
// Opened from Huma on the web (/write), not the Mac app: the link goes back to that tab, not to huma://.
const fromWeb = (() => {
  const key = 'huma-share-web:' + id;
  try { if (new URLSearchParams(location.search).has('web')) sessionStorage.setItem(key, '1'); return sessionStorage.getItem(key) === '1'; }
  catch { return new URLSearchParams(location.search).has('web'); }
})();
// Where /write asked to come back to once signed in (a document, Your Documents, or a writer page's option), kept for
// this tab across sign-in's redirects. Only those /write addresses, so the link can't send anyone elsewhere.
const returnTo = (() => {
  const valid = value => (/^\/write(\?(pages|page=[a-f0-9]{20}|shared=[A-Za-z0-9_-]{4,32}&do=(rename|download|hide|delete)))?$/.test(value ?? '') ? value : null);
  try {
    const asked = valid(new URLSearchParams(location.search).get('return'));
    if (asked) sessionStorage.setItem('huma-share-return', asked);
    return valid(sessionStorage.getItem('huma-share-return'));
  } catch { return valid(new URLSearchParams(location.search).get('return')); }
})();

function App() {
  const [data, setData] = useState(null), [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController(), get = (path, headers) => fetch(path, { headers, signal: controller.signal, redirect: 'error' });
    async function load() {
      if (signIn) {
        const response = await get('/api/worldid');
        const world = response.ok ? await response.json() : {};
        if (!world.appId) throw new Error('Sign-in is not set up on this host yet.');
        setData({ world }); return;
      }
      // Sharing from this page took a Privy sign-in (off for now). A Mac signed in with World ID shares by itself.
      throw new Error('Sign in with World ID in Huma, then press Share there again.');
      // if (!id || !/^[a-f0-9]{64}$/.test(secret)) throw new Error('Press Share in Huma to open this page.');
      // const responses = await Promise.all([get('/api/publications/pending/' + id, { Authorization: 'Bearer ' + secret }), get('/api/publication-config')]);
      // if (responses.some(r => !r.ok)) throw new Error('This share request ran out of time. Press Share in Huma again.');
      // const [pending, config] = await Promise.all(responses.map(r => r.json()));
      // if (!config.privyAppId) throw new Error('Sign-in is not set up on this host yet.');
      // setData({ pending, config });
    }
    load().catch(e => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, []);
  const loading = <Skeleton />;
  return <>
    <nav className="nav" aria-label="Main">
      <div className="nav_blur" aria-hidden="true"><i /><i /><i /><i /><i /></div>
      <a className="nav_logo" href="/" aria-label="Huma home"><span className="logo-mark" aria-hidden="true" /><span>Huma</span></a>
    </nav>
    <main><div className="card">
      {error ? <><h1>{signIn ? 'Sign in to Huma.' : 'Share your writing.'}</h1><p role="alert">{error}</p></>
        : data ? <Suspense fallback={loading}><WorldSignIn secret={secret} fromWeb={fromWeb} returnTo={returnTo} {...data} /></Suspense> : loading}
        {/* Privy: <Approval id={id} secret={secret} signIn={signIn} fromWeb={fromWeb} returnTo={returnTo} {...data} /> */}
    </div></main>
    <footer className="footer compact">
      <div className="footer_bar mono">
        <a className="footer_mini" href="/" aria-label="Huma home"><span className="logo-mark" aria-hidden="true" /><span>Huma</span></a>
        <nav aria-label="Footer"><a href="/#story">Why</a><a href="/download">Huma App</a><a href="/verify">Verify a link</a><a href="/ask">Ask for a link</a><a href="/deck/">Research</a><a href="/privacy">Privacy</a><a href="https://x.com/huma_social" target="_blank" rel="me noopener" aria-label="Huma on X">@huma_social</a></nav>
        <span className="footer_note">The human-first internet.</span>
      </div>
    </footer>
  </>;
}
createRoot(document.getElementById('root')).render(<App />);
