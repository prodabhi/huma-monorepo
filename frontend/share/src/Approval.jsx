import React, { useEffect, useRef, useState } from 'react';
import { PrivyProvider, usePrivy, useWallets, useSignMessage } from '@privy-io/react-auth';
import { publicationMessage, deviceAuthorizationMessage, deviceCode, SIGNIN_PENDING } from '../../publication-contract.mjs';
import Skeleton from './Skeleton.jsx';

const safePath = path => typeof path === 'string' && /^\/original\/[a-f0-9]{64}(?:#[a-f0-9]{64})?$/.test(path);
/** The account a person signed in with, for display only. */
const accountName = user => user?.email?.address ?? user?.google?.email ?? user?.apple?.email ?? user?.github?.username
  ?? user?.twitter?.username ?? user?.discord?.username ?? user?.linkedin?.email ?? 'your account';
const Check = () => <div className="done"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.2"
  strokeLinecap="round" strokeLinejoin="round"><path d="M4.5 10.5l3.5 3.5 7.5-8" /></svg></div>;

function Who({ user, label }) {
  const { logout } = usePrivy();
  return <div className="who"><span>{label} {accountName(user)}</span>
    <a href="#" onClick={e => { e.preventDefault(); logout(); }}>Sign out</a></div>;
}

function Publication({ id, secret: ticket, pending, fromWeb }) {
  const { ready, authenticated, login, getAccessToken, user } = usePrivy();
  const { wallets } = useWallets(), { signMessage } = useSignMessage();
  const wallet = wallets.find(w => w.walletClientType === 'privy')?.address;
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [result, setResult] = useState(pending.path);

  /** Your account's wallet signs this exact statement and master (free, no transaction), then the page is stored. */
  async function approve() {
    setBusy(true); setError('');
    try {
      const token = await getAccessToken();
      if (!token) throw new Error('Sign in first.');
      if (!wallet) throw new Error('Your account is still being set up. Try again in a moment.');
      const { signature } = await signMessage({ message: publicationMessage(pending.manifest) }, { address: wallet, uiOptions: { showWalletUIs: false } }); // after the Share click
      const response = await fetch('/api/publications/pending/' + id + '/publish', { method: 'POST', redirect: 'error',
        headers: { Authorization: 'Bearer ' + token, 'X-Huma-Ticket': ticket, 'Content-Type': 'application/json' },
        body: JSON.stringify({ wallet, signature }) });
      if (response.status === 429) throw new Error("You've shared the most pages for today. Try again tomorrow.");
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error ?? "Sharing didn't finish. Your page in Huma is unchanged.");
      if (!safePath(data.path)) throw new Error('Invalid sharing response.');
      setResult(data.path);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  // Sharing always takes a click here, so a link someone else sends can't publish as you.
  const returned = useRef(false);
  useEffect(() => {
    if (!result || pending.path || returned.current) return;
    returned.current = true;
    // The writing page on the web keeps the link; the Mac app is told through its own link.
    if (fromWeb) { try { new BroadcastChannel('huma-shared').postMessage({ id, path: result }); } catch {} }
    else location.href = 'huma://shared';
  }, [result]);
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard.writeText(new URL(result, location.origin).href).then(() => setCopied(true), () => {});

  if (result) return <>
    <Check />
    <h1>Your link is ready.</h1>
    <p>Anyone with this link can read your page and check you wrote it.{fromWeb ? ' Your page in Huma has the link too.' : ' Huma has the link too. You can close this tab.'}</p>
    <button className="button" onClick={copy}>{copied ? 'Copied' : 'Copy Link'}</button>
    <p><a href={result}>Open your link →</a></p>
  </>;

  return <>
    <h1>Share your writing.</h1>
    <p>Anyone with the link can see you wrote it.</p>
    {pending.text !== undefined ? <><div className="label">Your text</div><pre>{pending.text}</pre></> : null}
    {!ready ? <p role="status" className="small">Loading sign-in…</p>
      : !authenticated ? <button className="button" onClick={login}>Sign In to Share</button>
      : busy || !wallet ? <p role="status" className="small">{busy ? 'Sharing…' : 'Setting up your account…'}</p>
      : <>
          <Who user={user} label="Sharing as" />
          <button className="button" disabled={busy || !wallet} onClick={approve}>{busy ? 'Sharing…' : !wallet ? 'Setting up your account…' : 'Share'}</button>
        </>}
    {error ? <p role="alert">{error}</p> : null}
  </>;
}

/** Opened from Huma with a secret code and this Mac's publishing key. The person checks that the code here matches
 *  the one Huma shows and clicks Link; only then does the wallet authorize that key, so Finish can share without
 *  the browser. A link someone else sends shows a code that won't match their Huma. */
function SignIn({ secret, fromWeb, returnTo }) {
  const { ready, authenticated, login, getAccessToken, user } = usePrivy();
  const { wallets } = useWallets(), { signMessage } = useSignMessage(), wallet = wallets.find(w => w.walletClientType === 'privy')?.address;
  const [state, setState] = useState(''), [shortCode, setShortCode] = useState(''), sent = useRef(false);
  const [code, publicKey] = secret.split('.');
  const fromApp = /^[a-f0-9]{64}$/.test(code), device = /^04[0-9a-f]{128}$/.test(publicKey ?? '') ? publicKey : null;
  // Huma on the web started this sign-in in this browser (it keeps the code here, on the same site), so its key links
  // with no code to compare; a link that started anywhere else is refused, so nobody can link their key to your account.
  const ownRequest = (() => { try { return fromWeb && fromApp && localStorage.getItem(SIGNIN_PENDING) === code; } catch { return false; } })();
  useEffect(() => { if (device) deviceCode(device).then(setShortCode); }, [device]);
  async function link() {
    if (sent.current) return;
    sent.current = true; setState('sending');
    try {
      const token = await getAccessToken();
      const body = device ? { wallet, publicKey: device, signature: (await signMessage({ message: deviceAuthorizationMessage(wallet, device) },
        { address: wallet, uiOptions: { showWalletUIs: false } })).signature } : {};
      const response = await fetch('/api/publications/signin', { method: 'POST', redirect: 'error',
        headers: { Authorization: 'Bearer ' + token, 'X-Huma-Signin': code, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error();
      setState('sent');
      if (fromWeb) {
        // Straight back to the document; a sign-in window opened while writing closes itself.
        if (returnTo) { location.replace(returnTo); return; }
        // A sign-in window closes itself; a tab that isn't one (a script can't close it) goes to Your Documents instead.
        window.close(); setTimeout(() => location.replace('/write?pages'), 600);
      } else location.href = 'huma://signed-in'; // Back to the app; the first time, the browser asks whether to open Huma.
    } catch { sent.current = false; setState('error'); }
  }
  useEffect(() => { if (ownRequest && authenticated && wallet && device && !sent.current) link(); }, [ownRequest, authenticated, wallet, device]);

  if (!ready) return <Skeleton label="Loading sign-in…" />;
  if (fromWeb && !ownRequest && state !== 'sent') return <>
    <h1>Sign in to Huma.</h1>
    <p role="alert">This sign-in didn’t start in this browser. Close this tab, and sign in from Huma.</p>
  </>;
  if (!authenticated) return <>
    <h1>Sign in to Huma.</h1>
    <p>{fromWeb ? 'Your documents are kept in your account, so they open on any device.' : 'To get your links, sign in with Google, Apple or email.'}</p>
    <button className="button" onClick={login}>Sign In</button>
    <p className="small">You don't need crypto or money.</p>
  </>;
  if (fromWeb && state !== 'sent') return <>
    <h1>Signing you in…</h1>
    <p role="status" className="small">{!wallet ? 'Setting up your account…' : 'Linking this browser to your account…'}</p>
    {state === 'error' ? <><p role="alert">Linking didn't finish.</p><button className="button" onClick={link}>Try Again</button></> : null}
  </>;
  if (fromApp && state !== 'sent') return <>
    <h1>Link your Mac.</h1>
    {device ? <>
      <p>To share from Huma without this browser, link your Mac. Check that Huma shows this code:</p>
      <p className="code" aria-label="Mac code">{shortCode || '…'}</p>
      <p className="small">If Huma shows a different code, or you didn't just press Sign In in Huma, close this tab.</p>
    </> : <p>To finish signing in, press Continue.</p>}
    <Who user={user} label="Signed in as" />
    <button className="button" disabled={!wallet || state === 'sending' || (device && !shortCode)} onClick={link}>
      {state === 'sending' ? 'Linking…' : !wallet ? 'Setting up your account…' : device ? 'Link This Mac' : 'Continue'}</button>
    {state === 'error' ? <p role="alert">Linking didn't finish. Start again from Huma.</p> : null}
  </>;
  return <>
    <Check />
    <h1>You're signed in.</h1>
    <p>{fromWeb ? 'You can close this window and go back to your document.' : fromApp ? 'Huma is open again. You can close this tab.' : 'Go back to Huma. You can close this tab.'}</p>
    {fromApp && !fromWeb ? <a className="button secondary" href="huma://signed-in">Open Huma</a> : null}
    <Who user={user} label="Signed in as" />
  </>;
}

// Offered in this order, but only the ones turned on in the Privy dashboard, so nobody picks one
// Privy would refuse with "Not allowed". Every account gets an embedded wallet that signs
// publications and never needs gas. External wallets are not offered.
const METHODS = { google: 'google_oauth', apple: 'apple_oauth', email: 'email_auth', twitter: 'twitter_oauth', github: 'github_oauth', discord: 'discord_oauth' };
// Light paper and ink, like the rest of the site.
const privyConfig = loginMethods => ({ loginMethods, embeddedWallets: { ethereum: { createOnLogin: 'all-users' } },
  appearance: { theme: 'light', accentColor: '#222222', logo: '/brand/huma-mark.svg', walletList: [] } });

export default function Approval({ config, signIn, ...props }) {
  const [methods, setMethods] = useState(null);
  useEffect(() => {
    fetch('https://auth.privy.io/api/v1/apps/' + encodeURIComponent(config.privyAppId), { headers: { 'privy-app-id': config.privyAppId } })
      .then(r => r.ok ? r.json() : Promise.reject()).then(app => Object.keys(METHODS).filter(m => app[METHODS[m]] === true))
      .catch(() => ['email']).then(on => setMethods(on.length ? on : ['email']));
  }, [config.privyAppId]);
  if (!methods) return <Skeleton label="Loading sign-in…" />;
  return <PrivyProvider appId={config.privyAppId} config={privyConfig(methods)}>
    {signIn ? <SignIn {...props} /> : <Publication {...props} />}
  </PrivyProvider>;
}
