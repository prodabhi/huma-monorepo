import { exactKeys, fullMatch, statementHash, validateStatement, hex } from './verify-core/contract.mjs';

export const MASTER_LIMIT = 32 * 1024 * 1024;
// Long drafts carry one chunk proof per ~100 characters (about 2 MB at 10,000 characters).
export const PROOF_LIMIT = 8 * 1024 * 1024;
// The writing replay (replay-core.mjs) a writer may share with a page.
export const REPLAY_LIMIT = 4 * 1024 * 1024;
export const UPLOAD_LIMIT = Math.ceil(MASTER_LIMIT / 3) * 4 + PROOF_LIMIT * 2 + REPLAY_LIMIT * 2 + 4096;
/** A shared page's link path: the full /original/<id>#<token>, or the short /p/<code>#<key> (publications.mjs). */
export const FULL_LINK = /^\/original\/([a-f0-9]{64})(?:#([a-f0-9]{64}))?$/, SHORT_LINK = /^\/p\/([A-Za-z0-9]{8,12})(?:#([A-Za-z0-9]{16}))?$/;
/** The signal a page's World ID is made for: only this page's master and proof, so a proof can't badge another page. */
export const pageSignal = manifest => 'huma-page:' + manifest.master.hash + ':' + manifest.proof.hash;
/** What a World ID linking an account is made for: the publishing key of the browser linking it (worldid-verify.mjs). */
export const accountSignal = publicKey => 'huma-account:' + publicKey;
/** What a browser signs, with its publishing key, to sign in with World ID: its key and the request body's hash. */
export const worldIDSigninMessage = (publicKey, bodyHash) => `huma-worldid-signin-v1\n${publicKey}\n${bodyHash}`;
export const isPageLink = path => typeof path === 'string' && (FULL_LINK.test(path) || SHORT_LINK.test(path));
/** Where a browser keeps the sign-in it started (write/account.mjs), so the sign-in page links only its own. */
export const SIGNIN_PENDING = 'huma-signin-pending';
export const digest = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
const hash = value => fullMatch(/^[a-f0-9]{64}$/, value);
const types = { text: ['text/plain;charset=utf-8'], image: ['image/png', 'image/avif'], audio: ['audio/flac'], video: ['video/mp4', 'video/webm'] };
export function validateManifest(value) {
  exactKeys(value, ['kind', 'publicationNonce', 'master', 'proof', 'statement', 'statementHash', 'access']);
  exactKeys(value.master, ['hash', 'byteLength', 'mediaType']);
  exactKeys(value.proof, ['hash', 'byteLength']);
  const s = validateStatement(value.statement);
  if (value.kind !== 'huma-publication-v1' || !['public', 'link'].includes(value.access) ||
      !types[s.contentKind].includes(value.master.mediaType) ||
      ![value.publicationNonce, value.master.hash, value.proof.hash, value.statementHash].every(hash) ||
      !Number.isSafeInteger(value.master.byteLength) || value.master.byteLength < 1 || value.master.byteLength > MASTER_LIMIT ||
      !Number.isSafeInteger(value.proof.byteLength) || value.proof.byteLength < 1 || value.proof.byteLength > PROOF_LIMIT) throw new Error('Invalid publication.');
  return value;
}
export async function checkDownloadedPublication(source, id, master, proof) {
  if (!hash(id) || typeof source !== 'string' || new TextEncoder().encode(source).length > 8192 ||
      await digest(new TextEncoder().encode(source)) !== id) throw new Error('Publication manifest changed.');
  const manifest = validateManifest(JSON.parse(source));
  if (!(master instanceof Uint8Array) || !(proof instanceof Uint8Array) ||
      master.byteLength !== manifest.master.byteLength || proof.byteLength !== manifest.proof.byteLength ||
      await digest(master) !== manifest.master.hash || await digest(proof) !== manifest.proof.hash ||
      await statementHash(manifest.statement) !== manifest.statementHash) throw new Error('Published files changed.');
  // This checks transport integrity only. The caller must also run the pinned
  // evidence verifier over these downloaded bytes and compare its statement.
  return manifest;
}
export function expectedMaster(manifest, bytes) {
  return manifest.statement.contentKind === 'text'
    ? new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) : bytes;
}

/** The message a publisher's wallet or Mac signs: this exact publication. The server's one-time nonce and the
 *  access mode are included, so a signature can't be replayed to publish the same text again or make it public. */
export const publicationMessage = manifest => `Huma publication v2\nstatement ${manifest.statementHash}\nmaster ${manifest.master.hash}` +
  `\nnonce ${manifest.publicationNonce}\naccess ${manifest.access}`;

// The nine writing rules a long page proof reports (its public inputs 33-41; 42 is "all met"),
// in the words readers and writers see when one isn't met.
export const WRITING_RULES = ['it started from imported text', 'some text wasn\u2019t typed', 'it was typed for less than 20 seconds',
  'it has fewer than 30 key presses', 'some key presses looked unusual', 'key holds looked unusual',
  'the typing rhythm looked unusual', 'there was no natural pause', 'the typing speed looked unusual'];
/** The writing rules a page proof misses, from its base64 final inputs (v3: 44 fields, v2: 46); empty when it met all nine. */
export function unmetWritingRules(finalInputs) {
  const raw = Uint8Array.from(atob(finalInputs), c => c.charCodeAt(0));
  if (raw.length !== 46 * 32 && raw.length !== 44 * 32) throw new Error('Not a page proof.');
  return WRITING_RULES.filter((_, i) => raw[(33 + i) * 32 + 31] !== 1);
}

/** What a v2 page proof's statement says that the score uses, from its base64 final inputs (fields of `struct Final`). */
export function pageSummary(finalInputs) {
  const raw = Uint8Array.from(atob(finalInputs), c => c.charCodeAt(0));
  if (raw.length !== 46 * 32 && raw.length !== 44 * 32) throw new Error('Not a page proof.');
  const field = i => raw.slice(i * 32 + 28, i * 32 + 32).reduce((n, b) => n * 256 + b, 0);
  return { edits: field(16), samples: field(17), typingEdits: field(18), pasteEdits: field(19), presenceCount: field(25), onTime: field(27),
    rules: Array.from({ length: 9 }, (_, i) => raw[(33 + i) * 32 + 31] === 1) };
}
/** The page's Huma score, 0 to 100, worked out exactly as the Mac app does (HumaCore/HumaScore.swift):
 *  typed (70): the share of the final text typed by hand, from the replay this browser checked; typing while a
 *  non-Apple keyboard was plugged in counts at 60%, pasted text and other edits nothing. Without the replay, the share
 *  of edits that were typing, counted at 60%. Typing checks (20): the proof's seven typing rules. Touch ID (10): the
 *  share of checks answered within 10 seconds (all of it when none were asked). */
export const EXTERNAL_WEIGHT = 0.6;
/** Every page scores out of 100 within its check tier, and the tier is always shown beside the score: a page written
 *  in a browser (huma.social/write: no key press carries the Mac's input origin) is Huma's basic check, as a browser
 *  can't tell a keyboard from software typing; its typing counts whole, as it can't tell one keyboard from another. */
export const WEIGHTS = [70, 20, 10];
/** Where a page was written, and how strong that check is: the label shown with every score. */
export const CHECK_TIERS = {
  web: { name: 'Web browser', label: 'Web browser · basic check',
    about: 'A browser can’t confirm key presses came from a real keyboard. A passkey raises it to the passkey check; the Mac app, to the strong check.' },
  passkey: { name: 'Web browser', label: 'Web browser · passkey check',
    about: 'The writer’s passkey approved every check-in.' },
  mac: { name: 'Huma Mac app', label: 'Mac app · strong check',
    about: 'The Mac app confirmed each key press came from its keyboard.' },
};
/** A browser page whose every approved check-in its writer's passkey also approved (checked outside the proof, by the
 *  reader) is the passkey check; the passkey raises the tier only, never the score. */
export const checkTier = (browser, passkey = false) => (browser ? (passkey ? CHECK_TIERS.passkey : CHECK_TIERS.web) : CHECK_TIERS.mac);
/** The report's one passkey row, for a page with the passkey check: [label, value], from its proof's `passkey`. */
export const passkeyRow = proof => (n => ['Passkey', n === 1 ? 'Approved the check-in' : `Approved all ${n} check-ins`])(proof?.passkey?.assertions?.length ?? 0);
export const writtenInBrowser = journal => Number(journal?.origin_present) === 0;
/** Typing no person makes: unusual key timing, holds, rhythm or speed (WRITING_RULES 4, 5, 6 and 8). A page that
 *  misses any of them scores at most TYPING_CAP, however much of it was typed (HumaScore.swift does the same). */
export const HUMAN_TYPING_RULES = [4, 5, 6, 8], TYPING_CAP = 50;
/** `rhythmAutomated`: the shared replay's rhythm looked automated (replayRhythm below). It holds a browser page at
 *  TYPING_CAP too; a Mac page's score ignores it, as HumaScore.swift has no such check. */
export function humaScore({ composition, typingEdits, edits, rules, presenceCount, onTime, browser = false, passkey = false, rhythmAutomated = false }) {
  const typedShare = browser ? (composition ? (composition.total ? (composition.typed + (composition.external ?? 0)) / composition.total : 0) : edits ? typingEdits / edits : 0)
    : composition ? (composition.total ? (composition.typed + EXTERNAL_WEIGHT * (composition.external ?? 0)) / composition.total : 0)
    : edits ? EXTERNAL_WEIGHT * typingEdits / edits : 0;
  const checksMet = rules.length === 9 ? rules.slice(2, 9).filter(Boolean).length : 0;
  const onTimeCount = Math.min(onTime, presenceCount), touch = presenceCount ? onTimeCount / presenceCount : 1;
  const weights = WEIGHTS, capped = (rules.length === 9 && HUMAN_TYPING_RULES.some(i => rules[i] === false)) || (browser && rhythmAutomated === true);
  let raw = [weights[0] * typedShare, weights[1] * checksMet / 7, weights[2] * touch];
  const sum = raw[0] + raw[1] + raw[2];
  // Capped, each part shrinks alike, so the parts still add up to the score.
  if (capped && sum > TYPING_CAP) raw = raw.map(part => part * TYPING_CAP / sum);
  const value = Math.max(0, Math.min(100, Math.round(raw[0] + raw[1] + raw[2])));
  // Whole points for each part that add up to the score: each part rounded down, then the points left over go to
  // the parts with the largest remainders.
  const points = raw.map(Math.floor);
  const order = [0, 1, 2].sort((a, b) => (raw[b] - points[b]) - (raw[a] - points[a]) || a - b);
  for (let left = value - points.reduce((a, b) => a + b, 0), i = 0; left > 0; left--, i++) points[order[i]]++;
  // What readers are told: how much of the text was typed by hand (on any keyboard), and how much on another keyboard.
  const handTyped = composition?.total ? (composition.typed + (composition.external ?? 0)) / composition.total : null;
  const external = composition?.total ? (composition.external ?? 0) / composition.total : 0;
  return { value, capped, typedShare, checksMet, presenceOnTime: onTimeCount, presenceCount, browser, passkey: Boolean(browser && passkey), weights,
    points: { typed: points[0], checks: points[1], touch: points[2] }, handTyped, external: browser ? 0 : external };
}

// The rhythm of a shared replay, as readers check it: a person's gaps between letters follow the letters (some pairs
// are quick, some slow, the same pair alike each time) and the words (slower at a word's start), while software sends
// keys on a timer, at random, or from a fixed table. Worked out from the replay's typed edits alone (no key codes, so
// no keyboard layout): the gap from each typed character to the next one typed straight after it, in milliseconds.
// Checked against 323 real essays typed in a browser (school students', from a public keystroke dataset), whole and
// cut short at 200 to 1,500 characters: none is held. web/test/rhythm.test.mjs keeps modelled cases.
export const RHYTHM = {
  /** Gaps longer than this are pauses to think, not rhythm. */
  pause: 2000,
  /** Letter pairs judged: those typed at least `pairMin` times, and at least `minPairs` of them. */
  pairMin: 5, minPairs: 8,
  /** A metronome, judged from 150 gaps: gaps that vary under 10%, or most within 3 ms of the usual one (as typing.mjs
   *  judges key logs). People's gaps vary 50% and more. */
  minGaps: 150, evenVariation: 0.1, evenShare: 0.6,
  /** A fixed table, judged from 150 gaps: the same letter pair takes the same time, varying under 10% (people's vary
   *  15% and more). */
  pairVariation: 0.1,
  /** At random, judged from 500 gaps: letter pairs and word starts together make no real difference (z under 1.5).
   *  People show 3 and more from 500 gaps, and more the longer they type; delays drawn at random fall under 1.5
   *  about 19 times in 20. Shorter typing isn't judged this way: there, people and chance overlap. */
  minRandomGaps: 500, ignored: 1.5,
};
const TYPED = new Set(['typing', 'typing-external']);
const isLetter = c => c !== undefined && /\p{L}/u.test(c);
const average = values => values.reduce((a, b) => a + b, 0) / values.length;
const variation = values => { const m = average(values); return m ? Math.sqrt(average(values.map(v => (v - m) ** 2))) / m : 0; };
const middle = values => { const s = [...values].sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
/** Each value's rank among them all, ties sharing their average rank, and the sum of t³ - t over runs of t ties. */
function ranked(values) {
  const order = values.map((v, i) => [v, i]).sort((a, b) => a[0] - b[0]), ranks = new Array(values.length);
  let ties = 0;
  for (let i = 0; i < order.length;) {
    let j = i; while (j < order.length && order[j][0] === order[i][0]) j++;
    for (let k = i; k < j; k++) ranks[order[k][1]] = (i + j + 1) / 2;
    ties += (j - i) ** 3 - (j - i); i = j;
  }
  return { ranks, ties };
}
/** How much the groups differ (Kruskal-Wallis H, as a z-score against chance): about 0 when they're alike. */
function groupShift(groups) {
  const all = groups.flat(), n = all.length, { ranks, ties } = ranked(all);
  let h = 0, at = 0;
  for (const g of groups) { let sum = 0; for (let i = 0; i < g.length; i++) sum += ranks[at + i]; at += g.length; h += sum * sum / g.length; }
  h = 12 / (n * (n + 1)) * h - 3 * (n + 1);
  if (ties < n ** 3 - n) h /= 1 - ties / (n ** 3 - n);
  const df = groups.length - 1;
  return (h - df) / Math.sqrt(2 * df);
}
/** How strongly `a` runs larger than `b` (Mann-Whitney U as a z-score), or null when either has under 8. */
function runsLarger(a, b) {
  if (a.length < 8 || b.length < 8) return null;
  const { ranks, ties } = ranked([...a, ...b]), n1 = a.length, n2 = b.length, n = n1 + n2;
  let sum = 0; for (let i = 0; i < n1; i++) sum += ranks[i];
  const u = sum - n1 * (n1 + 1) / 2, spread = n1 * n2 / 12 * (n + 1 - ties / (n * (n - 1)));
  return spread > 0 ? (u - n1 * n2 / 2) / Math.sqrt(spread) : 0;
}
/**
 * Whether a replay's typing rhythm looks automated, from its frames (verifyReplay in replay-core.mjs). Deterministic,
 * and cheap enough for the server. `{ automated, reason, measures }`: reason is null when it looks like a person's or
 * there's too little typing to judge (`measures.gaps` under RHYTHM.minGaps).
 */
export function replayRhythm(frames) {
  const gaps = [], pairs = new Map(), inWord = [], wordStart = [];
  // The run of characters just typed in a row (its last few), where it ends, and when the last one came.
  let run = '', end = -1, last = 0, counts = false;
  for (const f of Array.isArray(frames) ? frames : []) {
    const typed = TYPED.has(f.kind) && f.length === 0 && typeof f.inserted === 'string' && f.inserted.length === 1;
    if (typed && run && f.location === end) {
      const c = f.inserted, p = run.at(-1), gap = f.time - last;
      // A key held down repeats the same character; those gaps are the keyboard's, not the writer's.
      if (counts && c !== p && gap >= 0 && gap < RHYTHM.pause) {
        gaps.push(gap);
        const pair = p + c; if (!pairs.has(pair)) pairs.set(pair, []); pairs.get(pair).push(gap);
        if (isLetter(c) && isLetter(p)) inWord.push(gap);
        else if (isLetter(c) && p === ' ' && isLetter(run.at(-2))) wordStart.push(gap);
      }
      run = (run + c).slice(-4); end++; last = f.time; counts = true;
    } else if (typed) { run = f.inserted; end = f.location + 1; last = f.time; counts = true; }
    else if (TYPED.has(f.kind) && f.inserted === '' && f.length === 1 && run && f.location === end - 1) {
      // Backspace: the run goes on, but the next gap is a correction's, not the rhythm's.
      run = run.slice(0, -1); end--; last = f.time; counts = false;
    } else { run = ''; end = -1; counts = false; }
  }
  const judged = [...pairs.values()].filter(g => g.length >= RHYTHM.pairMin), typical = gaps.length ? middle(gaps) : null;
  const measures = {
    gaps: gaps.length,
    gapVariation: gaps.length >= 2 ? variation(gaps) : null,
    evenGaps: typical === null ? null : gaps.filter(g => Math.abs(g - typical) <= 3).length / gaps.length,
    pairs: judged.length,
    pairVariation: judged.length >= RHYTHM.minPairs ? middle(judged.map(variation)) : null,
    pairShift: judged.length >= RHYTHM.minPairs ? groupShift(judged) : null,
    wordStartShift: runsLarger(wordStart, inWord),
  };
  // Both as one z-score: how much letter pairs and word starts shape the gaps.
  measures.rhythmShift = measures.pairShift === null ? null
    : measures.wordStartShift === null ? measures.pairShift : (measures.pairShift + measures.wordStartShift) / Math.SQRT2;
  const verdict = reason => ({ automated: reason !== null, reason, measures });
  if (gaps.length < RHYTHM.minGaps) return verdict(null);
  if (measures.gapVariation < RHYTHM.evenVariation || measures.evenGaps >= RHYTHM.evenShare) return verdict('a perfectly even rhythm');
  if (measures.pairVariation !== null && measures.pairVariation < RHYTHM.pairVariation) return verdict('each letter pair took the same time');
  if (gaps.length >= RHYTHM.minRandomGaps && measures.rhythmShift !== null && measures.rhythmShift < RHYTHM.ignored)
    return verdict('a rhythm that ignored letters and words');
  return verdict(null);
}
/** A share (0...1) as a whole percent that never rounds a part away: "100%" only when it's all, "0%" only when none. */
export function percentLabel(share) {
  if (!(share > 0)) return '0%';
  if (share >= 1) return '100%';
  return share < 0.01 ? '<1%' : Math.min(99, Math.max(1, Math.round(share * 100))) + '%';
}
/** The score's parts in one line: "100% typed · 7 of 7 typing checks · Touch ID 2 of 2" (ScoreRow.parts in the app). */
export function scoreLine(score) {
  const typed = score.handTyped === null ? (score.browser ? 'Replay not shared' : 'Replay not shared, so typing counts at 60%')
    : percentLabel(score.handTyped) + ' typed' + (score.external > 0 ? ` (${percentLabel(score.external)} on another keyboard)` : '');
  return [checkTier(score.browser, score.passkey).label, typed, `${score.checksMet} of 7 typing checks`, ...(score.presenceCount ? [`${score.browser ? 'Check-ins' : 'Touch ID'} ${score.presenceOnTime} of ${score.presenceCount}`] : [])].join(' · ');
}

// A Mac shares without the browser once the account's wallet has authorized its publishing key
// (a Secure Enclave P-256 key; publicKey is its 65-byte x9.63 form in hex) with this message.
export const deviceAuthorizationMessage = (wallet, publicKey) =>
  `Huma device authorization\nThis Mac may share pages for ${wallet.toLowerCase()}.\nkey ${publicKey.toLowerCase()}`;
/** A short code for a Mac's publishing key, shown both in Huma and on the sign-in page so a person only links
 *  their own Mac: the first 4 bytes of SHA-256 over the lowercase hex key, as "ABCD-1234". */
export async function deviceCode(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(publicKey.toLowerCase())));
  const hex = [...digest.slice(0, 4)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return hex.slice(0, 4) + '-' + hex.slice(4);
}

/** What the sharing Mac signs to take its link down. */
export const removalMessage = id => `Huma remove v1\npublication ${id}`;
/** What the sharing Mac signs to add a replay to its page (by the replay's SHA-256), or take it off ("none"). */
export const replayMessage = (id, replayHash) => `Huma replay v1\npublication ${id}\nreplay ${replayHash ?? 'none'}`;
/** What the sharing Mac signs to send a page to a writing request, so the inbox can say it came from that Mac. */
export const requestMessage = (request, id) => `Huma request v1\nrequest ${request}\npublication ${id}`;

/** The writer's name and face seed shown on a shared page, checked before it is kept. Both are chosen in
 *  the app and stated by the host, like the wallet: they aren't part of the proof. null when there's none. */
export const AVATAR_SEED = /^[A-Za-z0-9_-]{1,32}$/;
/** A writer's page address, huma.social/@handle: 3 to 20 lowercase letters, numbers or _, not one of the site's own words. */
export const HANDLE = /^[a-z0-9_]{3,20}$/;
export const RESERVED_HANDLES = new Set(['write', 'verify', 'ask', 'download', 'privacy', 'terms', 'api', 'p', 'original', 'avatar', 'admin', 'huma',
  'support', 'help', 'team', 'about', 'deck', 'w', 'writer', 'writers', 'settings', 'login', 'signin',
  'staff', 'security', 'moderator', 'moderators', 'mod', 'mods', 'official', 'humasocial', 'huma_social', 'huma_official', 'huma_team',
  'huma_support', 'humateam', 'administrator', 'admins', 'root', 'system', 'sysadmin', 'superuser', 'owner', 'null', 'undefined', 'nil',
  'none', 'anonymous', 'unknown', 'me', 'you', 'everyone', 'all', 'here', 'abuse', 'postmaster', 'webmaster', 'hostmaster', 'noreply',
  'no_reply', 'info', 'contact', 'legal', 'billing', 'press', 'news', 'status', 'blog', 'docs', 'mail', 'www', 'trust', 'safety',
  'trust_safety', 'verified', 'account', 'profile', 'signup', 'signout', 'logout', 'register', 'documents', 'publications', 'sessions',
  'share', 'replay', 'receipt', 'downloads', 'home', 'index', 'search', 'explore', 'new', 'test', 'bot', 'robots', 'favicon']);
export function writerHandle(value) {
  const handle = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!HANDLE.test(handle) || RESERVED_HANDLES.has(handle)) throw Object.assign(new Error('Choose a handle of 3 to 20 letters, numbers or _.'), { status: 400 });
  return handle;
}
/** The writer's name and face, and their handle when they chose one (pages shared from the Mac have none). */
export function writerProfile(value) {
  if (value === undefined || value === null) return null;
  const refuse = () => { throw Object.assign(new Error('Choose a name up to 40 characters.'), { status: 400 }); };
  if (typeof value !== 'object' || typeof value.name !== 'string' || typeof value.avatar !== 'string' || !AVATAR_SEED.test(value.avatar)) refuse();
  const name = value.name.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (!name || [...name].length > 40 || /\p{C}/u.test(name)) refuse();
  const handle = value.handle === undefined || value.handle === null || value.handle === '' ? null : writerHandle(value.handle);
  return { name, avatar: value.avatar, ...(handle ? { handle } : {}) };
}
/** What the sharing browser signs to show its page on the writer's page (huma.social/@handle), or take it off, and to
 *  rename it: with the time in milliseconds, so the server takes each signature once and only for a few minutes. */
export const listedMessage = (id, listed, time) => `Huma listed v2\npublication ${id}\nlisted ${listed ? 'yes' : 'no'}\ntime ${time}`;
export const titleMessage = (id, title, time) => `Huma title v2\npublication ${id}\ntitle ${title}\ntime ${time}`;
/** What a browser signs with its publishing key when it reads back its sign-in, to show it holds the key the account
 *  links: only then is the key kept as the account's (owners/, publications.mjs). */
export const signinMessage = (code, publicKey) => `Huma sign-in v1\ncode ${code}\nkey ${publicKey.toLowerCase()}`;
export const TITLE_LIMIT = 80;
/** A line made into a page's name: its first sentence, or its first clause when that's long, at most about 40
 *  characters, cut between words. */
export function shortTitle(line) {
  let name = String(line ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  const sentence = name.match(/^(.{3,}?[.!?])(\s|$)/);
  if (sentence) name = sentence[1];
  if (name.length > 40) { const clause = name.slice(12, 41).search(/[,;:–—]/); if (clause !== -1) name = name.slice(0, 12 + clause); }
  if (name.length > 40) { const cut = name.lastIndexOf(' ', 40); name = name.slice(0, cut > 15 ? cut : 40); }
  return name.replace(/[\s,;:–—-]+$/, '').replace(/(?<![.!?]{2})\.$/, '');
}
/** A title the writer chose, cleaned: one line, at most TITLE_LIMIT characters; '' when there's none. */
export const cleanTitle = title => [...(typeof title === 'string' ? title : '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim()].slice(0, TITLE_LIMIT).join('').trim();
/** The tiers a writer's pages reach, weakest first (CHECK_TIERS). */
export const TIER_ORDER = ['web', 'passkey', 'mac'];
/** A writer's level from their record: pages shared, rounded mean score, days since their first page and best tier. */
export function writerLevel({ pages = 0, average = null, days = 0, best = null } = {}) {
  const mean = average ?? 0;
  if (pages >= 40 && mean >= 85 && days >= 90 && (best === 'passkey' || best === 'mac')) return { level: 4, name: 'Trusted writer' };
  if (pages >= 15 && mean >= 80 && days >= 30) return { level: 3, name: 'Steady writer' };
  if (pages >= 5 && mean >= 70) return { level: 2, name: 'Writer' };
  return { level: 1, name: 'New writer' };
}
/** What a browser signs with its publishing key for each request about its account's documents (documents.mjs):
 *  the method, path, time in milliseconds and the body's SHA-256. */
export const documentRequestMessage = (method, pathname, time, bodyHash) => `huma-documents-v1\n${method}\n${pathname}\n${time}\n${bodyHash}`;
