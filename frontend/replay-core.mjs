// A page's writing replay: every edit the writer made, as the Mac recorded it, so readers can watch the page
// being written. The Mac signs its final checkpoint (edit-chain head, text hash, edit count) with the same
// capture key the page proof commits to, so a reader rebuilds the whole edit chain here and checks that
// signature: the replay can't be edited, cut or swapped without breaking it. Runs in browsers and Node.
export const REPLAY_KIND = 'huma-replay-v1';
export const REPLAY_LIMIT = 4 * 1024 * 1024;
const MAX_EVENTS = 50000, MAX_TEXT = 200000;
const encoder = new TextEncoder();

const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async value => hex(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? encoder.encode(value) : value));
/** Swift's JSONEncoder for an array of strings: JSON.stringify, plus "/" escaped as "\/". */
export const swiftJSON = values => JSON.stringify(values).replaceAll('/', '\\/');
const fail = message => { throw new Error(message ?? 'This replay is not valid.'); };
const base64 = value => {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4) fail();
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
};
const count = value => Number.isSafeInteger(value) && value >= 0;
/** A DER ECDSA signature as the 64 raw bytes WebCrypto expects. */
function p1363(der) {
    const read = (at) => {
        if (der[at] !== 2) fail(); const length = der[at + 1]; if (length < 1 || length > 33) fail();
        let value = der.subarray(at + 2, at + 2 + length); while (value.length > 32 && value[0] === 0) value = value.subarray(1);
        if (value.length > 32) fail(); const out = new Uint8Array(32); out.set(value, 32 - value.length); return [out, at + 2 + length];
    };
    if (der[0] !== 0x30 || der[1] !== der.length - 2) fail();
    const [r, next] = read(2), [s, end] = read(next); if (end !== der.length) fail();
    const out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
}

/** Checks the shape of a replay file and returns it parsed. */
export function parseReplay(source) {
    if (typeof source !== 'string' || source.length > REPLAY_LIMIT) fail();
    const r = JSON.parse(source), c = r?.checkpoint;
    if (!r || typeof r !== 'object' || Array.isArray(r) || r.kind !== REPLAY_KIND || typeof r.session !== 'string' || r.session.length > 64 ||
        typeof r.initialText !== 'string' || r.initialText.length > MAX_TEXT || !Array.isArray(r.events) || r.events.length > MAX_EVENTS ||
        Object.keys(r).some(k => !['kind', 'session', 'initialText', 'events', 'checkpoint'].includes(k))) fail();
    for (const e of r.events) if (!Array.isArray(e) || e.length !== 5 || !count(e[0]) || typeof e[1] !== 'string' || e[1].length > 32 ||
        !count(e[2]) || !count(e[3]) || typeof e[4] !== 'string') fail();
    if (!c || typeof c !== 'object' || c.version !== 2 || c.kind !== 'unattested-p256' || c.isFinal !== true || c.sessionID !== r.session ||
        ![c.sequence, c.captureCount, c.editCount, c.sampleCount, c.reportedTime?.unixMilliseconds, c.reportedTime?.elapsedMilliseconds].every(count) ||
        ![c.captureHead, c.editHead, c.textHash].every(v => /^[a-f0-9]{64}$/.test(v)) || !/^([a-f0-9]{64})?$/.test(c.previousCheckpoint) ||
        typeof c.challenge !== 'string' || c.challenge.length > 256 || typeof c.publicKey !== 'string' || typeof c.signature !== 'string') fail();
    return r;
}

/** Rebuilds the edit chain, checks the Mac's signature and the final text, and returns what the reader shows:
 *  each frame's time and edit, and how much of the final text was typed, pasted or there to begin with.
 *  `publicKey` is the page proof's capture key (base64); `text` is the page's verified text. */
/** UTF-16 units hashed across all edits (about a second of work). */
const REPLAY_WORK = 2_000_000_000;
export async function verifyReplay(source, { publicKey, text }) {
    const r = typeof source === 'string' ? parseReplay(source) : fail(), c = r.checkpoint;
    if (c.publicKey !== publicKey || base64(c.publicKey).length !== 65) fail('This replay was recorded with a different key.');
    // The signature first: it's cheap, and only a signed replay gets the costly rebuild below.
    const payload = swiftJSON(['huma-signed-checkpoint-v2', c.kind, c.sessionID, String(c.sequence), 'true', String(c.captureCount),
        String(c.editCount), String(c.sampleCount), c.captureHead, c.editHead, c.textHash, c.previousCheckpoint, c.challenge, c.publicKey,
        'device-clock-v1', String(c.reportedTime.unixMilliseconds), String(c.reportedTime.elapsedMilliseconds)]);
    const key = await crypto.subtle.importKey('raw', base64(c.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, p1363(base64(c.signature)), encoder.encode(payload)))
        fail('The Mac’s signature on this replay doesn’t check out.');
    // Each edit hashes the whole page, so the total is capped well above what a 10,000-character page needs.
    let work = 0;
    // Edits apply in UTF-16 offsets, as on the Mac; each one names its own text hash and links to the previous edit.
    let page = r.initialText, head = await sha256('huma-session-v1:' + r.session + ':' + r.initialText), elapsed = 0;
    // Where each character came from: i = there before, t = typed, p = pasted, o = other changes.
    let origin = 'i'.repeat(page.length);
    const removed = new Map(), frames = [];
    for (const [index, [time, kind, location, length, inserted]] of r.events.entries()) {
        if (time < elapsed || location > page.length || length > page.length - location) fail();
        const gone = page.slice(location, location + length);
        if (gone) removed.set(gone, origin.slice(location, location + length));
        // Undo and redo bring back what was there before, with where it first came from.
        // Typed on another keyboard (a non-Apple one was plugged in) is k: typed, but it counts for less in the score.
        const marks = kind === 'paste' ? 'p'.repeat(inserted.length) : ['typing', 'input-method', 'format-insert'].includes(kind) ? 't'.repeat(inserted.length)
            : kind === 'typing-external' ? 'k'.repeat(inserted.length)
            : removed.get(inserted)?.length === inserted.length ? removed.get(inserted) : 'o'.repeat(inserted.length);
        page = page.slice(0, location) + inserted + page.slice(location + length);
        origin = origin.slice(0, location) + marks + origin.slice(location + length);
        if ((work += page.length) > REPLAY_WORK) fail('This replay is too long to check.');
        const textHash = await sha256(page);
        head = await sha256(swiftJSON([String(index), String(time), kind, String(location), String(length), inserted, head, textHash]));
        frames.push({ time, kind, location, length, inserted, origin: marks });
        elapsed = time;
    }
    if (c.editCount !== r.events.length || c.editHead !== head || c.textHash !== await sha256(page)) fail('The replay doesn’t match what the Mac signed.');
    // The page's text, less only the final spaces and tabs the proof ignores.
    if (page !== text && page.replace(/[ \t]+$/, '') !== text.replace(/[ \t]+$/, '')) fail('The replay doesn’t end with this page’s text.');
    return { initialText: r.initialText, frames, finalText: page, duration: Math.max(elapsed, c.reportedTime.elapsedMilliseconds),
        composition: composition(origin), origin };
}

/** How much of the final text was typed, pasted, there before, or changed some other way (in UTF-16 units). */
export function composition(origin) {
    const totals = { typed: 0, external: 0, pasted: 0, before: 0, other: 0 }, names = { t: 'typed', k: 'external', p: 'pasted', i: 'before', o: 'other' };
    for (const mark of origin) totals[names[mark]]++;
    return { ...totals, total: origin.length };
}
