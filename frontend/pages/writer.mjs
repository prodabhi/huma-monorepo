// A writer's page (/@handle): their face, name, level and record on the left; the pages they chose to show on the right.
// Everything the writer chose (name, titles) goes in as text, never as markup.
import { CHECK_TIERS, AVATAR_SEED, isPageLink } from '/publication-contract.mjs';

const HANDLE = /^[a-z0-9_]{3,20}$/;
const head = document.getElementById('writer'), list = document.getElementById('pages');

const el = (tag, props = {}, ...children) => {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children.filter(child => child != null));
    return node;
};
const count = (n, one, many) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? one : many}`;
const validTime = ms => Number.isFinite(ms) && ms > 0 && !Number.isNaN(new Date(ms).getTime());
const monthYear = ms => new Date(ms).toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
const day = ms => new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const tierLabel = key => (Object.hasOwn(CHECK_TIERS, key) ? CHECK_TIERS[key].label : null);

function done() {
    document.body.classList.remove('loading');
    document.querySelector('main').removeAttribute('aria-busy');
}

/** No writer here: one line and a way to start writing. */
function missing(message = 'No writer with that handle.') {
    document.title = message === 'No writer with that handle.' ? 'No writer · Huma' : 'Writer · Huma';
    head.replaceChildren(
        el('h1', { className: 'page-title', textContent: message }),
        el('div', { className: 'page-actions' }, el('a', { className: 'button', href: '/write', textContent: 'Start Writing' })));
    list.replaceChildren();
    done();
}

function showWriter({ profile, record, level, worldId }, handle) {
    const name = typeof profile?.name === 'string' && profile.name.trim() ? profile.name.trim() : '@' + handle;
    document.title = `${name} (@${handle}) · Huma`;
    const face = typeof profile?.avatar === 'string' && AVATAR_SEED.test(profile.avatar)
        ? el('img', { className: 'face', alt: '', width: 72, height: 72, src: '/avatar/' + profile.avatar + '.svg' }) : null;
    const kicker = level && Number.isInteger(level.level) && typeof level.name === 'string'
        ? el('span', { className: 'kicker mono', textContent: `${level.name} · Level ${level.level}` }) : null;

    const rows = [];
    const row = (label, value) => rows.push(el('div', {}, el('dt', { textContent: label }), el('dd', { textContent: value })));
    if (Number.isFinite(record?.pages)) row('Pages proved', record.pages.toLocaleString('en-US'));
    if (Number.isFinite(record?.average)) row('Average score', `${record.average} / 100`);
    if (validTime(record?.since)) row('Writing since', monthYear(record.since));
    const best = tierLabel(record?.best);
    if (best) row('Best check', best);
    // Their account's World ID (documents.mjs): the same on every page they share, so it ties these pages to one real person.
    if (worldId?.verified === true && /^[0-9a-f]{12}$/.test(worldId.fingerprint ?? '')) row('Verified human', 'World ID ' + worldId.fingerprint);

    head.replaceChildren(...[face, kicker,
        el('h1', { className: 'page-title', textContent: name }),
        el('p', { className: 'mono handle', textContent: '@' + handle }),
        rows.length ? el('dl', { className: 'record mono' }, ...rows) : null].filter(Boolean));
}

/** One card per listed page, newest first; the whole card opens the page. */
// The writer, viewing their own page (signed in here as this handle), gets each page's options. Hiding happens here,
// signed with this browser's key (/write/writer-actions.js); renaming, downloading and deleting open /write.
function mine(handle) {
    try { return JSON.parse(localStorage.getItem('huma-profile') ?? 'null')?.handle === handle && Boolean(JSON.parse(localStorage.getItem('huma-account') ?? 'null')?.wallet); }
    catch { return false; }
}
function options(page) {
    // The page is named by its short link's code alone (no key), which opens nothing by itself.
    const act = what => '/write?shared=' + page.path.split('#')[0].slice(3) + '&do=' + what, item = (text, props) => el(props.href ? 'a' : 'button', { textContent: text, ...props });
    const menu = el('div', { className: 'more-menu' },
        item('Open', { href: page.path }),
        item('Rename', { href: act('rename') }),
        item('Download', { href: act('download') }),
        item('Copy Link', { type: 'button', onclick: async () => {
            try { await navigator.clipboard.writeText(new URL(page.path, location.origin).href); box.querySelector('summary').textContent = 'Copied'; } catch {}
            setTimeout(() => { box.open = false; box.querySelector('summary').textContent = '⋮'; }, 900);
        } }),
        item('Hide from Your Page', { type: 'button', onclick: () => hideHere(page, box) }),
        item('Delete', { href: act('delete'), className: 'danger' }));
    const box = el('details', { className: 'more' }, el('summary', { textContent: '⋮', title: 'Options' }), menu);
    box.querySelector('summary').setAttribute('aria-label', 'Options');
    box.addEventListener('toggle', () => { if (box.open) for (const other of document.querySelectorAll('details.more[open]')) if (other !== box) other.open = false; });
    return box;
}
/** Hides a page from this writer page without leaving it: the card goes once the server has it. */
async function hideHere(page, box) {
    const summary = box.querySelector('summary'), li = box.closest('li');
    box.open = false; summary.textContent = '…';
    try {
        const { hide } = await import('/write/writer-actions.js');
        await hide(page.path.split('#')[0].slice(3));
        const ul = li.parentElement; li.remove();
        if (!ul.children.length) list.replaceChildren(el('p', { className: 'empty', textContent: 'No public pages yet.' }));
        else list.querySelector('.list-head').textContent = count(ul.children.length, 'page', 'pages');
    } catch (error) {
        summary.textContent = '⋮';
        li.querySelector('.doc').append(el('p', { className: 'meta mono', textContent: error?.message || 'Couldn’t hide this page. Try again.' }));
    }
}
function showPages(pages, owner = false) {
    const items = (Array.isArray(pages) ? pages : []).filter(page => page && typeof page === 'object')
        .sort((a, b) => (Number(b.at) || 0) - (Number(a.at) || 0));
    if (!items.length) { list.replaceChildren(el('p', { className: 'empty', textContent: 'No public pages yet.' })); return; }
    list.replaceChildren(
        el('h2', { className: 'list-head mono', textContent: count(items.length, 'page', 'pages') }),
        el('ul', { className: 'docs' }, ...items.map(page => {
            const title = typeof page.title === 'string' && page.title.trim() ? page.title.trim() : 'Untitled page';
            const meta = [validTime(page.at) ? day(page.at) : null, Number.isFinite(page.words) ? count(page.words, 'word', 'words') : null].filter(Boolean).join(' · ');
            const tier = tierLabel(page.tier);
            const score = Number.isFinite(page.score)
                ? el('p', { className: 'score' }, el('b', { textContent: `Huma Score ${page.score} / 100` }), tier ? el('span', { textContent: tier }) : null) : null;
            const body = [el('h2', { textContent: title }), meta ? el('p', { className: 'meta mono', textContent: meta }) : null, score];
            // Only Huma page links open from here (/p/<code>#<key> or /original/<id>#<token>).
            const card = isPageLink(page.path) ? el('a', { className: 'doc', href: page.path }, ...body) : el('div', { className: 'doc' }, ...body);
            return el('li', {}, card, owner && /^\/p\/[A-Za-z0-9_-]{4,32}#/.test(page.path ?? '') ? options(page) : null);
        })));
}

async function load() {
    let handle = '';
    try { handle = decodeURIComponent(location.pathname.replace(/^\/@/, '').replace(/\/$/, '')).toLowerCase(); } catch {}
    if (!location.pathname.startsWith('/@') || !HANDLE.test(handle)) return missing();
    let response;
    try { response = await fetch('/api/writers/' + handle, { headers: { Accept: 'application/json' } }); } catch { return missing('Couldn’t load this writer. Try again.'); }
    if (response.status === 404) return missing();
    const data = await response.json().catch(() => null);
    if (!response.ok || !data || typeof data !== 'object') return missing('Couldn’t load this writer. Try again.');
    const shown = typeof data.profile?.handle === 'string' && HANDLE.test(data.profile.handle) ? data.profile.handle : handle;
    showWriter(data, shown);
    showPages(data.pages, mine(shown));
    done();
}

load();
