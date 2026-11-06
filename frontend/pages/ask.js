// Writing requests: /ask makes one, /r/<id> is the writer's page, /r/<id>/inbox#<key> is the requester's inbox.
const $ = id => document.getElementById(id);
const match = location.pathname.match(/^\/r\/([a-f0-9]{32})(\/inbox)?$/);
const view = match ? (match[2] ? 'inbox' : 'write') : 'create';
const section = document.querySelector(`[data-view="${view}"]`);
section.classList.add('active');
// A request or inbox shows grey shapes (ask.html) until it has loaded.
if (view !== 'create') section.classList.add('loading');

async function call(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers } });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error ?? 'Something went wrong. Try again.');
    return body;
}
function copyButtons() {
    for (const button of document.querySelectorAll('[data-copy]')) button.addEventListener('click', async () => {
        await navigator.clipboard.writeText($(button.dataset.copy).textContent);
        button.textContent = 'Copied'; setTimeout(() => { button.textContent = 'Copy'; }, 1500);
    });
}
const ago = time => {
    const minutes = Math.round((Date.now() - time) / 60000);
    if (minutes < 1) return 'just now';
    if (minutes < 60) return minutes + ' min ago';
    const hours = Math.round(minutes / 60); if (hours < 24) return hours + ' h ago';
    return new Date(time).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
};

if (view === 'create') {
    $('createForm').addEventListener('submit', async event => {
        event.preventDefault();
        const button = event.target.querySelector('button'); button.disabled = true; $('createError').textContent = '';
        try {
            const { id, key } = await call('/api/requests', { method: 'POST',
                body: JSON.stringify({ title: $('title').value, from: $('from').value, note: $('note').value }) });
            const share = location.origin + '/r/' + id, inbox = share + '/inbox#' + key;
            $('shareLink').textContent = share; $('inboxLink').textContent = inbox; $('openInbox').href = inbox;
            $('createForm').hidden = true; $('made').hidden = false; copyButtons();
        } catch (error) { $('createError').textContent = error.message; button.disabled = false; }
    });
}

if (view === 'write') {
    const id = match[1];
    try {
        const { title, from, note } = await call('/api/requests/' + id);
        document.title = title + ' · Huma';
        $('askFrom').textContent = from + ' asked you to write'; $('askTitle').textContent = title; $('askNote').textContent = note;
        $('sendLabel').textContent = 'Send to ' + from;
        $('openApp').href = 'huma://request?id=' + id;
    } catch (error) { $('askTitle').textContent = error.message; document.querySelector('.ask .card').hidden = true; }
    section.classList.remove('loading');
    $('pasteForm').addEventListener('submit', async event => {
        event.preventDefault();
        const button = event.target.querySelector('button'); button.disabled = true; $('pasteError').textContent = '';
        try {
            const { status, from } = await call('/api/requests/' + id + '/submit', { method: 'POST', body: JSON.stringify({ link: $('pasted').value }) });
            $('sentText').textContent = status === 'already-sent' ? 'Already sent to ' + from + '.' : 'Sent to ' + from + '.';
            $('sent').hidden = false; $('pasteForm').hidden = true;
        } catch (error) { $('pasteError').textContent = error.message; button.disabled = false; }
    });
}

if (view === 'inbox') {
    const id = match[1], key = location.hash.slice(1);
    $('copyShare').addEventListener('click', async () => {
        await navigator.clipboard.writeText(location.origin + '/r/' + id);
        $('copyShare').textContent = 'Copied'; setTimeout(() => { $('copyShare').textContent = 'Copy Link for Writers'; }, 1500);
    });
    // Three grey rows stand in for the pages until the first load.
    $('inboxList').replaceChildren(...Array.from({ length: 3 }, () => {
        const row = document.createElement('li'); row.className = 'ghost'; row.setAttribute('aria-hidden', 'true');
        row.innerHTML = '<i class="face"></i><span><i></i><i></i></span>'; return row;
    }));
    async function load() {
        try {
            const { title, submissions } = await call('/api/requests/' + id + '/inbox', { headers: { Authorization: 'Bearer ' + key } });
            document.title = title + ' · Inbox · Huma';
            $('inboxTitle').textContent = title;
            $('inboxCount').textContent = submissions.length === 1 ? '1 page' : submissions.length + ' pages';
            const rows = submissions.slice().sort((a, b) => b.at - a.at).map(s => {
                const row = document.createElement('li'), face = document.createElement('img'), who = document.createElement('div'), open = document.createElement('a');
                face.className = 'face'; face.alt = ''; face.width = 36; face.height = 36;
                if (s.avatar) face.src = '/avatar/' + s.avatar + '.svg';
                const name = document.createElement('strong'); name.textContent = s.name ?? 'No name';
                const detail = document.createElement('span');
                detail.textContent = s.words.toLocaleString() + (s.words === 1 ? ' word · ' : ' words · ') + ago(s.at);
                if (s.fromMac) { const mac = document.createElement('span'); mac.className = 'mac'; mac.textContent = '✓ Sent from the writer’s Mac'; who.append(name, detail, mac); }
                else who.append(name, detail);
                open.className = 'button small secondary'; open.textContent = 'Open'; open.target = '_blank'; open.rel = 'noopener';
                // A page sent by its short link keeps it: the token is then "<code>.<key>".
                open.href = s.token.includes('.') ? '/p/' + s.token.replace('.', '#') : '/original/' + s.page + '#' + s.token;
                row.append(face, who, open); return row;
            });
            if (!rows.length) { const empty = document.createElement('li'); empty.className = 'empty'; empty.textContent = 'No pages yet. Send the link to your writers.'; rows.push(empty); }
            $('inboxList').replaceChildren(...rows);
        } catch (error) { $('inboxError').textContent = error.message; for (const ghost of $('inboxList').querySelectorAll('.ghost')) ghost.remove(); }
    }
    await load();
    section.classList.remove('loading');
    setInterval(() => { if (!document.hidden) load(); }, 30000);
}
