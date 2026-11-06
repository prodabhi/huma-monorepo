// The shared page's replay: the text as it was written, edit by edit, with pasted text marked.
// Frames come from replay-core.mjs, already checked against the page proof. Long pauses are shortened.
const PAUSE = 1500, SNAPSHOT = 200, SPEEDS = [1, 4, 16];

function clock(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000), h = Math.floor(seconds / 3600), m = Math.floor(seconds / 60) % 60, s = seconds % 60;
    return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(s).padStart(2, '0');
}
const make = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text) node.textContent = text; return node; };

/** Shows the replay in place of `article` until Done. Returns a function that closes it. */
export function openPlayer(article, replay, onClose) {
    const { frames, initialText } = replay;
    // Play time: each gap counts at most PAUSE, so a page written over an hour plays in minutes.
    const play = []; let total = 0;
    frames.forEach((f, i) => { total += Math.min(PAUSE, f.time - (i ? frames[i - 1].time : 0)); play.push(total); });
    total += 600;
    // Text and origins every SNAPSHOT frames, so scrubbing never replays from the start.
    const snapshots = [{ text: initialText, origin: 'i'.repeat(initialText.length) }];
    let text = initialText, origin = snapshots[0].origin;
    frames.forEach((f, i) => {
        text = text.slice(0, f.location) + f.inserted + text.slice(f.location + f.length);
        origin = origin.slice(0, f.location) + f.origin + origin.slice(f.location + f.length);
        if ((i + 1) % SNAPSHOT === 0) snapshots.push({ text, origin });
    });

    const player = make('div', 'player'), view = make('div', 'replay-text');
    view.setAttribute('aria-live', 'off');
    const controls = make('div', 'replay-controls');
    const toggle = make('button', 'replay-play'); toggle.type = 'button';
    const scrub = make('input', 'replay-scrub'); Object.assign(scrub, { type: 'range', min: 0, max: total, step: 1, value: 0 });
    scrub.setAttribute('aria-label', 'Replay position');
    const time = make('span', 'replay-time');
    const speeds = make('div', 'replay-speeds'); speeds.setAttribute('role', 'group'); speeds.setAttribute('aria-label', 'Speed');
    let speed = 4;
    for (const value of SPEEDS) {
        const button = make('button', '', value + '×'); button.type = 'button'; button.setAttribute('aria-pressed', String(value === speed));
        button.addEventListener('click', () => { speed = value; for (const b of speeds.children) b.setAttribute('aria-pressed', String(b === button)); });
        speeds.append(button);
    }
    const done = make('button', 'replay-done', 'Done'); done.type = 'button';
    // Pastes as marks along the track, so they're easy to find.
    const track = make('div', 'replay-track');
    frames.forEach((f, i) => { if (f.kind === 'paste') { const mark = make('i'); mark.style.left = (play[i] / total * 100) + '%'; track.append(mark); } });
    const scrubber = make('div', 'replay-scrubber'); scrubber.append(track, scrub);
    controls.append(toggle, scrubber, time, speeds, done);
    const legend = make('p', 'replay-legend');
    legend.append(make('span', 'swatch'), 'Pasted text', make('span', 'sep', '·'), 'Long pauses are shortened.');
    player.append(controls, legend);

    const hidden = [...article.children];
    for (const node of hidden) node.hidden = true;
    article.before(player); article.append(view); article.classList.add('replaying');

    let at = 0, index = -1, playing = false, last = 0, frame = 0;
    /** The text after frame `n` (-1 is the start), from the nearest snapshot. */
    function state(n) {
        const s = Math.floor((n + 1) / SNAPSHOT), base = snapshots[s];
        let t = base.text, o = base.origin;
        for (let i = s * SNAPSHOT; i <= n; i++) {
            const f = frames[i];
            t = t.slice(0, f.location) + f.inserted + t.slice(f.location + f.length);
            o = o.slice(0, f.location) + f.origin + o.slice(f.location + f.length);
        }
        return { t, o };
    }
    function render() {
        const n = Math.min(frames.length - 1, play.findLastIndex(p => p <= at));
        if (n !== index) {
            index = n; const { t, o } = state(n), caret = n < 0 ? t.length : frames[n].location + frames[n].inserted.length;
            // Runs of pasted and not-pasted text, with the caret where the last edit ended.
            const nodes = []; let from = 0;
            for (let i = 0; i <= t.length; i++) {
                const edge = i === t.length || (i > from && (o[i] === 'p') !== (o[from] === 'p'));
                if ((edge || i === caret) && i > from) {
                    const piece = t.slice(from, i);
                    nodes.push(o[from] === 'p' ? make('mark', 'pasted', piece) : document.createTextNode(piece)); from = i;
                }
                if (i === caret) nodes.push(make('span', 'caret'));
            }
            view.replaceChildren(...nodes);
        }
        scrub.value = at;
        time.textContent = clock(n < 0 ? 0 : frames[n].time) + ' / ' + clock(replay.duration);
        toggle.textContent = playing ? 'Pause' : at >= total ? 'Replay' : 'Play';
        toggle.setAttribute('aria-label', toggle.textContent);
    }
    function tick(now) {
        if (!playing) return;
        at = Math.min(total, at + (now - last) * speed); last = now;
        if (at >= total) playing = false;
        render();
        if (playing) frame = requestAnimationFrame(tick);
    }
    function start() { if (at >= total) at = 0; playing = true; last = performance.now(); frame = requestAnimationFrame(tick); render(); }
    function stop() { playing = false; cancelAnimationFrame(frame); render(); }
    toggle.addEventListener('click', () => playing ? stop() : start());
    scrub.addEventListener('input', () => { at = Number(scrub.value); render(); });
    function close() {
        stop(); player.remove(); view.remove(); article.classList.remove('replaying');
        for (const node of hidden) node.hidden = false;
        onClose?.();
    }
    done.addEventListener('click', close);
    render();
    if (!matchMedia('(prefers-reduced-motion: reduce)').matches) start();
    return close;
}

/** "97% typed · 3% pasted" from the replay's breakdown of the final text. */
export function mixLabel({ typed, external = 0, pasted, before, other, total }) {
    // As percentLabel in publication-contract.mjs: a part is never rounded away, and "100%" means all of it.
    const percent = value => { const p = value / total * 100; return p >= 100 ? '100%' : p < 1 ? '<1%' : Math.min(99, Math.round(p)) + '%'; };
    const parts = [[typed, 'typed'], [external, 'typed on another keyboard'], [pasted, 'pasted'], [other, 'other edits'], [before, 'there before']]
        .filter(([value]) => value > 0);
    return parts.map(([value, name]) => percent(value) + ' ' + name).join(' · ');
}
