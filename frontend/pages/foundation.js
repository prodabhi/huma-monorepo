// The home page: smooth wheel scrolling, a typed loader that opens like an eye, the hero's picture in WebGL and
// scramble text.
// No dependencies: the server's CSP only allows same-origin scripts.
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
// The typed opening plays on a visitor's first visit only; after that the page opens straight on the headline.
const INTRO_SEEN = 'huma.intro';
const seenIntro = (() => { try { return localStorage.getItem(INTRO_SEEN) === '1'; } catch { return false; } })();
const skipIntro = reduced || seenIntro || new URLSearchParams(location.search).has('noloader');
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
const lerp = (a, b, t) => a + (b - a) * t;
const range = (v, a, b) => clamp((v - a) / (b - a));
const smooth = t => t * t * (3 - 2 * t);
const easeOut = t => 1 - Math.pow(1 - t, 3);
const easeInOut = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
const sleep = ms => new Promise(r => setTimeout(r, ms));
// Start Writing opens the editor in one click; on a Mac, the button beside it downloads the Mac app (an iPad says
// "Macintosh" too, but has touch).
if (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints <= 1) {
  for (const link of $$('[data-mac]')) link.hidden = false;
  for (const link of $$('[data-not-mac]')) link.hidden = true;
}

// ---------- Text ----------
const GLYPHS = '!<>-_\\/[]{}=+*^?#%&$';
const glyph = () => GLYPHS[Math.random() * GLYPHS.length | 0];
const blank = s => s.replace(/[^\n]/g, ' ');

// Types text in (or out) with a short tail of random glyphs; the untyped rest stays as spaces so nothing reflows.
function typeText(el, text, { cps = 60, tail = 6, reverse = false, pad = true } = {}) {
    return new Promise(resolve => {
        const start = performance.now();
        const step = now => {
            const k = Math.floor((now - start) / 1000 * cps);
            const shown = reverse ? Math.max(0, text.length - k) : Math.min(text.length, k);
            let out = text.slice(0, shown);
            const t = Math.min(tail, text.length - shown);
            for (let i = 0; i < t; i++) { const ch = text[shown + i]; out += ch === '\n' || ch === ' ' ? ch : glyph(); }
            if (pad) out += blank(text.slice(shown + t));
            el.textContent = out;
            if (reverse ? shown > 0 : shown < text.length) requestAnimationFrame(step);
            else { el.textContent = reverse ? (pad ? blank(text) : '') : text; resolve(); }
        };
        requestAnimationFrame(step);
    });
}

function prepareScramble(el) {
    el.dataset.text = el.innerText.replace(/ /g, ' ');
    el.style.whiteSpace = 'pre-line';
    el.textContent = blank(el.dataset.text);
}
const scrambleIn = el => typeText(el, el.dataset.text, { cps: Math.max(45, el.dataset.text.length / .75), tail: 5 });

// Splits a heading into its rendered lines (for the staggered intro), returning a function that undoes it.
function splitLines(el) {
    const html = el.innerHTML;
    const words = el.textContent.trim().split(/\s+/);
    el.textContent = '';
    const spans = words.map(w => { const s = document.createElement('span'); s.textContent = w + ' '; el.append(s); return s; });
    const lines = [];
    let top = null;
    for (const s of spans) { if (s.offsetTop !== top) { lines.push([]); top = s.offsetTop; } lines.at(-1).push(s.textContent); }
    el.textContent = '';
    lines.forEach((ws, i) => {
        const line = document.createElement('span');
        line.className = 'ln';
        line.textContent = ws.join('').trimEnd();
        line.style.transitionDelay = i * 110 + 'ms';
        el.append(line);
    });
    return () => { el.innerHTML = html; };
}

function setupPlusLinks(root = document) {
    for (const a of $$('.plus', root)) {
        if (a.dataset.plus) continue;
        a.dataset.plus = '1';
        const label = document.createElement('span');
        label.className = 'lbl';
        label.textContent = a.textContent.trim();
        const br = document.createElement('span');
        br.className = 'br';
        br.innerHTML = '<span>[</span><i>+</i><span>]</span>';
        a.textContent = '';
        a.append(label, br);
    }
}

// ---------- Smooth wheel scrolling (native scroll position, so sticky keeps working) ----------
const scroller = { y: scrollY, target: scrollY, active: false };
const maxY = () => document.documentElement.scrollHeight - innerHeight;
function setupScroll() {
    addEventListener('wheel', e => {
        if (document.body.classList.contains('is-loading')) { e.preventDefault(); return; }
        if (reduced || e.ctrlKey) return;
        e.preventDefault();
        const d = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaMode === 2 ? e.deltaY * innerHeight : e.deltaY;
        if (!scroller.active) scroller.y = scroller.target = scrollY;
        scroller.target = clamp(scroller.target + d, 0, maxY());
        scroller.active = true;
    }, { passive: false });
    addEventListener('scroll', () => { if (!scroller.active) scroller.y = scroller.target = scrollY; }, { passive: true });
    for (const a of $$('a[href^="#"]')) {
        const id = a.getAttribute('href');
        if (id.length < 2) continue;
        a.addEventListener('click', e => {
            const el = $(id);
            if (!el) return;
            e.preventDefault();
            scroller.y = scrollY;
            scroller.target = clamp(el.getBoundingClientRect().top + scrollY, 0, maxY());
            scroller.active = !reduced;
            if (reduced) scrollTo(0, scroller.target);
        });
    }
}
function stepScroll(dt) {
    if (!scroller.active) return;
    scroller.y = lerp(scroller.y, scroller.target, 1 - Math.pow(.9, dt * 60));
    if (Math.abs(scroller.target - scroller.y) < .5) { scroller.y = scroller.target; scroller.active = false; }
    scrollTo(0, scroller.y);
}

// ---------- WebGL ----------
const NOISE = `
float hash(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
uniform vec2 uRes;uniform float uTime;uniform float uProg;uniform vec2 uMouse;
uniform vec2 uImgSize;uniform sampler2D uImg;
vec2 cover(vec2 uv){float ra=uRes.x/uRes.y,ia=uImgSize.x/max(uImgSize.y,1.);
  vec2 s=ra>ia?vec2(1.,ia/ra):vec2(ra/ia,1.);return (uv-.5)*s+.5;}
`;

// The hero: the picture, with the figure right of centre on wide screens (toward it on narrow ones), a wash of its
// own paper calming the side the text is on, easing closer as you scroll.
const HERO = `
void main(){
  vec2 uv=gl_FragCoord.xy/uRes;float wide=smoothstep(.9,1.3,uRes.x/uRes.y);
  vec2 m=cover((uv-.5)/(1.+uProg*.3)+.5+uMouse*.004);m.x+=.18*(1.-wide);
  vec3 col=texture2D(uImg,m).rgb;
  vec3 bg=max(max(texture2D(uImg,vec2(.02,.55)).rgb,texture2D(uImg,vec2(.98,.9)).rgb),max(texture2D(uImg,vec2(.98,.55)).rgb,texture2D(uImg,vec2(.02,.9)).rgb));
  // narrow screens: the lower half (where the text is) fades out, and all of it as you scroll
  float wash=mix(max(1.-smoothstep(.42,.8,uv.y),smoothstep(.08,.45,uProg)*.85),1.-smoothstep(.06,.5,uv.x),wide)*.92;
  col=mix(col,bg,wash);
  vec2 v=uv-.5;col*=1.-.2*dot(v,v*vec2(1.,1.3));
  col+=(hash(gl_FragCoord.xy+fract(uTime*7.)*91.)-.5)*.025;
  gl_FragColor=vec4(col,1.);
}
`;

function compile(gl, vs, fs) {
    const prog = gl.createProgram();
    for (const [type, src] of [[gl.VERTEX_SHADER, vs], [gl.FRAGMENT_SHADER, fs]]) {
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh));
        gl.attachShader(prog, sh);
    }
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
    return prog;
}
const getUniforms = (gl, prog, names) => Object.fromEntries(names.map(n => [n, gl.getUniformLocation(prog, n)]));
function fit(canvas, gl, scale, cap = 2) {
    const r = Math.min(devicePixelRatio || 1, cap) * scale;
    const w = Math.max(1, Math.round(canvas.clientWidth * r)), h = Math.max(1, Math.round(canvas.clientHeight * r));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    gl.viewport(0, 0, w, h);
    return r;
}
const getGL = canvas => canvas.getContext('webgl', { antialias: false, alpha: false, depth: false, stencil: false, powerPreference: 'high-performance' });

// The hero's picture in WebGL. Nothing is drawn until the picture is on the GPU; until then the stage shows the
// same picture as its CSS background, and the canvas fades in over it (foundation.css).
function heroScene(canvas) {
    const gl = getGL(canvas);
    if (!gl) return null;
    const prog = compile(gl, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}', 'precision highp float;\n' + NOISE + HERO);
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const u = getUniforms(gl, prog, ['uRes', 'uTime', 'uProg', 'uMouse', 'uImgSize', 'uImg']);
    gl.bindTexture(gl.TEXTURE_2D, gl.createTexture());
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
    for (const [k, v] of [[gl.TEXTURE_MIN_FILTER, gl.LINEAR], [gl.TEXTURE_MAG_FILTER, gl.LINEAR], [gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE]]) gl.texParameteri(gl.TEXTURE_2D, k, v);
    let ready = false;
    const img = new Image();
    img.src = canvas.dataset.media;
    img.decode().then(() => {
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, img);
        gl.uniform2f(u.uImgSize, img.naturalWidth, img.naturalHeight);
        gl.uniform1i(u.uImg, 0);
        ready = true;
    }, () => {});
    return {
        draw(time, progress, mouse) {
            if (!ready) return;
            fit(canvas, gl, 1, 2);
            gl.uniform2f(u.uRes, canvas.width, canvas.height);
            gl.uniform1f(u.uTime, time);
            gl.uniform1f(u.uProg, progress);
            gl.uniform2f(u.uMouse, mouse[0], mouse[1]);
            gl.drawArrays(gl.TRIANGLES, 0, 3);
            canvas.classList.add('is-ready');
        },
    };
}

// The scenes are 100vh tall. On phones that's the height with the browser's bars hidden, which stays put while
// the bars slide in and out (innerHeight doesn't), so measure it from a stage and update it on resize.
let stageHeight = innerHeight;
const measureStage = () => { stageHeight = document.querySelector('.stage')?.offsetHeight || innerHeight; };

// ---------- Intro ----------
async function intro() {
    const loader = $('[data-loader]');
    const heroLabels = $$('.hero_one [data-scramble-in]');
    const restore = splitLines($('.hero_title'));
    const showText = () => {
        document.body.classList.remove('is-intro');
        heroLabels.forEach((el, i) => setTimeout(() => scrambleIn(el), 150 + i * 120));
    };
    const finish = () => {
        document.body.classList.remove('is-loading', 'is-intro');
        loader.classList.add('is-done');
        setTimeout(restore, 1800);
    };
    if (skipIntro) { heroLabels.forEach(el => { el.textContent = el.dataset.text; }); finish(); return; }
    try { localStorage.setItem(INTRO_SEEN, '1'); } catch {}
    document.body.classList.add('is-intro');
    let skipped = false;
    const skip = () => { skipped = true; };
    $('[data-skip]').addEventListener('click', skip);
    $('[data-skip]').classList.add('is-on');
    addEventListener('keydown', skip, { once: true });
    const wait = ms => new Promise(r => { const t0 = performance.now(); const tick = () => skipped || performance.now() - t0 >= ms ? r() : requestAnimationFrame(tick); tick(); });
    const codes = $$('[data-type]', loader).map(el => { const text = el.textContent; el.textContent = ''; return { el, text }; });
    const logo = $('.loader_logo', loader);
    await wait(250);
    logo.classList.add('is-on');
    await wait(550);
    if (!skipped) await Promise.all(codes.map((c, i) => sleep(i * 650).then(() => typeText(c.el, c.text, { cps: 75, tail: 8, pad: false }))));
    await wait(1000);
    if (!skipped) await Promise.all(codes.map(c => typeText(c.el, c.text, { cps: 110, tail: 8, reverse: true, pad: false })));
    logo.classList.remove('is-on');
    await wait(450);
    // The opening: a thin wide slit that widens first, then opens tall past the edges.
    const eye = (target, dur, onHalf) => new Promise(resolve => {
        const start = performance.now();
        let half = false;
        const step = now => {
            const t = skipped ? 1 : clamp((now - start) / dur);
            target.style.setProperty('--rx', lerp(4, 190, easeOut(Math.min(1, t * 1.25))) + 'vw');
            target.style.setProperty('--ry', lerp(.5, 190, Math.pow(easeInOut(t), 1.35)) + 'vh');
            if (!half && t > .38) { half = true; onHalf?.(); }
            if (t < 1) requestAnimationFrame(step); else resolve();
        };
        requestAnimationFrame(step);
    });
    loader.classList.add('is-eye');
    await eye(loader, 1500, showText);
    if (skipped) showText();
    finish();
}
// ---------- Main ----------
async function main() {
    await document.fonts.ready.catch(() => {});
    $$('[data-scramble-in]').forEach(prepareScramble);
    setupPlusLinks();
    setupScroll();
    const nav = $('[data-nav]');
    let heroGL = null;
    try { const c = $('[data-gl="hero"]'); if (c) heroGL = heroScene(c); } catch (e) { console.warn('hero', e); }
    measureStage();
    addEventListener('resize', measureStage);
    const hero = { el: $('[data-stage="hero"]'), p: 0, visible: false };
    const themed = $$('[data-theme]');

    // Labels below the hero scramble in as they scroll into view.
    const io = new IntersectionObserver(entries => {
        for (const e of entries) {
            if (!e.isIntersecting) continue;
            scrambleIn(e.target);
            io.unobserve(e.target);
        }
    }, { threshold: .25 });
    $$('[data-scramble-in]').forEach(el => { if (!el.closest('.hero_one')) io.observe(el); });

    const mouse = [0, 0], eased = [0, 0];
    addEventListener('pointermove', e => { mouse[0] = e.clientX / innerWidth - .5; mouse[1] = .5 - e.clientY / innerHeight; }, { passive: true });

    intro();
    let last = performance.now(), time = 0;
    const frame = now => {
        const dt = Math.min(.05, (now - last) / 1000);
        last = now;
        time += reduced ? dt * .2 : dt;
        stepScroll(dt);
        eased[0] = lerp(eased[0], mouse[0], .05); eased[1] = lerp(eased[1], mouse[1], .05);
        const vh = stageHeight;
        if (hero.el) {
            const r = hero.el.getBoundingClientRect();
            hero.visible = r.bottom > 0 && r.top < vh;
            hero.p = clamp(-r.top / Math.max(1, r.height - vh));
        }
        if (hero.visible) {
            heroGL?.draw(time, hero.p, eased);
            $('.hero_white').style.setProperty('--w', lerp(-40, 100, smooth(range(hero.p, .74, 1))) + '%');
        }
        // Nav colour follows whatever sits under it.
        const y = 45;
        let light = true;
        for (const el of themed) {
            const r = el.getBoundingClientRect();
            if (r.top > y || r.bottom < y) continue;
            light = el.dataset.theme !== 'dark';
            break;
        }
        nav.classList.toggle('is-light', light);
        requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
}
main();
