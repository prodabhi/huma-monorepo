// /foundation: smooth wheel scrolling, a typed loader that opens like an eye, sticky WebGL stages
// (lens sky, particle figures, particle flower, terrain), scramble text and scroll-linked overlays.
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
        if (a.hasAttribute('data-hover-scramble')) {
            const text = label.textContent;
            a.addEventListener('mouseenter', () => typeText(label, text, { cps: 40, tail: 4, pad: false }));
        }
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

// ---------- Nav ----------
function setupNav() {
    return $('[data-nav]');
}

// ---------- WebGL ----------
const NOISE = `
float hash(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
float noise(vec2 p){vec2 i=floor(p),f=fract(p);vec2 u=f*f*(3.-2.*f);
  return mix(mix(hash(i),hash(i+vec2(1,0)),u.x),mix(hash(i+vec2(0,1)),hash(i+vec2(1,1)),u.x),u.y);}
float fbm(vec2 p){float v=0.,a=.5;mat2 m=mat2(1.6,1.2,-1.2,1.6);for(int i=0;i<5;i++){v+=a*noise(p);p=m*p;a*=.5;}return v;}
float fbm3o(vec2 p){float v=0.,a=.5;mat2 m=mat2(1.6,1.2,-1.2,1.6);for(int i=0;i<3;i++){v+=a*noise(p);p=m*p;a*=.5;}return v;}
float hash3(vec3 p){p=fract(p*.3183099+.1);p*=17.;return fract(p.x*p.y*p.z*(p.x+p.y+p.z));}
float noise3(vec3 x){vec3 i=floor(x),f=fract(x);f=f*f*(3.-2.*f);
  return mix(mix(mix(hash3(i),hash3(i+vec3(1,0,0)),f.x),mix(hash3(i+vec3(0,1,0)),hash3(i+vec3(1,1,0)),f.x),f.y),
             mix(mix(hash3(i+vec3(0,0,1)),hash3(i+vec3(1,0,1)),f.x),mix(hash3(i+vec3(0,1,1)),hash3(i+vec3(1,1,1)),f.x),f.y),f.z);}
float fbm3(vec3 p){float v=0.,a=.5;for(int i=0;i<4;i++){v+=a*noise3(p);p=p*2.03+vec3(1.7,9.2,3.1);a*=.5;}return v;}
uniform vec2 uRes;uniform float uTime;uniform float uProg;uniform vec2 uMouse;
uniform float uHasImg;uniform vec2 uImgSize;uniform sampler2D uImg;
vec2 cover(vec2 uv){float ra=uRes.x/uRes.y,ia=uImgSize.x/max(uImgSize.y,1.);
  vec2 s=ra>ia?vec2(1.,ia/ra):vec2(ra/ia,1.);return (uv-.5)*s+.5;}
`;

// The hero: a streaked sky (or your photo) bent around a glass sphere that rises from the bottom edge.
const HERO = `
vec3 sky(vec2 uv){
  vec2 p=uv-vec2(.5,.6);p.x*=uRes.x/uRes.y;float r=length(p);
  vec3 col=mix(vec3(.64,.71,.84),vec3(.21,.35,.62),smoothstep(.05,1.,uv.y));
  float n=0.;
  for(int i=0;i<3;i++){
    vec2 q=p*(1.-.3*r)*(1.+float(i)*.045);
    q=vec2(q.x*.8,q.y*2.6);
    n+=fbm(q*1.1+vec2(uTime*.018,0.)+fbm(q*.6+3.)*1.5);
  }
  n/=3.;
  float fine=fbm(vec2(p.x*4.,p.y*14.)+vec2(uTime*.03,0.));
  float c=smoothstep(.36,.66,n*.85+fine*.3)*(.55+.45*smoothstep(.0,.6,uv.y));
  vec3 lit=vec3(.94,.89,.93),shade=vec3(.47,.50,.66);
  vec3 cc=mix(shade,lit,smoothstep(.42,.8,fine*.6+n*.6));
  return mix(col,cc,c*.95);
}
vec3 base(vec2 uv){return uHasImg>.5?texture2D(uImg,cover(uv)).rgb:sky(uv);}
// Your video instead of the sky and sphere: on wide screens the figure sits right of centre (the left margin
// is mirrored), a wash of the video's own background calms the side the text is on, and it eases closer
// as you scroll. A still (uHasImg 2) is already composed, so it stays as it is, only moved toward its figure on
// narrow screens.
vec3 film(vec2 uv,float asp){
  float wide=smoothstep(.9,1.3,asp),still=step(1.5,uHasImg);vec2 o=vec2(.5+.18*wide*(1.-still),.5);
  vec2 m=cover((uv-o)/(1.+uProg*.3)+o+uMouse*.004);
  if(still<.5)m.x=abs(m.x-.17*wide+.06*(1.-wide));else m.x+=.18*(1.-wide);
  vec3 v=texture2D(uImg,m).rgb;
  vec3 bg=max(max(texture2D(uImg,vec2(.02,.55)).rgb,texture2D(uImg,vec2(.98,.9)).rgb),max(texture2D(uImg,vec2(.98,.55)).rgb,texture2D(uImg,vec2(.02,.9)).rgb));
  // narrow screens: the lower half (where the text is) fades out, and all of it as you scroll
  float wash=mix(max(1.-smoothstep(.42,.8,uv.y),smoothstep(.08,.45,uProg)*.85),1.-smoothstep(.06,.5,uv.x),wide)*.92;
  return mix(v,bg,wash);
}
void main(){
  vec2 uv=gl_FragCoord.xy/uRes;float asp=uRes.x/uRes.y;vec3 col;
  if(uHasImg>.5)col=film(uv,asp);else{
  uv+=uMouse*.006;uv.y-=uProg*.07;
  vec2 s=vec2((uv.x-.5)*asp,uv.y);
  float R=.8*asp;vec2 c=vec2(0.,-R-.03+uProg*.42);
  vec2 dv=s-c;float d=length(dv);
  if(d>R){
    float k=.0028*R/(d-R+.03);
    vec2 sw=s+normalize(dv)*k;
    col=base(vec2(sw.x/asp+.5,sw.y));
  }else{
    vec2 q=dv/R;float l=length(q);float z=sqrt(max(0.,1.-l*l));
    vec3 refr=base(vec2(q.x*.42+.5,.6-q.y*.35));
    vec3 ground=mix(vec3(.30,.24,.17),vec3(.78,.63,.42),smoothstep(.82,1.,l));
    col=mix(refr*.8,ground,smoothstep(.7,1.,l)*.6);
    col=mix(col,vec3(.16,.15,.15),smoothstep(.9,.97,l)*(1.-smoothstep(.97,1.,l))*.55);
    col+=vec3(.95,.84,.66)*smoothstep(.99,1.,l)*.5;
    col*=.86+.14*z;
  }
  }
  vec2 v=gl_FragCoord.xy/uRes-.5;col*=1.-.2*dot(v,v*vec2(1.,1.3));
  col+=(hash(gl_FragCoord.xy+fract(uTime*7.)*91.)-.5)*.025;
  gl_FragColor=vec4(col,1.);
}`;

// The event stage: a ridge seen from a slowly advancing drone camera (or your video), with a swirl warp.
const SUMMIT = `
float h(vec2 p){float rx=p.x+sin(p.y*.21)*1.4+sin(p.y*.083+1.3)*2.2;
  return 3.*exp(-rx*rx*.09)+fbm3o(p*.22)*1.8-1.6;}
float hd(vec2 p){return h(p)+noise(p*1.3)*.25+noise(p*4.1)*.06;}
vec3 terrain(vec2 uv){
  vec2 p=uv*2.-1.;p.x*=uRes.x/uRes.y;
  vec3 ro=vec3(-.6,5.2-uProg*1.2,-6.+uProg*9.);
  vec3 ww=normalize(vec3(.12,-1.55,3.)),uu=normalize(cross(ww,vec3(0,1,0))),vv=cross(uu,ww);
  vec3 rd=normalize(p.x*uu+p.y*vv+1.6*ww);
  float t=.2;bool hit=false;
  for(int i=0;i<72;i++){vec3 q=ro+rd*t;float dh=q.y-h(q.xz);if(dh<.002*t){hit=true;break;}t+=dh*.5;if(t>45.)break;}
  vec3 haze=vec3(.91,.92,.93);
  vec3 skyc=mix(haze,vec3(.16,.21,.31),smoothstep(.05,.9,rd.y));
  if(!hit)return skyc;
  vec3 q=ro+rd*t;vec2 e=vec2(.03,0.);
  vec3 n=normalize(vec3(hd(q.xz-e.xy)-hd(q.xz+e.xy),2.*e.x,hd(q.xz-e.yx)-hd(q.xz+e.yx)));
  vec3 L=normalize(vec3(-.75,.62,-.1));float dif=clamp(dot(n,L),0.,1.);
  vec3 sand=mix(vec3(.47,.36,.24),vec3(.86,.72,.50),noise(q.xz*2.)*.5+.5);
  vec3 alb=mix(sand,vec3(.62,.60,.58),smoothstep(.55,.35,n.y));
  vec3 col=alb*(dif*1.25+.08);
  col=mix(col,vec3(.05,.06,.08),smoothstep(.22,.0,dif)*.85);
  return mix(col,haze,1.-exp(-t*.05));
}
void main(){
  vec2 uv=gl_FragCoord.xy/uRes;float asp=uRes.x/uRes.y;
  vec2 w=vec2(.72,1.05);vec2 dv=(uv-w)*vec2(asp,1.);float d=length(dv);
  float ang=1.9*exp(-d*1.6)*(.8+.2*sin(uTime*.3));
  float cs=cos(ang),sn=sin(ang);dv=mat2(cs,-sn,sn,cs)*dv;
  dv*=1.+.05*sin(d*26.-uTime*1.5)*exp(-abs(d-.55)*6.);
  vec2 wuv=w+dv/vec2(asp,1.);
  vec3 col=uHasImg>.5?texture2D(uImg,cover(wuv)).rgb:terrain(wuv);
  col+=(hash(gl_FragCoord.xy+fract(uTime*7.)*91.)-.5)*.025;
  gl_FragColor=vec4(col,1.);
}`;

const POINT_VS = `
attribute vec3 aA;attribute vec3 aB;attribute float aSeed;attribute float aTA;attribute float aTB;
uniform float uMix,uTime,uSize,uRot,uTilt,uScale,uFlutter,uDpr,uCycle;uniform vec2 uRes;uniform vec3 uOff;
varying float vA;varying float vT;
void main(){
  float m=clamp((uMix-aSeed*.35)/.65,0.,1.);m=m*m*(3.-2.*m);
  vT=mix(aTA,aTB,m);
  if(uCycle>.5)m=fract(uTime*.32+aSeed*7.13);
  vec3 p=mix(aA,aB,uCycle>.5?m*m:m);
  float k=sin(m*3.14159);
  p+=k*uFlutter*vec3(sin(aSeed*91.7+uTime*.7),cos(aSeed*53.3+uTime*.9),sin(aSeed*17.1+uTime*.5));
  p+=.014*vec3(sin(uTime*1.1+aSeed*40.),cos(uTime*.9+aSeed*30.),sin(uTime*.7+aSeed*20.));
  float c=cos(uRot),s=sin(uRot);p.xz=mat2(c,-s,s,c)*p.xz;
  float ct=cos(uTilt),st=sin(uTilt);p.yz=mat2(ct,-st,st,ct)*p.yz;
  p=p*uScale+uOff;
  float z=max(p.z+4.,.3);
  vec2 q=p.xy*(4./z);q.x*=uRes.y/uRes.x;
  gl_Position=vec4(q,0.,1.);
  gl_PointSize=uSize*uDpr*(4./z);
  vA=clamp(1.45-z*.11,.35,1.);
  if(uCycle>.5)vA*=sin(m*3.14159);
}`;
const POINT_FS = `precision mediump float;
uniform vec3 uCol,uEdge,uWarm;uniform float uAlpha;varying float vA;varying float vT;
void main(){vec2 c=gl_PointCoord-.5;float r=length(c);if(r>.5)discard;
  float a=smoothstep(.5,.38,r);vec3 col=mix(mix(uEdge,uCol,smoothstep(.47,.28,r)),uWarm,vT);
  gl_FragColor=vec4(col,a*uAlpha*vA);}`;

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

function screenScene(canvas, frag, { scale = 1, cap = 2 } = {}) {
    const gl = getGL(canvas);
    if (!gl) return null;
    const prog = compile(gl, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}', 'precision highp float;\n' + NOISE + frag);
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const u = getUniforms(gl, prog, ['uRes', 'uTime', 'uProg', 'uMouse', 'uHasImg', 'uImgSize', 'uImg']);
    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
    for (const [k, v] of [[gl.TEXTURE_MIN_FILTER, gl.LINEAR], [gl.TEXTURE_MAG_FILTER, gl.LINEAR], [gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE]]) gl.texParameteri(gl.TEXTURE_2D, k, v);
    let media = null, uploaded = false, size = [1, 1];
    return {
        canvas,
        setMedia(el) { media = el; uploaded = false; },
        draw(time, prog_, mouse) {
            // the generated scenes render below screen resolution to save work; your footage renders sharp
            fit(canvas, gl, media ? 1 : scale, media ? 2 : cap);
            let has = 0;
            if (media) {
                const video = media.tagName === 'VIDEO';
                const ready = video ? media.readyState >= 2 : media.complete && media.naturalWidth > 0;
                if (ready && (video || !uploaded)) {
                    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, media);
                    size = video ? [media.videoWidth, media.videoHeight] : [media.naturalWidth, media.naturalHeight];
                    uploaded = true;
                }
                has = uploaded ? (video ? 1 : 2) : 0;
            }
            gl.uniform2f(u.uRes, canvas.width, canvas.height);
            gl.uniform1f(u.uTime, time);
            gl.uniform1f(u.uProg, prog_);
            gl.uniform2f(u.uMouse, mouse[0], mouse[1]);
            gl.uniform1f(u.uHasImg, has);
            gl.uniform2f(u.uImgSize, size[0], size[1]);
            gl.uniform1i(u.uImg, 0);
            gl.drawArrays(gl.TRIANGLES, 0, 3);
        },
    };
}

// ---------- Point clouds ----------
function mulberry(a) { return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function unit(rnd) { let x, y, z, l; do { x = rnd() * 2 - 1; y = rnd() * 2 - 1; z = rnd() * 2 - 1; l = x * x + y * y + z * z; } while (l > 1 || l < 1e-4); l = Math.sqrt(l); return [x / l, y / l, z / l]; }
function fromFn(n, seed, fn) { const rnd = mulberry(seed); return Array.from({ length: n }, () => fn(rnd)); }
// Sorting every shape the same way pairs points top-to-bottom, so morphs sweep instead of scrambling.
// Each shape also notes its middle (ignoring the outer 2% of points), so a scene can keep every shape in one place.
function pack(pts) {
    pts.sort((a, b) => (b[1] * 3 + b[0] * .25) - (a[1] * 3 + a[0] * .25));
    const middle = k => { const v = pts.map(p => p[k]).sort((a, b) => a - b), at = f => v[Math.floor(f * (v.length - 1))]; return (at(.02) + at(.98)) / 2; };
    return { pos: new Float32Array(pts.flatMap(p => [p[0], p[1], p[2]])), tag: new Float32Array(pts.map(p => p[3] ?? 0)), mid: [middle(0), middle(1)] };
}

// ---------- Line drawings in dots ----------
// Figures are drawn the way an illustrator would: dense strokes for outlines and details, a light scatter
// for surfaces, so they read at a glance with small dots. A stroke's share of the points follows its
// length times its weight. Tag 1 marks bot points, which render in the warm colour.
function stroke(fn, w = 1, tag = 0, steps = 24) {
    let len = 0, prev = fn(0);
    for (let i = 1; i <= steps; i++) { const p = fn(i / steps); len += Math.hypot(p[0] - prev[0], p[1] - prev[1], p[2] - prev[2]); prev = p; }
    return { w: len * w, tag, at: fn };
}
const line = (a, b, w, tag) => stroke(t => a.map((v, i) => v + (b[i] - v) * t), w, tag, 1);
const arc = ([cx, cy, cz], r, w, tag, a0 = 0, a1 = Math.PI * 2) => stroke(t => { const a = a0 + (a1 - a0) * t; return [cx + Math.cos(a) * r, cy + Math.sin(a) * r, cz]; }, w, tag);
// Filled areas: a patch is weighted per unit area; a disc like a short stroke, so small ones stay solid.
const patch = (sample, area, w = 1, tag = 0) => ({ w: area * w, tag, sample });
const disc = ([cx, cy, cz], r, w = 1, tag = 0) => ({ w: r * 6 * w, tag, sample: rnd => { const a = rnd() * Math.PI * 2, k = Math.sqrt(rnd()) * r; return [cx + Math.cos(a) * k, cy + Math.sin(a) * k, cz]; } });
function rrect([cx, cy, cz], hw, hh, r, w, tag) {
    const x0 = cx - hw + r, x1 = cx + hw - r, y0 = cy - hh + r, y1 = cy + hh - r, q = Math.PI / 2;
    return [line([x0, cy + hh, cz], [x1, cy + hh, cz], w, tag), line([x0, cy - hh, cz], [x1, cy - hh, cz], w, tag),
        line([cx - hw, y0, cz], [cx - hw, y1, cz], w, tag), line([cx + hw, y0, cz], [cx + hw, y1, cz], w, tag),
        arc([x1, y1, cz], r, w, tag, 0, q), arc([x0, y1, cz], r, w, tag, q, 2 * q), arc([x0, y0, cz], r, w, tag, 2 * q, 3 * q), arc([x1, y0, cz], r, w, tag, 3 * q, 4 * q)];
}
// Spreads n points over the strokes and patches: evenly along each stroke, with a little jitter.
function drawing(prims, n, seed, jitter = .007) {
    prims = prims.flat(Infinity);
    const rnd = mulberry(seed), total = prims.reduce((sum, p) => sum + p.w, 0), pts = [];
    let carry = 0;
    for (const p of prims) {
        const exact = p.w / total * n + carry, k = Math.round(exact);
        carry = exact - k;
        for (let i = 0; i < k; i++) {
            const q = p.sample ? p.sample(rnd) : p.at((i + rnd()) / k);
            pts.push([q[0] + (rnd() - .5) * jitter * 2, q[1] + (rnd() - .5) * jitter * 2, q[2] + (rnd() - .5) * jitter * 2, p.tag]);
        }
    }
    while (pts.length < n) pts.push(pts[rnd() * pts.length | 0].slice());
    return pts.slice(0, n);
}

// A bot: a squared-off head with antenna, eyes, a grille mouth and ears, on a body with a chest panel
// (matching the #bot-mark icon). reach (-1 left, 1 right) stretches one arm out with a claw.
function robot([cx, cy, cz], s, turn = 0, reach = 0) {
    const c = Math.cos(turn), sn = Math.sin(turn);
    const P = ([x, y, z]) => [cx + (x * c - y * sn) * s, cy + (x * sn + y * c) * s, cz + z * s];
    const parts = [
        rrect([0, 0, 0], 1, .8, .2, 1.7, 1), patch(r => [(r() * 2 - 1) * .94, (r() * 2 - 1) * .74, 0], 2.8, .04, 1),
        disc([-.42, .16, 0], .19, 2.6, 1), disc([.42, .16, 0], .19, 2.6, 1),
        rrect([0, -.4, 0], .44, .13, .05, 1.3, 1), [-.22, 0, .22].map(x => line([x, -.53, 0], [x, -.27, 0], 1.1, 1)),
        line([0, .8, 0], [0, 1.1, 0], 1.7, 1), disc([0, 1.24, 0], .13, 2.6, 1),
        rrect([-1.13, 0, 0], .13, .3, .06, 1.3, 1), rrect([1.13, 0, 0], .13, .3, .06, 1.3, 1),
        line([-.2, -.8, 0], [-.2, -.98, 0], 1.4, 1), line([.2, -.8, 0], [.2, -.98, 0], 1.4, 1),
        rrect([0, -1.6, 0], .78, .62, .16, 1.7, 1), patch(r => [(r() * 2 - 1) * .72, -1.6 + (r() * 2 - 1) * .56, 0], 1.8, .04, 1),
        rrect([0, -1.48, 0], .34, .2, .05, 1.2, 1), disc([-.16, -1.86, 0], .07, 2.4, 1), disc([.16, -1.86, 0], .07, 2.4, 1),
    ];
    // arms: hanging, or one reaching out with a claw
    for (const side of [-1, 1]) {
        if (side === reach) parts.push(line([side * .78, -1.2, 0], [side * 1.65, -.98, 0], 1.7, 1), line([side * 1.65, -.98, 0], [side * 1.86, -.84, 0], 1.5, 1), line([side * 1.65, -.98, 0], [side * 1.84, -1.14, 0], 1.5, 1));
        else parts.push(line([side * .78, -1.2, 0], [side * 1.02, -1.9, 0], 1.7, 1), disc([side * 1.04, -1.98, 0], .09, 2.4, 1));
    }
    return parts.flat().map(p => ({ w: p.w * s, tag: p.tag, ...(p.sample ? { sample: r => P(p.sample(r)) } : { at: t => P(p.at(t)) }) }));
}
// A person as a filled pictogram: head, body, arms and legs. d = 1 faces right, -1 faces left.
function capsule(a, b, r, w = 1, tag = 0) {
    const ab = [b[0] - a[0], b[1] - a[1]], len2 = ab[0] ** 2 + ab[1] ** 2 || 1e-9;
    const lo = [Math.min(a[0], b[0]) - r, Math.min(a[1], b[1]) - r], hi = [Math.max(a[0], b[0]) + r, Math.max(a[1], b[1]) + r];
    return patch(rnd => {
        for (;;) {
            const x = lo[0] + rnd() * (hi[0] - lo[0]), y = lo[1] + rnd() * (hi[1] - lo[1]);
            const t = clamp(((x - a[0]) * ab[0] + (y - a[1]) * ab[1]) / len2), d = Math.hypot(x - a[0] - ab[0] * t, y - a[1] - ab[1] * t);
            if (d <= r) return [x, y, (rnd() < .5 ? -1 : 1) * Math.sqrt(r * r - d * d) * .7];
        }
    }, 2 * r * Math.sqrt(len2) + Math.PI * r * r, w, tag);
}
function figure(x0, d = 1, pose = 'talk') {
    const P = (x, y) => [x0 + x * d, y];
    const arms = {
        // forearms raised in front, palms out, holding something off
        shield: [[P(.1, .74), P(.36, .56), .065], [P(.36, .56), P(.4, 1.1), .06], [P(-.02, .74), P(.28, .5), .065], [P(.28, .5), P(.5, .86), .06]],
        // one hand out in conversation, the other at rest
        // one hand cupped behind the ear
        ear: [[P(-.06, .74), P(-.24, .92), .065], [P(-.24, .92), P(-.05, 1.1), .06], [P(.1, .74), P(.15, .44), .065], [P(.15, .44), P(.16, .18), .06]],
        // arms relaxed at the sides
        listen: [[P(.1, .74), P(.15, .44), .065], [P(.15, .44), P(.16, .18), .06], [P(-.1, .74), P(-.15, .44), .065], [P(-.15, .44), P(-.16, .18), .06]],
        talk: [[P(.12, .74), P(.3, .5), .065], [P(.3, .5), P(.54, .64), .06], [P(-.12, .74), P(-.17, .44), .065], [P(-.17, .44), P(-.18, .18), .06]],
    }[pose];
    return [
        capsule(P(.03, 1.12), P(.03, 1.12), .15), capsule(P(0, .72), P(0, .32), .2),
        capsule(P(.07, .24), P(.16, -.42), .085), capsule(P(.16, -.42), P(.18, -.95), .075), capsule(P(.18, -.98), P(.3, -.99), .045),
        capsule(P(-.07, .24), P(-.12, -.42), .085), capsule(P(-.12, -.42), P(-.2, -.95), .075), capsule(P(-.2, -.98), P(-.08, -.99), .045),
        ...arms.map(([a, b, r]) => capsule(a, b, r)),
    ];
}

// Moves a drawing in space (patch weights follow area, so density stays even).
function placed(prims, [dx, dy, dz], k = 1) {
    const f = q => [dx + q[0] * k, dy + q[1] * k, dz + q[2] * k];
    return prims.flat(Infinity).map(p => p.sample ? { w: p.w * k * k, tag: p.tag, sample: r => f(p.sample(r)) } : { w: p.w * k, tag: p.tag, at: t => f(p.at(t)) });
}
const weighted = (prims, k) => prims.flat(Infinity).map(p => ({ ...p, w: p.w * k }));
const poly = (pts, w, tag) => pts.slice(1).map((q, k) => line(pts[k], q, w, tag));
// Mouth to mouth: one person speaks, the sound reaches the other, who listens with a hand to the ear.
function oral(n, seed) {
    const mouth = [-.56, 1.08, 0];
    return drawing([
        weighted(figure(-.75, 1, 'talk'), 3), weighted(figure(.75, -1, 'ear'), 3),
        [.15, .27, .39].map(r => arc(mouth, r, .8, 0, -Math.PI * .22, Math.PI * .22)),
    ], n, seed);
}
// An open book: pages rising from the spine, stacked page edges, the cover, and lines of text.
function book(n, seed) {
    const rnd = mulberry(seed);
    const arch = u => .2 * Math.sin(Math.PI * u * .9) - .05 * u;
    const page = (s, u, v) => [s * (.02 + u), -.05 + v * .58 + arch(u), -.25 * Math.sin(Math.PI * u * .5)]; // v: -1 bottom, 1 top
    const prims = [line(page(1, 0, -1), page(1, 0, 1), 1.4)];
    for (const s of [-1, 1]) {
        prims.push(stroke(u => page(s, u, 1), 1.4), stroke(u => page(s, u, -1), 1.4), stroke(v => page(s, 1, v * 2 - 1), 1.4));
        for (const d of [.035, .07, .105, .15]) { // page edges under the open pages, then the cover
            const w = d > .12 ? 1.2 : .6;
            prims.push(stroke(u => { const p = page(s, u, -1); return [p[0] + s * d * u, p[1] - d, p[2]]; }, w));
            prims.push(stroke(v => { const p = page(s, 1, v * 2 - 1); return [p[0] + s * d, p[1] - d, p[2]]; }, w));
        }
        for (let j = 0; j < 9; j++) {
            if (j === 4) continue; // paragraph break
            const v = .72 - j * .18, end = j === 3 || j === 8 ? .45 + rnd() * .25 : .88;
            for (let u = .12; u < end - .04;) {
                const len = Math.min(end - u, .05 + rnd() * .13), u0 = u;
                prims.push(stroke(t => page(s, u0 + t * len, v), .75, 0, 4));
                u += len + .035;
            }
        }
        prims.push(patch(r => page(s, r(), r() * 2 - 1), 1.2, .5));
    }
    return drawing(prims, n, seed);
}
// A television set: cabinet, a screen with a presenter, knobs, speaker, antennas and legs.
function television(n, seed) {
    const z = -.15, b = .25, zm = z + b / 2, sx = -.24, sy = .04;
    const prims = [
        rrect([0, .02, z], 1, .68, .14, 1.4), rrect([0, .02, z + b], .96, .64, .12, .35),
        [[-1, .7], [1, .7], [-1, -.66], [1, -.66]].map(([x, y]) => line([x * .96, y, z], [x * .92, y * .94, z + b], .5)),
        rrect([sx, sy, z], .64, .5, .17, 1.4), rrect([sx, sy, z], .58, .44, .13, .6),
        Array.from({ length: 9 }, (_, k) => line([sx - .54, sy - .36 + k * .09, z], [sx + .54, sy - .36 + k * .09, z], .18)),
        arc([sx, sy + .1, z], .12, 1.2), arc([sx, sy - .36, z], .27, 1.2, 0, 0, Math.PI),
        line([sx - .27, sy - .36, z], [sx - .27, sy - .44, z], 1.2), line([sx + .27, sy - .36, z], [sx + .27, sy - .44, z], 1.2),
        arc([.72, .34, z], .1, 1.2), line([.72, .34, z], [.78, .41, z], 1.2), arc([.72, .07, z], .1, 1.2), line([.72, .07, z], [.66, .14, z], 1.2),
        [-.2, -.29, -.38, -.47].map(y => line([.6, y, z], [.84, y, z], .9)),
        arc([0, .7, zm], .13, 1.2, 0, 0, Math.PI), line([-.06, .8, zm], [-.55, 1.34, zm], 1.3), line([.06, .8, zm], [.5, 1.3, zm], 1.3),
        disc([-.55, 1.34, zm], .045, 2), disc([.5, 1.3, zm], .045, 2),
        line([-.7, -.66, zm], [-.8, -.92, zm], 1.3), line([.7, -.66, zm], [.8, -.92, zm], 1.3),
    ];
    return drawing(prims, n, seed);
}
// A newspaper: masthead, headline, a photo and columns of text, with the next page behind.
function newspaper(n, seed) {
    const rnd = mulberry(seed), z = -.05, prims = [rrect([0, .1, z], .75, 1, .02, 1.4), rrect([.07, .04, z + .18], .75, 1, .02, .35)];
    for (const y of [.97, .945, .92, .895]) prims.push(line([-.6, y, z], [.6, y, z], 1.1));
    prims.push(line([-.66, .83, z], [.66, .83, z], .9), line([-.66, .8, z], [.66, .8, z], .9));
    for (const [y, x1] of [[.7, .5], [.67, .5], [.6, .14], [.57, .14]]) prims.push(line([-.62, y, z], [x1, y, z], 1));
    prims.push(rrect([-.34, .26, z], .28, .2, .01, 1), Array.from({ length: 7 }, (_, k) => line([-.6 + k * .07, .06, z], [-.6 + k * .07 + .14, .46, z], .25)));
    const column = (x0, x1, y0, y1) => { for (let y = y0; y > y1; y -= .075) prims.push(line([x0, y, z], [x0 + (x1 - x0) * (.7 + rnd() * .3), y, z], .45)); };
    column(.04, .62, .46, -.86); column(-.62, -.06, -.04, -.86);
    return drawing(prims, n, seed);
}
// A rotary telephone: base, dial with finger holes, handset on its cradle, and a coiled cord.
function telephone(n, seed) {
    const z = 0, prims = [
        poly([[-.78, -.78, z], [-.52, -.05, z], [.52, -.05, z], [.78, -.78, z], [-.78, -.78, z]], 1.4),
        arc([0, -.42, z - .01], .3, 1.4), arc([0, -.42, z - .01], .1, 1.1),
        Array.from({ length: 10 }, (_, k) => { const a = Math.PI * (.35 + k * .155); return arc([Math.cos(a) * .21, -.42 + Math.sin(a) * .21, z - .02], .045, .9); }),
        line([.32, -.6, z - .02], [.4, -.68, z - .02], 1.2),
        line([-.42, -.05, z], [-.42, .1, z], 1.3), line([.42, -.05, z], [.42, .1, z], 1.3),
        rrect([-.74, .16, z - .02], .2, .15, .1, 1.3), rrect([.74, .16, z - .02], .2, .15, .1, 1.3),
        stroke(t => [(t - .5) * 1.2, .26 + Math.sin(Math.PI * t) * .2, z - .02], 1.3), stroke(t => [(t - .5) * 1.2, .14 + Math.sin(Math.PI * t) * .16, z - .02], 1.3),
        stroke(t => [-.78 - t * .42 + .05 * Math.sin(t * 50), -.6 - t * .38 + .05 * Math.cos(t * 50), z + .04 * Math.sin(t * 50)], .8, 0, 160),
    ];
    return drawing(prims, n, seed);
}
// A desktop computer: monitor with lines of text and a cursor, stand, keyboard and mouse.
function computer(n, seed) {
    const z = -.05, prims = [
        rrect([0, .38, z], .78, .58, .08, 1.4), rrect([0, .38, z], .66, .46, .05, .7),
        [[.66, .5], [.6, .3], [.52, .55], [.44, .2], [.36, .45]].map(([y, w]) => line([-.56, y + .1, z], [-.56 + w, y + .1, z], .55)),
        patch(r => [-.56 + .22 + r() * .05, .36 + .1 + (r() - .5) * .06, z], .006, 60),
        line([-.12, -.2, z], [-.18, -.42, z], 1.2), line([.12, -.2, z], [.18, -.42, z], 1.2), rrect([0, -.45, z], .42, .035, .02, 1.3),
        poly([[-.95, -.98, z], [-.78, -.62, z], [.78, -.62, z], [.95, -.98, z], [-.95, -.98, z]], 1.3),
    ];
    for (let r = 0; r < 4; r++) {
        const y = -.69 - r * .07, half = .72 + r * .045;
        if (r === 3) { prims.push(line([-.3, y, z], [.3, y, z], 1.2)); continue; }
        for (let x = -half; x < half - .05; x += .1) prims.push(line([x, y, z], [x + .06, y, z], .9));
    }
    prims.push(rrect([1.18, -.82, z], .1, .14, .09, 1.2), line([1.18, -.7, z], [1.18, -.8, z], .9), stroke(t => [1.18 - t * .2, -.68 + Math.sin(t * Math.PI) * .25, z], .6));
    return drawing(prims, n, seed);
}
// A smartphone: rounded body, a grid of apps, a dock, and messages coming in.
function smartphone(n, seed) {
    const z = -.05, prims = [rrect([0, .1, z], .55, 1.05, .16, 1.6), rrect([0, .1, z], .48, .97, .12, .4), rrect([0, 1.0, z], .12, .03, .03, 1.4), line([-.15, -.86, z], [.15, -.86, z], 1.2)];
    for (const y of [.74, .5, .26, .02, -.22]) for (const x of [-.33, -.11, .11, .33]) prims.push(rrect([x, y, z], .07, .07, .025, .75));
    for (const x of [-.33, -.11, .11, .33]) prims.push(rrect([x, -.66, z], .075, .075, .03, 1));
    const bubble = (cx, cy, w, d) => [rrect([cx, cy, z - .1], w, .1, .08, 1), poly([[cx - d * w * .5, cy - .1, z - .1], [cx - d * w * .8, cy - .2, z - .1], [cx - d * w * .2, cy - .1, z - .1]], 1), line([cx - w * .6, cy, z - .1], [cx + w * .4, cy, z - .1], .7)];
    prims.push(bubble(.95, .72, .28, 1), bubble(1.02, .34, .2, 1), bubble(-.92, .5, .24, -1));
    return drawing(prims, n, seed);
}
// A video call: a laptop with four people in a grid, and its camera dot.
function videocall(n, seed) {
    const z = -.05, prims = [rrect([0, .32, z], .98, .64, .06, 1.4), disc([0, .9, z], .025, 2),
        poly([[-.98, -.32, z], [-1.14, -.52, z], [1.14, -.52, z], [.98, -.32, z]], 1.3), line([-.18, -.42, z], [.18, -.42, z], .8)];
    for (const tx of [-.46, .46]) for (const ty of [.6, .04]) {
        prims.push(rrect([tx, ty, z], .42, .26, .03, .8), arc([tx, ty + .07, z], .08, 1.2), arc([tx, ty - .17, z], .16, 1.2, 0, 0, Math.PI));
    }
    return drawing(prims, n, seed);
}
// A globe icon: the half facing us (z < 0) with its rim, nodes, and arcs between them. The internet,
// and later the network of people.
function network(n, seed, R0 = .85, cy = .1) {
    const rnd = mulberry(seed);
    const S = (lat, lon, k = 1) => [Math.cos(lat) * Math.cos(lon) * R0 * k, Math.sin(lat) * R0 * k + cy, Math.cos(lat) * Math.sin(lon) * R0 * k];
    const prims = [arc([0, cy, 0], R0, 1.4, 0, 0, Math.PI * 2)];
    for (const lat of [-50, -25, 0, 25, 50]) prims.push(stroke(t => S(lat * Math.PI / 180, Math.PI * (1 + t)), .5));
    for (let k = 1; k < 6; k++) prims.push(stroke(t => S((t - .5) * Math.PI, Math.PI * (1 + k / 6)), .45));
    const nodes = [];
    while (nodes.length < 12) { const v = unit(rnd); if (v[2] < -.35) nodes.push(v); }
    for (const v of nodes) prims.push({ w: .4, tag: 0, sample: r => { const d = unit(r), k = .04 * Math.cbrt(r()); return [v[0] * R0 * 1.02 + d[0] * k, v[1] * R0 * 1.02 + cy + d[1] * k, v[2] * R0 * 1.02 + d[2] * k]; } });
    for (let i = 0, made = 0; made < 14 && i < 400; i++) {
        const a = nodes[rnd() * nodes.length | 0], b = nodes[rnd() * nodes.length | 0], dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
        if (dot > .9 || dot < .1) continue;
        made++;
        prims.push(stroke(t => { const v = a.map((x, j) => x * (1 - t) + b[j] * t), l = Math.hypot(...v) || 1, k = R0 * (1.02 + .12 * Math.sin(Math.PI * t)) / l; return [v[0] * k, v[1] * k + cy, v[2] * k]; }, 1));
    }
    return drawing(prims, n, seed);
}
// six bots spaced evenly around the globe
const BOT_RING = [30, 90, 150, 210, 270, 330].map((deg, i) => {
    const a = deg * Math.PI / 180;
    return { at: [Math.cos(a) * 1.3, .1 + Math.sin(a) * 1.08, (i % 2) * .2 - .1], s: .19 + (i % 2) * .02, turn: (i % 2 ? -1 : 1) * .08 };
});
const BOT_SWARM = [[.12, .95, 0], [.95, 1.05, .1], [.5, .05, -.1], [1.38, .22, .1], [.88, -.88, 0], [.06, -.78, .1]]
    .map((at, i) => ({ at, s: .165 + (i % 3) * .015, turn: (i % 2 ? 1 : -1) * .1 }));
const bots = (spots, n, seed, reach = 0) => drawing(spots.map(b => robot(b.at, b.s, b.turn, reach)), n, seed, .004);
function pollutedNet(n, seed) { const k = Math.round(n * .4); return [...network(k, seed, .62), ...bots(BOT_RING, n - k, seed + 1)]; }
function attack(n, seed) { const k = Math.round(n * .4); return [...drawing(figure(-.95, 1, 'shield'), k, seed), ...bots(BOT_SWARM, n - k, seed + 1, -1)]; }
function talking(n, seed) { return drawing([figure(-.72, 1), figure(.72, -1)], n, seed); }
// Streams of dots that run from one place to another on a loop (spam, attacks, conversation).
// Conversation: alternate dots go from each speaker's head to the other's.
function talkStream(n, seed, [a, b]) {
    const rnd = mulberry(seed), from = [], to = [];
    for (let i = 0; i < n; i++) { const [p, q] = i % 2 ? [a, b] : [b, a]; from.push(...p.map(v => v + (rnd() - .5) * .08)); to.push(...q.map(v => v + (rnd() - .5) * .08)); }
    return { count: n, from: new Float32Array(from), to: new Float32Array(to) };
}
function stream(n, seed, from, to) { const rnd = mulberry(seed); return { count: n, from: new Float32Array(Array.from({ length: n }, () => from(rnd)).flat()), to: new Float32Array(Array.from({ length: n }, () => to(rnd)).flat()) }; }
function pointScene(canvas, { shapes, count, ambient = 220, color, edge, warm = color, bg, size, alpha = 1, seed = 1, streams = [] }) {
    const gl = getGL(canvas);
    if (!gl) return null;
    const prog = compile(gl, POINT_VS, POINT_FS);
    gl.useProgram(prog);
    const u = getUniforms(gl, prog, ['uMix', 'uTime', 'uSize', 'uRot', 'uTilt', 'uScale', 'uFlutter', 'uDpr', 'uRes', 'uOff', 'uCol', 'uEdge', 'uWarm', 'uAlpha', 'uCycle']);
    const aA = gl.getAttribLocation(prog, 'aA'), aB = gl.getAttribLocation(prog, 'aB'), aSeed = gl.getAttribLocation(prog, 'aSeed');
    const aTA = gl.getAttribLocation(prog, 'aTA'), aTB = gl.getAttribLocation(prog, 'aTB');
    const buf = data => { const b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW); return b; };
    const shapeBufs = shapes.map(sh => ({ pos: buf(sh.pos), tag: buf(sh.tag) }));
    const rnd = mulberry(seed + 99);
    const seeds = buf(new Float32Array(Array.from({ length: count }, rnd)));
    const amb = buf(new Float32Array(fromFn(ambient, seed + 7, r => [(r() - .5) * 10, (r() - .5) * 7, r() * 6 - 1.5]).flat()));
    const ambSeeds = buf(new Float32Array(Array.from({ length: ambient }, rnd)));
    const flows = streams.map(f => ({ ...f, a: buf(f.from), b: buf(f.to), seeds: buf(new Float32Array(Array.from({ length: f.count }, rnd))) }));
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    const bind = (loc, b, n) => { gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, n, gl.FLOAT, false, 0, 0); };
    const untagged = () => { for (const loc of [aTA, aTB]) { gl.disableVertexAttribArray(loc); gl.vertexAttrib1f(loc, 0); } };
    return {
        canvas, mids: shapes.map(sh => sh.mid),
        // s: { i, m, rot, tilt, scale, off, flutter, ambOff, flows: [alpha per stream] }
        draw(time, s) {
            const dpr = fit(canvas, gl, 1);
            gl.clearColor(bg[0], bg[1], bg[2], 1);
            gl.clear(gl.COLOR_BUFFER_BIT);
            gl.uniform2f(u.uRes, canvas.width, canvas.height);
            gl.uniform1f(u.uTime, time);
            gl.uniform1f(u.uDpr, dpr);
            gl.uniform1f(u.uSize, size);
            gl.uniform3f(u.uCol, ...color);
            gl.uniform3f(u.uEdge, ...edge);
            gl.uniform3f(u.uWarm, ...warm);
            gl.uniform1f(u.uAlpha, alpha * .5);
            gl.uniform1f(u.uCycle, 0);
            // ambient specks, fainter than the figure
            bind(aA, amb, 3); bind(aB, amb, 3); bind(aSeed, ambSeeds, 1); untagged();
            gl.uniform1f(u.uMix, 0); gl.uniform1f(u.uFlutter, 0); gl.uniform1f(u.uScale, 1);
            gl.uniform1f(u.uRot, time * .02); gl.uniform1f(u.uTilt, 0);
            gl.uniform3f(u.uOff, 0, s.ambOff, 0);
            gl.drawArrays(gl.POINTS, 0, ambient);
            // the figure
            const i = Math.min(s.i, shapes.length - 1), j = Math.min(i + 1, shapes.length - 1);
            bind(aA, shapeBufs[i].pos, 3); bind(aB, shapeBufs[j].pos, 3); bind(aSeed, seeds, 1);
            bind(aTA, shapeBufs[i].tag, 1); bind(aTB, shapeBufs[j].tag, 1);
            gl.uniform1f(u.uAlpha, alpha * (s.fade ?? 1));
            gl.uniform1f(u.uMix, s.m); gl.uniform1f(u.uFlutter, s.flutter); gl.uniform1f(u.uScale, s.scale);
            gl.uniform1f(u.uRot, s.rot); gl.uniform1f(u.uTilt, s.tilt);
            gl.uniform3f(u.uOff, s.off[0], s.off[1], s.off[2]);
            gl.drawArrays(gl.POINTS, 0, count);
            untagged();
            // streams share the figure's transform so they land on it
            flows.forEach((f, k) => {
                const a = s.flows?.[k] ?? 0;
                if (a < .01) return;
                bind(aA, f.a, 3); bind(aB, f.b, 3); bind(aSeed, f.seeds, 1);
                gl.uniform1f(u.uCycle, 1); gl.uniform1f(u.uFlutter, f.flutter ?? .3); gl.uniform1f(u.uAlpha, alpha * a);
                gl.uniform3f(u.uCol, ...f.color); gl.uniform3f(u.uEdge, ...f.color);
                gl.drawArrays(gl.POINTS, 0, f.count);
            });
            gl.uniform1f(u.uCycle, 0); gl.uniform3f(u.uCol, ...color); gl.uniform3f(u.uEdge, ...edge);
        },
    };
}
// Scrolling past each threshold starts the next morph, which then plays out over a fixed time
// (faster if several thresholds were crossed at once), so figures never sit half-formed.
function morphPlayer(thresholds, seconds = 1.1) {
    let shown = 0;
    return (pos, dt) => {
        const target = thresholds.filter(t => pos >= t).length;
        const diff = target - shown;
        if (diff) shown += Math.sign(diff) * Math.min(Math.abs(diff), dt / seconds * Math.max(1, Math.abs(diff)));
        const i = Math.min(Math.floor(shown), thresholds.length - 1);
        return { i, m: easeInOut(clamp(shown - i)), shown };
    };
}
// The scenes are 100vh tall. On phones that's the height with the browser's bars hidden, which stays put while
// the bars slide in and out (innerHeight doesn't), so measure it from a stage and update it on resize.
let stageHeight = innerHeight;
const measureStage = () => { stageHeight = document.querySelector('.stage')?.offsetHeight || innerHeight; };
// Figures are sized to the viewport height; shrink them on portrait screens so they aren't cropped.
const fitScale = () => Math.min(1, innerWidth / stageHeight * 1.1);
// foundation.css ties the held scenes and the closing curtains to the scroll where the browser supports it.
const cssScroll = CSS.supports?.('animation-timeline: view()') ?? false;
const hex = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16) / 255);

function buildScenes() {
    const scenes = {};
    const tryScene = (name, make) => { const c = $(`[data-gl="${name}"]`); if (!c) return; try { scenes[name] = make(c); } catch (e) { console.warn(name, e); } };
    tryScene('hero', c => screenScene(c, HERO, { scale: .75, cap: 1.5 }));
    tryScene('summit', c => screenScene(c, SUMMIT, { scale: .62, cap: 1 }));
    const N = innerWidth < 700 ? 3800 : 5200;
    const shell = (r0, r1) => r => { const d = unit(r), k = r0 + r() * (r1 - r0); return [d[0] * k, d[1] * k * .7 + .1, d[2] * k]; };
    const onSphere = (R0, cy) => r => { const d = unit(r); return [d[0] * R0, d[1] * R0 + cy, d[2] * R0]; };
    const onHuman = drawing(figure(-.95, 1, 'shield'), 900, 41).map(p => p.slice(0, 3));
    const warm = hex('#c4664a');
    tryScene('feel', c => pointScene(c, {
        count: N, seed: 3, color: hex('#959ba2'), edge: hex('#8a9097'), warm, bg: hex('#f6f4f3'), size: 3.2,
        shapes: [pack(oral(N, 10)), pack(book(N, 11)), pack(newspaper(N, 16)), pack(telephone(N, 17)), pack(television(N, 12)), pack(computer(N, 18)),
            pack(network(N, 13)), pack(smartphone(N, 19)), pack(videocall(N, 20)), pack(pollutedNet(N, 14)), pack(attack(N, 15))],
        streams: [
            { ...stream(900, 31, shell(2, 3.4), onSphere(.62, .1)), color: warm, flutter: .25 },
            { ...stream(1100, 32, r => { const b = BOT_SWARM[r() * BOT_SWARM.length | 0]; return b.at.map(v => v + (r() - .5) * .2); }, r => onHuman[r() * onHuman.length | 0]), color: warm, flutter: .35 },
        ],
    }));
    const M = innerWidth < 700 ? 3800 : 5600;
    const heads = [[-.5, 1.08, 0], [.5, 1.08, 0]];
    tryScene('bloom', c => pointScene(c, {
        count: M, seed: 5, color: hex('#ffffff'), edge: hex('#e4e9ee'), bg: hex('#62778a'), size: 3.4, alpha: .96,
        shapes: [pack(fromFn(M, 21, r => [(r() - .5) * 22, -3.2 + (r() - .5) * .12, -5 + r() * 24])), pack(network(M, 22, .95)),
            pack(talking(M, 24))],
        streams: [{ ...talkStream(260, 33, heads), color: hex('#ffffff'), flutter: .05 }],
    }));
    return scenes;
}

// ---------- Media you supply ----------
async function loadMedia(scenes) {
    const files = await fetch('/foundation-media/index.json').then(r => r.ok ? r.json() : []).catch(() => []);
    const find = name => files.find(f => f.replace(/\.[^.]+$/, '') === name);
    const make = file => {
        if (/\.(mp4|webm)$/.test(file)) {
            // A still of the first frame (<name>-poster) shows while the video loads.
            const poster = find(file.replace(/\.[^.]+$/, '') + '-poster');
            // The hero draws its video into WebGL, which only accepts another site's video (R2) when fetched with CORS.
            const v = Object.assign(document.createElement('video'), { crossOrigin: 'anonymous', muted: true, loop: true, playsInline: true, autoplay: true, preload: 'auto',
                // ?cors: a new address, so a redirect a browser saved before the video was fetched with CORS isn't reused.
                src: '/foundation-media/' + file + '?cors', ...(poster ? { poster: '/foundation-media/' + poster } : {}) });
            v.setAttribute('muted', ''); v.play().catch(() => {});
            return v;
        }
        return Object.assign(new Image(), { src: '/foundation-media/' + file, alt: '', decoding: 'async' });
    };
    for (const el of $$('.card_media[data-media]')) {
        const file = find(el.dataset.media);
        if (!file) continue;
        el.append(make(file));
        el.classList.add('has-media');
    }
    for (const c of $$('canvas[data-media]')) {
        const file = find(c.dataset.media);
        if (!file || !scenes[c.dataset.gl]) continue;
        const media = make(file);
        scenes[c.dataset.gl].setMedia(media);
        // light footage needs dark text; switch once it is actually showing
        media.addEventListener(media.tagName === 'VIDEO' ? 'loadeddata' : 'load', () => c.closest('section').classList.add('has-media'), { once: true });
    }
}

// ---------- Banded overlays ----------
// Stepped bands of paper colour, like the reference's posterised fades. dir 'up' fills from the bottom.
function bands(dir, steps = 14, rgb = '246,244,243') {
    const stops = [];
    for (let i = 0; i <= steps; i++) {
        const a = (i / steps).toFixed(3), p0 = 25 + (i / (steps + 1)) * 25, p1 = 25 + ((i + 1) / (steps + 1)) * 25;
        stops.push(`rgba(${rgb},${a}) ${p0.toFixed(2)}%`, `rgba(${rgb},${a}) ${p1.toFixed(2)}%`);
    }
    return `linear-gradient(${dir === 'up' ? 'to bottom' : 'to top'}, rgba(${rgb},0) 0%, ${stops.join(', ')}, rgba(${rgb},1) 100%)`;
}
// From the globe's night to the blue below, in steps.
function wallGradient(steps = 22) {
    const from = hex('#0b0f14'), to = hex('#62778a'), stops = [];
    for (let i = 0; i < steps; i++) {
        const t = i / (steps - 1), c = from.map((v, k) => Math.round(lerp(v, to[k], t) * 255));
        const p0 = 6 + i * (52 / steps), p1 = 6 + (i + 1) * (52 / steps);
        stops.push(`rgb(${c}) ${p0.toFixed(2)}%`, `rgb(${c}) ${p1.toFixed(2)}%`);
    }
    return `linear-gradient(to bottom, #0b0f14 0%, ${stops.join(', ')}, #62778a 100%)`;
}

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
    const nav = setupNav();
    const scenes = buildScenes();
    loadMedia(scenes);

    const wall = $('.wall');
    const feelStage = $('.feel .stage'), globeStage = $('.globe .stage'), summitStage = $('.summit .stage');
    $('.wall_bands').style.background = wallGradient();
    $('.bloom_white').style.background = bands('up');
    $('.summit_bottom').style.background = bands('up');
    $('.summit_top').style.background = bands('down');
    $('.feel_dark').style.background = bands('up', 14, '11,15,20');
    const summitCode = $('.summit_code');
    measureStage();
    addEventListener('resize', measureStage);
    summitCode.textContent = $('.wall_code').textContent;
    const wallMark = $('.wall_mark');
    const parallax = $$('[data-parallax]').map(el => ({ el, v: Number(el.dataset.parallax), host: el.closest('section') }));
    const cards = $$('.card_media');
    const stages = $$('[data-stage]').map(el => ({ el, name: el.dataset.stage, p: 0, visible: false }));
    const stage = Object.fromEntries(stages.map(s => [s.name, s]));
    const themed = $$('[data-theme]');

    // Reveals: scramble labels, draw rules, fade rows in.
    const io = new IntersectionObserver(entries => {
        for (const e of entries) {
            if (!e.isIntersecting) continue;
            const el = e.target;
            if (el.matches('[data-scramble-in]')) { if (document.body.classList.contains('is-loading') && el.closest('.hero_one')) continue; scrambleIn(el); }
            else {
                el.classList.add('is-in', 'is-drawn');
            }
            io.unobserve(el);
        }
    }, { threshold: .25 });
    $$('[data-scramble-in]').forEach(el => { if (!el.closest('.hero_one')) io.observe(el); });
    $$('[data-row]').forEach(el => io.observe(el));

    const mouse = [0, 0], eased = [0, 0];
    addEventListener('pointermove', e => { mouse[0] = e.clientX / innerWidth - .5; mouse[1] = .5 - e.clientY / innerHeight; }, { passive: true });

    intro();
    // The first scene stays until its line has shown (after the title), then one scene per stretch of scrolling.
    const feelMorph = morphPlayer([.14, .2133, .2867, .36, .4333, .5067, .58, .6533, .7267, .8]);
    const bloomMorph = morphPlayer([.2, .5]);
    const captions = ['The first way to convey knowledge was mouth to mouth', 'Books carried words further than any voice', 'Newspapers brought the news to every door',
        'Phone calls carried a voice across the world', 'TV brought faces and voices into every home', 'Computers let anyone write and publish',
        'The internet connected everyone', 'Phones put it all in our pockets', 'Video calls let us see each other from anywhere',
        'Now bots flood the internet', 'Next, AI agents come for people'];
    const BOTS = 9; // the stage where bots arrive
    const caption = $('[data-caption]'), count = $('[data-count]'), captionBox = $('.feel_caption'), feelTitle = $('.feel_title');
    let captionAt = 0;
    const globeSection = $('.globe');
    let globe = null, globeLoading = false;

    let last = performance.now(), time = 0;
    const frame = now => {
        const dt = Math.min(.05, (now - last) / 1000);
        last = now;
        time += reduced ? dt * .2 : dt;
        stepScroll(dt);
        eased[0] = lerp(eased[0], mouse[0], .05); eased[1] = lerp(eased[1], mouse[1], .05);
        const vh = stageHeight;
        for (const s of stages) {
            const r = s.el.getBoundingClientRect();
            s.visible = r.bottom > 0 && r.top < vh;
            s.p = clamp(-r.top / Math.max(1, r.height - vh));
            s.top = r.top;
        }

        const hero = stage.hero;
        if (hero.visible) {
            scenes.hero?.draw(time, hero.p, eased);
            $('.hero_white').style.setProperty('--w', lerp(-40, 100, smooth(range(hero.p, .74, 1))) + '%');
        }
        const feel = stage.feel;
        if (feel.visible && scenes.feel) {
            const { i, m, shown } = feelMorph(feel.top > 0 ? -feel.top / vh : feel.p, dt);
            // Every scene's shape sits at the same middle, so the story doesn't hop up, down or sideways between them.
            const mids = scenes.feel.mids, a = mids[i], b = mids[Math.min(i + 1, mids.length - 1)], scale = .46 * fitScale();
            const mid = [lerp(a[0], b[0], m) * scale, lerp(a[1], b[1], m) * scale];
            scenes.feel.draw(time, {
                i, m, flutter: .22, scale,
                rot: -.2 + .1 * Math.sin(time * .3) + eased[0] * .2, tilt: .1 + eased[1] * .06,
                // beside the title while it's on screen (wide screens), then centred
                off: [(innerWidth > 860 ? lerp(.62, 0, smooth(range(feel.p, .02, .1))) : 0) - mid[0], lerp(-.42, -.12, smooth(range(feel.p, 0, .12))) - mid[1], 0], ambOff: lerp(-.3, 1.4, feel.p),
                // on narrow screens the title passes over the figure, so keep it faint until the title is by
                fade: innerWidth > 860 ? 1 : lerp(1, lerp(.3, 1, smooth(range(feel.p, .02, .08))), clamp(shown)),
                flows: [clamp(1 - Math.abs(shown - BOTS) * 1.5), clamp((shown - BOTS - .2) * 1.4)],
            });
            // The scene's line shows as soon as the story's title has scrolled past it, so the two never sit on top of
            // each other and the figure is never left without words.
            captionBox.style.opacity = smooth(clamp((captionBox.getBoundingClientRect().top + 80 - feelTitle.getBoundingClientRect().bottom) / 80));
            const at = Math.round(shown);
            if (at !== captionAt) {
                captionAt = at;
                typeText(caption, captions[at], { cps: 60, tail: 5, pad: false });
                count.textContent = `${String(at + 1).padStart(2, '0')} / ${captions.length}`;
                captionBox.classList.toggle('is-bot', at >= BOTS);
            }
            if (!cssScroll) $('.feel_dark').style.transform = `translateY(${lerp(100, -50, range(feel.p, .86, 1))}%)`;
        }
        if (!globeLoading && globeSection.getBoundingClientRect().top < vh * 2.5) {
            globeLoading = true;
            import('/foundation-globe.js').then(m => { globe = m.createGlobe(globeSection); }).catch(e => console.warn('globe', e));
        }
        globe?.setActive(stage.globe.visible);
        // While the story, the globe and the summit scroll in, hold their scenes at the top of the screen and
        // reveal them there, so no empty screen scrolls past between sections.
        if (!cssScroll) {
            const holdFeel = stage.feel.top > 0 && stage.feel.top < vh ? stage.feel.top : 0;
            feelStage.style.transform = holdFeel ? `translateY(${-holdFeel}px)` : '';
            const holdGlobe = stage.globe.top > 0 && stage.globe.top < vh ? stage.globe.top : 0;
            globeStage.style.transform = holdGlobe ? `translateY(${-holdGlobe}px)` : '';
            globeStage.style.opacity = holdGlobe ? clamp((vh - holdGlobe) / (vh * .35)) : '';
            const holdSummit = stage.summit.top > 0 && stage.summit.top < vh ? stage.summit.top : 0;
            summitStage.style.transform = holdSummit ? `translateY(${-holdSummit}px)` : '';
        }
        const bloom = stage.bloom;
        if (bloom.visible && scenes.bloom) {
            const { i, m, shown } = bloomMorph(bloom.p, dt);
            const spin = smooth(range(bloom.p, .12, .4));
            const rise = smooth(range(bloom.p, .88, 1));
            const enter = bloom.top > 0 ? range(bloom.top, vh, 0) : 1;
            scenes.bloom.draw(time, {
                i, m, flutter: .28, scale: .42 * fitScale(),
                // a gentle sway, so the globe keeps facing us and the two people keep facing each other
                rot: spin * (.2 * Math.sin(time * .35) + eased[0] * .25), tilt: .1 * spin,
                // on narrow screens the text sits on top, so the figure sits lower
                off: [0, lerp(-.6, 0, enter) - .1 - (innerWidth < 860 ? .26 : 0) + rise * 2.4, 0], ambOff: lerp(-1, 1.2, bloom.p),
                flows: [clamp((shown - 1.2) * 1.5)],
            });
            if (!cssScroll) $('.bloom_white').style.transform = `translateY(${lerp(100, -50, range(bloom.p, .86, 1))}%)`;
        }
        const summit = stage.summit;
        if (summit.visible) {
            scenes.summit?.draw(time, summit.p, eased);
            $('.summit_top').style.transform = `translateY(${summit.top > 0 ? lerp(0, -100, smooth(clamp((1 - summit.top / vh) / .7))) : -100}%)`;
            if (!cssScroll) $('.summit_bottom').style.transform = `translateY(${lerp(100, -50, range(summit.p, .86, 1))}%)`;
            summitCode.style.transform = `translateY(${lerp(30, -110, summit.p) * vh / 100}px)`;
            summitCode.style.opacity = range(summit.p, .06, .18) * (1 - range(summit.p, .55, .7));
        }

        const wr = wall.getBoundingClientRect();
        if (wr.bottom > 0 && wr.top < vh) {
            for (const { el, v, host } of parallax) if (host === wall) el.style.transform = `translate3d(0, ${-wr.top * v}px, 0)`;
            const k = range((vh * .5 - wr.top) / wr.height, .35, .7);
            wallMark.style.color = `rgba(${Math.round(lerp(246, 93, k))}, ${Math.round(lerp(244, 114, k))}, ${Math.round(lerp(243, 134, k))}, ${lerp(.95, .7, k)})`;
        }
        for (const c of cards) {
            const r = c.getBoundingClientRect();
            if (r.bottom < 0 || r.top > vh) continue;
            c.style.setProperty('--py', ((r.top + r.height / 2 - vh / 2) * -.06).toFixed(1) + 'px');
        }

        // Nav colour follows whatever sits under it.
        const y = 45;
        let light = true;
        for (const el of themed) {
            const r = el.getBoundingClientRect();
            if (r.top > y || r.bottom < y) continue;
            const t = el.dataset.theme, p = clamp((y - r.top) / Math.max(1, r.height - vh));
            if (el === hero.el) light = hero.el.classList.contains('has-media') || hero.p > .93;
            else if (el === bloom.el) light = bloom.p > .95;
            else if (el === stage.feel.el) light = stage.feel.p < .95;
            else if (el === summit.el) light = true;
            else if (t === 'mixed') light = (y - r.top) / r.height < .32;
            else light = t !== 'dark';
            break;
        }
        nav.classList.toggle('is-light', light);
        requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
}
main();
