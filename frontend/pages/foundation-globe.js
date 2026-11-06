// Globe for /foundation: MapLibre's globe projection over CARTO's dark basemap, with a soft halo and a
// starfield behind it. The points are an illustration, not live data: bots probe people and are turned
// away (red rings), verified people light up and connect to each other with arcs.
import * as maplibregl from '/vendor/maplibre/maplibre-gl.mjs';

const STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json';
// Approximate city centres, used only as plausible places for people to be.
const CITIES = [[-74, 40.7], [-118.2, 34], [-87.6, 41.9], [-79.4, 43.7], [-99.1, 19.4], [-46.6, -23.5], [-58.4, -34.6], [-77, -12], [-74.1, 4.7], [-0.1, 51.5], [2.35, 48.86], [13.4, 52.5], [12.5, 41.9], [-3.7, 40.4], [4.9, 52.4], [18.1, 59.3], [21, 52.2], [28.98, 41], [37.6, 55.75], [31.2, 30], [3.4, 6.5], [36.8, -1.3], [28, -26.2], [18.4, -33.9], [55.3, 25.2], [46.7, 24.7], [72.9, 19.1], [77.2, 28.6], [77.6, 12.97], [80.3, 13.1], [90.4, 23.8], [100.5, 13.75], [106.8, -6.2], [103.8, 1.35], [121, 14.6], [114.2, 22.3], [121.5, 31.2], [116.4, 39.9], [127, 37.5], [139.7, 35.7], [135.5, 34.7], [151.2, -33.9], [144.96, -37.8], [174.8, -36.85], [-123.1, 49.3], [-122.4, 37.8], [-104.99, 39.7], [-95.4, 29.8], [-80.2, 25.8], [-71.06, 42.36]];

function greatCircle([lon1, lat1], [lon2, lat2], n = 48) {
    const r = Math.PI / 180, toV = (lo, la) => [Math.cos(la * r) * Math.cos(lo * r), Math.cos(la * r) * Math.sin(lo * r), Math.sin(la * r)];
    const a = toV(lon1, lat1), b = toV(lon2, lat2);
    const d = Math.acos(Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))) || 1e-6;
    const pts = [];
    for (let i = 0; i <= n; i++) {
        const t = i / n, s1 = Math.sin((1 - t) * d) / Math.sin(d), s2 = Math.sin(t * d) / Math.sin(d);
        const v = [0, 1, 2].map(k => s1 * a[k] + s2 * b[k]);
        pts.push([Math.atan2(v[1], v[0]) / r, Math.atan2(v[2], Math.hypot(v[0], v[1])) / r]);
    }
    return pts;
}

function stars(canvas) {
    const ctx = canvas.getContext('2d');
    const pts = Array.from({ length: 900 }, () => [Math.random(), Math.random(), Math.random() * 1.1 + .2, Math.random()]);
    return drift => {
        const dpr = Math.min(devicePixelRatio || 1, 2), w = canvas.clientWidth, h = canvas.clientHeight;
        if (canvas.width !== Math.round(w * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr); }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);
        for (const [x, y, s, a] of pts) {
            ctx.globalAlpha = .25 + a * .55;
            ctx.fillStyle = '#e8edf2';
            ctx.beginPath();
            ctx.arc(((x + drift * (.2 + a * .3)) % 1) * w, y * h, s, 0, Math.PI * 2);
            ctx.fill();
        }
    };
}

// The page's bot icon (head, antenna, ears, eyes, mouth; same shapes as #bot-mark) for the map's symbol layer.
function botIcon(size = 48) {
    const c = Object.assign(document.createElement('canvas'), { width: size, height: size });
    const g = c.getContext('2d'), k = size / 40;
    const box = (x, y, w, h, r) => { g.beginPath(); g.roundRect(x * k, y * k, w * k, h * k, r * k); g.fill(); };
    const dot = (x, y, r) => { g.beginPath(); g.arc(x * k, y * k, r * k, 0, Math.PI * 2); g.fill(); };
    g.fillStyle = '#e0675c';
    box(18.8, 4.5, 2.4, 7, 1.2); dot(20, 4.5, 3); box(2.5, 18, 4, 9, 1.6); box(33.5, 18, 4, 9, 1.6); box(6, 10, 28, 25, 7.5);
    g.fillStyle = '#0b0f14';
    dot(14.5, 20.5, 3.4); dot(25.5, 20.5, 3.4); box(14, 27.5, 12, 2.6, 1.3);
    return g.getImageData(0, 0, size, size);
}
// The zoom at which the globe's radius is about 40% of the smaller side of its box.
const fitZoom = el => Math.log2(.4 * Math.min(el.clientWidth, el.clientHeight) * 2 * Math.PI / 512);

export function createGlobe(root) {
    const container = root.querySelector('[data-globe-map]');
    const halo = root.querySelector('.globe_halo');
    const sizeHalo = () => { halo.style.width = Math.round(.4 * Math.min(container.clientWidth, container.clientHeight) * 2 * 1.32) + 'px'; };
    sizeHalo();
    const drawStars = stars(root.querySelector('[data-globe-stars]'));
    maplibregl.setWorkerUrl(new URL('/vendor/maplibre/maplibre-gl-worker.mjs', location.href).href);
    const map = new maplibregl.Map({
        container, style: STYLE, center: [20, 22], zoom: fitZoom(container), minZoom: .3, maxZoom: 4,
        attributionControl: { compact: true }, interactive: true, scrollZoom: false, dragRotate: false, pitchWithRotate: false,
        renderWorldCopies: false, fadeDuration: 0,
    });
    map.scrollZoom.disable();
    map.touchZoomRotate.disableRotation();
    // The map's credit (OpenStreetMap, CARTO) stays behind its (i) button, which OSMF's attribution guideline allows.
    map.once('load', () => container.querySelector('.maplibregl-ctrl-attrib')?.classList.remove('maplibregl-compact-show'));

    const people = CITIES.map((c, i) => ({ id: i, at: [c[0] + (Math.random() - .5) * 2, c[1] + (Math.random() - .5) * 2], verified: 0 }));
    let bots = [], links = [], rings = [], nextId = 1000, active = false, ready = false;
    const fc = features => ({ type: 'FeatureCollection', features });
    const point = (at, props) => ({ type: 'Feature', geometry: { type: 'Point', coordinates: at }, properties: props });

    map.on('style.load', () => {
        map.setProjection({ type: 'globe' });
        map.setSky({ 'sky-color': '#0b0f14', 'horizon-color': '#1c2a3a', 'fog-color': '#0b0f14', 'atmosphere-blend': ['interpolate', ['linear'], ['zoom'], 0, .85, 4, .2] });
        map.addSource('links', { type: 'geojson', data: fc([]) });
        map.addSource('people', { type: 'geojson', data: fc([]) });
        map.addSource('bots', { type: 'geojson', data: fc([]) });
        map.addSource('rings', { type: 'geojson', data: fc([]) });
        map.addLayer({ id: 'links', type: 'line', source: 'links', layout: { 'line-cap': 'round' },
            paint: { 'line-color': '#9ec5ea', 'line-width': 1.6, 'line-opacity': ['get', 'o'] } });
        map.addLayer({ id: 'rings', type: 'circle', source: 'rings',
            paint: { 'circle-radius': ['get', 'r'], 'circle-color': 'rgba(0,0,0,0)', 'circle-stroke-color': '#e0675c', 'circle-stroke-width': 1.5, 'circle-stroke-opacity': ['get', 'o'], 'circle-pitch-alignment': 'map' } });
        map.addImage('bot', botIcon(), { pixelRatio: 2 });
        map.addLayer({ id: 'bots', type: 'symbol', source: 'bots',
            layout: { 'icon-image': 'bot', 'icon-size': 1, 'icon-allow-overlap': true, 'icon-ignore-placement': true },
            paint: { 'icon-opacity': ['get', 'o'] } });
        map.addLayer({ id: 'people', type: 'circle', source: 'people',
            paint: { 'circle-radius': ['+', 3.5, ['*', 2.5, ['get', 'v']]], 'circle-color': ['interpolate', ['linear'], ['get', 'v'], 0, '#dfe6ee', 1, '#8fd3a8'],
                'circle-stroke-color': '#0b0f14', 'circle-stroke-width': 1.5 } });
        ready = true;
    });

    // One step of the illustration: bots appear near people and don't count; people verify and connect.
    let lastBot = 0, lastLink = 0;
    function simulate(now, dt) {
        if (now - lastBot > 380) {
            lastBot = now;
            const p = people[Math.random() * people.length | 0];
            bots.push({ id: nextId++, at: [p.at[0] + (Math.random() - .5) * 14, p.at[1] + (Math.random() - .5) * 10], to: p.at, t: 0 });
        }
        if (now - lastLink > 650) {
            lastLink = now;
            const a = people[Math.random() * people.length | 0], b = people[Math.random() * people.length | 0];
            if (a !== b) { links.push({ path: greatCircle(a.at, b.at), t: 0 }); a.verified = b.verified = 1; }
        }
        for (const b of bots) {
            b.t += dt;
            if (b.t > 1.1 && !b.rejected) { b.rejected = true; rings.push({ at: b.at, t: 0 }); }
            if (!b.rejected) { b.at = [b.at[0] + (b.to[0] - b.at[0]) * dt * .9, b.at[1] + (b.to[1] - b.at[1]) * dt * .9]; }
        }
        bots = bots.filter(b => b.t < 1.6);
        for (const r of rings) r.t += dt;
        rings = rings.filter(r => r.t < 1);
        for (const l of links) l.t += dt;
        links = links.filter(l => l.t < 3.2);
        for (const p of people) p.verified = Math.max(0, p.verified - dt * .35);
        map.getSource('people').setData(fc(people.map(p => point(p.at, { v: p.verified }))));
        map.getSource('bots').setData(fc(bots.map(b => point(b.at, { o: b.rejected ? Math.max(0, 1 - (b.t - 1.1) * 2) : Math.min(1, b.t * 3) }))));
        map.getSource('rings').setData(fc(rings.map(r => point(r.at, { r: 4 + r.t * 22, o: 1 - r.t }))));
        map.getSource('links').setData(fc(links.map(l => {
            const grow = Math.min(1, l.t / .9), n = Math.max(2, Math.round(l.path.length * grow));
            return { type: 'Feature', geometry: { type: 'LineString', coordinates: l.path.slice(0, n) }, properties: { o: Math.min(1, (3.2 - l.t) / .8) * .9 } };
        })));
    }

    let last = performance.now(), tick = 0, drift = 0;
    const frame = now => {
        const dt = Math.min(.05, (now - last) / 1000);
        last = now;
        if (active) {
            drift += dt * .004;
            drawStars(drift);
            if (ready) {
                const c = map.getCenter();
                if (!map.isMoving()) map.jumpTo({ center: [c.lng + dt * 4, c.lat] });
                if ((tick += dt) > .08) { simulate(now, tick); tick = 0; }
            }
        }
        requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
    addEventListener('resize', () => { map.resize(); map.setZoom(fitZoom(container)); sizeHalo(); });
    return { setActive(on) { if (on && !active) { map.resize(); map.setZoom(fitZoom(container)); sizeHalo(); } active = on; } };
}
