// A page's writing report as a PDF, set out like a printed report. The cover says how the report works and gives the
// result, the contents and a code to see the page live. The text follows in full, pasted parts shaded and marked in the
// margin. The last page verifies it: the result and score, how the score adds up, the typing checks, the session, the
// proof and how to check it, with every source as a link. Every page is framed and watermarked and carries the text's
// SHA-256. The proof (and the writing replay, when there is one) travels inside the PDF, so the report alone can be
// checked at huma.social/verify. Made in the reader's browser (verify.mjs) and the writer's (frontend/write); the Mac app
// draws its own (PageReport.swift).
//
// makeReport(report, { PDFLib, fontkit, fonts: { serif, bold }, mark }) → PDF bytes. One typeface throughout. `report`:
//   title, writer?, started, ended, savedAt (Dates), madeBy (what made this PDF)
//   status { verified, headline, detail }      the result, in the words the shared page uses
//   score { value, rows [[part, result, points]], terms { typed (0…1, as counted), checks [met, of], touch [on time, asked] } }
//   rules [9 booleans]                         the writing rules the proof reports (WRITING_RULES order)
//   session [[label, value]]
//   proof { fingerprint, textHash, signingKey, parts, size }
//   link? (the shared page; none before it's shared), qr (rows of booleans: the link, or the verify page)
//   paragraphs [[{ text, pasted }]], attachment? { name, bytes }, replay? { name, bytes } (the writing replay, attached too)
//   mix? { typed, pasted, share }              the text's typed and pasted parts as labels, and the pasted share (0…1), when known
//   where? 'browser' for a page written in a browser, whose key isn't in a Secure Enclave (default: the Mac app)
//   tier? where it was written and how strong that check is (CHECK_TIERS label in publication-contract.mjs)
//   stopped? [[label, value]]: a recording that stopped before it was proved, and why; there's no score, rules or proof
//   textHash? the text's SHA-256 when there's no proof to carry it

export const VERIFY_URL = 'https://huma.social/verify', DOWNLOAD_URL = 'https://huma.social/download', SITE_URL = 'https://huma.social';
export const REPLAY_FILE = 'Huma-replay.json';
/** The tier shown with the score; the Mac app's own reports, made before tiers were passed in, are the strong check. */
const tierOf = report => report.tier ?? (report.where === 'browser' ? 'Web browser · basic check' : 'Mac app · strong check');
export const NOIR_URL = 'https://noir-lang.org/docs', BARRETENBERG_URL = 'https://barretenberg.aztec.network/docs';
export const ENCLAVE_URL = 'https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web';
/** The nine writing rules, as met (WRITING_RULES in publication-contract.mjs says how each is missed). */
export const RULES_MET = ['Started from a blank page', 'All text typed', 'Typed for 20 seconds or more', '30 key presses or more', 'Usual key presses',
    'Usual key holds', 'Usual typing rhythm', 'A natural pause', 'Usual typing speed'];

/** A PDF literal string as pdf-lib writes it, unescaped: backslashes and parentheses are escaped so a link
 *  can't close the string early. */
export const pdfLiteral = value => value.replace(/[\\()]/g, c => '\\' + c);
// US Letter, framed; the body runs between the running head and the footer.
const W = 612, H = 792, M = 66, CONTENT = W - 2 * M, BODY = 84, FOOT = H - 54, BOTTOM = FOOT - 16;
const INK = [0x1a, 0x1a, 0x1a], GREY = [0x4d, 0x4d, 0x4d], QUIET = [0x80, 0x80, 0x80], RULE = [0xcc, 0xcc, 0xcc];
const LINK = [0x1f, 0x3f, 0x6b], GREEN = [0x2e, 0x6b, 0x49], AMBER = [0x9a, 0x63, 0x14], TINT = [0xf2, 0xdc, 0xb5];

/** What the report cites, numbered in the order it's first cited, each with its full address: only those this page has. */
export function references(report) {
    const list = [{ key: 'site', title: 'How Huma works', about: 'what Huma checks, and how', url: SITE_URL }];
    if (report.stopped) return list.map((item, i) => ({ ...item, n: i + 1 }));
    list.push({ key: 'noir', title: 'Noir', about: 'language of Huma’s proof circuits', url: NOIR_URL },
        { key: 'barretenberg', title: 'Barretenberg', about: 'UltraHonk prover and verifier', url: BARRETENBERG_URL });
    if (report.where !== 'browser') list.push({ key: 'enclave', title: 'The Secure Enclave', about: 'Apple Platform Security; where the Mac keeps its signing key', url: ENCLAVE_URL });
    if (report.link) list.push({ key: 'page', title: 'Shared page', about: 'text, proof and replay, checked in your browser', url: report.link });
    list.push({ key: 'verify', title: 'Huma Verify', about: 'checks this PDF’s attached proof', url: VERIFY_URL });
    return list.map((item, i) => ({ ...item, n: i + 1 }));
}

export async function makeReport(report, { PDFLib, fontkit, fonts, mark }) {
    const { PDFDocument, PDFOperator, PDFOperatorNames, PDFString, rgb, degrees, AFRelationship, pushGraphicsState, popGraphicsState,
        concatTransformationMatrix, setFillingRgbColor, setCharacterSpacing, moveTo, lineTo, appendBezierCurve } = PDFLib;
    const color = ([r, g, b]) => rgb(r / 255, g / 255, b / 255);
    const doc = await PDFDocument.create();
    doc.registerFontkit(fontkit);
    const [serif, bold] = await Promise.all([fonts.serif, fonts.bold].map(bytes => doc.embedFont(bytes, { subset: true })));
    const name = report.title || 'Untitled';
    doc.setTitle(name + ' – Huma writing report'); doc.setCreator('Huma'); doc.setProducer('Huma');
    if (report.writer) doc.setAuthor(report.writer);
    doc.setSubject('Writing report: the text, with pasted parts marked, then the result, score, writing rules and the zero-knowledge proof, with sources. The proof file is attached.');
    doc.setCreationDate(report.savedAt); doc.setModificationDate(report.savedAt);
    const refs = references(report), p = report.proof;

    // Drawing, in points from the top-left corner of the page (PDF counts from the bottom).
    let page, top;
    const pages = [];
    const width = (value, size, font = serif) => font.widthOfTextAtSize(value, size);
    const text = (value, x, y, size, font = serif, ink = INK) => page.drawText(value, { x, y: H - y - size * 0.78, size, font, color: color(ink) });
    /** Capitals spaced out, as a printed report's small headings. */
    const caps = (value, x, y, size = 7.5, ink = QUIET, font = serif, spacing = size * 0.16) => {
        page.pushOperators(pushGraphicsState(), setCharacterSpacing(spacing));
        text(value.toUpperCase(), x, y, size, font, ink);
        page.pushOperators(popGraphicsState());
    };
    const capsWidth = (value, size = 7.5, font = serif, spacing = size * 0.16) => width(value.toUpperCase(), size, font) + spacing * (value.length - 1);
    const middle = w => (W - w) / 2;
    const rule = (y, ink = RULE, thickness = 0.5, from = M, to = W - M) => page.drawLine({ start: { x: from, y: H - y }, end: { x: to, y: H - y }, thickness, color: color(ink) });
    const annotate = (x, y, w, h, action) => page.node.addAnnot(doc.context.register(doc.context.obj({
        Type: 'Annot', Subtype: 'Link', Rect: [x, H - y - h, x + w, H - y], Border: [0, 0, 0], ...action })));
    const link = (x, y, w, h, url) => annotate(x, y, w, h, { A: { Type: 'Action', S: 'URI', URI: PDFString.of(pdfLiteral(url)) } });
    const goto = (x, y, w, h, sheet) => annotate(x, y, w, h, { Dest: [sheet.ref, 'XYZ', null, null, null] });
    /** A line cut to fit, ending in an ellipsis. */
    const fit = (value, size, font, room) => {
        if (width(value, size, font) <= room) return value;
        let cut = value.length;
        while (cut > 1 && width(value.slice(0, cut).trimEnd() + '…', size, font) > room) cut--;
        return value.slice(0, cut).trimEnd() + '…';
    };
    /** Huma's mark from its SVG path (absolute M, L and C), filled even-odd so the eyes stay open. */
    const drawMark = (x, y, height) => {
        const s = height / 710, list = [pushGraphicsState(), concatTransformationMatrix(s, 0, 0, -s, x, H - y), setFillingRgbColor(...INK.map(v => v / 255))];
        for (const [, command, args] of mark.matchAll(/([MLC])([^MLC]*)/g)) {
            const n = args.trim().split(/[\s,]+/).map(Number);
            if (command === 'M') list.push(moveTo(n[0], n[1]));
            else if (command === 'L') for (let i = 0; i < n.length; i += 2) list.push(lineTo(n[i], n[i + 1]));
            else for (let i = 0; i < n.length; i += 6) list.push(appendBezierCurve(n[i], n[i + 1], n[i + 2], n[i + 3], n[i + 4], n[i + 5]));
        }
        list.push(PDFOperator.of(PDFOperatorNames.FillEvenOdd), popGraphicsState());
        page.pushOperators(...list);
        return height * 413 / 710;
    };
    /** "HUMA" faintly across the page, under everything on it. */
    const watermark = () => {
        const word = 'HUMA', size = 132, spacing = 22, angle = Math.atan2(H - 200, W - 140);
        const w = width(word, size, bold) + spacing * (word.length - 1), cap = size * 0.66;
        const x = W / 2 - (w / 2) * Math.cos(angle) + (cap / 2) * Math.sin(angle), y = H / 2 - (w / 2) * Math.sin(angle) - (cap / 2) * Math.cos(angle);
        page.pushOperators(pushGraphicsState(), setCharacterSpacing(spacing));
        page.drawText(word, { x, y, size, font: bold, color: color(INK), opacity: 0.045, rotate: degrees(angle * 180 / Math.PI) });
        page.pushOperators(popGraphicsState());
    };
    const newPage = () => { page = doc.addPage([W, H]); pages.push(page); watermark(); top = BODY; };
    const need = height => { if (top + height > BOTTOM) newPage(); };

    // Runs of text ({ text, font, size, ink, url }) broken into lines between words; an address, hash or unspaced
    // script too long for a line breaks anywhere, between characters, measured once each.
    const lines = (runs, room, size) => {
        const out = [];
        let line = [], used = 0;
        const push = piece => { line.push(piece); used += piece.w; };
        const breakLine = () => { while (line.length && line.at(-1).space) used -= line.pop().w; out.push(line); line = []; used = 0; };
        for (const run of runs) {
            const font = run.font ?? serif, s = run.size ?? size;
            for (const part of run.text.split(/(\s+)/)) {
                if (!part) continue;
                if (/^\s+$/.test(part)) { if (line.length) push({ text: ' ', w: width(' ', s, font), space: true, run, font, size: s }); continue; }
                let rest = part;
                while (rest) {
                    const w = width(rest, s, font);
                    if (used + w <= room) { push({ text: rest, w, run, font, size: s }); break; }
                    if (line.length) { breakLine(); continue; }
                    const chars = [...rest];
                    let start = 0, filled = 0;
                    chars.forEach((c, i) => {
                        const cw = width(c, s, font);
                        if (filled + cw > room && i > start) { push({ text: chars.slice(start, i).join(''), w: filled, run, font, size: s }); breakLine(); start = i; filled = 0; }
                        filled += cw;
                    });
                    rest = chars.slice(start).join('');
                    if (width(rest, s, font) > room) { push({ text: rest, w: width(rest, s, font), run, font, size: s }); break; }
                }
            }
        }
        if (line.length) breakLine();
        return out;
    };
    const lineWidth = line => line.reduce((sum, piece) => sum + piece.w, 0);
    const drawLines = (list, x, y, size, leading, ink = INK, align = 'left') => {
        list.forEach((line, i) => {
            const baseline = y + i * leading + leading / 2 + size * 0.35;
            let at = align === 'center' ? middle(lineWidth(line)) : x;
            for (const piece of line) {
                if (!piece.space) {
                    page.drawText(piece.text, { x: at, y: H - baseline, size: piece.size, font: piece.font, color: color(piece.run.ink ?? (piece.run.url ? LINK : ink)) });
                    if (piece.run.url) link(at, y + i * leading, piece.w, leading, piece.run.url);
                }
                at += piece.w;
            }
        });
        return list.length * leading;
    };
    const paragraph = (runs, { x = M, room = CONTENT, size = 9.5, leading = 14, ink = INK, align } = {}) => {
        const list = lines(runs, room, size);
        need(list.length * leading);
        top += drawLines(list, x, top, size, leading, ink, align);
    };
    /** A section's heading: its number and name, over a rule. */
    const heading = (number, title) => {
        text(`${number}.`, M, top, 15, bold); text(title, M + 22, top, 15, bold);
        top += 24; rule(top, INK, 0.8); top += 14;
    };
    const day = date => date.toLocaleDateString('en-US', { dateStyle: 'long' });
    const time = (date, zone) => date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', ...(zone ? { timeZoneName: 'short' } : {}) });
    const written = day(report.started) === day(report.ended)
        ? time(report.started) === time(report.ended) ? `${day(report.started)}, ${time(report.ended, true)}`
        : `${day(report.started)}, ${time(report.started)} – ${time(report.ended, true)}`
        : `${day(report.started)}, ${time(report.started, true)} – ${day(report.ended)}, ${time(report.ended, true)}`;

    /** The result in a box, the score beside it; its height. */
    const pad = 16, scoreRoom = 118, detail = lines([{ text: report.status.detail ?? '' }], CONTENT - pad * 2 - scoreRoom - 12, 10).slice(0, 2);
    const boxHeight = Math.max(pad * 2 + 22 + detail.length * 14, 80);
    const resultBox = y => {
        const status = report.status, tone = status.verified ? GREEN : AMBER, h = boxHeight;
        page.drawRectangle({ x: M, y: H - y - h, width: CONTENT, height: h, borderColor: color(INK), borderWidth: 0.7 });
        page.drawRectangle({ x: M + 2.5, y: H - y - h + 2.5, width: CONTENT - 5, height: h - 5, borderColor: color(INK), borderWidth: 0.3 });
        const ix = M + pad + 6, iy = y + pad + 7.5;
        page.drawCircle({ x: ix, y: H - iy, size: 6.5, borderColor: color(tone), borderWidth: 1.1 });
        if (status.verified) page.drawSvgPath('M-2.8 0.2 L-0.9 2.1 L2.9 -1.9', { x: ix, y: H - iy, borderColor: color(tone), borderWidth: 1.2, borderLineCap: 1 });
        else {
            page.drawLine({ start: { x: ix, y: H - iy + 3.2 }, end: { x: ix, y: H - iy - 0.6 }, thickness: 1.2, color: color(tone), lineCap: 1 });
            page.drawCircle({ x: ix, y: H - iy - 3.1, size: 0.75, color: color(tone) });
        }
        text(status.headline, M + pad + 19, y + pad + 0.5, 13.5, bold, tone);
        drawLines(detail, M + pad, y + pad + 22, 10, 14, GREY);
        const sx = W - M - scoreRoom + 16;
        page.drawLine({ start: { x: sx - 16, y: H - y - 12 }, end: { x: sx - 16, y: H - y - h + 12 }, thickness: 0.4, color: color(RULE) });
        caps('Huma Score', sx, y + pad + 1, 7);
        if (report.score) {
            const value = String(report.score.value);
            text(value, sx, y + pad + 14, 32, bold);
            text('/ 100', sx + width(value, 32, bold) + 4, y + pad + 32, 10.5, serif, GREY);
            // Where it was written, and how strong that check is.
            text(tierOf(report), sx, y + pad + 50, 8.5, serif, GREY);
        } else text('None', sx, y + pad + 18, 18, bold, QUIET);
        return h;
    };

    // ——— Page 1, the cover: drawn last, once the pages it lists are known ———
    newPage();

    // ——— The document, in full, framed apart from the report: pasted parts shaded and marked in its margin ———
    newPage();
    const textFirst = pages.length;
    heading(1, 'The Document');
    const all = report.paragraphs.map(runs => runs.map(run => run.text).join('')).join('\n');
    const words = all.split(/\s+/).filter(Boolean).length, mix = report.mix;
    const pastedAny = report.paragraphs.some(runs => runs.some(run => run.pasted && run.text.trim())) || mix?.share > 0;
    // The frame: a box on each page the document runs over, named on its top edge and closed on its bottom one.
    const inset = 18, size = 11.5, leading = 17.5;
    let frameTop = top, continued = false;
    /** Room for one more line in the frame, or the frame closes here and goes on over the page. */
    const fits = height => { if (top + height > BOTTOM - 12) { closeFrame(false); newPage(); frameTop = top; continued = true; top += 22; } };
    const legend = (value, x, y) => {
        const w = capsWidth(value, 7), at = x ?? middle(w);
        page.drawRectangle({ x: at - 5, y: H - y - 5, width: w + 10, height: 10, color: rgb(1, 1, 1) });
        caps(value, at, y - 3.2, 7, GREY);
    };
    const closeFrame = last => {
        const bottom = top + 12;
        page.drawRectangle({ x: M, y: H - bottom, width: CONTENT, height: bottom - frameTop, borderColor: color(INK), borderWidth: 0.6 });
        legend(continued ? 'Document, continued' : 'Start of document', M + inset - 5, frameTop);
        legend(last ? 'End of document' : 'Continued on the next page', undefined, bottom);
        top = bottom;
    };
    top += 22;
    if (!all.trim()) { text('No text.', M + inset, top, size, serif, GREY); top += leading; }
    else for (const runs of report.paragraphs) {
        // Words keep whether they were pasted; lines break between words, and line breaks stay.
        const blocks = [[]];
        for (const run of runs) run.text.split(/(\n)/).forEach(part => { if (part === '\n') blocks.push([]); else if (part) blocks.at(-1).push({ text: part, pasted: run.pasted }); });
        for (const block of blocks) {
            const list = lines(block, CONTENT - 2 * inset, size);
            if (!list.length) { fits(leading); top += leading; continue; }
            for (const line of list) {
                fits(leading);
                if (line.some(piece => piece.run.pasted && !piece.space))
                    page.drawRectangle({ x: M + 7, y: H - top - leading + 2, width: 2.2, height: leading - 3, color: color(AMBER) });
                let x = M + inset;
                for (const piece of line) {
                    if (piece.run.pasted) page.drawRectangle({ x: x - 0.3, y: H - top - leading + 2, width: piece.w + 0.6, height: leading - 3, color: color(TINT) });
                    if (!piece.space) page.drawText(piece.text, { x, y: H - top - leading / 2 - size * 0.35, size, font: serif, color: color(INK) });
                    x += piece.w;
                }
                top += leading;
            }
        }
        top += 7;
    }
    closeFrame(true);

    // A summary of the document under it, at the foot of the page: its length, how much was typed and pasted, and the key.
    const facts = [`${words.toLocaleString('en-US')} ${words === 1 ? 'word' : 'words'}`];
    if (mix) facts.push(...(mix.share > 0 ? [`${mix.typed} typed`, `${mix.pasted} pasted`] : ['All typed']));
    const summaryHeight = 13 + 8 + 18 + (mix?.share > 0 ? 14 : 0) + (pastedAny || (p && !mix) ? 14 : 0);
    top += 28;
    need(summaryHeight);
    top = Math.max(top, BOTTOM - summaryHeight);
    caps('Summary', M, top); top += 13; rule(top, INK, 0.6); top += 8;
    text(facts.join('  ·  '), M, top, 10.5, serif, INK);
    top += 18;
    if (mix?.share > 0) {
        const typedWidth = CONTENT * (1 - mix.share);
        page.drawRectangle({ x: M, y: H - top - 6, width: CONTENT, height: 6, borderColor: color(QUIET), borderWidth: 0.5 });
        page.drawRectangle({ x: M + typedWidth, y: H - top - 6, width: CONTENT - typedWidth, height: 6, color: color(TINT), borderColor: color(QUIET), borderWidth: 0.5 });
        top += 14;
    }
    if (pastedAny) {
        page.drawRectangle({ x: M, y: H - top - 9, width: 14, height: 9, borderColor: color(QUIET), borderWidth: 0.5 });
        text('Typed', M + 19, top + 0.5, 9, serif, GREY);
        const px = M + 19 + width('Typed', 9) + 18;
        page.drawRectangle({ x: px, y: H - top - 9, width: 14, height: 9, color: color(TINT), borderColor: color(QUIET), borderWidth: 0.5 });
        page.drawRectangle({ x: px - 6, y: H - top - 9, width: 2.2, height: 9, color: color(AMBER) });
        text('Pasted: shaded, and marked in the margin', px + 19, top + 0.5, 9, serif, GREY);
        top += 14;
    } else if (p && !mix) {
        text('Which parts were pasted isn’t known: the writing replay wasn’t shared.', M, top, 9, serif, GREY);
        top += 14;
    }
    const textLast = pages.length;

    // ——— The last page: everything that verifies it ———
    newPage();
    const verifyAt = pages.length, verifyName = report.stopped ? 'Why It Stopped' : 'Verification';
    heading(2, verifyName);
    top += resultBox(top) + 24;

    // Two columns: how the score adds up, and the typing checks. A stopped recording shows what was measured instead.
    const gutter = 28, left = report.score ? 280 : CONTENT, right = CONTENT - left - gutter, rx = M + left + gutter;
    const columnTop = top;
    if (report.score || report.stopped) {
        caps(report.score ? 'Score' : 'What was measured', M, top);
        top += 13; rule(top, INK, 0.6, M, M + left);
        const rowsOf = report.score ? report.score.rows : report.stopped;
        const nameWidth = report.score ? 92 : 190;
        for (const [part, result, points] of rowsOf) {
            const values = lines([{ text: result }], left - nameWidth - (points ? 48 : 0), 9.5);
            const h = values.length * 13 + 8;
            need(h);
            text(part, M, top + 6, 9.5, serif, GREY);
            drawLines(values, M + nameWidth, top + 4, 9.5, 13);
            if (points) text(points, M + left - width(points, 9.5), top + 6, 9.5);
            top += h; rule(top, RULE, 0.5, M, M + left);
        }
        if (report.score) {
            const total = `${report.score.value} / 100`;
            text('Huma Score · ' + tierOf(report), M, top + 6, 9.5, bold); text(total, M + left - width(total, 9.5, bold), top + 6, 9.5, bold);
            top += 21; rule(top, INK, 0.6, M, M + left);
        }
    }
    if (report.score) {
        // The nine writing rules: a check for each one met, a cross for each one missed.
        let ry = columnTop;
        caps('Typing checks', rx, ry);
        ry += 13; page.drawLine({ start: { x: rx, y: H - ry }, end: { x: rx + right, y: H - ry }, thickness: 0.6, color: color(INK) });
        ry += 6;
        RULES_MET.forEach((ruleName, i) => {
            const met = report.rules?.[i] !== false, cx = rx + 4, cy = H - (ry + 6.5);
            if (met) page.drawSvgPath('M-3 0 L-1 2.2 L3.2 -2.4', { x: cx, y: cy, borderColor: color(GREEN), borderWidth: 1.2, borderLineCap: 1 });
            else page.drawSvgPath('M-2.6 -2.6 L2.6 2.6 M-2.6 2.6 L2.6 -2.6', { x: cx, y: cy, borderColor: color(AMBER), borderWidth: 1.2, borderLineCap: 1 });
            text(ruleName, rx + 14, ry + 2, 9.5, serif, met ? INK : AMBER);
            ry += 15;
        });
        top = Math.max(top, ry);
    }
    top += 22;

    // The session's figures, side by side: a small label over each value.
    if (report.session.length) {
        const perRow = 4, cell = CONTENT / perRow;
        caps('Session', M, top); top += 13; rule(top, INK, 0.6); top += 8;
        report.session.forEach(([label, figure], i) => {
            const x = M + (i % perRow) * cell, y = top + Math.floor(i / perRow) * 30;
            caps(label, x, y, 6.5);
            text(figure, x, y + 11, 10.5);
        });
        top += Math.ceil(report.session.length / perRow) * 30 + 10;
    }

    // The proof, in three hashes, and what's attached.
    if (p) {
        caps('Proof', M, top); top += 13; rule(top, INK, 0.6); top += 7;
        const proofRow = (label, value) => { text(label, M, top + 1, 9, serif, GREY); text(value, M + 100, top + 1, 8.5, serif); top += 14; };
        proofRow('Proof SHA-256', p.fingerprint);
        if (p.textHash) proofRow('Text SHA-256', p.textHash);
        proofRow('Signing key SHA-256', p.signingKey);
        const files = [report.attachment?.name, report.replay?.name].filter(Boolean).join(', ');
        paragraph([{ text: 'Proved with ', ink: GREY }, { text: 'Noir', url: NOIR_URL }, { text: ' on ', ink: GREY }, { text: 'Barretenberg', url: BARRETENBERG_URL },
            { text: `  ·  ${p.parts} ${p.parts === 1 ? 'proof' : 'proofs'}, ${p.size}` + (files ? `  ·  attached: ${files}` : ''), ink: GREY }], { size: 9, leading: 13 });
        top += 14;
    }

    // How to check it, and every source as a link, at the foot of the page.
    const qrSize = 62, room = CONTENT - qrSize - 24;
    top = Math.max(top, BOTTOM - qrSize - 12);
    const drawQR = (x, y, side) => {
        const cell = side / report.qr.length;
        report.qr.forEach((line, ry2) => line.forEach((on, rx2) => {
            if (on) page.drawRectangle({ x: x + rx2 * cell, y: H - (y + (ry2 + 1) * cell), width: cell + 0.02, height: cell + 0.02, color: color(INK) });
        }));
        link(x, y, side, side, report.link ?? VERIFY_URL);
    };
    if (report.qr) drawQR(W - M - qrSize, top, qrSize);
    caps('Check it', M, top);
    const check = !p ? [{ text: 'A stopped recording has no proof to check. Its typing is measured above.' }]
        : report.link ? [{ text: 'Open the shared page', url: report.link }, { text: ', or drop this PDF into ' }, { text: 'huma.social/verify', url: VERIFY_URL }, { text: '.' }]
        : [{ text: 'Drop this PDF into ' }, { text: 'huma.social/verify', url: VERIFY_URL }, { text: '.' }];
    drawLines(lines(check, room, 10), M, top + 12, 10, 14);
    caps('Links', M, top + 34);
    const sources = refs.filter(item => item.key !== 'page' && item.key !== 'verify');
    const linkRuns = sources.flatMap((item, i) => [...(i ? [{ text: '  ·  ', ink: QUIET }] : []), { text: item.title, url: item.url }]);
    drawLines(lines(linkRuns, room, 9), M, top + 45, 9, 12);

    // ——— The cover ———
    page = pages[0];
    let y = 58;
    const markHeight = 66;
    drawMark(W / 2 - markHeight * 413 / 710 / 2, y, markHeight);
    y += markHeight + 16;
    caps('Huma', middle(capsWidth('Huma', 24, bold, 8)), y, 24, INK, bold, 8);
    y += 32;
    text('huma.social', middle(width('huma.social', 12)), y, 12, serif, LINK);
    link(middle(width('huma.social', 12)), y - 2, width('huma.social', 12), 16, SITE_URL);
    y += 32;
    rule(y, INK, 0.9, W / 2 - 56, W / 2 + 56); rule(y + 3, INK, 0.35, W / 2 - 56, W / 2 + 56);
    y += 20;
    caps('Writing Report', middle(capsWidth('Writing Report', 13, serif, 4)), y, 13, GREY, serif, 4);
    y += 30;
    const below = y;
    // The title, centered, up to three lines; a longer one ends in an ellipsis.
    const titleLines = lines([{ text: name, font: bold }], CONTENT - 30, 24), title = titleLines.slice(0, 3);
    if (titleLines.length > 3) {
        const last = title[2], ellipsis = { text: '…', w: width('…', 24, bold), run: {}, font: bold, size: 24 };
        while (last.length && lineWidth(last) + ellipsis.w > CONTENT - 30) last.pop();
        while (last.at(-1)?.space) last.pop();
        last.push(ellipsis);
    }
    // How to read and check the report, in a few lines.
    const range = (a, b) => (a === b ? `${a}` : `${a}–${b}`);
    const steps = [
        ...(pastedAny ? ['Shaded text was pasted; the rest was typed.'] : mix ? ['All of the document was typed.'] : []),
        p ? 'To check it, drop this PDF into huma.social/verify.' : 'A stopped recording has no score or proof.',
        'Each page shows the text’s SHA-256.',
    ];
    const qr = 104, column = CONTENT - qr - 40, stepLines = steps.map(step => lines([{ text: step.trim() }], column - 16, 9.5));
    // The result, contents and steps sit at the foot of the cover; the title, centered in the room above them.
    const lowerHeight = Math.max(13 + 6 + 2 * 19 + 18 + 13 + 8 + stepLines.reduce((sum, list) => sum + list.length * 13.5 + 5, 0), report.qr ? qr + 30 : 0);
    const foot = BOTTOM - 8 - boxHeight - 28 - lowerHeight;
    const titleHeight = title.length * 30 + 8 + (report.writer ? 21 : 0) + 15 + 14;
    y = below + Math.max(0, (foot - below - titleHeight) / 2);
    y += drawLines(title, M, y, 24, 30, INK, 'center') + 8;
    if (report.writer) {
        const by = `by ${report.writer}`;
        text(by, middle(width(by, 12.5)), y, 12.5, serif, INK); y += 21;
    }
    text(written, middle(width(written, 10.5)), y, 10.5, serif, GREY); y += 15;
    const wx = middle(width('Written in Huma', 10.5));
    text('Written in ', wx, y, 10.5, serif, GREY);
    text('Huma', wx + width('Written in ', 10.5), y, 10.5, serif, LINK); link(wx + width('Written in ', 10.5), y - 2, width('Huma', 10.5), 14, SITE_URL);
    y = Math.max(y + 32, foot);
    y += resultBox(y) + 28;

    // The contents and how the report works on the left; the code to see the page live on the right.
    const lower = y;
    caps('Contents', M, y); y += 13; rule(y, INK, 0.6, M, M + column); y += 6;
    for (const [number, title2, at, to] of [[1, 'The Document', textFirst, textLast], [2, verifyName, verifyAt, verifyAt]]) {
        const label = `${number}.   ${title2}`, pagesLabel = range(at, to);
        text(label, M, y + 3, 10.5); text(pagesLabel, M + column - width(pagesLabel, 10.5), y + 3, 10.5);
        // Dot leaders between the name and its page.
        const from = M + width(label, 10.5) + 6, until = M + column - width(pagesLabel, 10.5) - 6;
        for (let dot = from; dot < until; dot += 4.5) page.drawCircle({ x: dot, y: H - (y + 11.5), size: 0.45, color: color(QUIET) });
        goto(M, y, column, 18, pages[at - 1]);
        y += 19;
    }
    y += 18;
    caps('How this report works', M, y); y += 13; rule(y, INK, 0.6, M, M + column); y += 8;
    stepLines.forEach((list, i) => {
        text(`${i + 1}.`, M, y + 2.5, 9.5, bold);
        y += drawLines(list, M + 16, y, 9.5, 13.5) + 5;
    });
    if (report.qr) {
        const qx = W - M - qr;
        drawQR(qx, lower, qr);
        const caption = report.link ? ['Scan to see it live', 'huma.social'] : ['Scan to check it', 'huma.social/verify'];
        text(caption[0], qx + (qr - width(caption[0], 9.5, bold)) / 2, lower + qr + 9, 9.5, bold);
        text(caption[1], qx + (qr - width(caption[1], 8.5)) / 2, lower + qr + 22, 8.5, serif, GREY);
    }

    // On every page: a double frame, the text's SHA-256 and the page number; past the cover, a running head.
    const textHash = p?.textHash ?? report.textHash;
    const made = `Made ${day(report.savedAt)} by ${report.madeBy}`;
    pages.forEach((sheet, i) => {
        page = sheet;
        page.drawRectangle({ x: 24, y: 24, width: W - 48, height: H - 48, borderColor: color(INK), borderWidth: 1.4 });
        page.drawRectangle({ x: 28.5, y: 28.5, width: W - 57, height: H - 57, borderColor: color(INK), borderWidth: 0.4 });
        if (i) {
            const head = 'Huma Writing Report', headWidth = capsWidth(head, 7);
            const markWidth = drawMark(M, 41, 10);
            text(fit(name, 9, serif, CONTENT - headWidth - markWidth - 30), M + markWidth + 7, 42, 9, serif, GREY);
            caps(head, W - M - headWidth, 43, 7);
            rule(58);
        }
        rule(FOOT);
        if (textHash) {
            const lead = 'Text SHA-256   ';
            text(lead, M, FOOT + 8, 7.5, serif, GREY);
            text(textHash, M + width(lead, 7.5), FOOT + 8, 7.5, serif, GREY);
        }
        const number = `Page ${i + 1} of ${pages.length}`;
        text(number, W - M - width(number, 7.5), FOOT + 8, 7.5, serif, GREY);
        if (i === pages.length - 1) text(made, M, FOOT - 13, 7.5, serif, QUIET);
    });

    if (report.attachment) {
        await doc.attach(report.attachment.bytes, report.attachment.name, {
            mimeType: 'application/json', description: 'The page proof. Drop this PDF or the file into huma.social/verify.',
            creationDate: report.savedAt, modificationDate: report.savedAt, afRelationship: AFRelationship.Data });
    }
    if (report.replay) {
        await doc.attach(report.replay.bytes, report.replay.name, {
            mimeType: 'application/json', description: 'Every edit, signed with the page proof’s key: how the page was written, and which parts were pasted.',
            creationDate: report.savedAt, modificationDate: report.savedAt, afRelationship: AFRelationship.Supplement });
    }
    return doc.save();
}

/** The page proof inside a report PDF, as text, or null when it has none (verify.mjs, for a dropped report). */
export async function attachedProof(bytes, PDFLib) { return (await attached(bytes, PDFLib)).proof; }
/** The page proof and, when the writer attached it, the writing replay inside a report PDF, as text (null when absent). */
export async function attached(bytes, PDFLib) {
    const { PDFDocument, PDFName, PDFArray, PDFDict, PDFRawStream, PDFHexString, PDFString } = PDFLib;
    const doc = await PDFDocument.load(bytes, { updateMetadata: false });
    const names = doc.catalog.lookup(PDFName.of('Names'), PDFDict);
    const files = names?.lookup(PDFName.of('EmbeddedFiles'), PDFDict);
    const list = files?.lookup(PDFName.of('Names'), PDFArray), found = { proof: null, replay: null };
    if (!list) return found;
    for (let i = 0; i + 1 < list.size(); i += 2) {
        const key = list.lookup(i);
        const fileName = key instanceof PDFHexString || key instanceof PDFString ? key.decodeText() : '';
        const spec = list.lookup(i + 1, PDFDict), embedded = spec.lookup(PDFName.of('EF'), PDFDict)?.lookup(PDFName.of('F'), PDFRawStream);
        if (!embedded || !/\.json$/i.test(fileName)) continue;
        const decoded = await embeddedBytes(embedded, PDFName);
        if (!decoded) continue;
        const body = new TextDecoder('utf-8', { fatal: true }).decode(decoded);
        if (fileName === REPLAY_FILE) found.replay ??= body; else found.proof ??= body;
    }
    return found;
}

// A page proof is at most 8 MB (PROOF_LIMIT); an attachment that inflates past that is skipped, so a tiny PDF can't
// expand to gigabytes in the reader's tab.
const ATTACHED_LIMIT = 8 * 1024 * 1024;
/** An attached file's bytes: stored as is or with one Flate filter (as Download Report writes it), else null. */
async function embeddedBytes(stream, PDFName) {
    const filter = stream.dict.lookup(PDFName.of('Filter')), parms = stream.dict.lookup(PDFName.of('DecodeParms'));
    const filters = filter === undefined ? [] : typeof filter.asArray === 'function' ? filter.asArray() : [filter];
    if (parms !== undefined || filters.length > 1 || filters.some(f => f !== PDFName.of('FlateDecode'))) return null;
    if (!filters.length) return stream.contents.length > ATTACHED_LIMIT ? null : stream.contents;
    try {
        const reader = new Blob([stream.contents]).stream().pipeThrough(new DecompressionStream('deflate')).getReader();
        const parts = []; let size = 0;
        for (let next = await reader.read(); !next.done; next = await reader.read()) {
            size += next.value.length;
            if (size > ATTACHED_LIMIT) { await reader.cancel(); return null; }
            parts.push(next.value);
        }
        const out = new Uint8Array(size); let at = 0;
        for (const part of parts) { out.set(part, at); at += part.length; }
        return out;
    } catch { return null; }
}
