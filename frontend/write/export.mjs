// The page itself, to keep or open elsewhere: as a PDF, a Word document or Markdown, with its styles, lists and links.
// Made in this browser from the editor's document (schema.mjs); nothing about the recording or the proof goes in.
import { STYLES, TEXT_BLOCKS, styleOf } from './schema.mjs';

/** The page as a list of lines of text: each with its paragraph style, block settings, list marker and depth. */
export function blocks(doc) {
  const out = [];
  const runsOf = node => {
    const runs = [];
    node.forEach(child => {
      if (child.type.name === 'hard_break') { runs.push({ text: '\n' }); return; }
      if (!child.isText) return;
      const run = { text: child.text };
      for (const mark of child.marks) {
        const n = mark.type.name;
        if (n === 'strong') run.bold = true; else if (n === 'em') run.italic = true; else if (n === 'underline') run.underline = true;
        else if (n === 'strike') run.strike = true; else if (n === 'sup' || n === 'sub') run.script = n;
        else if (n === 'link') run.href = mark.attrs.href; else if (n === 'size') run.size = mark.attrs.pt;
        else if (n === 'color') run.color = mark.attrs.value; else if (n === 'highlight') run.highlight = mark.attrs.value;
        else if (n === 'font') run.font = mark.attrs.family;
      }
      runs.push(run);
    });
    return runs;
  };
  const walk = (node, depth, marker, quote = false) => {
    const name = node.type.name;
    if (TEXT_BLOCKS.has(name)) out.push({ style: String(styleOf(node)), attrs: node.attrs, runs: runsOf(node), depth, marker, quote });
    else if (name === 'code_block') out.push({ style: 'paragraph', attrs: {}, runs: [{ text: node.textContent, code: true }], depth, marker, quote });
    else if (name === 'horizontal_rule' || name === 'page_break') out.push({ style: name });
    else if (name === 'blockquote') node.forEach(child => walk(child, depth + 1, null, true));
    else if (name === 'bullet_list' || name === 'ordered_list' || name === 'check_list') {
      let n = 0;
      node.forEach(item => {
        n++; let first = true;
        const mark = name === 'bullet_list' ? { kind: 'bullet', text: '•' } : name === 'ordered_list' ? { kind: 'number', text: n + '.' }
          : { kind: 'check', done: Boolean(item.attrs.done), text: item.attrs.done ? '☒' : '☐' };
        item.forEach(child => { walk(child, depth + 1, first ? mark : null, quote); first = false; });
      });
    }
  };
  doc.forEach(node => walk(node, 0, null));
  return out;
}

/** The page as a PDF: US Letter, 1-inch margins, its styles in Tinos (the report's serif). */
export async function pagePDF(doc, name, { PDFLib, fontkit, fonts }) {
  const { PDFDocument, PDFString, rgb, degrees } = PDFLib;
  const pdf = await PDFDocument.create();
  pdf.registerFontkit(fontkit);
  const [regular, bold] = await Promise.all([fonts.serif, fonts.bold].map(bytes => pdf.embedFont(bytes, { subset: true })));
  pdf.setTitle(name); pdf.setCreator('Huma'); pdf.setProducer('Huma');
  const W = 612, H = 792, M = 72;
  const hex = value => { const n = parseInt((value ?? '#000000').slice(1), 16); return rgb((n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255); };
  let page, y, empty;
  const newPage = () => { page = pdf.addPage([W, H]); y = M; empty = true; };
  newPage();
  for (const block of blocks(doc)) {
    if (block.style === 'page_break') { newPage(); continue; }
    if (block.style === 'horizontal_rule') {
      if (y + 12 > H - M) newPage();
      page.drawLine({ start: { x: M, y: H - y - 6 }, end: { x: W - M, y: H - y - 6 }, thickness: 0.75, color: hex('#bbbbbb') });
      y += 12; empty = false; continue;
    }
    const style = STYLES[block.style] ?? STYLES.paragraph, a = block.attrs ?? {};
    const spacing = (a.line ?? 1.15) * 1.15, left = M + block.depth * 36 + (a.indent ?? 0) * 0.75, room = Math.max(72, W - M - (a.right ?? 0) * 0.75 - left);
    if (!empty) y += a.before ?? style.before;
    // Pieces of text with their look, grouped into words so lines break only between words.
    const look = run => ({ font: run.bold ? bold : regular, size: (run.size ?? style.size) * (run.script ? 0.6 : 1), run });
    const measure = piece => piece.font.widthOfTextAtSize(piece.text, piece.size);
    const items = []; let word = [];
    const flush = () => { if (word.length) items.push({ word }); word = []; };
    for (const run of block.runs) {
      for (const part of run.text.split(/(\n|[^\S\n]+)/)) {
        if (!part) continue;
        if (part === '\n') { flush(); items.push({ br: true }); }
        else if (/^\s+$/.test(part)) { flush(); items.push({ space: { ...look(run), text: ' ' } }); }
        else word.push({ ...look(run), text: part });
      }
    }
    flush();
    const lines = []; let line = [], used = 0;
    const end = () => { while (line.length && line.at(-1).space) used -= line.pop().w; lines.push(line); line = []; used = 0; };
    const add = piece => { const w = measure(piece); line.push({ ...piece, w }); used += w; };
    for (const item of items) {
      if (item.br) { end(); continue; }
      if (item.space) { if (line.length) add({ ...item.space, space: true }); continue; }
      const w = item.word.reduce((sum, piece) => sum + measure(piece), 0);
      if (used + w <= room) { item.word.forEach(add); continue; }
      if (line.length) end();
      if (w <= room) { item.word.forEach(add); continue; }
      // A word longer than the line breaks between characters.
      for (const piece of item.word) for (const c of piece.text) {
        const one = { ...piece, text: c };
        if (used + measure(one) > room && line.length) end();
        add(one);
      }
    }
    end();
    lines.forEach((pieces, i) => {
      const size = Math.max(style.size, ...pieces.map(p => p.run.size ?? 0)), leading = size * spacing;
      if (y + leading > H - M) newPage();
      const baseline = y + leading - size * 0.25 - (leading - size) / 2;
      const width = pieces.reduce((sum, p) => sum + p.w, 0);
      let x = a.align === 'center' ? left + (room - width) / 2 : a.align === 'right' ? left + room - width : left;
      if (i === 0 && block.marker) {
        if (block.marker.kind === 'check') {
          const box = size * 0.7, bx = left - 18, by = baseline - box * 0.9;
          page.drawRectangle({ x: bx, y: H - by - box, width: box, height: box, borderColor: hex('#444444'), borderWidth: 0.75 });
          if (block.marker.done) page.drawSvgPath(`M ${box * 0.2} ${box * 0.5} L ${box * 0.42} ${box * 0.75} L ${box * 0.82} ${box * 0.22}`,
            { x: bx, y: H - by, borderColor: hex('#222222'), borderWidth: 1 });
        } else page.drawText(block.marker.text, { x: left - 18, y: H - baseline, size: style.size, font: regular, color: hex(style.color) });
      }
      for (const p of pieces) {
        const r = p.run, ink = hex(r.href ? '#1155cc' : r.color ?? style.color), shift = r.script === 'sup' ? size * 0.33 : r.script === 'sub' ? -size * 0.12 : 0;
        if (r.highlight) page.drawRectangle({ x, y: H - baseline - size * 0.25, width: p.w, height: size * 1.15, color: hex(r.highlight) });
        if (!p.space) page.drawText(p.text, { x, y: H - baseline + shift, size: p.size, font: p.font, color: ink, ...(r.italic || style.italic ? { ySkew: degrees(12) } : {}) });
        if (r.underline || r.href) page.drawLine({ start: { x, y: H - baseline - size * 0.12 }, end: { x: x + p.w, y: H - baseline - size * 0.12 }, thickness: size / 18, color: ink });
        if (r.strike) page.drawLine({ start: { x, y: H - baseline + size * 0.28 }, end: { x: x + p.w, y: H - baseline + size * 0.28 }, thickness: size / 18, color: ink });
        if (r.href && !p.space) page.node.addAnnot(pdf.context.register(pdf.context.obj({ Type: 'Annot', Subtype: 'Link', Border: [0, 0, 0],
          Rect: [x, H - baseline - size * 0.25, x + p.w, H - baseline + size * 0.9], A: { Type: 'Action', S: 'URI', URI: PDFString.of(r.href.replace(/[\\()]/g, c => '\\' + c)) } })));
        x += p.w;
      }
      y += leading;
    });
    if (!lines.length) y += style.size * spacing;
    y += a.after ?? style.after; empty = false;
  }
  return pdf.save();
}

// Word: the smallest .docx Word, Pages and Google Docs open, styles named as Word names them.
const xml = text => text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const STYLE_IDS = { paragraph: null, title: 'Title', subtitle: 'Subtitle', 1: 'Heading1', 2: 'Heading2', 3: 'Heading3', 4: 'Heading4', 5: 'Heading5', 6: 'Heading6' };
const twips = pt => Math.round(pt * 20);

/** The page as a Word document (.docx), as bytes. */
export function pageDocx(doc, name) {
  const links = [], body = [];
  for (const block of blocks(doc)) {
    if (block.style === 'page_break') { body.push('<w:p><w:r><w:br w:type="page"/></w:r></w:p>'); continue; }
    if (block.style === 'horizontal_rule') { body.push('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="BBBBBB"/></w:pBdr></w:pPr></w:p>'); continue; }
    const a = block.attrs ?? {}, id = STYLE_IDS[block.style], left = block.depth * 720 + Math.round((a.indent ?? 0) * 15);
    const props = [id ? `<w:pStyle w:val="${id}"/>` : '',
      a.before !== null && a.before !== undefined || a.after !== null && a.after !== undefined || a.line
        ? `<w:spacing${a.before != null ? ` w:before="${twips(a.before)}"` : ''}${a.after != null ? ` w:after="${twips(a.after)}"` : ''}${a.line ? ` w:line="${Math.round(a.line * 240)}" w:lineRule="auto"` : ''}/>` : '',
      left || block.marker ? `<w:ind w:left="${left}"${block.marker ? ' w:hanging="360"' : ''}/>` : '',
      a.align ? `<w:jc w:val="${a.align === 'justify' ? 'both' : a.align}"/>` : ''].join('');
    const runs = block.runs.map(run => {
      const rp = [run.font ? `<w:rFonts w:ascii="${xml(run.font)}" w:hAnsi="${xml(run.font)}" w:cs="${xml(run.font)}"/>` : run.code ? '<w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/>' : '',
        run.bold ? '<w:b/>' : '', run.italic ? '<w:i/>' : '', run.strike ? '<w:strike/>' : '',
        run.href ? '<w:color w:val="1155CC"/>' : run.color ? `<w:color w:val="${run.color.slice(1).toUpperCase()}"/>` : '',
        run.size ? `<w:sz w:val="${Math.round(run.size * 2)}"/>` : '', run.highlight ? `<w:shd w:val="clear" w:color="auto" w:fill="${run.highlight.slice(1).toUpperCase()}"/>` : '',
        run.underline || run.href ? '<w:u w:val="single"/>' : '', run.script ? `<w:vertAlign w:val="${run.script === 'sup' ? 'superscript' : 'subscript'}"/>` : ''].join('');
      const content = run.text === '\n' ? '<w:br/>' : run.text.split(/(\t|\n)/).map(part => part === '\t' ? '<w:tab/>' : part === '\n' ? '<w:br/>' : part ? `<w:t xml:space="preserve">${xml(part)}</w:t>` : '').join('');
      const r = `<w:r>${rp ? `<w:rPr>${rp}</w:rPr>` : ''}${content}</w:r>`;
      if (!run.href) return r;
      links.push(run.href);
      return `<w:hyperlink r:id="link${links.length}">${r}</w:hyperlink>`;
    }).join('');
    const marker = block.marker ? `<w:r><w:t xml:space="preserve">${xml(block.marker.text)}</w:t></w:r><w:r><w:tab/></w:r>` : '';
    body.push(`<w:p>${props ? `<w:pPr>${props}</w:pPr>` : ''}${marker}${runs}</w:p>`);
  }
  const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
  const head = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const style = (id, label, s) => `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${label}"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>`
    + `<w:pPr><w:keepNext/><w:spacing w:before="${twips(s.before)}" w:after="${twips(s.after)}"/>${id.startsWith('Heading') ? `<w:outlineLvl w:val="${Number(id.slice(7)) - 1}"/>` : ''}</w:pPr>`
    + `<w:rPr><w:sz w:val="${s.size * 2}"/>${s.color ? `<w:color w:val="${s.color.slice(1).toUpperCase()}"/>` : ''}${s.italic ? '<w:i/>' : ''}</w:rPr></w:style>`;
  const styles = `${head}<w:styles ${W}><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Arial" w:cs="Arial"/><w:sz w:val="22"/></w:rPr></w:rPrDefault>`
    + '<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
    + '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
    + Object.entries(STYLE_IDS).filter(([, id]) => id).map(([key, id]) => style(id, id === 'Title' || id === 'Subtitle' ? id : 'heading ' + id.slice(7), STYLES[key])).join('')
    + '<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/><w:rPr><w:color w:val="1155CC"/><w:u w:val="single"/></w:rPr></w:style></w:styles>';
  const files = {
    '[Content_Types].xml': `${head}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`
      + '<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
      + '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
      + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>',
    '_rels/.rels': `${head}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`
      + '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>',
    'docProps/core.xml': `${head}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${xml(name)}</dc:title><dc:creator>Huma</dc:creator></cp:coreProperties>`,
    'word/document.xml': `${head}<w:document ${W}><w:body>${body.join('')}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>`,
    'word/styles.xml': styles,
    'word/_rels/document.xml.rels': `${head}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="styles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`
      + links.map((href, i) => `<Relationship Id="link${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${xml(href)}" TargetMode="External"/>`).join('') + '</Relationships>',
  };
  return zip(Object.entries(files).map(([path, text]) => [path, new TextEncoder().encode(text)]));
}

/** The page as Markdown: headings, emphasis, lists and links; formatting Markdown has no word for is left out. */
export function pageMarkdown(doc) {
  const escape = text => text.replace(/([\\`*_[\]<>#])/g, '\\$1');
  const out = [];
  let listed = false;
  for (const block of blocks(doc)) {
    if (block.style === 'page_break') continue;
    const inList = Boolean(block.marker) || (listed && block.depth > 0 && !block.quote);
    if (listed && !inList) out.push('');
    listed = inList;
    if (block.style === 'horizontal_rule') { out.push('---', ''); continue; }
    let text = block.runs.map(run => {
      if (run.text === '\n') return '  \n';
      let t = escape(run.text);
      if (!t.trim()) return t;
      if (run.code) t = '`' + run.text + '`';
      if (run.bold && run.italic) t = `***${t}***`; else if (run.bold) t = `**${t}**`; else if (run.italic) t = `*${t}*`;
      if (run.strike) t = `~~${t}~~`;
      return run.href ? `[${t}](${run.href.replace(/[()\s]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))})` : t;
    }).join('');
    const indent = '   '.repeat(Math.max(0, block.depth - 1));
    if (block.marker) text = indent + (block.marker.kind === 'bullet' ? '- ' : block.marker.kind === 'number' ? block.marker.text + ' ' : block.marker.done ? '- [x] ' : '- [ ] ') + text;
    else if (block.style === 'title') text = '# ' + text;
    else if (/^[1-6]$/.test(block.style)) text = '#'.repeat(Math.min(6, Number(block.style) + 1)) + ' ' + text;
    else if (block.quote) text = '> ' + text;
    else if (inList) text = indent + '   ' + text;
    out.push(text, ...(inList ? [] : ['']));
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

// A .zip with its files stored as they are: Word reads it, and the page is small enough not to need compressing.
const CRC = Array.from({ length: 256 }, (_, n) => { for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1; return n >>> 0; });
const crc32 = bytes => { let c = 0xffffffff; for (const b of bytes) c = CRC[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
export function zip(files) {
  const parts = [], central = []; let offset = 0;
  for (const [path, data] of files) {
    const name = new TextEncoder().encode(path), crc = crc32(data);
    const local = new DataView(new ArrayBuffer(30));
    [[0, 0x04034b50, 4], [4, 20, 2], [6, 0x0800, 2], [8, 0, 2], [10, 0, 2], [12, 0x21, 2], [14, crc, 4], [18, data.length, 4], [22, data.length, 4], [26, name.length, 2], [28, 0, 2]]
      .forEach(([at, v, n]) => (n === 4 ? local.setUint32(at, v, true) : local.setUint16(at, v, true)));
    const entry = new DataView(new ArrayBuffer(46));
    [[0, 0x02014b50, 4], [4, 20, 2], [6, 20, 2], [8, 0x0800, 2], [10, 0, 2], [12, 0, 2], [14, 0x21, 2], [16, crc, 4], [20, data.length, 4], [24, data.length, 4],
      [28, name.length, 2], [30, 0, 2], [32, 0, 2], [34, 0, 2], [36, 0, 2], [38, 0, 4], [42, offset, 4]]
      .forEach(([at, v, n]) => (n === 4 ? entry.setUint32(at, v, true) : entry.setUint16(at, v, true)));
    parts.push(new Uint8Array(local.buffer), name, data); central.push(new Uint8Array(entry.buffer), name);
    offset += 30 + name.length + data.length;
  }
  const size = central.reduce((sum, b) => sum + b.length, 0), endRecord = new DataView(new ArrayBuffer(22));
  [[0, 0x06054b50, 4], [4, 0, 2], [6, 0, 2], [8, files.length, 2], [10, files.length, 2], [12, size, 4], [16, offset, 4], [20, 0, 2]]
    .forEach(([at, v, n]) => (n === 4 ? endRecord.setUint32(at, v, true) : endRecord.setUint16(at, v, true)));
  return new Blob([...parts, ...central, new Uint8Array(endRecord.buffer)]);
}
