// node:path (POSIX), as much as the engine uses.
const normalize = parts => { const out = []; for (const part of parts) { if (!part || part === '.') continue; if (part === '..') out.pop(); else out.push(part); } return out; };
export function join(...segments) {
  const joined = segments.filter(s => s !== '').join('/');
  const body = normalize(joined.split('/')).join('/');
  return (joined.startsWith('/') ? '/' : '') + body || '.';
}
export function dirname(p) { const i = p.replace(/\/+$/, '').lastIndexOf('/'); return i < 0 ? '.' : i === 0 ? '/' : p.slice(0, i); }
export function basename(p) { const s = p.replace(/\/+$/, ''); return s.slice(s.lastIndexOf('/') + 1); }
export default { join, dirname, basename, sep: '/' };
