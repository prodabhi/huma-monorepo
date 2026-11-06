// Menus and pop-ups: the menu bar's menus, the toolbar's drop-downs and palettes. They open under what opened them,
// keep the page's selection (nothing in them takes the focus from the text unless typed into), and close on a click
// outside or Escape. Arrow keys move through a menu; → and ← open and close a submenu.

export const icon = (name, extra = '') => `<svg class="i${extra ? ' ' + extra : ''}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const escape = text => String(text).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

let open = [];        // the open pop-ups, outermost first: { el, anchor, close }
let onCloseAll = () => {};

/** Close every pop-up, or those from `level` in. */
export function closeAll(level = 0) {
  const closing = open.splice(level);
  for (const p of closing.reverse()) { p.el.remove(); p.anchor?.setAttribute?.('aria-expanded', 'false'); p.onClose?.(); }
  if (!open.length) onCloseAll();
}
export const isOpen = () => open.length > 0;
export function whenAllClosed(fn) { onCloseAll = fn; }

function place(el, anchor, { side = 'below', alignRight = false } = {}) {
  const r = anchor.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight, vw = innerWidth, vh = innerHeight;
  let left, top;
  if (side === 'right') { left = r.right - 4; top = r.top - 8; if (left + w > vw - 8) left = r.left - w + 4; }
  else { left = alignRight ? r.right - w : r.left; top = r.bottom + 2; if (top + h > vh - 8 && r.top - h - 2 > 8) top = r.top - h - 2; }
  el.style.left = Math.max(8, Math.min(left, vw - w - 8)) + 'px';
  el.style.top = Math.max(8, Math.min(top, vh - h - 8)) + 'px';
}

/** Show `el` as a pop-up under `anchor`. `level` 0 replaces whatever is open; a submenu passes its parent's level + 1. */
export function popup(anchor, el, { level = 0, side, alignRight, onClose } = {}) {
  closeAll(level);
  el.classList.add('popup');
  el.addEventListener('mousedown', e => { if (!e.target.closest('input, textarea, select')) e.preventDefault(); });
  document.body.append(el);
  place(el, anchor, { side, alignRight });
  anchor?.setAttribute?.('aria-expanded', 'true');
  const entry = { el, anchor, onClose };
  open.push(entry);
  return () => { const i = open.indexOf(entry); if (i !== -1) closeAll(i); };
}

/**
 * A menu. Items: { label, icon, keys, run, checked, disabled, submenu, hint, style, className } or 'separator'.
 * `submenu` is a list or a function that returns one.
 */
export function menu(anchor, items, options = {}) {
  const level = options.level ?? 0, el = document.createElement('div');
  el.className = 'menu' + (options.className ? ' ' + options.className : '');
  el.setAttribute('role', 'menu');
  const rows = [];
  for (const item of items) {
    if (item === 'separator') { el.insertAdjacentHTML('beforeend', '<div class="menu-sep" role="separator"></div>'); continue; }
    if (item.heading) { el.insertAdjacentHTML('beforeend', `<div class="menu-heading">${escape(item.heading)}</div>`); continue; }
    const row = document.createElement('div');
    row.className = 'menu-item' + (item.className ? ' ' + item.className : '');
    row.setAttribute('role', item.checked !== undefined ? 'menuitemcheckbox' : 'menuitem');
    if (item.checked !== undefined) row.setAttribute('aria-checked', String(Boolean(item.checked)));
    if (item.disabled) row.setAttribute('aria-disabled', 'true');
    const lead = item.checked !== undefined ? (item.checked ? icon('check') : '<span class="i"></span>') : item.icon ? icon(item.icon) : '<span class="i"></span>';
    row.innerHTML = `${options.noIcons ? '' : lead}<span class="menu-label"${item.style ? ` style="${escape(item.style)}"` : ''}>${escape(item.label)}</span>`
      + (item.hint ? `<span class="menu-hint">${escape(item.hint)}</span>` : '')
      + (item.keys ? `<span class="menu-keys">${escape(item.keys)}</span>` : '')
      + (item.submenu ? icon('arrow_right', 'menu-more') : '');
    row.addEventListener('mouseenter', () => activate(rows.indexOf(entry), true));
    row.addEventListener('click', () => choose(entry));
    const entry = { row, item };
    rows.push(entry); el.append(row);
  }
  let active = -1, timer;
  function activate(index, hover = false) {
    clearTimeout(timer);
    rows.forEach((r, i) => r.row.classList.toggle('active', i === index));
    active = index;
    const entry = rows[index];
    if (!entry) return;
    if (!hover) entry.row.scrollIntoView({ block: 'nearest' });
    // A submenu opens when its row is pointed at for a moment; another row's closes.
    if (entry.item.submenu && !entry.item.disabled) timer = setTimeout(() => openSub(entry), hover ? 120 : 0);
    else if (hover) timer = setTimeout(() => closeAll(level + 1), 120);
  }
  function openSub(entry) {
    if (open[level + 1]?.anchor === entry.row) return;
    const list = typeof entry.item.submenu === 'function' ? entry.item.submenu() : entry.item.submenu;
    menu(entry.row, list, { level: level + 1, side: 'right' });
  }
  function choose(entry) {
    if (!entry || entry.item.disabled) return;
    if (entry.item.submenu) { openSub(entry); return; }
    closeAll();
    entry.item.run?.();
  }
  el.menuKeys = e => {
    const enabled = rows.map((r, i) => (r.item.disabled ? -1 : i)).filter(i => i >= 0);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const at = enabled.indexOf(active), next = e.key === 'ArrowDown' ? enabled[(at + 1) % enabled.length] : enabled[(at - 1 + enabled.length) % enabled.length];
      activate(next ?? enabled[0]); return true;
    }
    if (e.key === 'ArrowRight' && rows[active]?.item.submenu) { openSub(rows[active]); setTimeout(() => open[level + 1]?.el.menuKeys?.({ key: 'ArrowDown' })); return true; }
    if (e.key === 'ArrowLeft' && level > 0) { closeAll(level); return true; }
    if (e.key === 'Enter' || e.key === ' ') { choose(rows[active]); return true; }
    return false;
  };
  popup(anchor, el, { level, side: options.side, alignRight: options.alignRight, onClose: options.onClose });
  if (options.select !== undefined) activate(options.select);
  return el;
}

// Keys while a menu is open go to the innermost menu; Escape closes it. A click outside closes everything.
addEventListener('keydown', e => {
  if (!open.length) return;
  const top = open[open.length - 1];
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeAll(open.length - 1); return; }
  if (e.target.closest?.('.popup input, .popup textarea')) return;
  if (top.el.menuKeys?.(e)) { e.preventDefault(); e.stopPropagation(); }
}, true);
addEventListener('mousedown', e => {
  if (!open.length || e.target.closest?.('.popup') || open.some(p => p.anchor?.contains?.(e.target))) return;
  closeAll();
}, true);
addEventListener('resize', () => closeAll());
addEventListener('blur', () => closeAll());
