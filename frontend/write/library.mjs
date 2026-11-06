// The writer's pages, kept in this browser (IndexedDB), as Docs keeps a list of documents: each page's text and
// formatting, and once it's proved, what it proved, so its report can be made again. Nothing leaves the browser.

const DB = 'huma-pages', PAGES = 'pages', PROOFS = 'proofs';
let opening;
function db() {
  opening ??= new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(PAGES, { keyPath: 'id' });
      request.result.createObjectStore(PROOFS);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return opening;
}
async function run(store, mode, work) {
  const tx = (await db()).transaction(store, mode), result = work(tx.objectStore(store));
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(result.result);
    tx.onerror = tx.onabort = () => reject(tx.error);
  });
}

/** A new page's id: short, and safe in a link. */
export const newId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 20);
export const isId = id => /^[a-f0-9]{20}$/.test(id ?? '');

/** Every page, the most recently changed first. */
export async function pages() { return ((await run(PAGES, 'readonly', s => s.getAll())) ?? []).sort((a, b) => b.updated - a.updated); }
export const page = id => run(PAGES, 'readonly', s => s.get(id));
/** Saves a page: { id, title, doc, text, words, status: 'draft' | 'proved', score, created, updated }. */
export const putPage = record => run(PAGES, 'readwrite', s => s.put(record));
export async function removePage(id) {
  await run(PAGES, 'readwrite', s => s.delete(id));
  await run(PROOFS, 'readwrite', s => s.delete(id));
}
/** What the prover returned for a proved page ({ envelope, report, recording, text }). */
export const proof = id => run(PROOFS, 'readonly', s => s.get(id));
export const putProof = (id, result) => run(PROOFS, 'readwrite', s => s.put(result, id));
