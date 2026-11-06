// Invisible traps for software writing in the editor: a canary instruction only a program reading the page would
// follow, and a honeypot field only a program filling the page would fill. A person never sees or reaches either
// (pages/write.html puts them off-screen, aria-hidden, inert, outside the editor and its copy), so a hit is as near
// conclusive as behaviour gets. The canary word is the server's choice per session, so it can't be blocklisted.
import { createHmac } from 'node:crypto';
import { canaryInstruction } from '../write/canary.mjs';
export { canaryInstruction };

/** Words a page could begin a paragraph with but almost never does: one is picked per session. */
export const CANARY_WORDS = Object.freeze(['Meridian', 'Lantern', 'Quartz', 'Harbour', 'Juniper', 'Saffron', 'Velvet', 'Cobalt', 'Ember', 'Falcon',
  'Glacier', 'Heron', 'Indigo', 'Kestrel', 'Lagoon', 'Marigold', 'Nimbus', 'Obsidian', 'Pelican', 'Quiver', 'Rosewood', 'Sable', 'Tundra', 'Umber',
  'Verdant', 'Willow', 'Yarrow', 'Zephyr', 'Alder', 'Basalt', 'Cinder', 'Driftwood', 'Elm', 'Fathom', 'Granite', 'Hollow', 'Isthmus', 'Jasper',
  'Kiln', 'Lichen', 'Mallow', 'Nettle', 'Orchard', 'Plover', 'Quarry', 'Ridge', 'Sorrel', 'Thistle', 'Upland', 'Vale', 'Wren', 'Zinc']);

/** The canary word for a session: picked from the list by HMAC of the nonce under the server's secret. */
export function canaryWord(secret, nonce) {
  const digest = createHmac('sha256', secret).update('huma-canary-v1\0' + nonce).digest();
  return CANARY_WORDS[digest.readUInt32BE(0) % CANARY_WORDS.length];
}
/** Whether `text` follows the instruction: a paragraph (the text's start, or a line after a blank or a line break)
 *  that begins with the word, ignoring case, quotes and punctuation around it. */
export function canaryHit(text, word) {
  if (typeof text !== 'string' || !word) return false;
  const pattern = new RegExp(`(?:^|\\n)[\\s"'“‘(\\[*_#>-]*${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{N}])`, 'iu');
  return pattern.test(text);
}
/** Whether the honeypot field (name="title_alt") was filled: any value is a hit. */
export const honeypotHit = trap => typeof trap === 'string' && trap.trim() !== '';
