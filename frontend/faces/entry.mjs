// Writers' faces for the Mac app, drawn on the Mac: the same DiceBear "Dylan" (Natalia Spivak, CC BY 4.0)
// and the same output as the site's /avatar/<seed>.svg in registry.mjs. Built into extra/Resources/Faces.js.
import { Avatar, Style } from '@dicebear/core';
import dylan from '@dicebear/styles/dylan.json' with { type: 'json' };

// JavaScriptCore has no structuredClone; DiceBear only clones plain JSON data (the style and the options).
globalThis.structuredClone ??= function clone(value) {
    if (Array.isArray(value)) return value.map(clone);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]));
    return value;
};
const style = new Style(dylan);
globalThis.humaFace = seed => new Avatar(style, { seed }).toString().replace(/<!--[\s\S]*?-->/g, '');
