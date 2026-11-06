import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { Avatar, Style } from '@dicebear/core';
import dylan from '@dicebear/styles/dylan.json' with { type: 'json' };

// The Mac app draws faces with extra/Resources/Faces.js in JavaScriptCore. Run it the same way, with no web APIs
// (no structuredClone), and check it draws exactly the face the site's /avatar/<seed>.svg serves.
test('the app face script draws the same face as the site', async () => {
    const script = await readFile(new URL('../../extra/Resources/Faces.js', import.meta.url), 'utf8');
    const context = vm.createContext({});
    vm.runInContext(script, context);
    const style = new Style(dylan);
    for (const seed of ['abc23defgh', 'k7mq2xpz9a', 'Z_-9', 'a']) {
        const expected = new Avatar(style, { seed }).toString().replace(/<!--[\s\S]*?-->/g, '');
        assert.equal(context.humaFace(seed), expected, seed);
    }
});
