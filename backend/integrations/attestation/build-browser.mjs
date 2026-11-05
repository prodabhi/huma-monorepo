import { build } from 'esbuild';
import { readFile, mkdir } from 'node:fs/promises';
const root = new URL('../../../', import.meta.url);
const pem = await readFile(new URL('./certificates/Apple_App_Attestation_Root_CA.pem', import.meta.url), 'utf8');
const attestationRoot = pem.replace(/-----[^\n]+-----|\s/g, '');
const receiptRoot = (await readFile(new URL('./certificates/AppleRootCA-G3.cer', import.meta.url))).toString('base64');
const output = new URL('frontend/dist/device-verifier.js', root);
await mkdir(new URL('./', output), { recursive: true });
await build({ entryPoints: [new URL('./browser-entry.mjs', import.meta.url).pathname], outfile: output.pathname,
    bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true,
    define: { APPLE_ATTESTATION_ROOT: JSON.stringify(attestationRoot), APPLE_RECEIPT_ROOT: JSON.stringify(receiptRoot) } });
console.log('Built local browser Apple-evidence verifier.');
