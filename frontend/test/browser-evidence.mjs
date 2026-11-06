// Real isolated Chrome, local assets only. No browser automation dependency.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { readFile, mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRegistry } from '../registry.mjs';
const temporary=await mkdtemp(path.join(tmpdir(),'huma-browser-evidence-'));
// The old transport cases run only in this disposable compatibility harness.
const registry=await createRegistry({store:path.join(temporary,'store'), allowLegacyUploads: true, publicationOptions: {
  // This local-only acceptance server never contacts Privy or creates a wallet.
  authenticate: async token => { if (token !== 'browser-fixture-owner') throw new Error('Invalid fixture authorization'); return '1'.repeat(64); },
}});
const handler=registry.listeners('request')[0];
const fixtures={
  '/fixture/replay':new URL('../../backend/zkvm/verifier/tests/fixtures/timed-receipt.json',import.meta.url),
  '/fixture/compact':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Bucket250.json',import.meta.url),
  '/fixture/unicode':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/BucketUnicode.json',import.meta.url),
  '/fixture/native':new URL('../../build/Huma-evidence-native.evidence.json',import.meta.url),
  '/fixture/assurance':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Assurance250.json',import.meta.url),
  '/fixture/swift-assurance':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/SwiftLiveV4.json',import.meta.url),
  '/fixture/assurance-v5':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/AssuranceV5.json',import.meta.url),
  '/fixture/cp32':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/AssuranceCP32.json',import.meta.url),
  '/fixture/cp32-boundary':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/AssuranceCP32Boundary.json',import.meta.url),
  '/fixture/small64':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Assurance64.json',import.meta.url),
  '/fixture/small64-unicode':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Assurance64Unicode.json',import.meta.url),
  '/fixture/small128-boundary':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Assurance128Boundary.json',import.meta.url),
  '/fixture/small128-unicode':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Assurance128Unicode.json',import.meta.url),
  '/fixture/long':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long600.json',import.meta.url),
  '/fixture/policy-failed':new URL('../../extra/experiments/noir-compact/browser/test/fixtures/AssuranceRate.json',import.meta.url),
};
for (const [kind, extension] of [['image','png'],['audio','flac'],['video','mp4']]) {
  fixtures['/fixture/'+kind]=new URL('../../extra/experiments/noir-media/reader/test/fixtures/'+kind+'.json',import.meta.url);
  fixtures['/fixture/'+kind+'-master']=new URL('../../extra/experiments/noir-media/reader/test/fixtures/'+kind+'.'+extension,import.meta.url);
}
let finishReport;
const completed=new Promise(resolve=>{finishReport=resolve;});
const server=http.createServer(async(req,res)=>{
  try {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; frame-src 'self'");
    if(req.url==='/acceptance') {res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Huma evidence acceptance</title><pre>Running</pre><script type="module" src="/acceptance.mjs"></script>');}
    else if(req.url==='/acceptance.mjs') {res.setHeader('Content-Type','text/javascript');res.end(await readFile(new URL('./browser-evidence-page.mjs',import.meta.url)));}
    else if(fixtures[req.url]) {res.setHeader('Content-Type','application/json');res.end(await readFile(fixtures[req.url]));}
    else if(req.url==='/report'&&req.method==='POST') {
      const chunks=[];let size=0;
      for await(const chunk of req) {size+=chunk.length;if(size>65536)throw new Error('Oversized report');chunks.push(chunk);}
      const report=JSON.parse(Buffer.concat(chunks));res.end('ok');finishReport(report);
    } else await handler(req,res);
  } catch {if(!res.headersSent)res.writeHead(500);res.end();}
});
let chrome,timer;
try {
  for(const fixture of Object.values(fixtures))await readFile(fixture);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url=`http://127.0.0.1:${server.address().port}/acceptance`;
  // Chrome owns its OS sandbox; nested sandbox-exec prevents its helpers from
  // initializing. Keep that sandbox and restrict the test origin with CSP/DNS.
  chrome=spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',[
    '--headless=new','--no-first-run','--disable-background-networking','--disable-component-update','--disable-sync',
    '--disable-default-apps','--disable-extensions','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
    `--user-data-dir=${path.join(temporary,'chrome')}`,url],
    {detached:true,stdio:['ignore','ignore','pipe']});
  let errors='';chrome.stderr.on('data',chunk=>{if(errors.length<2048)errors+=chunk;});
  const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Browser acceptance timed out: '+errors)),55000);});
  const report=await Promise.race([completed,deadline]);
  if(!Array.isArray(report.results)||report.results.length<46||report.failed||report.passed!==report.results.length)throw new Error(JSON.stringify(report));
  report.sameOriginCSP=true;report.externalDNSDisabled=true;report.osNetworkDeny=false;
  await mkdir(new URL('../../build/',import.meta.url),{recursive:true});
  await writeFile(new URL('../../build/evidence-browser-results.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report));
} finally {
  clearTimeout(timer);
  if(chrome?.pid) {try{process.kill(-chrome.pid,'SIGTERM');}catch{} await new Promise(resolve=>{if(chrome.exitCode!==null)resolve();else {chrome.once('exit',resolve);setTimeout(()=>{try{process.kill(-chrome.pid,'SIGKILL');}catch{}resolve();},2000).unref();}});}
  server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
  await rm(temporary,{recursive:true,force:true});
}
