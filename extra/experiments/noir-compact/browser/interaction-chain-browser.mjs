// Actual isolated Chrome, using only an ephemeral loopback server and profile.
import {build} from 'esbuild';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdtemp,rm,mkdir,copyFile,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkAsset} from './profile.mjs';
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(here,'../../../..');
const work=path.join(root,'build/research/noir-interaction/rollover-full-v3');
const reportPath=path.join(work,'browser-chain-results.json');
try{await stat(reportPath);throw new Error('Existing browser report is immutable');}catch(e){if(e.code!=='ENOENT')throw e;}
const temporary=await mkdtemp(path.join(tmpdir(),'huma-interaction-browser-'));
let chrome,server,timer;
try{
  await mkdir(path.join(temporary,'assets'));
  for(const name of ['barretenberg.wasm','barretenberg-threads.wasm','g2.dat']){
    await checkAsset(name,new Uint8Array(await readFile(path.join(here,'assets',name))));
    await copyFile(path.join(here,'assets',name),path.join(temporary,'assets',name));
  }
  let replaced=0;
  await build({absWorkingDir:here,entryPoints:['interaction-chain-page.mjs'],outfile:path.join(temporary,'page.js'),
    bundle:true,format:'esm',platform:'browser',target:'es2022',legalComments:'eof',
    plugins:[{name:'pinned-local-wasm',setup(builder){
      builder.onLoad({filter:/bb\.js\/dest\/browser\/barretenberg_wasm\/fetch_code\/browser\/index\.js$/},async()=>{
        replaced++;return {contents:await readFile(path.join(here,'asset-loader.mjs'),'utf8'),loader:'js',resolveDir:here};
      });
    }}]});
  if(replaced!==1)throw new Error('Expected exactly one pinned SDK asset-loader replacement');
  const partialWork=path.join(root,'build/research/noir-interaction/typing10000-v2');
  const partialReport=JSON.parse(await readFile(path.join(partialWork,'proof-results.json'),'utf8'));
  const partial={kind:'huma-replay-interaction-chain-experiment-v1',profile:'interaction10000-ops120-v1',chunks:[]};
  for(const row of partialReport.cases){
    const directory=path.join(partialWork,'target','proof-Chunk'+row.index);
    partial.chunks.push({proof:(await readFile(path.join(directory,'proof'))).toString('base64'),
      publicInputs:(await readFile(path.join(directory,'public_inputs'))).toString('base64')});
  }
  const files={
    '/page.js':[path.join(temporary,'page.js'),'text/javascript'],
    '/chain.json':[path.join(work,'public-component-chain.json'),'application/json'],
    '/key':[path.join(work,'target/setup/vk'),'application/octet-stream'],
  };
  for(const name of ['barretenberg.wasm','barretenberg-threads.wasm','g2.dat'])files['/assets/'+name]=[
    path.join(temporary,'assets',name),name.endsWith('.wasm')?'application/wasm':'application/octet-stream'];
  let finish;const completed=new Promise(resolve=>{finish=resolve;});
  server=http.createServer(async(req,res)=>{
    try{
      res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; frame-src 'none'");
      if(req.url==='/') {res.setHeader('content-type','text/html');res.end('<!doctype html><title>Huma component acceptance</title><pre>Running</pre><script type="module" src="/page.js"></script>');}
      else if(req.url==='/partial.json'){res.setHeader('content-type','application/json');res.end(JSON.stringify(partial));}
      else if(files[req.url]){res.setHeader('content-type',files[req.url][1]);res.end(await readFile(files[req.url][0]));}
      else if(req.url==='/report'&&req.method==='POST'){
        let size=0;const chunks=[];for await(const c of req){size+=c.length;if(size>65536)throw new Error('Oversized report');chunks.push(c);}
        const report=JSON.parse(Buffer.concat(chunks));res.end('ok');finish(report);
      }else{res.writeHead(404);res.end();}
    }catch{if(!res.headersSent)res.writeHead(500);res.end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  chrome=spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',[
    '--headless=new','--no-first-run','--disable-background-networking','--disable-component-update','--disable-sync',
    '--disable-default-apps','--disable-extensions','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
    '--user-data-dir='+path.join(temporary,'chrome'),'http://127.0.0.1:'+server.address().port+'/'],
    {detached:true,stdio:['ignore','ignore','pipe']});
  let errors='';chrome.stderr.on('data',b=>{if(errors.length<2048)errors+=b;});
  const launched=new Promise((_,reject)=>chrome.once('error',reject));
  const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Browser deadline: '+errors)),55000);});
  const report=await Promise.race([completed,launched,deadline]);
  if(report.failed||report.passed!==8||report.results.length!==8)throw new Error(JSON.stringify(report));
  report.sameOriginCSP=true;report.externalDNSDisabled=true;report.osNetworkDeny=false;
  await writeFile(reportPath,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  process.stdout.write(JSON.stringify(report)+'\n');
}finally{
  clearTimeout(timer);
  if(chrome?.pid&&chrome.exitCode===null&&chrome.signalCode===null){
    try{process.kill(-chrome.pid,'SIGTERM');}catch{}
    await new Promise(resolve=>{chrome.once('exit',resolve);setTimeout(()=>{
      if(chrome.exitCode===null&&chrome.signalCode===null){try{process.kill(-chrome.pid,'SIGKILL');}catch{}}resolve();
    },2000).unref();});
  }
  if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  await rm(temporary,{recursive:true,force:true});
}
