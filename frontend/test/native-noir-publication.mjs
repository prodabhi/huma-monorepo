// Calls the actual Swift app proof service and sharing adapter on a disposable
// pre-recorded capture. Only the local test server approves; no provider account.
import { createRegistry } from '../registry.mjs';
import { spawn } from 'node:child_process';
import { mkdtemp,rm,readFile,writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const temporary=await mkdtemp(path.join(tmpdir(),'huma-native-noir-'));
const server=await createRegistry({store:temporary,publicationOptions:{
  authenticate:async token=>{if(token!=='noir-fixture-owner')throw Error('Fixture authentication rejected');return '3'.repeat(64);},
}});
let child,timer;let errors='',stdout='',handled=false,approved=false;
const reuse=process.argv.includes('--reuse');
const legacy=process.argv.includes('--legacy');
const boundary=process.argv.includes('--boundary');
const extended=boundary||process.argv.includes('--extended');
const adaptive=process.argv.includes('--adaptive-short')?'short':process.argv.includes('--adaptive-medium')?'medium':process.argv.includes('--adaptive-boundary')?'boundary':undefined;
if(adaptive&&(extended||legacy||reuse))throw Error('Adaptive acceptance uses its own fresh output.');
if(legacy&&!reuse)throw Error('Legacy mode verifies an existing V4 proof only.');
if(legacy&&extended)throw Error('Select one capture profile.');
const variant=adaptive?'adaptive-'+adaptive:boundary?'cp32-boundary':extended?'cp32-slow':legacy?'legacy':'v5';
const freshRoot='build/research/noir-native-app-'+(adaptive||extended?variant:'v5')+'-v1';
const run=process.argv.find(arg=>arg.startsWith('--run='))?.slice(6);
if(run&&!/^[a-zA-Z0-9-]{1,64}$/.test(run))throw Error('Invalid local acceptance run name.');
const output=(legacy?'build/research/noir-native-app-legacy-cp32compat-v1':reuse?(extended?freshRoot+'-cached':'build/research/noir-native-app-v5-cp32compat-v1'):freshRoot)+(run?'-'+run:'');
const proofFile=legacy?'build/research/noir-native-app-v1/proof.json':freshRoot+'/proof.json';
const capture=adaptive?'build/research/noir-assurance-native/live-'+(adaptive==='boundary'?'cp32-boundary':'adaptive-'+adaptive)+'-v1/document.huma':extended?'build/research/noir-assurance-native/live-'+variant+'-v1/document.huma':'build/research/noir-assurance-native/live-v4-250-v2/document.huma';
const probe=process.env.HUMA_NOIR_ACCEPTANCE_PROBE??'build/HumaNoirPublicationProbe.app/Contents/MacOS/HumaNoirProbe';
try {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  child=spawn(probe,[
    capture,output,base,
    ...(reuse?[proofFile]:[])],
    {detached:true,stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',chunk=>{
    stdout+=chunk;const match=stdout.match(/Noir publication fixture approval: http:\/\/127\.0\.0\.1:[0-9]+\/share\/([a-f0-9]{64})#([a-f0-9]{64})/);
    if(!match||handled)return;handled=true;
    fetch(base+'/api/publications/pending/'+match[1]+'/publish',{method:'POST',
      headers:{Authorization:'Bearer noir-fixture-owner','X-Huma-Ticket':match[2]}})
      .then(response=>{if(!response.ok)throw Error('Fixture approval failed');approved=true;})
      .catch(error=>{errors+=error.message;child.kill('SIGTERM');});
  });
  child.stderr.on('data',chunk=>{if(errors.length<4000)errors+=chunk;});
  const code=await Promise.race([new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);}),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Native Noir acceptance timed out')),190000);})]);
  if(code!==0||!approved)throw Error(errors.slice(-3000));
  const report=JSON.parse(await readFile(path.join(output,'acceptance.json'),'utf8'));
  if(!report.passed||report.newProofGenerated===reuse||!report.localPublicationVerified||report.backend!=='noir-assurance-v'+(legacy?4:5))throw Error('Incomplete native acceptance');
  if(extended&&(report.profile!=='assurance256-cp32-v1'||report.checkpointSignaturesVerified!==(boundary?32:24)))throw Error('Expanded profile did not preserve every original signature');
  if(adaptive&&(report.profile!==(adaptive==='short'?'assurance64-v1':'assurance128-cp32-v1')||(adaptive==='boundary'&&report.checkpointSignaturesVerified!==32)))throw Error('Adaptive profile dropped evidence or selected the wrong circuit');
  await writeFile('build/noir-'+variant+'-native-'+(reuse?'cached':'publication')+'-results.json',JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report));
} finally {
  clearTimeout(timer);
  if(child?.exitCode===null){try{process.kill(-child.pid,'SIGKILL');}catch{}await new Promise(resolve=>child.once('exit',resolve));}
  server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
  await rm(temporary,{recursive:true,force:true});
}
