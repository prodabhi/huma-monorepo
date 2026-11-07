#!/usr/bin/env python3
"""Size complete-history circuit buckets without changing signed captures."""
import argparse,base64,hashlib,json,os,subprocess
from pathlib import Path
import assurance_cases as v4
import public_text_cases as optimized

BUCKETS={
    'standard':v4.PROFILES['cast256'],
    'short64':dict(OPS=372,SCALARS=64,BYTES=256,SAMPLES=132,CPS=8,PRES=8),
    'short128':dict(OPS=756,SCALARS=128,BYTES=512,SAMPLES=260,CPS=32,PRES=8),
}

def circuit(limits):
    source=optimized.circuit(public_text=False,algebraic=True)
    for key,value in limits.items():
        old=f'global {key}:u32={v4.PROFILES["cast256"][key]};'
        if source.count(old)!=1:raise ValueError('Review changed source before resizing')
        source=source.replace(old,f'global {key}:u32={value};')
    return source

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name',required=True)
    p.add_argument('--checkpoints',type=int,choices=[8,16,32],required=True)
    p.add_argument('--presence',type=int,choices=[8,16],default=8)
    p.add_argument('--bucket',choices=BUCKETS,default='standard')
    p.add_argument('--capture',type=Path,default=v4.ROOT/'build/research/noir-assurance-native/live-v4-250-v2/document.huma')
    a=p.parse_args();os.umask(0o077)
    if not a.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    if a.bucket!='standard' and (a.checkpoints!=BUCKETS[a.bucket]['CPS'] or a.presence!=8):
        raise ValueError('Use the candidate checkpoint capacity and eight presence slots')
    work=v4.ROOT/'build/research/noir-capacity'/a.name
    if work.exists():raise ValueError('Use a new experiment directory')
    raw=a.capture.read_bytes();doc=json.loads(raw);session=doc['session'].copy()
    snapshot=json.loads(base64.b64decode(session.pop('experimentalCompactSnapshot')))
    request=json.dumps(dict(witness=dict(text=doc['text'],session=session),snapshot=snapshot)).encode()
    checked=subprocess.run([str(v4.NATIVE),'assurance-worker-input'],input=request,capture_output=True,timeout=20)
    if checked.returncode:raise ValueError('Original signed capture failed complete input validation')
    eligibility=None
    if a.bucket!='standard':
        checked=subprocess.run([str(v4.NATIVE),'profile-fit'],input=request,capture_output=True,timeout=20)
        if checked.returncode:raise ValueError('Complete input failed circuit-size validation')
        eligibility=next(x for x in json.loads(checked.stdout)['candidates'] if x['name']==a.bucket)
        if not eligibility['eligible']:raise ValueError('Whole history does not fit candidate: '+','.join(eligibility['reasons']))
    snapshot=snapshot['result'];private=snapshot['private'];capsule=snapshot['capsule']
    limits=dict(BUCKETS[a.bucket],CPS=a.checkpoints,PRES=a.presence)
    if eligibility is not None and limits!=eligibility['limits']:raise ValueError('Native and circuit bounds differ')
    inputs=v4.inputs(private,capsule,limits)
    if v4.project(json.loads(json.dumps(inputs['expected'])))!=capsule['journal']:raise ValueError('Original signed journal changed')
    source=circuit(limits)
    (work/'src').mkdir(parents=True)
    sources={'main.nr':source,'bytes.nr':(v4.ROOT/'extra/experiments/noir-replay/src/bytes.nr').read_text(),
      'commit.nr':(v4.HERE/'src/commit.nr').read_text(),'assurance.nr':(v4.HERE/'src/assurance.nr').read_text()}
    for name,body in sources.items():(work/'src'/name).write_text(body)
    (work/'Nargo.toml').write_text((v4.HERE/'Nargo.toml').read_text().replace('../../../build/research/noir-sha256',str(v4.ROOT/'build/research/noir-sha256')))
    v4.write(work/'inputs.json',inputs);v4.write(work/'capsule.json',capsule)
    (work/'Prover.toml').write_text('\n'.join(k+' = '+v4.fixture.toml(v) for k,v in inputs.items())+'\n')
    offline=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']
    timing,_=v4.budget.limited(['/usr/bin/nice','-n','10',*offline,v4.TOOLS/'noir/nargo','execute'],work)
    _,raw_gates=v4.budget.limited(['/usr/bin/nice','-n','10',*offline,v4.TOOLS/'bb/bb','gates','-b',work/'target/huma_compact_experiment.json','-t','noir-recursive'],work)
    program=json.loads((work/'target/huma_compact_experiment.json').read_text())
    public=[x for x in program['abi']['parameters'] if x['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected':raise ValueError('Unexpected public ABI')
    (work/'reader-abi.json').write_text(json.dumps(public[0]['type'],separators=(',',':')))
    result=dict(softwareFixtureOnly=True,proofGenerated=False,newSignaturesGenerated=False,bucket=a.bucket,
      completeHistoryEligibility=eligibility,registeredForProving=False,
      originalCaptureSha256=hashlib.sha256(raw).hexdigest(),limits=limits,checkpointSignatures=len(capsule['signatures']),
      presenceSignatures=len(capsule['presence_signatures']),signedJournalPreserved=True,compileAndWitness=timing,
      gates=json.loads(raw_gates),bytecodeSha256=hashlib.sha256(program['bytecode'].encode()).hexdigest(),
      sourceSha256={name:hashlib.sha256(body.encode()).hexdigest() for name,body in sources.items()})
    v4.write(work/'results.json',result);print(json.dumps(result),flush=True)
if __name__=='__main__':main()
