#!/usr/bin/env python3
"""Bounded V4 circuit research with NEW software-key fixtures, never user identity."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import verify as v3

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture
import size as budget

TOOLS=ROOT/'build/research/noir-tools'
NATIVE=ROOT/'build/research/noir-compact-native-target/release/huma-compact-experiment'
PROFILES={'tiny':dict(OPS=256,SCALARS=64,BYTES=128,CPS=2,SAMPLES=84,PRES=2),
          'cast256':dict(OPS=1536,SCALARS=256,BYTES=1024,CPS=8,SAMPLES=516,PRES=8)}

def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)

def project(journal):
    """Check every padded slot before projecting the fixed profile to its capsule."""
    base=journal['replay'];count=base.pop('checkpoint_count')
    if not 2<=count<=len(base['checkpoint_roots']):raise ValueError('Invalid V4 checkpoint count')
    for roots in [base['checkpoint_roots'],journal['checkpoint_roots']]:
        if any(x!='0' for x in roots[count:]):raise ValueError('Nonzero unused checkpoint')
        del roots[count:]
    approved=journal['approved']
    if not 1<=approved<=journal['presence_count']<=len(journal['presence_roots']):raise ValueError('Invalid V4 presence count')
    if any(x!='0' for x in journal['presence_roots'][approved:]):raise ValueError('Nonzero unused presence root')
    del journal['presence_roots'][approved:]
    return journal

def verify(work,proof_dir,capsule,text=None,expected_key=None,tool_prefix=()):
    artifact=json.loads((work/'target/huma_compact_experiment.json').read_text())
    public=[p for p in artifact['abi']['parameters'] if p['visibility']=='public']
    if len(public)!=1 or public[0]['name']!='expected':raise ValueError('Unsupported ABI')
    raw=(proof_dir/'public_inputs').read_bytes()
    if not 0<len(raw)<=131072 or len(raw)%32:raise ValueError('Invalid public input length')
    values=iter(int.from_bytes(raw[i:i+32],'big') for i in range(0,len(raw),32))
    journal=project(v3.decode(public[0]['type'],values))
    if next(values,None) is not None or journal!=capsule['journal']:raise ValueError('Capsule is not the proven journal')
    env=dict(os.environ,HARDWARE_CONCURRENCY='2')
    p=subprocess.run([str(x) for x in [*tool_prefix,TOOLS/'bb/bb','verify','-p',proof_dir/'proof','-i',proof_dir/'public_inputs',
        '-k',work/'target/setup/vk','-t','noir-recursive','-c',ROOT/'build/research/noir-crs']],env=env,capture_output=True,timeout=15)
    if p.returncode:raise ValueError('V4 SNARK rejected')
    p=subprocess.run([str(x) for x in [*tool_prefix,NATIVE,'assurance-signatures']],input=json.dumps(capsule),text=True,capture_output=True,timeout=15)
    if p.returncode:raise ValueError('V4 checkpoint/presence signatures rejected')
    key=json.loads(p.stdout)['keyHash']
    if expected_key is not None and key!=expected_key:raise ValueError('Capture key differs')
    if text is not None:
        canonical=text.rstrip(' \t').encode()
        if len(canonical)!=journal['replay']['byte_length'] or list(hashlib.sha256(canonical).digest())!=journal['replay']['text_hash']:
            raise ValueError('Reader text differs')
    vk_hash=hashlib.sha256((work/'target/setup/vk').read_bytes()).digest()
    identity=hashlib.sha256(b'HUMA_COMPACT_ASSURANCE_ID_V4\0'+vk_hash+raw+bytes(capsule['public_key'])).hexdigest()
    return dict(verified=True,experimental=True,proofIdentity=identity,keyHash=key,programKeyHash=vk_hash.hex(),
        checkpointSignatures=len(capsule['signatures']),presenceSignatures=len(capsule['presence_signatures']),journal=journal)

def inputs(private,capsule,limits):
    r=private['replay'];words=r['words'];origins=private['origins'];presence=private['presence'];checkpoints=r['checkpoints']
    if len(words)>limits['OPS'] or len(origins)>limits['SAMPLES'] or len(presence)>limits['PRES'] or len(checkpoints)>limits['CPS']:
        raise ValueError('Complete session exceeds V4 profile; nothing is discarded')
    timings=[];elapsed=0
    for offset,word in enumerate(words):
        code=word>>56;arg=word&((1<<56)-1)
        if code in [3,4]:
            elapsed+=arg>>16;timings.append(dict(offset=offset,elapsed=elapsed,key=arg&65535,up=code==4))
        elif code==5:elapsed+=arg>>40
        elif code==11:elapsed+=arg
    expected=json.loads(json.dumps(capsule['journal']));count=len(checkpoints)
    expected['replay']['checkpoint_count']=count
    expected['replay']['checkpoint_roots']+=['0']*(limits['CPS']-count)
    expected['checkpoint_roots']+=['0']*(limits['CPS']-count)
    expected['presence_roots']+=['0']*(limits['PRES']-len(expected['presence_roots']))
    return dict(nonce=r['nonce'],salt=r['salt'],ops=[dict(code=w>>56,arg=w&((1<<56)-1)) for w in words]+[dict(code=0,arg=0)]*(limits['OPS']-len(words)),
        op_count=len(words),checkpoints=[dict(c,presence=n) for c,n in zip(checkpoints,private['checkpoint_presence'])]
            +[dict(offset=0,unix=0,elapsed=0,presence=0)]*(limits['CPS']-count),
        timings=timings+[dict(offset=0,elapsed=0,key=0,up=False)]*(limits['SAMPLES']-len(timings)),
        origins=origins+[dict(present=False,pid=0,state=0,keyboard=0,repeated=False)]*(limits['SAMPLES']-len(origins)),
        presence=presence+[dict(offset=0,nonce=['0','0'],reason=0,issued=0,answered=0,outcome=0)]*(limits['PRES']-len(presence)),expected=expected)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name',required=True)
    source=p.add_mutually_exclusive_group()
    source.add_argument('--fixture',type=Path,default=ROOT/'backend/zkvm/common/tests/fixtures/presence-typed.json')
    source.add_argument('--case',choices=['typed250','rollover','repeat','unpaired','rate','dwell','missing-origin','late','timeout','u64max'])
    p.add_argument('--profile',choices=PROFILES,default='tiny')
    p.add_argument('--prove',action='store_true')
    p.add_argument('--threads',choices=[2,8],type=int,default=2)
    a=p.parse_args()
    if not a.name.replace('-','').isalnum():p.error('Use a local alphanumeric name')
    env=dict(os.environ,DEVELOPER_DIR='/Library/Developer/CommandLineTools',CARGO_TARGET_DIR=str(ROOT/'build/research/noir-compact-native-target'),
        RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY=str(a.threads))
    subprocess.run(['cargo','build','--release','--manifest-path',str(HERE/'native/Cargo.toml'),'--locked','--jobs','2'],env=env,check=True)
    if subprocess.check_output([str(TOOLS/'bb/bb'),'--version'],text=True).strip()!='5.2.1':p.error('Wrong backend')
    if '1.0.0-beta.25' not in subprocess.check_output([str(TOOLS/'noir/nargo'),'--version'],text=True):p.error('Wrong compiler')
    work=ROOT/'build/research/noir-assurance'/a.name;(work/'src').mkdir(parents=True,exist_ok=True)
    raw=json.dumps(dict(case=a.case)).encode() if a.case else a.fixture.read_bytes()
    if len(raw)>32*1024*1024:raise ValueError('Fixture too large')
    manifest=work/'fixture-metadata.json'
    if manifest.exists():
        meta=json.loads(manifest.read_text())
        if meta['sourceSha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('Use a new name for a new fixture')
        for name in ['private','capsule','text'] if a.case else ['private','capsule']:
            if meta[name+'Sha256']!=hashlib.sha256((work/(name+'.json')).read_bytes()).hexdigest():raise ValueError('Frozen fixture changed')
        private=json.loads((work/'private.json').read_text());capsule=json.loads((work/'capsule.json').read_text())
    else:
        result=subprocess.run([str(NATIVE),'assurance-case',a.case] if a.case else [str(NATIVE),'assurance-fixture'],
            input=b'' if a.case else raw,capture_output=True,env=env,timeout=30)
        if result.returncode:raise RuntimeError(result.stderr.decode()[-1000:])
        out=json.loads(result.stdout);private=out['private'];capsule=out['capsule']
        write(work/'private.json',private);write(work/'capsule.json',capsule)
        if a.case:write(work/'text.json',out['text'])
        write(manifest,dict(sourceSha256=hashlib.sha256(raw).hexdigest(),**{name+'Sha256':hashlib.sha256((work/(name+'.json')).read_bytes()).hexdigest() for name in (['private','capsule','text'] if a.case else ['private','capsule'])}))
    source=(HERE/'candidates/assurance-v4.nr').read_text()
    for name,default in PROFILES['tiny'].items():
        # Original replay constants retain their small legacy defaults.
        old=default if name not in ['SCALARS','BYTES','SAMPLES'] else dict(SCALARS=64,BYTES=128,SAMPLES=80)[name]
        before=f'global {name}:u32={old};'
        if source.count(before)!=1:raise ValueError('Profile constants changed')
        source=source.replace(before,f'global {name}:u32={PROFILES[a.profile][name]};')
    sources={'main.nr':source,'commit.nr':(HERE/'src/commit.nr').read_text(),
        'assurance.nr':(HERE/'src/assurance.nr').read_text(),'bytes.nr':(ROOT/'extra/experiments/noir-replay/src/bytes.nr').read_text()}
    for name,body in sources.items():
        path=work/'src'/name
        if (work/'target/setup/vk').exists() and path.read_text()!=body:raise ValueError('Use a new experiment name for circuit changes')
        path.write_text(body)
    (work/'Nargo.toml').write_text((HERE/'Nargo.toml').read_text().replace('../../../build/research/noir-sha256',str(ROOT/'build/research/noir-sha256')))
    values=inputs(private,capsule,PROFILES[a.profile]);write(work/'inputs.json',values)
    (work/'Prover.toml').write_text('\n'.join(k+' = '+fixture.toml(v) for k,v in values.items())+'\n')
    budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY=str(a.threads))
    compiled,_=budget.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute'],work)
    gates_timing,raw_gates=budget.limited(['/usr/bin/nice','-n','10',TOOLS/'bb/bb','gates','-b',work/'target/huma_compact_experiment.json','-t','noir-recursive'],work)
    gates=json.loads(raw_gates)
    report=dict(experimental=True,softwareKeysOnly=True,profile=a.profile,limits=PROFILES[a.profile],proofGenerated=False,
        compileAndWitness=compiled,gates=gates,gateCounter=gates_timing,operations=len(private['replay']['words']),
        samples=len(private['origins']),presence=len(private['presence']),checkpointCount=len(private['replay']['checkpoints']),threads=a.threads)
    write(work/'sizing-results.json',report);print(json.dumps(report),flush=True)
    if a.prove:
        if gates['functions'][0]['circuit_size']>2_100_000:raise ValueError('Proof exceeds reviewed gate budget')
        target=work/'target';proof=target/f'proof-{a.threads}-threads'
        common=['-b',target/'huma_compact_experiment.json','-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
        def worker(args):
            r=subprocess.run([str(x) for x in [TOOLS/'worker-bench',TOOLS/'bb/bb',*args]],cwd=work,env=env,capture_output=True,text=True,timeout=195)
            if r.returncode:raise RuntimeError(r.stderr[-1500:])
            return json.loads(r.stdout)
        worker(['write_vk',*common,'-o',target/'setup'])
        started=time.monotonic();warm,_=budget.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute'],work)
        timing=worker(['prove',*common,'-w',target/'huma_compact_experiment.gz','-k',target/'setup/vk','-o',proof])
        checked=verify(work,proof,capsule,json.loads((work/'text.json').read_text()) if a.case else json.loads(raw)['text'])
        report.update(proofGenerated=True,verified=checked['verified'],proofIdentity=checked['proofIdentity'],programKeyHash=checked['programKeyHash'],
            proveMs=timing['elapsedMs'],warmWitness=warm,contiguousWitnessProveVerifyMs=round((time.monotonic()-started)*1000,2),
            checkpointSignatures=checked['checkpointSignatures'],presenceSignatures=checked['presenceSignatures'])
        write(work/'public.json',dict(kind='huma-compact-assurance-public-proof-v4',profile='assurance256-v1',
            proof=base64.b64encode((proof/'proof').read_bytes()).decode(),publicInputs=base64.b64encode((proof/'public_inputs').read_bytes()).decode(),
            publicKey=base64.b64encode(bytes(capsule['public_key'])).decode(),
            signatures=[base64.b64encode(bytes(s)).decode() for s in capsule['signatures']],
            presenceSignatures=[base64.b64encode(bytes(s)).decode() for s in capsule['presence_signatures']],
            text=json.loads((work/'text.json').read_text()) if a.case else json.loads(raw)['text']))
    report['sourceHashes']={name:hashlib.sha256(body.encode()).hexdigest() for name,body in sources.items()}
    write(work/'results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
