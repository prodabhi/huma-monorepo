#!/usr/bin/env python3
"""Prove varied synthetic sessions with ONE already compiled cast256 circuit/VK."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import run
import verify

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture
import size


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--threads',type=int,choices=[2,8],default=8)
    a=p.parse_args()
    work=ROOT/'build/research/noir-compact/cast256';target=work/'target';tools=ROOT/'build/research/noir-tools'
    artifact=target/'huma_compact_experiment.json';vk=target/'setup/vk'
    if not vk.is_file():p.error('Build cast256 with run.py first')
    pinned=hashlib.sha256(vk.read_bytes()).hexdigest();program=hashlib.sha256(artifact.read_bytes()).hexdigest()
    abi=json.loads(artifact.read_text())['abi']
    params={x['name']:x['type'] for x in abi['parameters']}
    assert params['ops']['length']==1536 and params['checkpoints']['length']==8
    assert 'checkpoint_count' in [x['name'] for x in params['expected']['fields']]
    env=dict(os.environ,HARDWARE_CONCURRENCY=str(a.threads),RAYON_NUM_THREADS='2')
    size.ENV.update(HARDWARE_CONCURRENCY=str(a.threads),RAYON_NUM_THREADS='2')
    reports=[]
    for label,case,legacy_path in [
        ('Bucket50','typing50-v3','build/research/noir-typing-fixtures/typing-50-current.json'),
        ('Bucket250','typing250-v4','build/research/noir-typing-fixtures/typing-250-current.json'),
        ('BucketUnicode','unicode-v4','backend/zkvm/common/tests/fixtures/swift-timed.json'),
    ]:
        origin=ROOT/'build/research/noir-compact'/case
        metadata=json.loads((origin/'fixture-metadata.json').read_text())
        for name,key in [('private.json','privateSha256'),('capsule.json','capsuleSha256')]:
            assert hashlib.sha256((origin/name).read_bytes()).hexdigest()==metadata[key]
        private=json.loads((origin/'private.json').read_text());capsule=json.loads((origin/'capsule.json').read_text())
        legacy=json.loads((ROOT/legacy_path).read_text())
        assert run.scalar_capacity(legacy)<=256 and len(legacy['text'].encode())<=1024
        words=private['words'];count=len(private['checkpoints'])
        assert len(words)<=1536 and 2<=count<=8
        expected=copy.deepcopy(capsule['journal'])
        expected.update(checkpoint_count=count,checkpoint_roots=expected['checkpoint_roots']+['0']*(8-count))
        values=dict(nonce=private['nonce'],salt=private['salt'],op_count=len(words),
            ops=[dict(code=x>>56,arg=x&((1<<56)-1)) for x in words]+[dict(code=0,arg=0)]*(1536-len(words)),
            checkpoints=private['checkpoints']+[dict(offset=0,unix=0,elapsed=0)]*(8-count),expected=expected)
        run.write(work/(label+'.toml'),'\n'.join(k+' = '+fixture.toml(v) for k,v in values.items())+'\n')
        run.write(work/(label+'-capsule.json'),json.dumps(capsule))
        output=target/(label+'-'+str(a.threads)+'-threads')
        start=time.monotonic()
        witness,_=size.limited(['/usr/bin/nice','-n','10',tools/'noir/nargo','execute',label,'--prover-name',label],work)
        result=subprocess.run([str(x) for x in [tools/'worker-bench',tools/'bb/bb','prove','-b',artifact,
            '-t','noir-recursive','-c',ROOT/'build/research/noir-crs','-w',target/(label+'.gz'),'-k',vk,'-o',output]],
            env=env,cwd=work,text=True,capture_output=True,timeout=195)
        if result.returncode:raise RuntimeError(result.stderr[-1500:])
        timing=json.loads(result.stdout);before_verify=time.monotonic()
        checked=verify.verify(work,output,work/(label+'-capsule.json'),legacy['text'])
        stop=time.monotonic()
        assert checked['verified'] and checked['programKeyHash']==pinned and checked['checkpointCapacity']==8
        assert hashlib.sha256(artifact.read_bytes()).hexdigest()==program and hashlib.sha256(vk.read_bytes()).hexdigest()==pinned
        report=dict(case=label,experimental=True,proofGenerated=True,verified=True,allSignaturesVerified=True,
            noSetupBetweenStages=True,sharedProgramAndVK=True,threads=a.threads,operations=len(words),checkpoints=count,
            witnessMs=witness['wallMs'],proveMs=timing['elapsedMs'],verifyMs=round((stop-before_verify)*1000,2),
            contiguousWitnessProveVerifyMs=round((stop-start)*1000,2),vkSha256=pinned,artifactSha256=program,
            proofIdentity=checked['proofIdentity'])
        reports.append(report);print(json.dumps(report),flush=True)
    run.write(work/f'fixed-profile-{a.threads}-threads.json',json.dumps(reports,indent=2)+'\n')
