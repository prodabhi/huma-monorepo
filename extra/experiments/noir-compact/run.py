#!/usr/bin/env python3
"""Build/test a NEW synthetic compact protocol; never a migrated production proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import verify

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture
import size as budget
TOOLS=ROOT/'build/research/noir-tools'
NATIVE=ROOT/'build/research/noir-compact-native-target/release/huma-compact-experiment'


def write(path,text):
    with open(path,'w',encoding='utf-8') as f:f.write(text)
    path.chmod(0o600)


def scalar_capacity(legacy):
    # Include intermediate documents that may be larger than the final draft.
    text=legacy['session']['initialText'];maximum=len(text)
    for edit in legacy['session']['events']:
        raw=text.encode('utf-16-le')
        start=edit['location']*2;end=start+edit['removedLength']*2
        if not 0<=start<=end<=len(raw):raise ValueError('Invalid fixture edit range')
        # Strict decoding also rejects edits through a surrogate pair.
        before=raw[:start].decode('utf-16-le');after=raw[end:].decode('utf-16-le')
        text=before+edit['insertedText']+after
        maximum=max(maximum,len(text))
    if text!=legacy['text']:raise ValueError('Fixture text differs from edit replay')
    return max(64,((maximum+63)//64)*64)


def checkpoint_hints(words,checkpoints):
    elapsed=edits=samples=0
    prefixes=[(elapsed,edits,samples)]
    for word in words:
        code=word>>56;arg=word&((1<<56)-1)
        if code in [3,4]:elapsed+=arg>>16;samples+=1
        elif code==5:elapsed+=arg>>40
        elif code==10:edits+=1
        elif code==11:elapsed+=arg
        prefixes.append((elapsed,edits,samples))
    return [dict(c,stream_elapsed=prefixes[c['offset']][0],edits=prefixes[c['offset']][1],
                 samples=prefixes[c['offset']][2]) for c in checkpoints]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',type=Path,default=ROOT/'build/research/noir-typing-fixtures/typing-50-current.json')
    parser.add_argument('--name',default='typing50-v4')
    parser.add_argument('--candidate',choices=['none','decoding-hints','field-geometry','flat-transitions','packed-prefixes','bounded-checkpoints'],default='none')
    parser.add_argument('--profile',choices=['exact','cast256'],default='exact')
    parser.add_argument('--threads',type=int,choices=[2,8],default=2)
    parser.add_argument('--prove',action='store_true')
    a=parser.parse_args()
    if not a.name.replace('-','').isalnum():parser.error('Use an alphanumeric local experiment name')
    if (a.profile!='exact')!=(a.candidate=='bounded-checkpoints'):
        parser.error('The fixed cast256 profile requires the bounded-checkpoints candidate')
    env=dict(os.environ,DEVELOPER_DIR='/Library/Developer/CommandLineTools',RAYON_NUM_THREADS='2',
             HARDWARE_CONCURRENCY=str(a.threads),CARGO_TARGET_DIR=str(ROOT/'build/research/noir-compact-native-target'))
    subprocess.run(['cargo','build','--release','--manifest-path',str(HERE/'native/Cargo.toml'),'--jobs','2'],env=env,check=True)
    if subprocess.check_output([str(TOOLS/'bb/bb'),'--version'],text=True).strip()!='5.2.1':parser.error('Run pinned tool preparer')
    if '1.0.0-beta.25' not in subprocess.check_output([str(TOOLS/'noir/nargo'),'--version'],text=True):parser.error('Unexpected compiler')
    work=ROOT/'build/research/noir-compact'/a.name
    (work/'src').mkdir(parents=True,exist_ok=True)
    raw=a.fixture.read_bytes()
    if len(raw)>32*1024*1024:parser.error('Fixture exceeds resource bound')
    legacy=json.loads(raw)
    scalar_cap=scalar_capacity(legacy)
    byte_cap=max(64,((len(legacy['text'].encode())+63)//64)*64)
    start=time.monotonic()
    fixture_hash=hashlib.sha256(raw).hexdigest()
    metadata=work/'fixture-metadata.json'
    if metadata.exists():
        saved=json.loads(metadata.read_text())
        if saved['sourceSha256']!=fixture_hash:raise RuntimeError('Use a new experiment name for a changed fixture')
        private=json.loads((work/'private.json').read_text());capsule=json.loads((work/'capsule.json').read_text())
        if saved['privateSha256']!=hashlib.sha256((work/'private.json').read_bytes()).hexdigest() or saved['capsuleSha256']!=hashlib.sha256((work/'capsule.json').read_bytes()).hexdigest():
            raise RuntimeError('Frozen synthetic fixture changed')
    else:
        if (work/'private.json').exists() and (work/'capsule.json').exists():
            private=json.loads((work/'private.json').read_text());capsule=json.loads((work/'capsule.json').read_text())
        else:
            p=subprocess.run([str(NATIVE),'fixture',str(scalar_cap)],input=raw,capture_output=True,env=env,timeout=45)
            if p.returncode:raise RuntimeError(p.stderr.decode()[-1000:])
            native=json.loads(p.stdout);private=native['private'];capsule=native['capsule']
    words=private['words'];op_cap=((len(words)+11)//12)*12;cp_count=len(private['checkpoints'])
    if op_cap>65536 or cp_count>1024:parser.error('Experiment exceeds reviewed operation/checkpoint capacity')
    cp_capacity=cp_count
    if a.profile=='cast256':
        if op_cap>1536 or scalar_cap>256 or byte_cap>1024 or cp_count>8:
            parser.error('Complete session exceeds cast256 profile; no history is omitted')
        op_cap=1536;scalar_cap=256;byte_cap=1024;cp_capacity=8
    write(work/'private.json',json.dumps(private));write(work/'capsule.json',json.dumps(capsule))
    write(metadata,json.dumps(dict(sourceSha256=fixture_hash,
        privateSha256=hashlib.sha256((work/'private.json').read_bytes()).hexdigest(),
        capsuleSha256=hashlib.sha256((work/'capsule.json').read_bytes()).hexdigest())))
    source=(HERE/('src/main.nr' if a.candidate=='none' else f'candidates/{a.candidate}.nr')).read_text()
    for old,new in [('OPS:u32=256',f'OPS:u32={op_cap}'),('SCALARS:u32=64',f'SCALARS:u32={scalar_cap}'),
                    ('BYTES:u32=128',f'BYTES:u32={byte_cap}'),('CPS:u32=2',f'CPS:u32={cp_capacity}')]:
        assert source.count(old)==1;source=source.replace(old,new)
    if (work/'target/setup/vk').exists() and (work/'src/main.nr').read_text()!=source:
        raise RuntimeError('Use a new experiment name for a changed circuit')
    for source_path in [HERE/'src/commit.nr',ROOT/'extra/experiments/noir-replay/src/bytes.nr']:
        target_path=work/'src'/source_path.name
        if (work/'target/setup/vk').exists() and target_path.read_bytes()!=source_path.read_bytes():
            raise RuntimeError('Use a new experiment name for changed circuit helpers')
    (work/'src/main.nr').write_text(source)
    shutil.copy2(HERE/'src/commit.nr',work/'src/commit.nr')
    shutil.copy2(ROOT/'extra/experiments/noir-replay/src/bytes.nr',work/'src/bytes.nr')
    (work/'Nargo.toml').write_text((HERE/'Nargo.toml').read_text().replace('../../../build/research/noir-sha256',str(ROOT/'build/research/noir-sha256')))
    def decoded(w):
        code=w>>56;arg=w&((1<<56)-1);p=[0,0,0,0]
        if code in [1,9]:p=[arg&65535,arg>>16,0,0]
        elif code in [3,4]:p=[arg>>16,arg&65535,0,0]
        elif code==5:p=[arg>>40,arg&65535,(arg>>16)&65535,(arg>>32)&255]
        return dict(code=code,arg=arg,p=p)
    if a.candidate=='decoding-hints':
        ops=[decoded(w) for w in words]+[dict(code=0,arg=0,p=[0,0,0,0])]*(op_cap-len(words))
    else:
        ops=[dict(code=w>>56,arg=w&((1<<56)-1)) for w in words]+[dict(code=0,arg=0)]*(op_cap-len(words))
    checkpoints=checkpoint_hints(words,private['checkpoints']) if a.candidate=='packed-prefixes' else private['checkpoints']
    expected=dict(capsule['journal'])
    if a.profile=='cast256':
        checkpoints=checkpoints+[dict(offset=0,unix=0,elapsed=0)]*(cp_capacity-cp_count)
        expected.update(checkpoint_count=cp_count,checkpoint_roots=expected['checkpoint_roots']+['0']*(cp_capacity-cp_count))
    values=dict(nonce=private['nonce'],salt=private['salt'],ops=ops,op_count=len(words),
                checkpoints=checkpoints,expected=expected)
    write(work/'inputs.json',json.dumps(values))
    write(work/'Prover.toml','\n'.join(k+' = '+fixture.toml(v) for k,v in values.items())+'\n')
    budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY=str(a.threads))
    compile_cost,_=budget.limited(['/usr/bin/nice','-n','10',TOOLS/'noir/nargo','execute'],work)
    gate_cost,raw_gates=budget.limited(['/usr/bin/nice','-n','10',TOOLS/'bb/bb','gates','-b',work/'target/huma_compact_experiment.json','-t','noir-recursive'],work)
    gates=json.loads(raw_gates)
    result=dict(experimental=True,newProtocol=True,notAppRelease=True,fixture=a.fixture.name,
        proofGenerated=False,publicKeyDisclosed=True,allSignaturesVerified=True,attestationVerified=False,trustedTime=False,
        operations=len(words),operationCapacity=op_cap,scalarCapacity=scalar_cap,byteCapacity=byte_cap,
        checkpoints=cp_count,checkpointCapacity=cp_capacity,profile=a.profile,compileAndWitness=compile_cost,gateCounter=gate_cost,gates=gates,
        threads=a.threads,nice=10,noir='1.0.0-beta.25',bb='5.2.1',zeroKnowledge=True)
    print(json.dumps(result),flush=True)
    write(work/'sizing-results.json',json.dumps(result,indent=2)+'\n')
    if a.prove:
        count=gates['functions'][0]['circuit_size']
        if count>2_100_000:raise RuntimeError('Review larger proof budget before proving')
        target=work/'target';out=target/f'proof-{a.threads}-threads'
        common=['-b',target/'huma_compact_experiment.json','-t','noir-recursive','-c',ROOT/'build/research/noir-crs']
        def worker(args):
            p=subprocess.run([str(x) for x in [TOOLS/'worker-bench',TOOLS/'bb/bb',*args]],env=env,cwd=work,text=True,capture_output=True,timeout=195)
            if p.returncode:raise RuntimeError(p.stderr[-1500:])
            return json.loads(p.stdout)
        worker(['write_vk',*common,'-o',target/'setup'])
        timing=worker(['prove',*common,'-w',target/'huma_compact_experiment.gz','-k',target/'setup/vk','-o',out])
        started=time.monotonic();checked=verify.verify(work,out,work/'capsule.json',legacy['text'])
        result.update(proofGenerated=True,verified=checked['verified'],proveMs=timing['elapsedMs'],
            verifyMs=round((time.monotonic()-started)*1000,2),proofIdentity=checked['proofIdentity'],
            proofBytes=(out/'proof').stat().st_size,publicInputBytes=(out/'public_inputs').stat().st_size,
            vkSha256=hashlib.sha256((target/'setup/vk').read_bytes()).hexdigest())
        result['witnessProveVerifyMs']=round(compile_cost['wallMs']+result['proveMs']+result['verifyMs'],2)
    result['fixtureSetupCompileAndChecksMs']=round((time.monotonic()-start)*1000,2)
    result['sourceSha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (work/'src').glob('*.nr')}
    result['nativeSourceSha256']={str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [HERE/'native/Cargo.toml',HERE/'native/Cargo.lock',*(HERE/'native/src').glob('*.rs')]}
    result['artifactSha256']=hashlib.sha256((work/'target/huma_compact_experiment.json').read_bytes()).hexdigest()
    write(work/f'results-{a.threads}-threads.json',json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
