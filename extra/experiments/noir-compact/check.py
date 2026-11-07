#!/usr/bin/env python3
"""Freeze signed roots; mutate private replay and composite public evidence."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import verify

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'extra/experiments/noir-replay'))
import fixture
NARGO=ROOT/'build/research/noir-tools/noir/nargo'


def solve(work,name,values,accepted):
    input_path=work/(name+'.toml')
    input_path.write_text('\n'.join(k+' = '+fixture.toml(v) for k,v in values.items())+'\n')
    input_path.chmod(0o600)
    start=time.monotonic()
    p=subprocess.run(['/usr/bin/nice','-n','10',str(NARGO),'execute',name,'--prover-name',name],
        cwd=work,env=dict(os.environ,RAYON_NUM_THREADS='2'),text=True,capture_output=True,timeout=45)
    if accepted:
        passed=p.returncode==0 and 'Circuit witness successfully solved' in p.stdout
    else:passed=p.returncode!=0 and any(x in p.stderr for x in ['Failed constraint','Assertion failed'])
    if not passed:raise RuntimeError(name+': '+p.stderr[-1500:]+p.stdout[-500:])
    result=dict(case=name,accepted=accepted,wallMs=round((time.monotonic()-start)*1000,2))
    print(json.dumps(result),flush=True);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('name',default='typing50-v4',nargs='?')
    p.add_argument('--threads',type=int,choices=[2,8],default=2);a=p.parse_args()
    if not a.name.replace('-','').isalnum():p.error('Invalid experiment name')
    work=ROOT/'build/research/noir-compact'/a.name
    original=json.loads((work/'inputs.json').read_text())
    cases=[solve(work,'Valid',original,True)]
    variants=[]
    def change(name,fn):
        values=copy.deepcopy(original);fn(values);variants.append((name,values))
    def first(values,code):return next(o for o in values['ops'][:values['op_count']] if o['code']==code)
    change('ChangedKeyTiming',lambda v:first(v,3).update(arg=first(v,3)['arg']^(1<<16)))
    change('ChangedKeyCode',lambda v:first(v,3).update(arg=first(v,3)['arg']^1))
    change('ChangedScalar',lambda v:first(v,9).update(arg=88))
    change('SurrogateScalar',lambda v:first(v,9).update(arg=0xd800))
    change('InvalidSource',lambda v:first(v,5).update(arg=first(v,5)['arg']&~(255<<32)))
    change('ChangedSource',lambda v:first(v,5).update(arg=(first(v,5)['arg']&~(255<<32))|(2<<32)))
    change('ChangedLocation',lambda v:first(v,5).update(arg=first(v,5)['arg']^1))
    change('UnknownOpcode',lambda v:v['ops'][1].update(code=14))
    change('ExtraArgumentBits',lambda v:v['ops'][1].update(arg=1<<56))
    change('Salt',lambda v:v['salt'].__setitem__(0,'1'))
    change('ZeroSalt',lambda v:v.update(salt=['0','0']))
    change('Nonce',lambda v:v['nonce'].__setitem__(0,'1'))
    change('ChangedPublicRoot',lambda v:v['expected'].update(capture_root='1'))
    change('ChangedPublicText',lambda v:v['expected']['text_hash'].__setitem__(0,v['expected']['text_hash'][0]^1))
    change('ChangedPublicCount',lambda v:v['expected'].update(samples=0))
    change('ChangedClock',lambda v:v['checkpoints'][-1].update(unix=1))
    change('UncoveredFinalOps',lambda v:v['checkpoints'][-1].update(offset=v['op_count']-1))
    change('WrongStart',lambda v:v['checkpoints'][0].update(offset=0))
    if original['op_count']<len(original['ops']):
        change('NonzeroPadding',lambda v:v['ops'][-1].update(code=3))
    if 'checkpoint_count' in original['expected']:
        count=original['expected']['checkpoint_count']
        change('TooFewCheckpoints',lambda v:v['expected'].update(checkpoint_count=1))
        change('TooManyCheckpoints',lambda v:v['expected'].update(checkpoint_count=len(v['checkpoints'])+1))
        if count<len(original['checkpoints']):
            change('NonzeroCheckpointPadding',lambda v:v['checkpoints'][count].update(offset=1))
            change('NonzeroRootPadding',lambda v:v['expected']['checkpoint_roots'].__setitem__(count,'1'))
    for name,values in variants:cases.append(solve(work,name,values,False))
    # The proof can be valid while signatures or reader text are invalid: the
    # mandatory composite verifier must reject in that case as well.
    proof=work/f'target/proof-{a.threads}-threads'
    capsule=json.loads((work/'capsule.json').read_text())
    original_result=verify.verify(work,proof,work/'capsule.json')
    checks=[]
    def reject(name,body=None,text=None,key=None,proof_dir=proof):
        path=work/(name+'.json');path.write_text(json.dumps(capsule if body is None else body))
        try:verify.verify(work,proof_dir,path,text,key)
        except (ValueError,StopIteration):checks.append(dict(case=name,rejected=True))
        else:raise RuntimeError('Composite verifier accepted '+name)
    for label,fn in [
        ('BadSignature',lambda c:c['signatures'][0].__setitem__(10,c['signatures'][0][10]^1)),
        ('ReorderedSignatures',lambda c:c['signatures'].reverse()),
        ('MissingSignature',lambda c:c['signatures'].pop()),
        ('ChangedKey',lambda c:c['public_key'].__setitem__(30,c['public_key'][30]^1)),
        ('UnprovenPublicTime',lambda c:c['journal'].update(end_unix=1)),
    ]:
        bad=copy.deepcopy(capsule);fn(bad);reject(label,bad)
    reject('WrongExpectedKey',key='0'*64)
    reject('ChangedReaderText',text='Different text')
    if 'checkpoint_count' in original['expected']:
        extra=copy.deepcopy(capsule);extra['journal']['checkpoint_roots'].append('0');extra['signatures'].append([0]*8)
        reject('PaddingCannotBecomeSignedCheckpoint',extra)
    for filename in ['proof','public_inputs']:
        folder=work/('Mutated-'+filename);folder.mkdir(exist_ok=True)
        for item in ['proof','public_inputs']:
            data=bytearray((proof/item).read_bytes())
            if item==filename:data[-1]^=1
            (folder/item).write_bytes(data)
        reject('Changed-'+filename,proof_dir=folder)
    (work/'constraint-results.json').write_text(json.dumps(cases,indent=2)+'\n')
    (work/'reader-results.json').write_text(json.dumps(dict(originalVerified=original_result['verified'],checks=checks),indent=2)+'\n')
    print('Composite rejections:',len(checks),flush=True)
