#!/usr/bin/env python3
"""Adversarial witness checks against the fixed media membership artifact."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import protocol
import run

work=run.ROOT/'build/research/noir-media/membership-v1'
cases=run.prepare_media(work)
image=cases[0][3]
artifact=work/'target/huma_media_membership.json'
pin=hashlib.sha256(artifact.read_bytes()).hexdigest()
def execute(name,values,reject):
    run.write(work/'mutation.toml','\n'.join(k+' = '+run.toml_fixture.toml(v) for k,v in values.items())+'\n')
    try:
        run.size.limited(['/usr/bin/nice','-n','10',run.TOOLS/'noir/nargo','execute','mutation','--prover-name','mutation'],work)
    except RuntimeError as error:
        rejection=any(marker in str(error) for marker in ['Assertion failed','assertion failed','error: Failed constraint'])
        if not reject or not rejection:raise
    else:
        if reject:raise AssertionError('Accepted '+name)
    assert hashlib.sha256(artifact.read_bytes()).hexdigest()==pin
    return dict(name=name,passed=True,rejected=reject)
results=[]
for name,_,_,values in cases:results.append(execute(name+' positive',values,False))
changes=[
    ('private sample altered',lambda v:v['openings'][0]['bytes'].__setitem__(0,v['openings'][0]['bytes'][0]^1)),
    ('sibling altered',lambda v:v['openings'][0]['siblings'][0].__setitem__(0,v['openings'][0]['siblings'][0][0]^1)),
    ('empty leaf',lambda v:v['openings'][0].__setitem__('len',0)),
    ('oversized leaf',lambda v:v['openings'][0].__setitem__('len',protocol.LEAF_BYTES+1)),
    ('wrong sampled position',lambda v:v['expected']['sampled_indices'].__setitem__(0,v['expected']['sampled_indices'][0]^1)),
    ('wrong sealed root',lambda v:v['expected']['sealed_root'].__setitem__(0,v['expected']['sealed_root'][0]^1)),
    ('wrong encoded master hash',lambda v:v['expected']['encoded_hash'].__setitem__(0,v['expected']['encoded_hash'][0]^1)),
    ('wrong layout',lambda v:v['expected']['layout_hash'].__setitem__(0,v['expected']['layout_hash'][0]^1)),
    ('wrong edit list',lambda v:v['expected']['edit_root'].__setitem__(0,v['expected']['edit_root'][0]^1)),
    ('unsupported medium',lambda v:v['expected'].__setitem__('kind',4)),
    ('wrong profile',lambda v:v['expected'].__setitem__('profile',2)),
    ('empty encoded asset',lambda v:v['expected'].__setitem__('encoded_length',0)),
    ('oversized tree',lambda v:v['expected'].__setitem__('leaf_count',257)),
]
for name,change in changes:
    values=copy.deepcopy(image);change(values);results.append(execute(name,values,True))
values=copy.deepcopy(image)
for i in range(100):
    values['expected']['challenge']=list(protocol.digest(b'DIFFERENT-CHALLENGE'+bytes([i])))
    if protocol.indices(values['expected'])!=image['expected']['sampled_indices']:break
else:raise AssertionError('No different selection')
results.append(execute('challenge cannot reuse old selected positions',values,True))
small=protocol.fixture(2,b'encoded-fixture',[bytes(range(9))],b'layout',bytes([1])*32,bytes([2])*32)
results.append(execute('partial leaf positive',small,False))
small['openings'][0]['bytes'][-1]=1
results.append(execute('nonzero unused private padding',small,True))
result=dict(experimental=True,proofGenerated=False,artifactSha256=pin,passed=len(results),results=results)
run.write(work/'witness-checks.json',json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
