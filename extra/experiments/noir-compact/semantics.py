#!/usr/bin/env python3
"""Recompute commitments around forged replay claims; never produces proofs/keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import check
import run
import algebraic_replay

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate',choices=['none','flat-transitions','packed-prefixes','bounded-checkpoints','algebraic'],default='none')
    p.add_argument('--overflow-control',action='store_true',help='Test-only baseline with final range guard removed; no proof or VK')
    p.add_argument('--algebraic-control',choices=['movement','unicode','remaining'],help='Weaken one exact replay constraint; never generate a proof or VK')
    a=p.parse_args()
    if a.overflow_control and a.candidate!='none':p.error('Overflow control targets the baseline only')
    if a.algebraic_control and a.candidate!='algebraic':p.error('Algebraic control requires the matching replay candidate')
    env=dict(os.environ,DEVELOPER_DIR='/Library/Developer/CommandLineTools',
             CARGO_TARGET_DIR=str(ROOT/'build/research/noir-compact-native-target'))
    subprocess.run(['cargo','build','--release','--manifest-path',str(HERE/'native/Cargo.toml'),
                    '--example','semantic_cases','--jobs','2'],env=env,check=True)
    cases=json.loads(subprocess.check_output([str(ROOT/'build/research/noir-compact-native-target/release/examples/semantic_cases')]))
    work=ROOT/'build/research/noir-compact'/('semantic-'+a.candidate+('-control' if a.overflow_control else '')+('-control-'+a.algebraic_control if a.algebraic_control else ''))
    (work/'src').mkdir(parents=True,exist_ok=True)
    source=(HERE/('src/main.nr' if a.candidate=='none' else 'candidates/'+('bounded-checkpoints' if a.candidate=='algebraic' else a.candidate)+'.nr')).read_text()
    if a.candidate=='algebraic':source=algebraic_replay.optimize(source)
    for before,after in [('OPS:u32=256','OPS:u32=264'),('BYTES:u32=128','BYTES:u32=64')]:
        assert source.count(before)==1;source=source.replace(before,after)
    if a.candidate in ['bounded-checkpoints','algebraic']:source=source.replace('CPS:u32=2','CPS:u32=8')
    if a.overflow_control:
        assert source.count('elapsed.assert_max_bit_size::<64>();')==1
        source=source.replace('elapsed.assert_max_bit_size::<64>();','// TEST ONLY: deliberately omitted final elapsed range guard.')
        (work/'NOT_A_VERIFIER.txt').write_text('Weakened test-only counterfactual. No proof or verification key may be generated from this directory.\n')
        cases=[c for c in cases if c['name']=='ElapsedOverflow']
    if a.algebraic_control:
        needle,case={
            'movement':('gated17(move_l,cursor as Field-target as Field-1);','MoveAwayAndBack'),
            'unicode':('assert((scalar<=0x10ffff)&!((scalar>=0xd800)&(scalar<=0xdfff)));','InvalidUnicode'),
            'remaining':('assert((finishing as Field)*(remaining as Field)==0);','EndBeforeDeletion'),
        }[a.algebraic_control]
        assert source.count(needle)==1;source=source.replace(needle,'// DELIBERATELY WEAKENED TEST CONTROL')
        (work/'NOT_A_VERIFIER.txt').write_text('Weakened witness-only test; never generate a VK or proof.\n')
        cases=[c for c in cases if c['name']==case]
    if (work/'target/setup/vk').exists():raise RuntimeError('Semantic test directory must never contain a VK')
    (work/'src/main.nr').write_text(source)
    shutil.copy2(HERE/'src/commit.nr',work/'src/commit.nr')
    shutil.copy2(ROOT/'extra/experiments/noir-replay/src/bytes.nr',work/'src/bytes.nr')
    (work/'Nargo.toml').write_text((HERE/'Nargo.toml').read_text().replace('../../../build/research/noir-sha256',str(ROOT/'build/research/noir-sha256')))
    results=[]
    for c in cases:
        w=c['private'];words=w['words']
        checkpoints=w['checkpoints']
        if a.candidate=='packed-prefixes':
            checkpoints=run.checkpoint_hints(words,checkpoints)
            # For the forged overflow witness, the malicious hint fits its ABI.
            for cp in checkpoints:cp['stream_elapsed']&=(1<<64)-1
        expected=dict(c['expected'])
        if a.candidate in ['bounded-checkpoints','algebraic']:
            expected.update(checkpoint_count=2,checkpoint_roots=expected['checkpoint_roots']+['0']*6)
            checkpoints=checkpoints+[dict(offset=0,unix=0,elapsed=0)]*6
        values=dict(nonce=w['nonce'],salt=w['salt'],op_count=len(words),
            ops=[dict(code=x>>56,arg=x&((1<<56)-1)) for x in words]+[dict(code=0,arg=0)]*(264-len(words)),
            checkpoints=checkpoints,expected=expected)
        results.append(check.solve(work,c['name'],values,True if a.overflow_control or a.algebraic_control else c['accepted']))
    summary=dict(experimental=True,proofGenerated=False,recomputedCommitments=True,candidate=a.candidate,
        weakenedOverflowControl=a.overflow_control,weakenedAlgebraicControl=a.algebraic_control,
        sourceSha256=hashlib.sha256(source.encode()).hexdigest(),cases=results)
    (work/'semantic-results.json').write_text(json.dumps(summary,indent=2)+'\n')
