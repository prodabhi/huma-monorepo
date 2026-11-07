#!/usr/bin/env python3
"""Continuation constraints and malicious state/root claims; no proof or keys."""
import argparse,copy,hashlib,json
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    parser.add_argument('--genesis-control',action='store_true')
    parser.add_argument('--packing-control',action='store_true')
    args=parser.parse_args();work=args.work.resolve()
    artifact=work/'target/huma_continuation_component.json';artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    fixture=json.loads((work/'reference.json').read_text());reports=[]
    if 'hostile' not in fixture:raise ValueError('Use a newly generated reference with explicit forged-genesis cases')
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    for selected in fixture['selected']:
        values={k:v for k,v in selected.items() if k!='index'}
        reports.append(checks.execute(work,'ValidChunk'+str(selected['index']),values,True))
    original={k:v for k,v in fixture['selected'][1].items() if k!='index'}
    variants=[]
    def variant(name,mutate):
        values=copy.deepcopy(original);mutate(values);variants.append((name,values))
    variant('ChangedCursor',lambda v:v['state'].update(cursor=v['state']['cursor']^1))
    variant('ChangedTime',lambda v:v['state'].update(elapsed=v['state']['elapsed']^1))
    variant('ChangedCounter',lambda v:v['state'].update(samples=v['state']['samples']+1))
    variant('ChangedSource',lambda v:v['state'].update(source=2))
    variant('ChangedPrivateBuffer',lambda v:v['state']['buffer'].__setitem__(0,v['state']['buffer'][0]^1))
    variant('ChangedTranscriptHead',lambda v:v['state'].update(head='1'))
    variant('ChangedSessionNonce',lambda v:v['expected']['nonce'].__setitem__(0,'2'))
    variant('ChangedStartOffset',lambda v:v['expected'].update(start_offset=v['expected']['start_offset']+12))
    variant('ChangedEndOffset',lambda v:v['expected'].update(end_offset=v['expected']['end_offset']+12))
    variant('ChangedEndRoot',lambda v:v['expected'].update(end_root='1'))
    variant('ChangedCapturePrefix',lambda v:v['expected'].update(capture_root='1'))
    variant('ChangedOperation',lambda v:v['ops'][0].update(arg=v['ops'][0]['arg']^1))
    alias=copy.deepcopy(original)
    assert alias['state']['buffer'][1]>0
    alias['state']['buffer'][0]+=1<<21;alias['state']['buffer'][1]-=1
    variants.append(('PackedScalarAlias',alias))
    final={k:v for k,v in fixture['selected'][-1].items() if k!='index'}
    if final['op_count']<len(final['ops']):
        padding=copy.deepcopy(final);padding['ops'][-1]['code']=3;variants.append(('NonzeroPadding',padding))
    for hostile in fixture['hostile']:
        values={k:v for k,v in hostile.items() if k!='name'};variants.append((hostile['name'],values))
    for name,values in variants:reports.append(checks.execute(work,'Reject'+name,values,False))
    if artifact_hash!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Frozen continuation circuit changed')
    controls=[]
    if args.genesis_control:
        control=work.parent/(work.name+'-unsafe-genesis-control')
        if control.exists():raise ValueError('Control output already exists')
        (control/'src').mkdir(parents=True)
        source=(work/'src/main.nr').read_text()
        start=source.index('    // GENESIS_BEGIN:');end=source.index('    // GENESIS_END')
        source=source[:start]+'    // TEST ONLY: genesis constraints deliberately removed.\n'+source[end:]
        (control/'src/main.nr').write_text(source)
        (control/'src/commit.nr').write_bytes((work/'src/commit.nr').read_bytes())
        (control/'Nargo.toml').write_bytes((work/'Nargo.toml').read_bytes())
        (control/'NOT_A_VERIFIER.txt').write_text('Weakened witness-only counterfactual. Never generate a verification key or proof.\n')
        for hostile in fixture['hostile']:
            values={k:v for k,v in hostile.items() if k!='name'}
            controls.append(checks.execute(control,'Unsafe'+hostile['name'],values,True))
        assert not (control/'target/setup').exists()
    if args.packing_control:
        control=work.parent/(work.name+'-unsafe-packing-control')
        if control.exists():raise ValueError('Control output already exists')
        (control/'src').mkdir(parents=True)
        source=(work/'src/main.nr').read_text();needle='        (s.buffer[i] as Field).assert_max_bit_size::<21>();'
        assert source.count(needle)==1;source=source.replace(needle,'        // TEST ONLY: omitted packed-scalar range bound.')
        (control/'src/main.nr').write_text(source)
        (control/'src/commit.nr').write_bytes((work/'src/commit.nr').read_bytes())
        (control/'Nargo.toml').write_bytes((work/'Nargo.toml').read_bytes())
        (control/'NOT_A_VERIFIER.txt').write_text('Weakened witness-only scalar-alias control. Never generate a key or proof.\n')
        controls.append(checks.execute(control,'UnsafePackedAlias',alias,True))
        assert not (control/'target/setup').exists()
    result=dict(kind='huma-continuation-constraints-v1',artifactSha256=artifact_hash,cases=reports,
        unsafeControls=controls,proofGenerated=False,verificationKeyCreated=False,completeHumaSessionProof=False)
    cases.write(work/'constraint-results.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
