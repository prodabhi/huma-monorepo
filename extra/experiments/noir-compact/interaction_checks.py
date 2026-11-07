#!/usr/bin/env python3
"""Combined-state witnesses, altered input, and no-proof genesis controls."""
import argparse,copy,hashlib,json,os
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('work',type=Path)
    parser.add_argument('--genesis-control',action='store_true');args=parser.parse_args();os.umask(0o077)
    work=args.work.resolve();artifact=work/'target/huma_continuation_component.json'
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest();fixture=json.loads((work/'reference.json').read_text())
    if work.parent!=cases.ROOT/'build/research/noir-interaction':raise ValueError('Use an isolated interaction build')
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    reports=[]
    def input(row):return {k:v for k,v in row.items() if k not in ['index','name']}
    for row in fixture['selected']:
        reports.append(checks.execute(work,'ValidChunk'+str(row['index']),input(row),True))
    original=input(fixture['selected'][len(fixture['selected'])//2]);variants=[]
    def variant(label,change,base=original):
        value=copy.deepcopy(base);change(value)
        if value==base:raise ValueError(label+': mutation did not change the input')
        variants.append((label,value))
    variant('ChangedReplayTime',lambda v:v['state'].update(elapsed=v['state']['elapsed']^1))
    variant('ChangedPrivateText',lambda v:v['state']['buffer'].__setitem__(0,v['state']['buffer'][0]^1))
    variant('ChangedHeldKey',lambda v:v['state']['interaction']['behavior']['held'].__setitem__(255,'1'))
    variant('ChangedRateWindow',lambda v:v['state']['interaction']['behavior']['rate_ring'].__setitem__(0,v['state']['interaction']['behavior']['rate_ring'][0]^1))
    variant('ChangedDownCount',lambda v:v['state']['interaction']['behavior'].update(downs=v['state']['interaction']['behavior']['downs']+1))
    variant('ChangedPairs',lambda v:v['state']['interaction']['behavior'].update(pairs=v['state']['interaction']['behavior']['pairs']+1))
    variant('ChangedAnomalies',lambda v:v['state']['interaction']['behavior'].update(anomalies=v['state']['interaction']['behavior']['anomalies']+1))
    variant('ChangedPause',lambda v:v['state']['interaction']['behavior'].update(pause=not v['state']['interaction']['behavior']['pause']))
    variant('ChangedRateResult',lambda v:v['state']['interaction']['behavior'].update(rate_ok=not v['state']['interaction']['behavior']['rate_ok']))
    variant('ChangedOriginHead',lambda v:v['state']['interaction'].update(origin_head='1'))
    variant('ChangedOriginTail',lambda v:v['state']['interaction']['origin_tail'].__setitem__(0,'1'))
    variant('ChangedOriginCount',lambda v:v['state']['interaction'].update(origin_present=v['state']['interaction']['origin_present']+1))
    variant('ChangedSessionNonce',lambda v:v['expected']['nonce'].__setitem__(0,'2'))
    for field in ['start_root','end_root','capture_root','origin_root']:
        variant('Changed'+field.title().replace('_',''),lambda v,k=field:v['expected'].update({k:'1'}))
    variant('ChangedStartOffset',lambda v:v['expected'].update(start_offset=v['expected']['start_offset']+12))
    variant('ChangedEndOffset',lambda v:v['expected'].update(end_offset=v['expected']['end_offset']+12))
    variant('ChangedOperation',lambda v:v['ops'][0].update(arg=v['ops'][0]['arg']^1))
    sample=next((i for i,o in enumerate(original['ops']) if o['code'] in [3,4]),None)
    if sample is not None:
        for field in ['pid','state','keyboard']:
            variant('ChangedInput'+field.title(),lambda v,k=field:v['origins'][sample].update({k:v['origins'][sample][k]^1}))
        variant('ChangedRepeat',lambda v:v['origins'][sample].update(repeated=not v['origins'][sample]['repeated']))
    non_sample=next((i for i,o in enumerate(original['ops']) if o['code'] not in [3,4]),None)
    if non_sample is not None:variant('OriginOnNonKeyOperation',lambda v:v['origins'][non_sample].update(present=True,state=1))
    final=input(fixture['selected'][-1])
    variant('ForgedPolicyResult',lambda v:v['expected'].update(policy_satisfied=not v['expected']['policy_satisfied']),final)
    for rule in range(9):variant('ForgedRule'+str(rule),lambda v,n=rule:v['expected']['rules'].__setitem__(n,not v['expected']['rules'][n]),final)
    variant('ForgedPublicOriginCount',lambda v:v['expected'].update(origin_present=v['expected']['origin_present']+1),final)
    if final['op_count']<len(final['ops']):
        variant('NonzeroPadding',lambda v:v['ops'][-1].update(code=3),final)
        variant('OriginInPadding',lambda v:v['origins'][-1].update(present=True,state=1),final)
    for row in fixture['hostile']:variants.append((row['name'],input(row)))
    for label,value in variants:reports.append(checks.execute(work,'Reject'+label,value,False))
    if digest!=hashlib.sha256(artifact.read_bytes()).hexdigest():raise ValueError('Frozen circuit changed')
    controls=[]
    if args.genesis_control:
        control=work.parent/(work.name+'-unsafe-genesis-control')
        if control.exists():raise ValueError('Use a new control output name')
        (control/'src').mkdir(parents=True);source=(work/'src/main.nr').read_text()
        start=source.index('        // INTERACTION_GENESIS_BEGIN');end=source.index('        // INTERACTION_GENESIS_END')
        source=source[:start]+'        // TEST ONLY: interaction genesis removed.\n'+source[end:]
        (control/'src/main.nr').write_text(source)
        for name in ['assurance.nr','commit.nr']:(control/'src'/name).write_bytes((work/'src'/name).read_bytes())
        (control/'Nargo.toml').write_bytes((work/'Nargo.toml').read_bytes())
        (control/'NOT_A_VERIFIER.txt').write_text('Weakened witness-only control. Never generate a verification key or proof.\n')
        for row in fixture['hostile']:controls.append(checks.execute(control,'Unsafe'+row['name'],input(row),True))
        assert not (control/'target/setup').exists()
    report=dict(kind='huma-interaction-continuation-constraints-v1',artifactSha256=digest,cases=reports,
        unsafeControls=controls,proofGenerated=False,verificationKeyCreated=False,completeHumaSessionProof=False)
    cases.write(work/'constraint-results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
