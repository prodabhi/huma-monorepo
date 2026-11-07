#!/usr/bin/env python3
"""Differential V4 witnesses, tampering, and no-key/no-proof weakened controls."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
import subprocess
import time
import assurance_cases as cases

def toml(path,values):
    path.write_text('\n'.join(k+' = '+cases.fixture.toml(v) for k,v in values.items())+'\n');path.chmod(0o600)

def execute(work,label,values,success):
    toml(work/(label+'.toml'),values)
    started=time.monotonic()
    command=['/usr/bin/nice','-n','10',cases.TOOLS/'noir/nargo','execute',label,'--prover-name',label]
    try:
        stats,_=cases.budget.limited(command,work)
        accepted=True
    except RuntimeError as error:
        # Resource limits and compiler errors are not evidence of a rejected witness.
        if not any(s in str(error) for s in ['Assertion failed','assertion failed','error: Failed constraint']):raise
        accepted=False;stats={'wallMs':round((time.monotonic()-started)*1000,2)}
    if accepted!=success:raise AssertionError(f'{label}: expected accepted={success}, got {accepted}')
    return dict(case=label,accepted=accepted,expectedAccepted=success,**stats)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True)
    p.add_argument('--work-dir',type=Path,help='Explicit local candidate build for differential witness checks')
    p.add_argument('--controls',action='store_true',help='Build weakened tiny controls without setup/proofs')
    a=p.parse_args();work=a.work_dir.resolve() if a.work_dir else cases.ROOT/'build/research/noir-assurance'/a.name
    artifact=work/'target/huma_compact_experiment.json'
    artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    abi=json.loads(artifact.read_text())['abi'];params={p['name']:p['type'] for p in abi['parameters']}
    constants={k:int(v) for k,v in re.findall(r'global (SCALARS|BYTES):u32=(\d+);',(work/'src/main.nr').read_text())}
    limits=dict(OPS=params['ops']['length'],SCALARS=constants['SCALARS'],BYTES=constants['BYTES'],CPS=params['checkpoints']['length'],
        SAMPLES=params['origins']['length'],PRES=params['presence']['length'])
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    reports=[];values_by_case={}
    names=(['typed250'] if limits['SCALARS']>=250 else [])+['rollover','repeat','unpaired','rate','dwell','missing-origin','late','timeout','u64max']
    for name in names:
        saved=work/('case-'+name+'.json')
        if saved.exists():out=json.loads(saved.read_text())
        else:
            result=subprocess.run([str(cases.NATIVE),'assurance-case',name],input=b'',capture_output=True,timeout=30)
            if result.returncode:raise RuntimeError(result.stderr.decode()[-1000:])
            out=json.loads(result.stdout);cases.write(saved,out)
        values=cases.inputs(out['private'],out['capsule'],limits);values_by_case[name]=values
        report=execute(work,'Valid'+name.replace('-',''),values,True)
        report.update(policySatisfied=out['capsule']['journal']['policy_satisfied'],softwareKeysOnly=True,proofGenerated=False)
        reports.append(report);print(json.dumps(report),flush=True)
    original=values_by_case['rollover'];bad=[]
    value=copy.deepcopy(original);value['origins'][0]['pid']^=1;bad.append(('OriginPID',value))
    value=copy.deepcopy(original);value['origins'][0]['keyboard']^=1;bad.append(('KeyboardType',value))
    value=copy.deepcopy(original);value['origins'][0]['repeated']=True;bad.append(('RepeatFlag',value))
    value=copy.deepcopy(original);value['presence'][0]['nonce'][0]='1';bad.append(('PresenceNonce',value))
    value=copy.deepcopy(original);value['presence'][1]['answered']=value['presence'][1]['issued']+10001;bad.append(('LateSeal',value))
    value=copy.deepcopy(original);value['checkpoints'][1]['presence']=0;bad.append(('OmittedPresenceCoverage',value))
    value=copy.deepcopy(original);value['expected']['on_time']+=1;bad.append(('PublicPresenceCount',value))
    value=copy.deepcopy(original);value['timings'][0]['elapsed']+=1;bad.append(('UnboundSampleTime',value))
    value=copy.deepcopy(original);value['origins'][-1]['present']=True;bad.append(('UnusedOriginPadding',value))
    value=copy.deepcopy(original);value['expected']['presence_roots'][-1]='1';bad.append(('UnusedPresenceRoot',value))
    # Forge a passing rate report using timings from a different rhythm. The
    # authentic operation transcript and its signature roots are unchanged.
    forged_time=copy.deepcopy(values_by_case['rate'])
    for t in forged_time['timings'][:forged_time['expected']['replay']['samples']]:t['elapsed']=100+(t['elapsed']-100)*20
    forged_time['expected']['rules'][8]=True;forged_time['expected']['policy_satisfied']=True
    bad.append(('ForgedHumanRhythm',forged_time))
    duplicate=copy.deepcopy(values_by_case['rate']);count=duplicate['expected']['replay']['samples']
    duplicate['timings'][count-1]=copy.deepcopy(duplicate['timings'][count-2])
    duplicate['expected']['rules'][4]=False;bad.append(('ReusedKeySample',duplicate))
    for name,value in bad:
        report=execute(work,'Reject'+name,value,False);reports.append(report);print(json.dumps(report),flush=True)
    assert hashlib.sha256(artifact.read_bytes()).hexdigest()==artifact_hash,'Circuit changed during cases'
    controls=[]
    if a.controls:
        for label,needle,bad_value in [
            ('UnboundTime','            assert(t.elapsed as Field==times[t.offset+1]);',forged_time),
            ('ReusedSample','if i>0 {assert(t.offset>previous_sample_offset);}',duplicate),
        ]:
            control=cases.ROOT/'build/research/noir-assurance'/('unsafe-control-'+label.lower())
            assert not (control/'target/setup').exists(),'Control must never have a verification key'
            (control/'src').mkdir(parents=True,exist_ok=True)
            for path in (work/'src').glob('*.nr'):
                text=path.read_text()
                if path.name=='main.nr':
                    for key,value in limits.items():text=text.replace(f'global {key}:u32={value};',f'global {key}:u32={cases.PROFILES["tiny"][key]};')
                    assert text.count(needle)==1;text=text.replace(needle,'')
                (control/'src'/path.name).write_text(text)
            (control/'Nargo.toml').write_bytes((work/'Nargo.toml').read_bytes())
            # Use the identical real sample data/forged report in a small profile.
            v=copy.deepcopy(bad_value);tiny=cases.PROFILES['tiny']
            v['ops']=v['ops'][:tiny['OPS']];v['origins']=v['origins'][:tiny['SAMPLES']];v['timings']=v['timings'][:tiny['SAMPLES']]
            v['presence']=v['presence'][:tiny['PRES']];v['checkpoints']=v['checkpoints'][:tiny['CPS']]
            v['expected']['replay']['checkpoint_roots']=v['expected']['replay']['checkpoint_roots'][:tiny['CPS']]
            v['expected']['checkpoint_roots']=v['expected']['checkpoint_roots'][:tiny['CPS']]
            v['expected']['presence_roots']=v['expected']['presence_roots'][:tiny['PRES']]
            report=execute(control,'Unsafe'+label,v,True);report.update(weakenedControl=True,proofGenerated=False,verificationKeyCreated=False)
            assert not (control/'target/setup').exists();controls.append(report);print(json.dumps(report),flush=True)
    result=dict(experimental=True,softwareKeysOnly=True,artifactSha256=artifact_hash,limits=limits,cases=reports,controls=controls)
    cases.write(work/'constraint-results.json',result)

if __name__=='__main__':main()
