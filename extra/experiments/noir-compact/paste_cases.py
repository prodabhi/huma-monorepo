#!/usr/bin/env python3
"""Prove the existing zero-paste policy's constraints, without generating proofs."""
import copy,hashlib,json,subprocess
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

work=cases.ROOT/'build/research/noir-capacity/cp32-pres8-v1'
artifact=work/'target/huma_compact_experiment.json'
bytecode=hashlib.sha256(json.loads(artifact.read_text())['bytecode'].encode()).hexdigest()
assert bytecode=='d2816750fd1278beb70c16743e4851561f9d5b30c57770f1a707a4d16ef2d2bc'
reports=[]
for name,label in [('paste-small','OneCharacter'),('paste-large','BulkText')]:
    result=subprocess.run([str(cases.NATIVE),'assurance-case',name],capture_output=True,timeout=20)
    if result.returncode:raise RuntimeError('Disposable paste fixture failed')
    fixture=json.loads(result.stdout)
    values=cases.inputs(fixture['private'],fixture['capsule'],dict(cases.PROFILES['cast256'],CPS=32))
    assert values['expected']['rules']==[True,False,True,True,True,True,True,True,True]
    reports.append(checks.execute(work,'Paste'+label+'FailedPolicy',values,True))
    forged=copy.deepcopy(values);forged['expected']['rules'][1]=True;forged['expected']['policy_satisfied']=True
    reports.append(checks.execute(work,'Paste'+label+'ForgedPass',forged,False))
assert hashlib.sha256(json.loads(artifact.read_text())['bytecode'].encode()).hexdigest()==bytecode
report=dict(policy='huma-writing-rules-v1',pasteAllowanceCharacters=0,circuitUnchanged=True,
    proofGenerated=False,ownerIdentityUsed=False,cases=reports)
cases.write(cases.ROOT/'build/no-paste-constraint-results.json',report)
print(json.dumps(report))
