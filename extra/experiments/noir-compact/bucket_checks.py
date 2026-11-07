#!/usr/bin/env python3
"""Boundary witnesses for a frozen small full-policy circuit; no VK or proofs."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work',type=Path)
    args=parser.parse_args();work=args.work.resolve()
    artifact=work/'target/huma_compact_experiment.json'
    artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    sizing=json.loads((work/'results.json').read_text());limits=sizing['limits']
    if limits['SCALARS'] not in [64,128]:raise ValueError('Unsupported boundary capacity')
    if hashlib.sha256(json.loads(artifact.read_text())['bytecode'].encode()).hexdigest()!=sizing['bytecodeSha256']:
        raise ValueError('Frozen circuit differs from sizing evidence')
    saved=work/'boundary-fixtures.json'
    if not saved.exists():
        binary=cases.ROOT/'build/research/noir-compact-native-target/release/examples/bucket_boundaries'
        out=subprocess.run([str(binary),str(limits['SCALARS'])],capture_output=True,timeout=20)
        if out.returncode:raise RuntimeError(out.stderr.decode()[-1000:])
        cases.write(saved,json.loads(out.stdout))
    reports=[]
    for fixture in json.loads(saved.read_text()):
        values=cases.inputs(fixture['private'],fixture['capsule'],limits)
        report=checks.execute(work,'Boundary'+fixture['name'],values,fixture['accepted'])
        report.update(completeHistory=True,softwareKeysOnly=True,policySatisfied=fixture['capsule']['journal']['policy_satisfied'])
        reports.append(report);print(json.dumps(report),flush=True)
    if hashlib.sha256(artifact.read_bytes()).hexdigest()!=artifact_hash:raise ValueError('Circuit changed during checks')
    cases.write(work/'boundary-results.json',dict(artifactSha256=artifact_hash,fixtureSha256=hashlib.sha256(saved.read_bytes()).hexdigest(),
        proofGenerated=False,verificationKeyCreated=False,ownerIdentityUsed=False,cases=reports))

if __name__=='__main__':main()
