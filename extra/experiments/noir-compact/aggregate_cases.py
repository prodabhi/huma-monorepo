#!/usr/bin/env python3
"""Research recursive verification of existing software proofs; no app changes."""
import argparse,base64,hashlib,json,os,subprocess,urllib.request
import assurance_cases as cases
import assurance_checks as checks

ROOT=cases.ROOT;TOOLS=cases.TOOLS
OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']
WRAPPER_URL='https://raw.githubusercontent.com/AztecProtocol/aztec-packages/v5.2.1/barretenberg/noir/bb_proof_verification/src/lib.nr'
WRAPPER_SHA256='258cd5979844a2627688e6efcad07637b1e90624b3af77e0dc3e6ff45a9aa84c'

def fields(raw):
    if len(raw)%32:raise ValueError('Non-field-aligned artifact')
    result=[int.from_bytes(raw[i:i+32],'big') for i in range(0,len(raw),32)]
    if any(x>=21888242871839275222246405745257275088548364400416034343698204186575808495617 for x in result):
        raise ValueError('Noncanonical field artifact')
    return [str(x) for x in result]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',required=True);parser.add_argument('--children',type=int,choices=[1,2],default=1)
    args=parser.parse_args();os.umask(0o077)
    if not args.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    work=ROOT/'build/research/noir-aggregation'/args.name
    if work.exists():raise ValueError('Use a new experiment directory')
    if subprocess.check_output([str(TOOLS/'bb/bb'),'--version'],text=True).strip()!='5.2.1':raise ValueError('Unexpected backend version')
    if '1.0.0-beta.25' not in subprocess.check_output([str(TOOLS/'noir/nargo'),'--version'],text=True):raise ValueError('Unexpected compiler version')
    key=ROOT/'extra/experiments/noir-compact/browser/assets/assurance64.vk';raw_key=key.read_bytes()
    if hashlib.sha256(raw_key).hexdigest()!='bf1319ff4d1bc49029fa4875a9c5f529a5d17ec85bae5547ace311bbbbc3d3df':
        raise ValueError('Unrecognized inner verifier key')
    vk=fields(raw_key)
    if len(vk)!=115:raise ValueError('Wrong key shape')
    # Fetch only pinned public source during preparation; crypto children are offline.
    wrapper=ROOT/'build/research/noir-recursion-sources-v1/bb-lib.nr'
    if not wrapper.exists():
        with urllib.request.urlopen(WRAPPER_URL,timeout=20) as response:body=response.read(32769)
        if hashlib.sha256(body).hexdigest()!=WRAPPER_SHA256:raise ValueError('Official wrapper checksum differs')
        wrapper.parent.mkdir(parents=True,exist_ok=True);wrapper.write_bytes(body)
    body=wrapper.read_bytes()
    if hashlib.sha256(body).hexdigest()!=WRAPPER_SHA256:
        raise ValueError('Review changed backend wrapper')
    (work/'src').mkdir(parents=True)
    (work/'src/bb.nr').write_bytes(body)
    (work/'src/commit.nr').write_bytes((cases.HERE/'src/commit.nr').read_bytes())
    source='mod bb;\nmod commit;\nfn main(proofs:[[Field;458];'+str(args.children)+'],expected:pub [[Field;94];'+str(args.children)+']) {\n'
    source+='    let vk:[Field;115]=['+','.join(vk)+'];\n    let key_hash=commit::hash(vk);\n'
    source+='    for i in 0..'+str(args.children)+' {bb::verify_honk_proof(vk,proofs[i],expected[i],key_hash);}\n}\n'
    (work/'src/main.nr').write_text(source)
    (work/'Nargo.toml').write_text('[package]\nname="huma_recursive_component"\ntype="bin"\nauthors=[]\n[dependencies]\n')
    inputs={'proofs':[],'expected':[]}
    for name in ['Assurance64','Assurance64Unicode'][:args.children]:
        fixture=json.loads((cases.HERE/'browser/test/fixtures'/(name+'.json')).read_text())
        if fixture['profile']!='assurance64-v1':raise ValueError('Wrong fixture profile')
        proof=fields(base64.b64decode(fixture['proof']));public=fields(base64.b64decode(fixture['publicInputs']))
        if len(proof)!=458 or len(public)!=94:raise ValueError('Wrong recursive proof shape')
        inputs['proofs'].append(proof);inputs['expected'].append(public)
    cases.write(work/'inputs.json',inputs);checks.toml(work/'Prover.toml',inputs)
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    witness,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,TOOLS/'noir/nargo','execute'],work)
    gate_time,raw_gates=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,TOOLS/'bb/bb','gates',
        '-b',work/'target/huma_recursive_component.json','-t','noir-recursive'],work)
    report=dict(kind='huma-recursive-component-sizing-v1',softwareFixturesOnly=True,ownerIdentityUsed=False,
        children=args.children,innerVerifierKeyPinned=True,innerZeroKnowledge=True,outerZeroKnowledge=True,
        proofGenerated=False,witnessExecutionIsNotCryptographicVerification=True,
        completeHumaSessionProof=False,tenThousandCharactersSupported=False,
        witness=witness,gates=json.loads(raw_gates),gateTiming=gate_time,
        wrapperSource=WRAPPER_URL,wrapperSha256=hashlib.sha256(body).hexdigest(),
        sourceSha256=hashlib.sha256(source.encode()).hexdigest())
    cases.write(work/'results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
