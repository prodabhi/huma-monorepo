#!/usr/bin/env python3
"""Terminal-state to raw/canonical Unicode text linkage. Research only."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks
import interaction_cases as interaction
from continuation_cases import OFFLINE

MASTER_CASES=['master-'+name for name in ['trailing','gap','nfc','nfd','newline','crlf','nbsp','nul','bom','maxscalar','empty','spaces']]

def circuit(capacity,operations):
    source=interaction.circuit(capacity,operations)
    if source.count('fn main(')!=1:raise ValueError('Review changed interaction source')
    source=source[:source.index('fn main(')]
    return source+'''
struct Final {
    nonce:[Field;2],state_root:Field,capture_root:Field,origin_root:Field,op_count:u32,
    raw_scalars:u32,canonical_scalars:u32,raw_bytes:u32,canonical_bytes:u32,
    raw_commitment:Field,canonical_commitment:Field,rules:[bool;9],policy_satisfied:bool,
    origin_present:u32,origin_hid:u32,
}
fn main(salt:[Field;2],state:State,expected:pub Final) {
    for i in 0..2 {salt[i].assert_max_bit_size::<128>();expected.nonce[i].assert_max_bit_size::<128>();}
    assert((salt[0]!=0)|(salt[1]!=0));shape(state);
    assert((state.phase==1)&(state.baseline_end>0)&(state.offset>0)&(state.remaining==0));
    assert(expected.state_root==state_root(state,expected.nonce,salt));
    assert(expected.op_count==state.offset);
    let mut capture=[0;3];
    for i in 0..12 {let mut scale:Field=1;for _ in 0..i%4 {scale*=4611686018427387904;}capture[i/4]+=(state.tail[i] as Field)*scale;}
    assert(expected.capture_root==commit::hash([0x48554d410303,state.head,state.offset as Field,capture[0],capture[1],capture[2]]));
    assert(expected.origin_root==origin_prefix(state.interaction,state.samples));
    assert((expected.origin_present==state.interaction.origin_present)&(expected.origin_hid==state.interaction.origin_hid));
    let rules=assurance::behavior_rules(state.interaction.behavior,state.initial_bytes as Field,state.edits as Field,state.typing as Field,state.elapsed);
    let mut satisfied=true;for i in 0..9 {assert(expected.rules[i]==rules[i]);satisfied&=rules[i];}
    assert(expected.policy_satisfied==satisfied);
    let used=state.left+SCALARS-state.right;let mut logical=[0u32;SCALARS];
    let mut raw_bytes:u32=0;let mut canonical_bytes:u32=0;let mut canonical_scalars:u32=0;
    let mut utf16_total:u32=0;let mut utf16_cursor:u32=0;
    for i in 0..SCALARS {
        let active=i<used;let after_left=(if i>=state.left {i}else{state.left})-state.left;
        let candidate=if i<state.left {i}else{state.right+after_left};
        let index=if active {candidate}else{0};let value=if active {state.buffer[index]}else{0};
        assert((value<=0x10ffff)&!((value>=0xd800)&(value<=0xdfff)));logical[i]=value;
        let bytes=if value<128 {1}else if value<2048 {2}else if value<65536 {3}else{4};
        raw_bytes+=if active {bytes}else{0};
        utf16_total+=if active {width(value)}else{0};
        utf16_cursor+=if i<state.left {width(value)}else{0};
        if active&(value!=32)&(value!=9) {canonical_scalars=i+1;canonical_bytes=raw_bytes;}
    }
    assert((utf16_total==state.total)&(utf16_cursor==state.cursor));
    assert(canonical_scalars>0);
    assert((expected.raw_scalars==used)&(expected.canonical_scalars==canonical_scalars));
    assert((expected.raw_bytes==raw_bytes)&(expected.canonical_bytes==canonical_bytes));
    let mut raw=[0;5+(SCALARS+11)/12];let mut canonical=[0;5+(SCALARS+11)/12];
    raw[0]=0x48554d410604;raw[1]=SCALARS as Field;raw[2]=0;raw[3]=used as Field;raw[4]=raw_bytes as Field;
    canonical[0]=raw[0];canonical[1]=raw[1];canonical[2]=1;canonical[3]=canonical_scalars as Field;canonical[4]=canonical_bytes as Field;
    for i in 0..SCALARS {
        let mut scale:Field=1;for _ in 0..i%12 {scale*=2097152;}
        raw[5+i/12]+=(logical[i] as Field)*scale;
        canonical[5+i/12]+=(if i<canonical_scalars {logical[i] as Field}else{0})*scale;
    }
    // TEXT_BINDING_BEGIN: the reader must check these against the same UTF-8 master.
    assert(expected.raw_commitment==commit::hash(raw));
    assert(expected.canonical_commitment==commit::hash(canonical));
    // TEXT_BINDING_END
}
'''

def native(name):
    exe=cases.ROOT/'build/research/noir-compact-native-target/release/examples/interaction_cases'
    result=subprocess.run([str(exe),name,'--terminal'],capture_output=True,timeout=60)
    if result.returncode:raise RuntimeError(result.stderr.decode()[-1500:])
    return json.loads(result.stdout)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True)
    p.add_argument('--case',choices=['revision','rollover','typing10000','emoji10000','baseline10000',*MASTER_CASES],required=True)
    a=p.parse_args();os.umask(0o077)
    if not a.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    work=cases.ROOT/'build/research/noir-finalization'/a.name
    if work.exists():raise ValueError('Existing experiments are immutable')
    (work/'src').mkdir(parents=True);fixture=native(a.case);cases.write(work/'reference.json',fixture)
    if not fixture['expectedAccepted']:raise ValueError('Empty canonical text is a negative witness, never a proof candidate')
    source=circuit(fixture['capacity'],fixture['chunkOperations']);(work/'src/main.nr').write_text(source)
    for n in ['commit.nr','assurance.nr']:(work/'src'/n).write_bytes((cases.HERE/'src'/n).read_bytes())
    (work/'Nargo.toml').write_text('[package]\nname="huma_text_finalization"\ntype="bin"\nauthors=[]\n[dependencies]\n')
    checks.toml(work/'Prover.toml',fixture['inputs']);cases.write(work/'inputs.json',fixture['inputs'])
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    solved,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute'],work)
    _,raw=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'bb/bb','gates',
        '-b',work/'target/huma_text_finalization.json','-t','noir-recursive'],work)
    report=dict(kind='huma-text-finalization-sizing-v1',case=a.case,capacity=fixture['capacity'],
        compileAndWitness=solved,gates=json.loads(raw),sourceSha256=hashlib.sha256(source.encode()).hexdigest(),
        dependencySha256={n:hashlib.sha256((work/'src'/n).read_bytes()).hexdigest() for n in ['commit.nr','assurance.nr']},
        expected=fixture['inputs']['expected'],completeHumaSessionProof=False,proofGenerated=False,
        appChanged=False,ownerIdentityUsed=False)
    cases.write(work/'results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
