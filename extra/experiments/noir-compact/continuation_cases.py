#!/usr/bin/env python3
"""Bounded replay-continuation research. Not a complete Huma session proof."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks
import public_text_cases as optimized

OFFLINE=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network-outbound)']

def circuit(capacity,operations):
    original=optimized.circuit(public_text=False,algebraic=True)
    helper=original[original.index('// SCALARS<=65535:'):original.index('fn utf8_scalar')]
    loop=original[original.index('    for i in 0..OPS {'):original.index('    assert((phase==1)&(baseline_end>0));')]
    before='        phases[i+1]=phase;times[i+1]=elapsed;edit_counts[i+1]=edits;sample_counts[i+1]=samples;\n'
    if loop.count(before)!=1 or loop.count('baseline_end=if baseline_done {i+1}')!=1:
        raise ValueError('Review changed replay loop before adding continuation state')
    loop=loop.replace(before,'').replace('baseline_end=if baseline_done {i+1}','baseline_end=if baseline_done {state.offset+i+1}')
    metadata=['s.left','s.right','s.cursor','s.total','s.target','s.remaining','s.phase','s.elapsed','s.edits','s.samples',
        's.typing','s.paste','s.source','s.initial_bytes','s.baseline_end','s.offset']
    root_meta=['0x48554d410601','nonce[0]','nonce[1]','salt[0]','salt[1]','SCALARS as Field']
    root_meta += [x+' as Field' for x in metadata]+['s.head']+[f's.tail[{i}] as Field' for i in range(12)]
    assert len(root_meta)==35
    source=f'''mod commit;
global SCALARS:u32={capacity};
global OPS:u32={operations};
struct Op {{code:u8,arg:u64}}
struct State {{
    buffer:[u32;SCALARS],left:u32,right:u32,cursor:u32,total:u32,target:u32,remaining:u32,
    phase:u8,elapsed:u64,edits:u32,samples:u32,typing:u32,paste:u32,source:u8,
    initial_bytes:u32,baseline_end:u32,offset:u32,head:Field,tail:[u64;12],
}}
struct Boundary {{nonce:[Field;2],start_root:Field,end_root:Field,start_offset:u32,end_offset:u32,capture_root:Field,final_step:bool}}
{helper}
fn state_root(s:State,nonce:[Field;2],salt:[Field;2])->Field {{
    let metadata=[{','.join(root_meta)}];
    let mut fields=[0;35+(SCALARS+11)/12];
    for i in 0..35 {{fields[i]=metadata[i];}}
    for i in 0..SCALARS {{
        (s.buffer[i] as Field).assert_max_bit_size::<21>();
        let mut scale:Field=1;for _ in 0..i%12 {{scale*=2097152;}}
        fields[35+i/12]+=(s.buffer[i] as Field)*scale;
    }}
    for i in 0..12 {{(s.tail[i] as Field).assert_max_bit_size::<62>();}}
    commit::hash(fields)
}}
fn shape(s:State) {{
    for value in [s.left,s.right] {{(value as Field).assert_max_bit_size::<16>();}}
    for value in [s.cursor,s.total,s.target,s.remaining] {{(value as Field).assert_max_bit_size::<17>();assert(value<=2*SCALARS);}}
    for value in [s.edits,s.samples,s.typing,s.paste,s.initial_bytes,s.baseline_end,s.offset] {{(value as Field).assert_max_bit_size::<32>();}}
    (s.elapsed as Field).assert_max_bit_size::<64>();
    (s.phase as Field).assert_max_bit_size::<8>();(s.source as Field).assert_max_bit_size::<8>();
    assert((s.left<=s.right)&(s.right<=SCALARS)&(s.cursor<=s.total)&(s.target<=s.total));
    assert((s.phase<=4)&(s.offset<=65536)&(s.baseline_end<=s.offset));
    assert((s.phase==0)==(s.baseline_end==0));
    assert((s.edits+s.samples<=s.offset)&(s.typing+s.paste<=s.edits)&(s.initial_bytes<=4*SCALARS));
    assert((s.source<=6)|(s.source==255));
    for i in 0..12 {{if i>=s.offset%12 {{assert(s.tail[i]==0);}}}}
}}
fn main(salt:[Field;2],state:State,ops:[Op;OPS],op_count:u32,expected:pub Boundary) {{
    for i in 0..2 {{salt[i].assert_max_bit_size::<128>();expected.nonce[i].assert_max_bit_size::<128>();}}
    assert((salt[0]!=0)|(salt[1]!=0));(op_count as Field).assert_max_bit_size::<32>();
    assert((op_count>0)&(op_count<=OPS)&(OPS%12==0));
    shape(state);assert(state.offset%12==0);
    if !expected.final_step {{assert(op_count==OPS);}}
    assert(expected.start_offset==state.offset);
    assert(expected.start_root==state_root(state,expected.nonce,salt));
    // GENESIS_BEGIN: no unproved time, counters, text or transcript prefix.
    if state.offset==0 {{
        assert((state.left==0)&(state.right==SCALARS)&(state.cursor==0)&(state.total==0));
        assert((state.target==0)&(state.remaining==0)&(state.phase==0)&(state.elapsed==0));
        assert((state.edits==0)&(state.samples==0)&(state.typing==0)&(state.paste==0)&(state.source==0));
        assert((state.initial_bytes==0)&(state.baseline_end==0));
        assert(state.head==commit::seed(expected.nonce,salt));
        for i in 0..SCALARS {{assert(state.buffer[i]==0);}}
    }}
    // GENESIS_END
    let mut buffer=state.buffer;let mut left=state.left;let mut right=state.right;
    let mut cursor=state.cursor;let mut total=state.total;let mut target=state.target;let mut remaining=state.remaining;
    let mut phase=state.phase;let mut elapsed:Field=state.elapsed as Field;
    let mut edits:Field=state.edits as Field;let mut samples:Field=state.samples as Field;
    let mut typing:Field=state.typing as Field;let mut paste:Field=state.paste as Field;
    let mut source=state.source;let mut initial_bytes:Field=state.initial_bytes as Field;let mut baseline_end=state.baseline_end;
    let mut words=[0;OPS];
{loop}
    elapsed.assert_max_bit_size::<64>();
    for count in [edits,samples,typing,paste,initial_bytes] {{count.assert_max_bit_size::<32>();}}
    let mut heads=[0;OPS/12+1];heads[0]=state.head;
    for block in 0..OPS/12 {{
        let mut packed=[0;3];
        for i in 0..12 {{let mut scale:Field=1;for _ in 0..i%4 {{scale*=4611686018427387904;}}packed[i/4]+=words[block*12+i]*scale;}}
        heads[block+1]=commit::block(heads[block],packed);
    }}
    let mut tail=[0u64;12];let mut packed=[0;3];
    let start=op_count/12*12;
    for i in 0..12 {{
        let index=start+i;let safe=if index<OPS {{index}}else{{0}};
        let word=if index<op_count {{words[safe]}}else{{0}};tail[i]=word as u64;
        let mut scale:Field=1;for _ in 0..i%4 {{scale*=4611686018427387904;}}packed[i/4]+=word*scale;
    }}
    let after=State {{buffer,left,right,cursor,total,target,remaining,phase,elapsed:elapsed as u64,
        edits:edits as u32,samples:samples as u32,typing:typing as u32,paste:paste as u32,source,
        initial_bytes:initial_bytes as u32,baseline_end,offset:state.offset+op_count,head:heads[op_count/12],tail}};
    shape(after);assert(expected.end_offset==after.offset);
    assert(expected.end_root==state_root(after,expected.nonce,salt));
    assert(expected.capture_root==commit::hash([0x48554d410303,after.head,after.offset as Field,packed[0],packed[1],packed[2]]));
    if expected.final_step {{assert((phase==1)&(baseline_end>0));}}
}}
'''
    return source

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True)
    parser.add_argument('--case',choices=['revision','typing10000','emoji10000','baseline10000'],required=True)
    args=parser.parse_args();os.umask(0o077)
    if not args.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    work=cases.ROOT/'build/research/noir-continuation'/args.name
    if work.exists():raise ValueError('Existing continuation experiments are immutable')
    work.mkdir(parents=True);(work/'src').mkdir()
    reference=cases.ROOT/'build/research/noir-compact-native-target/release/examples/continuation_cases'
    result=subprocess.run([str(reference),args.case],capture_output=True,timeout=60)
    if result.returncode:raise RuntimeError(result.stderr.decode()[-1500:])
    fixture=json.loads(result.stdout);cases.write(work/'reference.json',fixture)
    source=circuit(fixture['capacity'],fixture['chunkOperations'])
    (work/'src/main.nr').write_text(source);(work/'src/commit.nr').write_bytes((cases.HERE/'src/commit.nr').read_bytes())
    (work/'Nargo.toml').write_text('[package]\nname="huma_continuation_component"\ntype="bin"\nauthors=[]\n[dependencies]\n')
    first=fixture['selected'][0];values={k:v for k,v in first.items() if k!='index'}
    cases.write(work/'inputs.json',values);checks.toml(work/'Prover.toml',values)
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    solved,_=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'noir/nargo','execute'],work)
    _,raw=cases.budget.limited(['/usr/bin/nice','-n','10',*OFFLINE,cases.TOOLS/'bb/bb','gates',
        '-b',work/'target/huma_continuation_component.json','-t','noir-recursive'],work)
    report=dict(kind='huma-continuation-component-sizing-v1',case=args.case,capacity=fixture['capacity'],
        chunkOperations=fixture['chunkOperations'],scalarPack=fixture['scalarPack'],nativeChunks=fixture['chunks'],nativeOperations=fixture['totalOperations'],
        allNativeBoundariesMatchIndependentReplay=True,capturePrefixesMatchExistingProtocol=True,
        completeHumaSessionProof=False,allChunksZkProved=False,proofGenerated=False,appChanged=False,ownerIdentityUsed=False,
        compileAndWitness=solved,gates=json.loads(raw),sourceSha256=hashlib.sha256(source.encode()).hexdigest())
    cases.write(work/'results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
