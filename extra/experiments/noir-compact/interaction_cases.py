#!/usr/bin/env python3
"""Combined replay/behavior/origin continuation research; no session admission."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
import assurance_cases as cases
import assurance_checks as checks
import continuation_cases as replay

FIXTURES=['revision','typing10000','emoji10000','baseline10000','rollover','repeat','unpaired',
          'rate','dwell','missing-origin','u64max','paste-small','paste-large']

def circuit(capacity,operations):
    source=replay.circuit(capacity,operations)
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('Review changed replay source before adding interaction state')
        source=source.replace(old,new)
    once('mod commit;','mod commit;\nmod assurance;\nuse assurance::{Behavior,Origin};\n'
        'struct Interaction {behavior:Behavior,origin_head:Field,origin_tail:[Field;6],origin_present:u32,origin_hid:u32}')
    once('offset:u32,head:Field,tail:[u64;12],','offset:u32,head:Field,tail:[u64;12],interaction:Interaction,')
    once('capture_root:Field,final_step:bool}',
         'capture_root:Field,final_step:bool,origin_root:Field,rules:[bool;9],policy_satisfied:bool,origin_present:u32,origin_hid:u32}')
    once('fn state_root(s:State,nonce:[Field;2],salt:[Field;2])->Field',
         'fn replay_root(s:State,nonce:[Field;2],salt:[Field;2])->Field')
    metadata=['0x48554d410603','nonce[0]','nonce[1]','salt[0]','salt[1]','s.origin_head']
    metadata += [f's.origin_tail[{i}]' for i in range(6)]
    metadata += ['s.origin_present as Field','s.origin_hid as Field']
    metadata += ['s.behavior.'+k for k in ['downs','pairs','good_dwells','good_intervals','anomalies']]
    metadata += ['s.behavior.previous_down as Field','s.behavior.pause as Field','s.behavior.rate_ok as Field']
    assert len(metadata)==22
    helpers='''
fn interaction_root(s:Interaction,nonce:[Field;2],salt:[Field;2])->Field {
    let metadata=[METADATA];let mut fields=[0;157];
    for i in 0..22 {fields[i]=metadata[i];}
    for i in 0..256 {
        s.behavior.held[i].assert_max_bit_size::<65>();
        fields[22+i/2]+=s.behavior.held[i]*if i%2==0 {1}else{36893488147419103232};
    }
    for i in 0..20 {
        (s.behavior.rate_ring[i] as Field).assert_max_bit_size::<64>();
        let mut scale:Field=1;for _ in 0..i%3 {scale*=18446744073709551616;}
        fields[150+i/3]+=(s.behavior.rate_ring[i] as Field)*scale;
    }
    commit::hash(fields)
}
fn state_root(s:State,nonce:[Field;2],salt:[Field;2])->Field {
    commit::hash([0x48554d410602,replay_root(s,nonce,salt),interaction_root(s.interaction,nonce,salt)])
}
fn interaction_shape(s:Interaction,elapsed:u64,samples:u32) {
    let b=s.behavior;
    for value in [b.downs,b.pairs,b.good_dwells,b.good_intervals,b.anomalies] {
        value.assert_max_bit_size::<32>();assert((value as u32)<=samples);
    }
    assert((b.good_dwells as u32)<=b.pairs as u32);assert((b.good_intervals as u32)<=b.downs as u32);
    assert(b.previous_down<=elapsed);
    for i in 0..256 {b.held[i].assert_max_bit_size::<65>();assert((b.held[i] as u128)<=elapsed as u128+1);}
    for i in 0..20 {assert(b.rate_ring[i]<=elapsed);if i>=b.downs as u32 {assert(b.rate_ring[i]==0);}}
    for i in 0..6 {s.origin_tail[i].assert_max_bit_size::<98>();if i>=samples%6 {assert(s.origin_tail[i]==0);}}
    assert((s.origin_hid<=s.origin_present)&(s.origin_present<=samples));
}
fn finish_origins(mut s:Interaction,values:[Field;OPS+6],count:u32)->Interaction {
    assert(count<=OPS+5);let mut heads=[0;OPS/6+2];heads[0]=s.origin_head;
    for block in 0..OPS/6+1 {
        let mut p=[0;3];for i in 0..6 {p[i/2]+=values[block*6+i]*if i%2==0 {1}else{316912650057057350374175801344};}
        heads[block+1]=commit::hash([0x48554d410402,heads[block],p[0],p[1],p[2]]);
    }
    s.origin_head=heads[count/6];let start=count/6*6;
    for i in 0..6 {let index=start+i;s.origin_tail[i]=if index<count {values[index]}else{0};}s
}
fn origin_prefix(s:Interaction,count:u32)->Field {
    let mut p=[0;3];for i in 0..6 {p[i/2]+=s.origin_tail[i]*if i%2==0 {1}else{316912650057057350374175801344};}
    commit::hash([0x48554d410403,s.origin_head,count as Field,p[0],p[1],p[2]])
}
'''.replace('METADATA',','.join(metadata))
    once('fn shape(s:State) {',helpers+'\nfn shape(s:State) {\n    interaction_shape(s.interaction,s.elapsed,s.samples);')
    once('ops:[Op;OPS],op_count:u32,expected:pub Boundary)',
         'ops:[Op;OPS],origins:[Origin;OPS],op_count:u32,expected:pub Boundary)')
    genesis='''        // INTERACTION_GENESIS_BEGIN
        let b=state.interaction.behavior;
        for value in [b.downs,b.pairs,b.good_dwells,b.good_intervals,b.anomalies] {assert(value==0);}
        assert((b.previous_down==0)&!b.pause&b.rate_ok);
        for i in 0..256 {assert(b.held[i]==0);}for i in 0..20 {assert(b.rate_ring[i]==0);}
        assert((state.interaction.origin_present==0)&(state.interaction.origin_hid==0));
        assert(state.interaction.origin_head==commit::hash([0x48554d410401,expected.nonce[0],expected.nonce[1],salt[0],salt[1]]));
        // INTERACTION_GENESIS_END
'''
    once('        for i in 0..SCALARS {assert(state.buffer[i]==0);}',
         '        for i in 0..SCALARS {assert(state.buffer[i]==0);}\n'+genesis)
    once('    let mut words=[0;OPS];','''    let mut words=[0;OPS];let mut interaction=state.interaction;
    let mut origin_values=[0;OPS+6];for i in 0..6 {origin_values[i]=interaction.origin_tail[i];}
    let mut local_samples:u32=0;''')
    update='''        // One origin per real key sample, attached to this operation's time.
        let origin=origins[i];
        for value in [origin.pid,origin.state,origin.keyboard] {(value as Field).assert_max_bit_size::<32>();}
        assert(sample | (!origin.present&(origin.pid==0)&(origin.state==0)&(origin.keyboard==0)&!origin.repeated));
        let origin_value=assurance::origin_value(origin);
        let origin_index=state.samples%6+local_samples;
        origin_values[origin_index]=if sample {origin_value}else{origin_values[origin_index]};
        local_samples+=sample as u32;
        interaction.origin_present+=(sample&origin.present) as u32;
        interaction.origin_hid+=(sample&origin.present&(origin.state==1)) as u32;
        elapsed.assert_max_bit_size::<64>();
        interaction.behavior=assurance::behavior_step(interaction.behavior,code,if sample {(arg&65535) as u16}else{0},elapsed as u64,origin);
'''
    once('        samples+=sample as Field;edits+=end as Field;',update+'        samples+=sample as Field;edits+=end as Field;')
    once('    let after=State {','    interaction=finish_origins(interaction,origin_values,state.samples%6+local_samples);\n    let after=State {')
    once('head:heads[op_count/12],tail};','head:heads[op_count/12],tail,interaction};')
    once('    if expected.final_step {assert((phase==1)&(baseline_end>0));}',
'''    assert(expected.origin_root==origin_prefix(interaction,after.samples));
    assert((expected.origin_present==interaction.origin_present)&(expected.origin_hid==interaction.origin_hid));
    let rules=assurance::behavior_rules(interaction.behavior,initial_bytes,edits,typing,after.elapsed);
    let mut satisfied=true;
    for i in 0..9 {
        assert(expected.rules[i]==(expected.final_step & rules[i]));satisfied&=rules[i];
    }
    assert(expected.policy_satisfied==(expected.final_step & satisfied));
    if expected.final_step {assert((phase==1)&(baseline_end>0));}''')
    return source

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True)
    parser.add_argument('--case',choices=FIXTURES,required=True);args=parser.parse_args();os.umask(0o077)
    if not args.name.replace('-','').isalnum():raise ValueError('Use a local experiment name')
    work=cases.ROOT/'build/research/noir-interaction'/args.name
    if work.exists():raise ValueError('Existing experiments are immutable')
    (work/'src').mkdir(parents=True)
    native=cases.ROOT/'build/research/noir-compact-native-target/release/examples/interaction_cases'
    result=subprocess.run([str(native),args.case],capture_output=True,timeout=60)
    if result.returncode:raise RuntimeError(result.stderr.decode()[-1500:])
    fixture=json.loads(result.stdout);cases.write(work/'reference.json',fixture)
    source=circuit(fixture['capacity'],fixture['chunkOperations']);(work/'src/main.nr').write_text(source)
    for name in ['commit.nr','assurance.nr']:(work/'src'/name).write_bytes((cases.HERE/'src'/name).read_bytes())
    (work/'Nargo.toml').write_text('[package]\nname="huma_continuation_component"\ntype="bin"\nauthors=[]\n[dependencies]\n')
    values={k:v for k,v in fixture['selected'][0].items() if k!='index'}
    checks.toml(work/'Prover.toml',values);cases.write(work/'inputs.json',values)
    cases.budget.ENV.update(RAYON_NUM_THREADS='2',HARDWARE_CONCURRENCY='2')
    solved,_=cases.budget.limited(['/usr/bin/nice','-n','10',*replay.OFFLINE,cases.TOOLS/'noir/nargo','execute'],work)
    _,raw=cases.budget.limited(['/usr/bin/nice','-n','10',*replay.OFFLINE,cases.TOOLS/'bb/bb','gates',
        '-b',work/'target/huma_continuation_component.json','-t','noir-recursive'],work)
    report=dict(kind='huma-interaction-continuation-sizing-v1',case=args.case,capacity=fixture['capacity'],
        chunkOperations=fixture['chunkOperations'],nativeChunks=fixture['chunks'],nativeOperations=fixture['totalOperations'],
        scalarPack=12,compileAndWitness=solved,gates=json.loads(raw),
        sourceSha256=hashlib.sha256(source.encode()).hexdigest(),
        dependencySha256={n:hashlib.sha256((work/'src'/n).read_bytes()).hexdigest() for n in ['commit.nr','assurance.nr']},
        completeHumaSessionProof=False,allChunksZkProved=False,proofGenerated=False,appChanged=False,ownerIdentityUsed=False)
    cases.write(work/'results.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':main()
