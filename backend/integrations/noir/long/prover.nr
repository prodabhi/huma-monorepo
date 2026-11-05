// assurance-long-v2 prover: chunk steps folded into one chain proof, and a final step over the same carried State.
// Every signed event's P-256 signature is checked in-circuit. Built by prover.mjs into start, fold and final programs; native mirror: experiments/noir-compact/native/src/long.rs.
use crate::commit;
use crate::assurance::{self,Behavior,Origin};

pub global SCALARS:u32=10000;
pub global OPS:u32=528;
pub global SLOTS:u32=8;
// Signed events the final step may apply; the planner moves any earlier ones into a part with no operations.
pub global TAIL:u32=4;
pub global PRES:u32=64;
// Final-step text capacity; prover.mjs builds one final program per tier (1024, 4096, 10000).
pub global TEXT:u32=10000;
pub struct Op {code:u8,arg:u64}
pub struct Interaction {behavior:Behavior,origin_head:Field,origin_tail:[Field;6],origin_present:u32,origin_hid:u32}
// Signed checkpoint/presence history carried between chunks.
pub struct Events {
    checkpoints:u32,checkpoint_root:Field,presence:u32,presence_head:Field,approved:u32,on_time:u32,
    last_approval:u64,longest:u64,latencies:[u64;PRES],nonces:[Field;PRES],
    last_reason:u8,last_outcome:u8,last_latency:u64,last_offset:u32,clock:u64,floor:u64,
    start_unix:u64,prior_unix:u64,rollback:bool,prior_offset:u32,sealed:bool,end_elapsed:u64,
    text:[Field;2],digest:Field,
}
pub struct State {
    buffer:[u32;SCALARS],left:u32,right:u32,cursor:u32,total:u32,target:u32,remaining:u32,
    phase:u8,elapsed:u64,edits:u32,samples:u32,typing:u32,paste:u32,source:u8,
    initial_bytes:u32,baseline_end:u32,offset:u32,head:Field,tail:[u64;12],interaction:Interaction,events:Events,
}
// SCALARS<=65535: gap indices fit 16 bits; UTF-16 counts fit 17.
// These checks also reject field underflow before conversion.
fn bounded16(v:Field)->u32 {v.assert_max_bit_size::<16>();v as u32}
fn bounded17(v:Field)->u32 {v.assert_max_bit_size::<17>();v as u32}
fn gated17(active:bool,v:Field) {(if active {v}else{0}).assert_max_bit_size::<17>();}
fn width(scalar:u32)->u32 {if scalar>=65536 {2}else{1}}

fn replay_root(s:State,nonce:[Field;2],salt:[Field;2])->Field {
    let metadata=[0x48554d410601,nonce[0],nonce[1],salt[0],salt[1],SCALARS as Field,s.left as Field,s.right as Field,s.cursor as Field,s.total as Field,s.target as Field,s.remaining as Field,s.phase as Field,s.elapsed as Field,s.edits as Field,s.samples as Field,s.typing as Field,s.paste as Field,s.source as Field,s.initial_bytes as Field,s.baseline_end as Field,s.offset as Field,s.head,s.tail[0] as Field,s.tail[1] as Field,s.tail[2] as Field,s.tail[3] as Field,s.tail[4] as Field,s.tail[5] as Field,s.tail[6] as Field,s.tail[7] as Field,s.tail[8] as Field,s.tail[9] as Field,s.tail[10] as Field,s.tail[11] as Field];
    let mut fields=[0;35+(SCALARS+11)/12];
    for i in 0..35 {fields[i]=metadata[i];}
    for i in 0..SCALARS {
        (s.buffer[i] as Field).assert_max_bit_size::<21>();
        let mut scale:Field=1;for _ in 0..i%12 {scale*=2097152;}
        fields[35+i/12]+=(s.buffer[i] as Field)*scale;
    }
    for i in 0..12 {(s.tail[i] as Field).assert_max_bit_size::<62>();}
    commit::hash(fields)
}

fn interaction_root(s:Interaction,nonce:[Field;2],salt:[Field;2])->Field {
    let metadata=[0x48554d410603,nonce[0],nonce[1],salt[0],salt[1],s.origin_head,s.origin_tail[0],s.origin_tail[1],s.origin_tail[2],s.origin_tail[3],s.origin_tail[4],s.origin_tail[5],s.origin_present as Field,s.origin_hid as Field,s.behavior.downs,s.behavior.pairs,s.behavior.good_dwells,s.behavior.good_intervals,s.behavior.anomalies,s.behavior.previous_down as Field,s.behavior.pause as Field,s.behavior.rate_ok as Field];let mut fields=[0;157];
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
fn events_root(e:Events,nonce:[Field;2],salt:[Field;2])->Field {
    let metadata=[0x48554d410704,nonce[0],nonce[1],salt[0],salt[1],e.checkpoints as Field,e.checkpoint_root,
        e.presence as Field,e.presence_head,e.approved as Field,e.on_time as Field,e.last_approval as Field,e.longest as Field,
        e.last_reason as Field,e.last_outcome as Field,e.last_latency as Field,e.last_offset as Field,e.clock as Field,e.floor as Field,
        e.start_unix as Field,e.prior_unix as Field,e.rollback as Field,e.prior_offset as Field,e.sealed as Field,e.end_elapsed as Field,
        e.text[0],e.text[1],e.digest];
    let mut fields=[0;28+(PRES+2)/3+PRES];
    for i in 0..28 {fields[i]=metadata[i];}
    for i in 0..PRES {
        let mut scale:Field=1;for _ in 0..i%3 {scale*=18446744073709551616;}
        fields[28+i/3]+=(e.latencies[i] as Field)*scale;
        fields[28+(PRES+2)/3+i]=e.nonces[i];
    }
    commit::hash(fields)
}
fn state_root(s:State,nonce:[Field;2],salt:[Field;2])->Field {
    commit::hash([0x48554d410702,replay_root(s,nonce,salt),interaction_root(s.interaction,nonce,salt),events_root(s.events,nonce,salt)])
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
fn events_shape(e:Events,offset:u32) {
    assert((e.presence<=PRES)&(e.approved<=e.presence)&(e.on_time<=e.approved));
    assert((e.last_reason<=2)&(e.last_outcome<=4)&(e.prior_offset<=offset)&(e.last_offset<=offset));
    for i in 0..PRES {
        if i>=e.approved {assert(e.latencies[i]==0);}
        if i>=e.presence {assert(e.nonces[i]==0);}
    }
}
fn shape(s:State) {
    interaction_shape(s.interaction,s.elapsed,s.samples);events_shape(s.events,s.offset);
    for value in [s.left,s.right] {(value as Field).assert_max_bit_size::<16>();}
    for value in [s.cursor,s.total,s.target,s.remaining] {(value as Field).assert_max_bit_size::<17>();assert(value<=2*SCALARS);}
    for value in [s.edits,s.samples,s.typing,s.paste,s.initial_bytes,s.baseline_end,s.offset] {(value as Field).assert_max_bit_size::<32>();}
    (s.elapsed as Field).assert_max_bit_size::<64>();
    (s.phase as Field).assert_max_bit_size::<8>();(s.source as Field).assert_max_bit_size::<8>();
    assert((s.left<=s.right)&(s.right<=SCALARS)&(s.cursor<=s.total)&(s.target<=s.total));
    assert((s.phase<=4)&(s.offset<=1048576)&(s.baseline_end<=s.offset));
    assert((s.phase==0)==(s.baseline_end==0));
    assert((s.edits+s.samples<=s.offset)&(s.typing+s.paste<=s.edits)&(s.initial_bytes<=4*SCALARS));
    assert((s.source<=6)|(s.source==255));
    for i in 0..12 {if i>=s.offset%12 {assert(s.tail[i]==0);}}
}
fn origin_prefix(s:Interaction,count:u32)->Field {
    let mut p=[0;3];for i in 0..6 {p[i/2]+=s.origin_tail[i]*if i%2==0 {1}else{316912650057057350374175801344};}
    commit::hash([0x48554d410403,s.origin_head,count as Field,p[0],p[1],p[2]])
}

// ---- Chunk step: up to OPS operations and SLOTS signed events. ----
pub struct Event {kind:u8,offset:u32,unix:u64,elapsed:u64,last:bool,nonce:[Field;2],reason:u8,issued:u64,answered:u64,outcome:u8}
pub struct Boundary {pub start_root:Field,pub end_root:Field,pub genesis:bool}
// Public inputs of every chain proof: the state reached from genesis, the fold key, and the capture key.
pub struct Link {pub end_root:Field,pub chain_key:Field,pub device:Field}
// Capture prefix at local extended count c (the chunk's first 12-word block includes the carried tail).
fn capture_at(ext:[Field;OPS+12],heads:[Field;(OPS+12)/12+1],c:u32,position:u32)->Field {
    let start=c/12*12;let mut packed=[0;3];
    for i in 0..12 {
        let index=start+i;let safe=if index<OPS+12 {index}else{0};
        let value=if index<c {ext[safe]}else{0};
        let mut scale:Field=1;for _ in 0..i%4 {scale*=4611686018427387904;}
        packed[i/4]+=value*scale;
    }
    commit::hash([0x48554d410303,heads[c/12],position as Field,packed[0],packed[1],packed[2]])
}
fn origin_at(values:[Field;OPS+6],heads:[Field;(OPS+6)/6+1],c:u32,count:Field)->Field {
    let start=c/6*6;let mut packed=[0;3];
    for i in 0..6 {
        let index=start+i;let safe=if index<OPS+6 {index}else{0};
        let value=if index<c {values[safe]}else{0};
        packed[i/2]+=value*if i%2==0 {1}else{316912650057057350374175801344};
    }
    commit::hash([0x48554d410403,heads[c/6],count,packed[0],packed[1],packed[2]])
}
// Offset of an event within the current step, 0..=count; inactive slots use 0.
fn local(e:Event,start:u32,count:u32)->u32 {
    let lf=((e.offset as Field)-(start as Field))*((e.kind!=0) as Field);lf.assert_max_bit_size::<16>();
    let l=lf as u32;assert(l<=count);l
}
// Applies up to SLOTS signed checkpoint/presence events at local offsets 0..=count. Per-offset
// values come from a chunk's replay, or from the terminal state in the final step (count 0).
// SHA-256 of the message the capture key signs: domain || root (32 bytes, big-endian), as WebCrypto and SecKey hash it.
fn signed_digest(checkpoint:bool,root:Field)->[u8;32] {
    let cp="HUMA_LONG_ASSURANCE_CHECKPOINT_V1".as_bytes();let pr="HUMA_LONG_ASSURANCE_PRESENCE_V1".as_bytes();
    let r:[u8;32]=root.to_be_bytes();
    // Two padded blocks: 34+32 bytes (528 bits) for checkpoints, 32+32 bytes (512 bits) for presence.
    let mut a=[0u8;128];let mut b=[0u8;128];
    for i in 0..33 {a[i]=cp[i];}for i in 0..31 {b[i]=pr[i];}
    for i in 0..32 {a[34+i]=r[i];b[32+i]=r[i];}
    a[66]=0x80;a[126]=0x02;a[127]=0x10;b[64]=0x80;b[126]=0x02;
    let mut words=[[0u32;16];2];
    for k in 0..32 {
        let mut w:u32=0;
        for j in 0..4 {let byte=if checkpoint {a[4*k+j]}else{b[4*k+j]};w=(w<<8)+(byte as u32);}
        words[k/16][k%16]=w;
    }
    let iv=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let state=std::hash::sha256_compression(words[1],std::hash::sha256_compression(words[0],iv));
    let mut digest=[0u8;32];
    for j in 0..8 {for k in 0..4 {digest[4*j+k]=(state[j]>>(24-8*(k as u32))) as u8;}}
    digest
}
/// Commitment to the capture public key (uncompressed x, y), carried by every chain proof and the final statement.
pub fn device_root(x:[u8;32],y:[u8;32])->Field {
    let mut h=[0;4];
    for i in 0..16 {h[0]=h[0]*256+x[i] as Field;h[1]=h[1]*256+x[16+i] as Field;h[2]=h[2]*256+y[i] as Field;h[3]=h[3]*256+y[16+i] as Field;}
    commit::hash([0x48554d410801,h[0],h[1],h[2],h[3]])
}
pub struct Device {pub x:[u8;32],pub y:[u8;32]}
fn apply_events<let N:u32,let V:u32>(mut ev:Events,events:[Event;SLOTS],text:[Field;2],nonce:[Field;2],start:u32,count:u32,baseline_end:u32,
        phases:[u8;N],times:[Field;N],edit_counts:[Field;N],sample_counts:[Field;N],next_times:[Field;N],has_next:[bool;N],
        prefixes:[Field;SLOTS],oprefixes:[Field;SLOTS],device:Device,signatures:[[u8;64];V])->Events {
    // A presence answer with no later input in its own chunk bounds this chunk's first input.
    assert(!has_next[0] | (next_times[0] as u64>=ev.floor));
    let mut floor=if has_next[0] {0}else{ev.floor};
    let mut previous_active=true;
    for j in 0..SLOTS {
        let e=events[j];let active=e.kind!=0;let is_cp=e.kind==1;let is_pr=e.kind==2;
        assert(e.kind<=2);assert(previous_active|!active);previous_active=active;
        assert(is_cp | ((e.unix==0)&(e.elapsed==0)&!e.last));
        assert(is_pr | ((e.nonce==[0,0])&(e.reason==0)&(e.issued==0)&(e.answered==0)&(e.outcome==0)));
        assert(active | (e.offset==0));
        let l=local(e,start,count);
        let t=times[l] as u64;let ed=edit_counts[l];let sa=sample_counts[l];
        assert(!active | ((e.offset>=ev.prior_offset)&!ev.sealed&(phases[l]==1)));
        let prefix=prefixes[j];let oprefix=oprefixes[j];
        // Checkpoint: V4 base and bound roots; the sealing checkpoint binds the text commitments.
        let first=ev.checkpoints==0;
        assert(!is_cp | ((e.unix<=253402300799999)&(e.elapsed>=ev.clock)&(e.elapsed>=t)));
        assert(!(is_cp&first) | ((e.offset==baseline_end)&(e.elapsed==0)&(ev.presence==0)));
        assert(!e.last | ((l==count)&(ev.checkpoints>=1)&(ev.presence>0)&(ev.last_reason==2)&(ev.last_outcome==1)
            &(ev.last_latency<=10000)&(ev.last_offset==e.offset)));
        let base=commit::hash([0x48554d410304,prefix,ev.checkpoints as Field,ed+sa,ed,sa,e.unix as Field,e.elapsed as Field,
            e.last as Field,ev.checkpoint_root,if e.last {text[0]}else{0},if e.last {text[1]}else{0}]);
        let bound=commit::hash([0x48554d410408,base,oprefix,ev.presence_head,ev.presence as Field]);
        // Presence: unique nonce, ordered times, and no input before the answer.
        for k in 0..2 {e.nonce[k].assert_max_bit_size::<128>();}
        let packed=e.nonce[0]+e.nonce[1]*340282366920938463463374607431768211456;
        let mut fresh=packed!=0;for k in 0..PRES {fresh&=ev.nonces[k]!=packed;}
        assert(!is_pr | (fresh&(ev.presence<PRES)&(e.issued>=ev.clock)&(e.answered>=e.issued)&((e.reason==1)|(e.reason==2))
            &(e.outcome>=1)&(e.outcome<=4)&(e.issued>=t)));
        assert(!is_pr | !has_next[l] | (e.answered<=next_times[l] as u64));
        let issue=commit::hash([0x48554d410405,nonce[0],nonce[1],ev.presence as Field,ev.presence_head,prefix,oprefix,ed,sa,
            e.nonce[0],e.nonce[1],e.reason as Field,e.issued as Field]);
        let response=commit::hash([0x48554d410406,issue,e.answered as Field,e.outcome as Field]);
        let approved=is_pr&(e.outcome==1);
        // Checkpoints and approved presence answers are signed by the capture key.
        let signed=is_cp|approved;
        if j<V {
            let valid=std::ecdsa_secp256r1::verify_signature(device.x,device.y,signatures[j],signed_digest(is_cp,if is_cp {bound}else{response}));
            assert(valid|!signed);
        } else {assert(!active);}
        let latency_f=(e.answered as Field-e.issued as Field)*(is_pr as Field);latency_f.assert_max_bit_size::<64>();
        let gap_f=(e.answered as Field-ev.last_approval as Field)*(approved as Field);gap_f.assert_max_bit_size::<64>();
        let latency=latency_f as u64;let gap=gap_f as u64;
        let signed_checkpoint=commit::hash([0x48554d410703,ev.digest,1,bound]);
        let signed_presence=commit::hash([0x48554d410703,ev.digest,2,response]);
        ev.digest=if is_cp {signed_checkpoint}else if approved {signed_presence}else{ev.digest};
        ev.rollback|=is_cp&!first&(e.unix<ev.prior_unix);
        ev.start_unix=if is_cp&first {e.unix}else{ev.start_unix};
        ev.checkpoint_root=if is_cp {base}else{ev.checkpoint_root};
        ev.prior_unix=if is_cp {e.unix}else{ev.prior_unix};
        ev.checkpoints+=is_cp as u32;
        ev.sealed|=e.last;ev.end_elapsed=if e.last {e.elapsed}else{ev.end_elapsed};
        ev.text=if e.last {text}else{ev.text};
        ev.presence_head=if is_pr {commit::hash([0x48554d410407,ev.presence_head,issue,response])}else{ev.presence_head};
        ev.on_time+=(approved&(latency<=10000)) as u32;
        ev.longest=if approved&(gap>ev.longest) {gap}else{ev.longest};
        ev.last_approval=if approved {e.answered}else{ev.last_approval};
        let slot=if approved {ev.approved}else{0};ev.latencies[slot]=if approved {latency}else{ev.latencies[slot]};
        ev.approved+=approved as u32;
        let index=if is_pr {ev.presence}else{0};ev.nonces[index]=if is_pr {packed}else{ev.nonces[index]};
        ev.last_reason=if is_pr {e.reason}else{ev.last_reason};ev.last_outcome=if is_pr {e.outcome}else{ev.last_outcome};
        ev.last_latency=if is_pr {latency}else{ev.last_latency};ev.last_offset=if is_pr {e.offset}else{ev.last_offset};
        ev.presence+=is_pr as u32;
        floor=if is_pr&!has_next[l]&(e.answered>floor) {e.answered}else{floor};
        ev.clock=if is_cp {e.elapsed}else if is_pr {e.answered}else{ev.clock};
        ev.prior_offset=if active {e.offset}else{ev.prior_offset};
    }
    ev.floor=floor;
    ev
}
pub fn chunk(nonce:[Field;2],salt:[Field;2],state:State,ops:[Op;OPS],origins:[Origin;OPS],op_count:u32,
        events:[Event;SLOTS],text:[Field;2],device:Device,signatures:[[u8;64];SLOTS],expected:Boundary) {
    let after=step(nonce,salt,state,ops,origins,op_count,events,text,device,signatures,expected);
    assert(expected.end_root==state_root(after,nonce,salt));
}
/// One part's transition from `state` (whose root is expected.start_root); returns the state it reaches.
/// The caller binds that state: a part proof to expected.end_root, the final step to its statement.
pub fn step(nonce:[Field;2],salt:[Field;2],state:State,ops:[Op;OPS],origins:[Origin;OPS],op_count:u32,
        events:[Event;SLOTS],text:[Field;2],device:Device,signatures:[[u8;64];SLOTS],expected:Boundary)->State {
    for i in 0..2 {salt[i].assert_max_bit_size::<128>();nonce[i].assert_max_bit_size::<128>();}
    assert((salt[0]!=0)|(salt[1]!=0));(op_count as Field).assert_max_bit_size::<32>();assert(op_count<=OPS);
    shape(state);assert(!state.events.sealed);
    assert(expected.genesis==(state.offset==0));
    assert(expected.start_root==state_root(state,nonce,salt));
    // Genesis: no unproved time, counters, text, transcript prefix, behavior or signed history.
    if state.offset==0 {
        assert((state.left==0)&(state.right==SCALARS)&(state.cursor==0)&(state.total==0));
        assert((state.target==0)&(state.remaining==0)&(state.phase==0)&(state.elapsed==0));
        assert((state.edits==0)&(state.samples==0)&(state.typing==0)&(state.paste==0)&(state.source==0));
        assert((state.initial_bytes==0)&(state.baseline_end==0));
        assert(state.head==commit::seed(nonce,salt));
        for i in 0..SCALARS {assert(state.buffer[i]==0);}
        let b=state.interaction.behavior;
        for value in [b.downs,b.pairs,b.good_dwells,b.good_intervals,b.anomalies] {assert(value==0);}
        assert((b.previous_down==0)&!b.pause&b.rate_ok);
        for i in 0..256 {assert(b.held[i]==0);}for i in 0..20 {assert(b.rate_ring[i]==0);}
        assert((state.interaction.origin_present==0)&(state.interaction.origin_hid==0));
        assert(state.interaction.origin_head==commit::hash([0x48554d410401,nonce[0],nonce[1],salt[0],salt[1]]));
        let e=state.events;
        assert((e.checkpoints==0)&(e.checkpoint_root==0)&(e.presence==0)&(e.approved==0)&(e.on_time==0));
        assert((e.last_approval==0)&(e.longest==0)&(e.last_reason==0)&(e.last_outcome==0)&(e.last_latency==0)&(e.last_offset==0));
        assert((e.clock==0)&(e.floor==0)&(e.start_unix==0)&(e.prior_unix==0)&!e.rollback&(e.prior_offset==0)&(e.end_elapsed==0));
        assert((e.text==[0,0])&(e.digest==0));
        assert(e.presence_head==commit::hash([0x48554d410404,nonce[0],nonce[1],salt[0],salt[1]]));
    }
    let mut buffer=state.buffer;let mut left=state.left;let mut right=state.right;
    let mut cursor=state.cursor;let mut total=state.total;let mut target=state.target;let mut remaining=state.remaining;
    let mut phase=state.phase;let mut elapsed:Field=state.elapsed as Field;
    let mut edits:Field=state.edits as Field;let mut samples:Field=state.samples as Field;
    let mut typing:Field=state.typing as Field;let mut paste:Field=state.paste as Field;
    let mut source=state.source;let mut initial_bytes:Field=state.initial_bytes as Field;let mut baseline_end=state.baseline_end;
    let mut words=[0;OPS];let mut interaction=state.interaction;
    let mut origin_values=[0;OPS+6];for i in 0..6 {origin_values[i]=interaction.origin_tail[i];}
    let mut local_samples:u32=0;
    // Values at each local offset 0..=op_count, for event checks after replay.
    let mut phases=[0u8;OPS+1];let mut times=[0;OPS+1];let mut edit_counts=[0;OPS+1];let mut sample_counts=[0;OPS+1];
    let mut inputs=[false;OPS];
    phases[0]=phase;times[0]=elapsed;edit_counts[0]=edits;sample_counts[0]=samples;
    for i in 0..OPS {
        let o=ops[i];let code=o.code;let arg=o.arg;
        assert(code<64);(arg as Field).assert_max_bit_size::<56>();
        words[i]=(code as Field)*72057594037927936+arg as Field;
        if i>=op_count {assert((code==0)&(arg==0));}else{assert((code>=1)&(code<=13));}
        // One bounded gap-buffer read/write per operation; no whole-array shift.
        let read_index=if code==6 {if left!=0 {left-1}else{0}}
            else if (code==7)|(code==8) {if right!=SCALARS {right}else{0}}else{0};
        let read=buffer[read_index];
        let write_index=if code==6 {if right!=0 {right-1}else{0}}
            else if (code==1)|(code==9)|(code==7) {if left!=SCALARS {left}else{0}}else{read_index};
        let scalar_op=(code==1)|(code==9);
        let scalar_field=if scalar_op {arg as Field}else{0};scalar_field.assert_max_bit_size::<21>();
        let scalar=scalar_field as u32;
        assert((scalar<=0x10ffff)&!((scalar>=0xd800)&(scalar<=0xdfff)));
        let write=if scalar_op {scalar}else{read};
        buffer[write_index]=write;
        let baseline=code==1;let baseline_done=code==2;
        let sample=(code==3)|(code==4);let begin=code==5;
        let move_l=code==6;let move_r=code==7;let deletion=code==8;
        let insertion=code==9;let end=code==10;let advance=code==11;
        let flags=(code==12)|(code==13);
        let location=(arg&65535) as u32;
        let removed=((arg>>16)&65535) as u32;
        let next_source=((arg>>32)&255) as u8;
        // phase is constructed from constants 0..4. Gap indices obey
        // left<=right<=SCALARS at entry and after every step.
        let p=phase as Field;let finishing=insertion|end;
        assert(((baseline|baseline_done) as Field)*p==0);
        assert(((sample|begin|advance|flags) as Field)*(p-1)==0);
        assert(((move_l|move_r) as Field)*(p-2)==0);
        assert((deletion as Field)*(p-2)*(p-3)==0);
        assert((finishing as Field)*(p-2)*(p-3)*(p-4)==0);
        assert(((baseline_done|move_l|move_r|deletion|end) as Field)*(arg as Field)==0);
        assert((deletion as Field)*(cursor as Field-target as Field)==0);
        assert((finishing as Field)*(remaining as Field)==0);
        assert((finishing as Field)*(p-4)*(cursor as Field-target as Field)==0);
        assert(!(baseline|insertion) | (left!=right));
        assert(!move_l | (left!=0));
        assert(!(move_r|deletion) | (right!=SCALARS));
        gated17(begin,total as Field-location as Field-removed as Field);
        assert(!begin | (((next_source!=0)&(next_source<=6))|(next_source==255)));
        gated17(move_l,cursor as Field-target as Field-1);
        gated17(move_r,target as Field-cursor as Field-1);
        // Checked unsigned remaining subtraction below enforces deletion capacity.
        assert(!advance | (arg!=0));
        (if flags {arg as Field}else{0}).assert_max_bit_size::<32>();
        initial_bytes+=if baseline {if write<128 {1}else if write<2048 {2}else if write<65536 {3}else{4}}else{0};
        baseline_end=if baseline_done {state.offset+i+1}else{baseline_end};
        elapsed+=if sample {(arg>>16) as Field}else if begin {(arg>>40) as Field}else if advance {arg as Field}else{0};
        // One origin per real key sample, attached to this operation's time.
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
        samples+=sample as Field;edits+=end as Field;
        typing+=(end & (source==1)) as Field;paste+=(end & (source==2)) as Field;
        target=if begin {location}else{target};remaining=if begin {removed}else{remaining};
        source=if begin {next_source}else{source};
        // Select geometry updates once, after validating the opcode, rather than
        // threading four integer states through every branch of the interpreter.
        let add_scalar=((code==1)|(code==9)) as u32;
        let move_left=(code==6) as u32;let move_right=(code==7) as u32;let remove=(code==8) as u32;
        left=bounded16(left as Field+add_scalar as Field+move_right as Field-move_left as Field);
        right=bounded16(right as Field+move_right as Field+remove as Field-move_left as Field);
        cursor=bounded17(cursor as Field+(add_scalar as Field)*(width(write) as Field)+(move_right as Field)*(width(read) as Field)-(move_left as Field)*(width(read) as Field));
        total=bounded17(total as Field+(add_scalar as Field)*(width(write) as Field)-(remove as Field)*(width(read) as Field));
        remaining=bounded16(remaining as Field-(remove as Field)*(width(read) as Field));
        phase=if (code==2)|(code==10) {1}else if code==5 {2}else if code==8 {3}else if code==9 {4}else{phase};
        assert((left<=right)&(right<=SCALARS));
        phases[i+1]=phase;times[i+1]=elapsed;edit_counts[i+1]=edits;sample_counts[i+1]=samples;
        inputs[i]=(i<op_count)&(sample|begin);
    }

    elapsed.assert_max_bit_size::<64>();
    for count in [edits,samples,typing,paste,initial_bytes] {count.assert_max_bit_size::<32>();}
    // Capture transcript continues the carried partial block, so chunks may end anywhere.
    let r=state.offset%12;
    let mut ext=[0;OPS+12];
    for j in 0..12 {ext[j]=state.tail[j] as Field;}
    for i in 0..OPS {ext[r+i]=words[i];}
    let mut heads=[0;(OPS+12)/12+1];heads[0]=state.head;
    for block in 0..(OPS+12)/12 {
        let mut packed=[0;3];
        for i in 0..12 {let mut scale:Field=1;for _ in 0..i%4 {scale*=4611686018427387904;}packed[i/4]+=ext[block*12+i]*scale;}
        heads[block+1]=commit::block(heads[block],packed);
    }
    let end=r+op_count;let mut tail=[0u64;12];
    for i in 0..12 {let index=end/12*12+i;let safe=if index<OPS+12 {index}else{0};tail[i]=if index<end {ext[safe] as u64}else{0};}
    let ro=state.samples%6;
    let mut oheads=[0;(OPS+6)/6+1];oheads[0]=interaction.origin_head;
    for block in 0..(OPS+6)/6 {
        let mut p=[0;3];for i in 0..6 {p[i/2]+=origin_values[block*6+i]*if i%2==0 {1}else{316912650057057350374175801344};}
        oheads[block+1]=commit::hash([0x48554d410402,oheads[block],p[0],p[1],p[2]]);
    }
    let ocount=ro+local_samples;
    interaction.origin_head=oheads[ocount/6];
    for i in 0..6 {let index=ocount/6*6+i;let safe=if index<OPS+6 {index}else{0};interaction.origin_tail[i]=if index<ocount {origin_values[safe]}else{0};}
    // next_times[l]: elapsed after the first key/edit-begin operation at local index >= l.
    let mut next_times=[0;OPS+1];let mut has_next=[false;OPS+1];
    for j in 0..OPS {let i=OPS-1-j;next_times[i]=if inputs[i] {times[i+1]}else{next_times[i+1]};has_next[i]=inputs[i]|has_next[i+1];}
    let mut prefixes=[0;SLOTS];let mut oprefixes=[0;SLOTS];
    for j in 0..SLOTS {
        let l=local(events[j],state.offset,op_count);let sa=sample_counts[l];
        prefixes[j]=capture_at(ext,heads,r+l,state.offset+l);
        oprefixes[j]=origin_at(origin_values,oheads,ro+((sa-(state.samples as Field)) as u32),sa);
    }
    let ev=apply_events(state.events,events,text,nonce,state.offset,op_count,baseline_end,
        phases,times,edit_counts,sample_counts,next_times,has_next,prefixes,oprefixes,device,signatures);
    let after=State {buffer,left,right,cursor,total,target,remaining,phase,elapsed:elapsed as u64,
        edits:edits as u32,samples:samples as u32,typing:typing as u32,paste:paste as u32,source,
        initial_bytes:initial_bytes as u32,baseline_end,offset:state.offset+op_count,head:heads[end/12],tail,interaction,events:ev};
    shape(after);
    after
}

// ---- Final step: the public statement of a sealed terminal state. ----
pub struct Final {
    nonce:[Field;2],pub state_root:Field,capture_root:Field,origin_root:Field,presence_root:Field,
    bound_root:Field,op_count:u32,raw_scalars:u32,canonical_scalars:u32,raw_bytes:u32,canonical_bytes:u32,
    raw_commitment:Field,canonical_commitment:Field,text_capacity:u32,initial_bytes:u32,edits:u32,samples:u32,
    typing:u32,paste:u32,start_unix:u64,end_unix:u64,elapsed:u64,clock_back:bool,
    checkpoint_count:u32,presence_count:u32,approved:u32,on_time:u32,missed:u32,
    median_response:u64,longest_gap:u64,origin_present:u32,origin_hid:u32,
    rules:[bool;9],policy_satisfied:bool,event_digest:Field,pub device:Field,
}
// The chain's last state plus any events at its end (the seal), so finishing needs no extra chunk.
pub fn finalize(nonce:[Field;2],salt:[Field;2],state:State,events:[Event;SLOTS],text:[Field;2],device:Device,signatures:[[u8;64];TAIL],expected:Final) {
    for i in 0..2 {salt[i].assert_max_bit_size::<128>();nonce[i].assert_max_bit_size::<128>();}
    assert((salt[0]!=0)|(salt[1]!=0));shape(state);
    assert(expected.nonce==nonce);
    assert(expected.state_root==state_root(state,nonce,salt));
    assert(expected.op_count==state.offset);
    let mut capture=[0;3];
    for i in 0..12 {let mut scale:Field=1;for _ in 0..i%4 {scale*=4611686018427387904;}capture[i/4]+=(state.tail[i] as Field)*scale;}
    let capture_root=commit::hash([0x48554d410303,state.head,state.offset as Field,capture[0],capture[1],capture[2]]);
    let origin_root=origin_prefix(state.interaction,state.samples);
    let e=apply_events(state.events,events,text,nonce,state.offset,0,state.baseline_end,[state.phase],[state.elapsed as Field],
        [state.edits as Field],[state.samples as Field],[0],[false],[capture_root;SLOTS],[origin_root;SLOTS],device,signatures);
    assert(e.sealed&(state.phase==1)&(state.baseline_end>0)&(state.remaining==0)&(e.approved>0)&(e.end_elapsed>=e.last_approval));
    assert((expected.capture_root==capture_root)&(expected.origin_root==origin_root)&(expected.presence_root==e.presence_head));
    assert(expected.bound_root==commit::hash([0x48554d410409,capture_root,origin_root,e.presence_head]));
    assert((expected.initial_bytes==state.initial_bytes)&(expected.edits==state.edits)&(expected.samples==state.samples));
    assert((expected.typing==state.typing)&(expected.paste==state.paste));
    assert((expected.start_unix==e.start_unix)&(expected.end_unix==e.prior_unix)&(expected.elapsed==e.end_elapsed)&(expected.clock_back==e.rollback));
    assert((expected.checkpoint_count==e.checkpoints)&(expected.presence_count==e.presence)&(expected.approved==e.approved));
    assert((expected.on_time==e.on_time)&(expected.missed==e.presence-e.on_time));
    // Upper-middle median of approved latencies, as in the V4 report.
    let mut latencies=e.latencies;
    for i in 0..PRES {if i>=e.approved {latencies[i]=18446744073709551615;}}
    for _ in 0..PRES {for j in 0..PRES-1 {let a=latencies[j];let b=latencies[j+1];latencies[j]=if a<b {a}else{b};latencies[j+1]=if a<b {b}else{a};}}
    assert(expected.median_response==latencies[e.approved/2]);
    let tail_gap=e.end_elapsed-e.last_approval;
    assert(expected.longest_gap==if tail_gap>e.longest {tail_gap}else{e.longest});
    assert((expected.origin_present==state.interaction.origin_present)&(expected.origin_hid==state.interaction.origin_hid));
    let rules=assurance::behavior_rules(state.interaction.behavior,state.initial_bytes as Field,state.edits as Field,state.typing as Field,e.end_elapsed);
    let mut satisfied=true;for i in 0..9 {assert(expected.rules[i]==rules[i]);satisfied&=rules[i];}
    assert(expected.policy_satisfied==satisfied);
    assert(expected.event_digest==e.digest);
    assert(expected.device==device_root(device.x,device.y));
    // Terminal text: raw and canonical commitments, which the sealing checkpoint signed.
    let used=state.left+SCALARS-state.right;let mut logical=[0u32;TEXT];assert(used<=TEXT);
    let mut raw_bytes:u32=0;let mut canonical_bytes:u32=0;let mut canonical_scalars:u32=0;
    let mut utf16_total:u32=0;let mut utf16_cursor:u32=0;
    for i in 0..TEXT {
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
    let mut raw=[0;5+(TEXT+11)/12];let mut canonical=[0;5+(TEXT+11)/12];
    raw[0]=0x48554d410604;raw[1]=TEXT as Field;raw[2]=0;raw[3]=used as Field;raw[4]=raw_bytes as Field;
    canonical[0]=raw[0];canonical[1]=raw[1];canonical[2]=1;canonical[3]=canonical_scalars as Field;canonical[4]=canonical_bytes as Field;
    for i in 0..TEXT {
        let mut scale:Field=1;for _ in 0..i%12 {scale*=2097152;}
        raw[5+i/12]+=(logical[i] as Field)*scale;
        canonical[5+i/12]+=(if i<canonical_scalars {logical[i] as Field}else{0})*scale;
    }
    let raw_commitment=commit::hash(raw);let canonical_commitment=commit::hash(canonical);
    assert((expected.raw_commitment==raw_commitment)&(expected.canonical_commitment==canonical_commitment)&(expected.text_capacity==TEXT));
    assert((e.text[0]==canonical_commitment)&(e.text[1]==raw_commitment));
}
