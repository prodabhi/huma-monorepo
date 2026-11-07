mod bytes;
mod commit;
use bytes::{Bytes,canonical_length};

global OPS:u32=256;
global SCALARS:u32=64;
global BYTES:u32=128;
global CPS:u32=2;
// Parameters are untrusted decoding hints. Each active opcode checks ranges and
// reconstructs its entire authenticated argument, so a hint cannot change data.
struct Op {code:u8,arg:Field,p:[Field;4]}
struct Checkpoint {offset:u32,unix:u64,elapsed:u64}
struct Journal {
    session_nonce:[Field;2],capture_root:Field,text_hash:[u8;32],
    byte_length:u32,raw_byte_length:u32,initial_bytes:u32,
    edits:u32,samples:u32,captures:u32,typing:u32,paste:u32,op_count:u32,
    start_unix:u64,end_unix:u64,elapsed:u64,clock_back:bool,checkpoint_roots:[Field;CPS],
}
fn width(wide:bool)->u32 {if wide {2}else{1}}
fn valid_scalar(arg:Field,p:[Field;4]) {
    p[0].assert_max_bit_size::<16>();p[1].assert_max_bit_size::<5>();
    assert((p[1] as u8)<=16);assert(arg==p[0]+65536*p[1]);
    let low=p[0] as u16;
    assert(!((p[1]==0)&(low>=0xd800)&(low<=0xdfff)));
}
fn utf8_scalar(value:u32)->Bytes<4> {
    if value<128 {Bytes::<4>::empty().push(value as u8)}
    else if value<2048 {Bytes::<4>::empty().push((192+(value>>6)) as u8).push((128+(value&63)) as u8)}
    else if value<65536 {Bytes::<4>::empty().push((224+(value>>12)) as u8).push((128+((value>>6)&63)) as u8).push((128+(value&63)) as u8)}
    else {Bytes::<4>::empty().push((240+(value>>18)) as u8).push((128+((value>>12)&63)) as u8).push((128+((value>>6)&63)) as u8).push((128+(value&63)) as u8)}
}

fn main(nonce:[Field;2],salt:[Field;2],ops:[Op;OPS],op_count:u32,
        checkpoints:[Checkpoint;CPS],expected:pub Journal) {
    for i in 0..2 {nonce[i].assert_max_bit_size::<128>();salt[i].assert_max_bit_size::<128>();}
    assert((salt[0]!=0)|(salt[1]!=0));assert((op_count>0)&(op_count<=OPS));
    assert(OPS<=65536);assert((SCALARS>0)&(SCALARS<=65535));assert((BYTES>0)&(CPS>=2));
    let mut buffer=[0;SCALARS];let mut wides=[false;SCALARS];
    let mut left=0;let mut right=SCALARS;
    let mut cursor=0;let mut total=0;let mut target=0;let mut remaining=0;
    let mut phase=0u8;let mut elapsed:Field=0;let mut edits:Field=0;let mut samples:Field=0;
    let mut typing:Field=0;let mut paste:Field=0;let mut source=0u8;let mut initial_bytes:Field=0;let mut baseline_end=0;
    let mut phases=[0u8;OPS+1];let mut times=[0;OPS+1];
    let mut edit_counts=[0;OPS+1];let mut sample_counts=[0;OPS+1];
    let mut words=[0;OPS];
    for i in 0..OPS {
        let o=ops[i];let code=o.code;let arg=o.arg;let p=o.p;
        assert(code<64);
        words[i]=(code as Field)*72057594037927936+arg;
        if i>=op_count {assert((code==0)&(arg==0));}else{assert((code>=1)&(code<=13));}
        // One bounded gap-buffer read/write per operation; no whole-array shift.
        let read_index=if code==6 {if left>0 {left-1}else{0}}
            else if (code==7)|(code==8) {if right<SCALARS {right}else{0}}else{0};
        let read=buffer[read_index];let read_wide=wides[read_index];
        let write_index=if code==6 {if right>0 {right-1}else{0}}
            else if (code==1)|(code==9)|(code==7) {if left<SCALARS {left}else{0}}else{read_index};
        let write=if (code==1)|(code==9) {arg}else{read};
        let write_wide=if (code==1)|(code==9) {p[1]!=0}else{read_wide};
        buffer[write_index]=write;wides[write_index]=write_wide;
        if code==1 {
            assert((phase==0)&(left<right));valid_scalar(arg,p);
            left+=1;cursor+=width(write_wide);total+=width(write_wide);
            let low=p[0] as u16;
            initial_bytes+=if write_wide {4}else if low<128 {1}else if low<2048 {2}else{3};
        } else if code==2 {
            assert((phase==0)&(arg==0));phase=1;baseline_end=i+1;
        } else if (code==3)|(code==4) {
            assert(phase==1);p[0].assert_max_bit_size::<40>();p[1].assert_max_bit_size::<16>();
            assert(arg==p[0]*65536+p[1]);elapsed+=p[0];samples+=1;
        } else if code==5 {
            assert(phase==1);p[0].assert_max_bit_size::<16>();p[1].assert_max_bit_size::<16>();
            p[2].assert_max_bit_size::<16>();p[3].assert_max_bit_size::<8>();
            assert(arg==p[0]*1099511627776+p[3]*4294967296+p[2]*65536+p[1]);
            target=p[1] as u32;remaining=p[2] as u32;source=p[3] as u8;
            assert((target<=total)&(remaining<=total-target));
            assert(((source>=1)&(source<=6))|(source==255));
            elapsed+=p[0];phase=2;
        } else if code==6 {
            assert((arg==0)&(phase==2)&(cursor>target)&(left>0));
            left-=1;right-=1;cursor-=width(read_wide);
        } else if code==7 {
            assert((arg==0)&(phase==2)&(cursor<target)&(right<SCALARS));
            left+=1;right+=1;cursor+=width(read_wide);
        } else if code==8 {
            assert((arg==0)&((phase==2)|(phase==3))&(cursor==target)&(right<SCALARS));
            assert(remaining>=width(read_wide));remaining-=width(read_wide);total-=width(read_wide);right+=1;phase=3;
        } else if code==9 {
            assert((phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(cursor==target))&(left<right));
            valid_scalar(arg,p);left+=1;cursor+=width(write_wide);total+=width(write_wide);phase=4;
        } else if code==10 {
            assert((arg==0)&(phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(cursor==target)));
            phase=1;edits+=1;typing+=(source==1) as Field;paste+=(source==2) as Field;
        } else if code==11 {
            assert((phase==1)&(arg!=0));arg.assert_max_bit_size::<56>();elapsed+=arg;
        } else if (code==12)|(code==13) {
            assert(phase==1);arg.assert_max_bit_size::<32>();
        }
        assert((left<=right)&(right<=SCALARS));
        phases[i+1]=phase;times[i+1]=elapsed;edit_counts[i+1]=edits;sample_counts[i+1]=samples;
    }
    assert((phase==1)&(baseline_end>0));
    // Each delta is at most 2^56-1 and OPS <= 2^16, so the entire sum is below
    // 2^72 and cannot wrap the field. All deltas are nonnegative: checking the
    // final u64 bound also bounds every prefix. Counts are <= OPS (initial
    // bytes <= 4*SCALARS), so their Field additions cannot wrap either.
    elapsed.assert_max_bit_size::<64>();
    let mut text=Bytes::<BYTES>::empty();
    let count=left+SCALARS-right;
    for i in 0..SCALARS {
        if i<count {
            let index=if i<left {i}else{right+i-left};
            text=text.add(utf8_scalar(buffer[index] as u32));
        }
    }
    let canonical_len=canonical_length(text);assert(canonical_len>0);
    let text_hash=Bytes {data:text.data,len:canonical_len}.hash();
    let mut heads=[0;OPS/12+1];heads[0]=commit::seed(nonce,salt);
    for block in 0..OPS/12 {
        let mut packed=[0;3];
        for i in 0..12 {
            let mut scale=1;
            for _ in 0..i%4 {scale*=4611686018427387904;}
            packed[i/4]+=words[block*12+i]*scale;
        }
        heads[block+1]=commit::block(heads[block],packed);
    }
    let mut hash0:Field=0;let mut hash1:Field=0;
    for i in 0..16 {hash0=hash0*256+text_hash[i] as Field;hash1=hash1*256+text_hash[i+16] as Field;}
    let mut previous=0;let mut prior_offset=0;let mut prior_elapsed=0;let mut prior_unix=0;let mut rollback=false;
    for i in 0..CPS {
        let c=checkpoints[i];
        assert((c.offset>=prior_offset)&(c.offset<=op_count)&(c.unix<=253402300799999)&(c.elapsed>=prior_elapsed));
        assert((phases[c.offset]==1)&(c.elapsed>=times[c.offset] as u64));
        if i==0 {assert((c.offset==baseline_end)&(c.elapsed==0));}else{rollback|=c.unix<prior_unix;}
        let last=i==CPS-1;if last {assert(c.offset==op_count);}
        let e=edit_counts[c.offset];let s=sample_counts[c.offset];
        let prefix=commit::prefix(words,heads,c.offset);
        previous=commit::hash([0x48554d410304,prefix,i as Field,e+s,e,s,
            c.unix as Field,c.elapsed as Field,last as Field,previous,if last {hash0}else{0},if last {hash1}else{0}]);
        assert(expected.checkpoint_roots[i]==previous);
        prior_offset=c.offset;prior_elapsed=c.elapsed;prior_unix=c.unix;
    }
    assert(expected.session_nonce==nonce);assert(expected.capture_root==commit::prefix(words,heads,op_count));
    assert(expected.text_hash==text_hash);assert(expected.byte_length==canonical_len);assert(expected.raw_byte_length==text.len);
    assert(expected.initial_bytes as Field==initial_bytes);assert(expected.edits as Field==edits);assert(expected.samples as Field==samples);
    assert(expected.captures as Field==edits+samples);assert(expected.typing as Field==typing);assert(expected.paste as Field==paste);assert(expected.op_count==op_count);
    assert(expected.start_unix==checkpoints[0].unix);assert(expected.end_unix==prior_unix);
    assert(expected.elapsed==prior_elapsed);assert(expected.clock_back==rollback);
}
