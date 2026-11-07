mod bytes;
mod commit;
use bytes::{Bytes,canonical_length};

global OPS:u32=256;
global SCALARS:u32=64;
global BYTES:u32=128;
global CPS:u32=2;
struct Op {code:u8,arg:u64}
struct Checkpoint {offset:u32,unix:u64,elapsed:u64}
struct Journal {
    session_nonce:[Field;2],capture_root:Field,text_hash:[u8;32],
    byte_length:u32,raw_byte_length:u32,initial_bytes:u32,
    edits:u32,samples:u32,captures:u32,typing:u32,paste:u32,op_count:u32,
    start_unix:u64,end_unix:u64,elapsed:u64,clock_back:bool,checkpoint_roots:[Field;CPS],
}
fn time(previous:Field,delta:u64)->Field {previous+delta as Field}
fn width(scalar:u32)->u32 {if scalar>=65536 {2}else{1}}
fn valid_scalar(value:u64) {assert((value<=0x10ffff)&!((value>=0xd800)&(value<=0xdfff)));}
fn utf8_scalar(value:u32)->Bytes<4> {
    if value<128 {Bytes::<4>::empty().push(value as u8)}
    else if value<2048 {Bytes::<4>::empty().push((192+(value>>6)) as u8).push((128+(value&63)) as u8)}
    else if value<65536 {Bytes::<4>::empty().push((224+(value>>12)) as u8).push((128+((value>>6)&63)) as u8).push((128+(value&63)) as u8)}
    else {Bytes::<4>::empty().push((240+(value>>18)) as u8).push((128+((value>>12)&63)) as u8).push((128+((value>>6)&63)) as u8).push((128+(value&63)) as u8)}
}

fn main(nonce:[Field;2],salt:[Field;2],ops:[Op;OPS],op_count:u32,
        checkpoints:[Checkpoint;CPS],expected:pub Journal) {
    for i in 0..2 {nonce[i].assert_max_bit_size::<128>();salt[i].assert_max_bit_size::<128>();}
    assert((salt[0]!=0)|(salt[1]!=0));assert((op_count>0)&(op_count<=OPS));assert(OPS<=65536);
    assert((SCALARS>0)&(SCALARS<=65535));assert((BYTES>0)&(CPS>=2));
    let mut buffer=[0u32;SCALARS];
    let mut left:Field=0;let mut right:Field=SCALARS as Field;
    let mut cursor:Field=0;let mut total:Field=0;let mut target=0u32;let mut remaining:Field=0;
    let mut phase=0u8;let mut elapsed:Field=0;let mut edits:Field=0;let mut samples:Field=0;
    let mut typing:Field=0;let mut paste:Field=0;let mut source=0u8;let mut initial_bytes:Field=0;let mut baseline_end=0;
    let mut phases=[0u8;OPS+1];let mut times=[0;OPS+1];
    let mut edit_counts=[0;OPS+1];let mut sample_counts=[0;OPS+1];
    let mut words=[0;OPS];
    for i in 0..OPS {
        let o=ops[i];let code=o.code;let arg=o.arg;
        assert(code<64);(arg as Field).assert_max_bit_size::<56>();
        words[i]=(code as Field)*72057594037927936+arg as Field;
        if i>=op_count {assert((code==0)&(arg==0));}else{assert((code>=1)&(code<=13));}
        // Geometry is explicitly bounded before casts and after every update.
        left.assert_max_bit_size::<16>();right.assert_max_bit_size::<16>();
        cursor.assert_max_bit_size::<17>();total.assert_max_bit_size::<17>();
        remaining.assert_max_bit_size::<16>();
        let l=left as u32;let r=right as u32;
        let c=cursor as u32;let t=total as u32;let rem=remaining as u32;
        // One bounded gap-buffer read/write per operation; no whole-array shift.
        let read_index=if code==6 {if l>0 {l-1}else{0}}
            else if (code==7)|(code==8) {if r<SCALARS {r}else{0}}else{0};
        let read=buffer[read_index];
        let write_index=if code==6 {if r>0 {r-1}else{0}}
            else if (code==1)|(code==9)|(code==7) {if l<SCALARS {l}else{0}}else{read_index};
        let write=if (code==1)|(code==9) {arg as u32}else{read};
        buffer[write_index]=write;
        if code==1 {
            assert((phase==0)&(l<r));valid_scalar(arg);
            initial_bytes+=if write<128 {1}else if write<2048 {2}else if write<65536 {3}else{4};
        } else if code==2 {
            assert((phase==0)&(arg==0));baseline_end=i+1;
        } else if (code==3)|(code==4) {
            assert(phase==1);elapsed=time(elapsed,arg>>16);samples+=1;
        } else if code==5 {
            assert(phase==1);target=(arg&65535) as u32;remaining=((arg>>16)&65535) as Field;
            source=((arg>>32)&255) as u8;
            assert((target<=t)&((remaining as u32)<=t-target));
            assert(((source>=1)&(source<=6))|(source==255));
            elapsed=time(elapsed,arg>>40);
        } else if code==6 {
            assert((arg==0)&(phase==2)&(c>target)&(l>0));
        } else if code==7 {
            assert((arg==0)&(phase==2)&(c<target)&(r<SCALARS));
        } else if code==8 {
            assert((arg==0)&((phase==2)|(phase==3))&(c==target)&(r<SCALARS));
            assert(rem>=width(read));
        } else if code==9 {
            assert((phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(c==target))&(l<r));
            valid_scalar(arg);
        } else if code==10 {
            assert((arg==0)&(phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(c==target)));
            edits+=1;typing+=(source==1) as Field;paste+=(source==2) as Field;
        } else if code==11 {
            assert((phase==1)&(arg>0));elapsed=time(elapsed,arg);
        } else if (code==12)|(code==13) {
            assert((phase==1)&(arg<=4294967295));
        }
        // Select geometry updates once, after validating the opcode, rather than
        // threading four integer states through every branch of the interpreter.
        let add_scalar=((code==1)|(code==9)) as Field;
        let move_left=(code==6) as Field;let move_right=(code==7) as Field;let remove=(code==8) as Field;
        left=left+add_scalar+move_right-move_left;
        right=right+move_right+remove-move_left;
        cursor=cursor+add_scalar*(width(write) as Field)+move_right*(width(read) as Field)-move_left*(width(read) as Field);
        total=total+add_scalar*(width(write) as Field)-remove*(width(read) as Field);
        remaining-=remove*(width(read) as Field);
        phase=if (code==2)|(code==10) {1}else if code==5 {2}else if code==8 {3}else if code==9 {4}else{phase};
        left.assert_max_bit_size::<16>();right.assert_max_bit_size::<16>();
        cursor.assert_max_bit_size::<17>();total.assert_max_bit_size::<17>();remaining.assert_max_bit_size::<16>();
        assert(((left as u32)<=(right as u32))&((right as u32)<=SCALARS));
        phases[i+1]=phase;times[i+1]=elapsed;edit_counts[i+1]=edits;sample_counts[i+1]=samples;
    }
    assert((phase==1)&(baseline_end>0));
    // Each delta is at most 2^56-1 and OPS <= 2^16, so the entire sum is below
    // 2^72 and cannot wrap the field. All deltas are nonnegative: checking the
    // final u64 bound also bounds every prefix. Counts are <= OPS (initial
    // bytes <= 4*SCALARS), so their Field additions cannot wrap either.
    elapsed.assert_max_bit_size::<64>();
    let mut data=[0u8;BYTES];let mut byte_length=0u32;
    let end_left=left as u32;let end_right=right as u32;
    let count=end_left+SCALARS-end_right;
    for i in 0..SCALARS {
        let active=i<count;
        let index=if active {if i<end_left {i}else{end_right+i-end_left}}else{0};
        let encoded=utf8_scalar(buffer[index]);
        assert(!active | (byte_length+encoded.len<=BYTES));
        // Select each bounded write instead of selecting a whole BYTES-sized
        // array across a conditional on every scalar.
        for j in 0..4 {
            let take=active & (j<encoded.len);
            let at=if take {byte_length+j}else{0};
            let old=data[at];data[at]=if take {encoded.data[j]}else{old};
        }
        byte_length+=if active {encoded.len}else{0};
    }
    let text=Bytes {data,len:byte_length};
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
