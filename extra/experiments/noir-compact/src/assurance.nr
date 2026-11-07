use crate::commit;
pub struct Origin {pub present:bool,pub pid:u32,pub state:u32,pub keyboard:u32,pub repeated:bool}
pub struct KeyTiming {pub offset:u32,pub elapsed:u64,pub key:u16,pub up:bool}
pub struct Presence {pub offset:u32,pub nonce:[Field;2],pub reason:u8,pub issued:u64,pub answered:u64,pub outcome:u8}

pub fn origin_value(o:Origin)->Field {
    assert(o.present | ((o.pid==0)&(o.state==0)&(o.keyboard==0)&!o.repeated));
    o.pid as Field + (o.state as Field)*4294967296 + (o.keyboard as Field)*18446744073709551616
        + (o.repeated as Field)*79228162514264337593543950336 + (o.present as Field)*158456325028528675187087900672
}
pub fn origin_heads<let S:u32>(nonce:[Field;2],salt:[Field;2],values:[Field;S])->[Field;S/6+1] {
    let mut heads=[0;S/6+1];heads[0]=commit::hash([0x48554d410401,nonce[0],nonce[1],salt[0],salt[1]]);
    for block in 0..S/6 {
        let mut packed=[0;3];
        for i in 0..6 {packed[i/2]+=values[block*6+i]*if i%2==0 {1}else{316912650057057350374175801344};}
        heads[block+1]=commit::hash([0x48554d410402,heads[block],packed[0],packed[1],packed[2]]);
    }
    heads
}
pub fn origin_prefix<let S:u32,let H:u32>(values:[Field;S],heads:[Field;H],count:u32)->Field {
    assert(count<=S);let start=count/6*6;let mut packed=[0;3];
    for i in 0..6 {
        let index=start+i;let at=if index<S {index}else{0};
        let value=if index<count {values[at]}else{0};
        packed[i/2]+=value*if i%2==0 {1}else{316912650057057350374175801344};
    }
    commit::hash([0x48554d410403,heads[count/6],count as Field,packed[0],packed[1],packed[2]])
}

// One memory read/write per key slot and one per rate-ring slot, rather than
// comparisons against every previous keystroke. A zero slot means not held;
// elapsed+1 is a Field so u64::MAX remains exactly representable.
pub struct Behavior {
    pub held:[Field;256],pub rate_ring:[u64;20],pub downs:Field,pub pairs:Field,pub good_dwells:Field,
    pub good_intervals:Field,pub anomalies:Field,pub previous_down:u64,pub pause:bool,pub rate_ok:bool,
}
pub fn behavior_empty()->Behavior {
    Behavior {held:[0;256],rate_ring:[0;20],downs:0,pairs:0,good_dwells:0,good_intervals:0,
        anomalies:0,previous_down:0,pause:false,rate_ok:true}
}
pub fn behavior_step(mut b:Behavior,code:u8,key:u16,elapsed:u64,origin:Origin)->Behavior {
    let sample=(code==3)|(code==4);assert(!sample | (key<256));
    let slot=if sample {key as u32}else{0};let old=b.held[slot];
    let down=code==3;let up=code==4;let repeat=down & origin.repeated;let fresh=down & !origin.repeated;
    b.anomalies+=(repeat & (old==0)) as Field + (fresh & (old!=0)) as Field + (up & (old==0)) as Field;
    let held_time=(if old!=0 {old-1}else{elapsed as Field}) as u64;
    let dwell=elapsed-held_time;
    let paired=up & (old!=0);b.pairs+=paired as Field;
    b.good_dwells+=(paired & (dwell>=10)&(dwell<=2000)) as Field;
    b.held[slot]=if fresh {elapsed as Field+1}else if up {0}else{old};
    let previous=if b.downs!=0 {b.previous_down}else{elapsed};
    let interval=elapsed-previous;
    let follow=fresh & (b.downs!=0);
    b.good_intervals+=(follow & (interval>=5)&(interval<=30000)) as Field;
    b.pause|=follow & (interval>=500);
    b.previous_down=if fresh {elapsed}else{b.previous_down};
    let ring=(b.downs as u32)%20;let oldest=b.rate_ring[ring];
    let filled=(b.downs as u32)>=20;
    let old_time=if filled {oldest}else{elapsed};
    b.rate_ok&=!(fresh & filled & (elapsed-old_time<1000));
    b.rate_ring[ring]=if fresh {elapsed}else{oldest};
    b.downs+=fresh as Field;b
}
pub fn behavior_rules(b:Behavior,initial_bytes:Field,edits:Field,typing:Field,duration:u64)->[bool;9] {
    // Counts are nonnegative sums of at most OPS<=65536 indicators. Their
    // u32 products below 100*OPS cannot wrap or truncate.
    let e=edits as u32;let t=typing as u32;let n=b.downs as u32;let p=b.pairs as u32;
    let d=b.good_dwells as u32;let intervals=b.good_intervals as u32;
    [initial_bytes==0,(e>0)&(t==e),duration>=20000,n>=30,
     (b.anomalies==0)&(p*100>=n*90),(p>0)&(d*100>=p*90),
     (n>1)&(intervals*100+90>=n*90),b.pause,(n>0)&b.rate_ok]
}
