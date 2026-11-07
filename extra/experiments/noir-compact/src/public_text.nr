use crate::commit;

// Fixed profile: domain + exact canonical length + 31-byte big-endian words,
// right padded with zero bytes. Every packed word is below 2^248 < BN254 Fr.
// This commitment links replay to the public text; the mandatory reader also
// checks the existing signed SHA-256 against that SAME text.
pub fn commitment<let B:u32>(data:[u8;B],len:u32)->Field {
    assert((len>0)&(len<=B));
    let mut input=[0;2+(B+30)/31];input[0]=0x48554d410501;input[1]=len as Field;
    for block in 0..(B+30)/31 {
        let mut word=0;
        for i in 0..31 {
            let index=block*31+i;
            let active=(index<B)&(index<len);let at=if active {index}else{0};
            word=word*256+if active {data[at] as Field}else{0};
        }
        input[block+2]=word;
    }
    commit::hash(input)
}
