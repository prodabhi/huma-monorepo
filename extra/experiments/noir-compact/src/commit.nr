// Fixed-length framing of Noir beta.25 Poseidon2Hasher, matched by native tests.
pub fn hash<let N:u32>(input:[Field;N]) -> Field {
    let mut state=[0,0,0,(N as Field)*18446744073709551616];
    for block in 0..N/3 {
        for j in 0..3 {state[j]+=input[block*3+j];}
        state=std::hash::poseidon2_permutation(state);
    }
    for j in 0..N%3 {state[j]+=input[N/3*3+j];}
    std::hash::poseidon2_permutation(state)[0]
}
pub fn seed(nonce:[Field;2],salt:[Field;2])->Field {
    hash([0x48554d410301,nonce[0],nonce[1],salt[0],salt[1]])
}
pub fn block(previous:Field,packed:[Field;3])->Field {
    hash([0x48554d410302,previous,packed[0],packed[1],packed[2]])
}
pub fn prefix<let O:u32,let B:u32>(words:[Field;O],heads:[Field;B],count:u32)->Field {
    assert(count<=O);
    let start=count/12*12;
    let mut packed=[0;3];
    for i in 0..12 {
        let index=start+i;
        let safe=if index<O {index}else{0};
        let value=if index<count {words[safe]}else{0};
        let mut scale=1;
        for _ in 0..i%4 {scale*=4611686018427387904;}
        packed[i/4]+=value*scale;
    }
    hash([0x48554d410303,heads[count/12],count as Field,packed[0],packed[1],packed[2]])
}
