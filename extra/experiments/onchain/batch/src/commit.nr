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
