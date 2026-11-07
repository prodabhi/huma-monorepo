use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

// Match the pinned Noir beta.25 Poseidon2Hasher framing: length << 64 in the
// capacity, rate three, a permutation per full block and always one final one.
pub fn hash(input: &[Fr]) -> Fr {
    let mut state = [Fr::from(0u64); 4];
    state[3] = Fr::from(input.len() as u64) * Fr::from(1u128 << 64);
    let mut chunks = input.chunks_exact(3);
    for block in &mut chunks {
        for i in 0..3 { state[i] += block[i]; }
        state = taceo_poseidon2::bn254::t4::permutation(&state);
    }
    for (i, item) in chunks.remainder().iter().enumerate() { state[i] += item; }
    taceo_poseidon2::bn254::t4::permutation(&state)[0]
}

pub fn bytes(value: Fr) -> [u8;32] {
    let raw = value.into_bigint().to_bytes_be();
    let mut result = [0u8;32]; result[32-raw.len()..].copy_from_slice(&raw); result
}
pub fn halves(value: &[u8;32]) -> [Fr;2] {
    [Fr::from_be_bytes_mod_order(&value[..16]), Fr::from_be_bytes_mod_order(&value[16..])]
}
pub fn parse(value: &str) -> Result<Fr,String> {
    if value.is_empty() || value.len()>77 { return Err("Invalid field length".into()); }
    let field = value.parse::<Fr>().map_err(|_| "Invalid field".to_string())?;
    if field.to_string() != value { return Err("Noncanonical field".into()); }
    Ok(field)
}

const SEED: u64 = 0x48554d410301;
const BLOCK: u64 = 0x48554d410302;
const PREFIX: u64 = 0x48554d410303;
pub const CHECKPOINT: u64 = 0x48554d410304;

pub struct Transcript { heads: Vec<Fr> }
impl Transcript {
    pub fn new(nonce: [Fr;2], salt: [Fr;2], words: &[u64]) -> Self {
        let mut heads = vec![hash(&[Fr::from(SEED),nonce[0],nonce[1],salt[0],salt[1]])];
        for block in words.chunks_exact(12) {
            let packed = pack(block);
            heads.push(hash(&[Fr::from(BLOCK),*heads.last().unwrap(),packed[0],packed[1],packed[2]]));
        }
        Self { heads }
    }
    /// Hashes newly completed blocks of an append-only word list.
    pub fn extend(&mut self, words: &[u64]) {
        while words.len() >= self.heads.len()*12 {
            let start = (self.heads.len()-1)*12;
            let packed = pack(&words[start..start+12]);
            self.heads.push(hash(&[Fr::from(BLOCK),*self.heads.last().unwrap(),packed[0],packed[1],packed[2]]));
        }
    }
    pub fn prefix(&self, words: &[u64], count: usize) -> Fr {
        let block = count/12;
        let partial = pack(&words[block*12..count]);
        hash(&[Fr::from(PREFIX),self.heads[block],Fr::from(count as u64),partial[0],partial[1],partial[2]])
    }
}
fn pack(words: &[u64]) -> [Fr;3] {
    let mut result = [Fr::from(0u64);3];
    let base = Fr::from(1u64 << 62);
    for (i, word) in words.iter().enumerate() {
        assert!(*word < 1u64 << 62);
        let mut scale = Fr::from(1u64);
        for _ in 0..i%4 { scale *= base; }
        result[i/4] += Fr::from(*word)*scale;
    }
    result
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn noir_beta25_known_hash() {
        let expected = Fr::from_be_bytes_mod_order(&hex::decode("2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db").unwrap());
        assert_eq!(hash(&[1u64,2,3,4,5].map(Fr::from)),expected);
    }
    #[test] fn prefix_length_and_block_boundaries_bind() {
        let words = vec![0u64;25];
        let t = Transcript::new([Fr::from(1u64);2],[Fr::from(2u64);2],&words);
        let roots: std::collections::HashSet<_> = (0..=25).map(|n|bytes(t.prefix(&words,n))).collect();
        assert_eq!(roots.len(),26);
    }
}
