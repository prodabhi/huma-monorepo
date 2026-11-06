// Batch commitments: the same Poseidon2 framing as integrations/noir/batch/src/commit.nr and commit.mjs.
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use base64::Engine;

pub const LEAF_DOMAIN: u64 = 0x48554d41b001;
pub const ROOT_DOMAIN: u64 = 0x48554d41b002;

/// commit::hash: rate three, length << 64 in the capacity, one permutation per full block and a final one.
pub fn hash(input: &[Fr]) -> Fr {
    let mut state = [Fr::from(0u64); 4];
    state[3] = Fr::from(input.len() as u64) * Fr::from(1u128 << 64);
    let mut blocks = input.chunks_exact(3);
    for block in &mut blocks {
        for i in 0..3 { state[i] += block[i]; }
        state = taceo_poseidon2::bn254::t4::permutation(&state);
    }
    for (i, item) in blocks.remainder().iter().enumerate() { state[i] += item; }
    taceo_poseidon2::bn254::t4::permutation(&state)[0]
}

/// A page's leaf: its circuit key hash and its complete public statement.
pub fn leaf(key_hash: Fr, statement: &[Fr]) -> Fr {
    hash(&[Fr::from(LEAF_DOMAIN), key_hash, hash(statement)])
}

pub fn root(leaves: &[Fr]) -> Fr {
    let mut input = vec![Fr::from(ROOT_DOMAIN)];
    input.extend_from_slice(leaves);
    hash(&input)
}

/// A canonical field element from 32 big-endian bytes; values at or above the modulus are refused.
pub fn from_bytes(bytes: &[u8]) -> Option<Fr> {
    if bytes.len() != 32 { return None; }
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 32 - 8 * (i + 1);
        *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().ok()?);
    }
    Fr::from_bigint(BigInt::new(limbs))
}

/// `0x` and 64 lowercase or uppercase hex digits.
pub fn from_hex(value: &str) -> Option<Fr> {
    let digits = value.strip_prefix("0x")?;
    if digits.len() != 64 { return None; }
    from_bytes(&hex::decode(digits).ok()?)
}

/// Field elements of a base64 public input or proof blob (32 bytes each, big-endian).
pub fn fields_of(base64: &str) -> Option<Vec<Fr>> {
    let raw = base64::engine::general_purpose::STANDARD.decode(base64).ok()?;
    if raw.len() % 32 != 0 { return None; }
    raw.chunks_exact(32).map(from_bytes).collect()
}

pub fn to_hex(value: Fr) -> String {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values from integrations/noir/batch/commit.mjs, which the circuit itself is tested against.
    #[test]
    fn matches_the_reader_and_circuit_framing() {
        assert_eq!(to_hex(hash(&[])), "0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e");
        let four: Vec<Fr> = (1..=4u64).map(Fr::from).collect();
        assert_eq!(to_hex(hash(&four)), "0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9");
    }

    #[test]
    fn refuses_noncanonical_fields() {
        let modulus = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        assert!(from_hex(modulus).is_none());
        assert!(from_hex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000").is_some());
        assert!(from_hex("0x01").is_none());
        assert!(fields_of("AAAA").is_none());
        assert_eq!(to_hex(from_hex(&format!("0x{:064x}", 7)).unwrap()), format!("0x{:064x}", 7));
    }
}
