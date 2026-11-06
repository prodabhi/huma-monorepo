mod bb;
mod commit;

// One on-chain proof for a batch of published pages.
//
// Each slot checks one page's zero-knowledge proof against the verification key of a Huma
// short-page circuit; keys outside the pinned set are rejected. The only public output is a
// commitment to every (key, statement) pair, so verifying a batch on-chain costs the same
// however full it is. Every input here is already public (published ZK proofs and their
// statements), so batches are proved on the sharing server, never on the writer's Mac.
// Unused slots carry a known public test proof.

// Pages whose statement has 94 public inputs, and those with 142.
global SMALL_SLOTS: u32 = 2;
global LARGE_SLOTS: u32 = 2;
global SMALL: u32 = 94;
global LARGE: u32 = 142;
// Poseidon2 hashes of the pinned verification keys (equal to bb's own key hashes).
global SMALL_KEYS: [Field; 3] = [
    0x17c103561f785a7b80c1d917db2612f276a1583d532f8935229bd4de5b04b30d, // assurance64-v1
    0x0157685ede27f32fdd79223af0fa1033773fcf97c772fe24f3351d41e002a5d0, // assurance256-v1
    0x12c5717ae7f3a2e98da5f6c6ae373c4999a9272679274b820aa3e3f05d18478a, // assurance256-v2
];
global LARGE_KEYS: [Field; 2] = [
    0x218201853a8bf4dcf363c65ffaf94f94134fc3f576c9e1c43770d1e7dc32979d, // assurance128-cp32-v1
    0x194304d383ebb642f24f36ab60799f5b8586d6e817d9a7ceb86f1f9e87f9a924, // assurance256-cp32-v1
];
global LEAF: Field = 0x48554d41b001; // "HUMA" batch leaf domain
global ROOT: Field = 0x48554d41b002; // "HUMA" batch root domain

fn pinned<let K: u32>(key_hash: Field, keys: [Field; K]) -> bool {
    let mut found = false;
    for i in 0..K { found |= key_hash == keys[i]; }
    found
}

/// The leaf a reader recomputes from a page's proof: its circuit key and its full statement.
fn leaf<let P: u32>(key_hash: Field, statement: [Field; P]) -> Field {
    commit::hash([LEAF, key_hash, commit::hash(statement)])
}

fn main(
    small_keys: [[Field; 115]; SMALL_SLOTS], small_proofs: [[Field; 458]; SMALL_SLOTS], small: [[Field; SMALL]; SMALL_SLOTS],
    large_keys: [[Field; 115]; LARGE_SLOTS], large_proofs: [[Field; 458]; LARGE_SLOTS], large: [[Field; LARGE]; LARGE_SLOTS],
) -> pub Field {
    let mut leaves = [0; SMALL_SLOTS + LARGE_SLOTS];
    for i in 0..SMALL_SLOTS {
        let key_hash = commit::hash(small_keys[i]);
        assert(pinned(key_hash, SMALL_KEYS), "unpinned circuit");
        bb::verify_honk_proof(small_keys[i], small_proofs[i], small[i], key_hash);
        leaves[i] = leaf(key_hash, small[i]);
    }
    for i in 0..LARGE_SLOTS {
        let key_hash = commit::hash(large_keys[i]);
        assert(pinned(key_hash, LARGE_KEYS), "unpinned circuit");
        bb::verify_honk_proof(large_keys[i], large_proofs[i], large[i], key_hash);
        leaves[SMALL_SLOTS + i] = leaf(key_hash, large[i]);
    }
    commit::hash([ROOT, leaves[0], leaves[1], leaves[2], leaves[3]])
}
