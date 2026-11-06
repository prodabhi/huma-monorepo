// SHA-256 for a private prefix in a statically bounded byte array.
// Construct exactly ceil((capacity + 9)/64) candidate padded blocks, then select
// the state after the real final block. Padding/length bytes are constrained
// directly; there is no host digest or unconstrained padding witness to trust.
pub fn digest<let N: u32>(data: [u8;N], len: u32) -> [u8;32] {
    assert(len <= N);
    // Capacity is compile-time; all current callers are small bounded payloads.
    assert(N <= 0xffff_ffb7);
    let max_blocks = (N + 72) / 64;
    let used_blocks = (len + 72) / 64;
    let bit_length = len as u64 * 8;
    let length_bytes: [u8;8] = (bit_length as Field).to_be_bytes();
    let mut state: [u32;8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                             0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut result = [0u32;8];
    for block in 0..max_blocks {
        let last = block + 1 == used_blocks;
        let mut words = [0u32;16];
        for word in 0..16 {
            let mut packed: Field = 0;
            for byte in 0..4 {
                let offset = word * 4 + byte;
                let position = block * 64 + offset;
                let safe = if position < N { position } else { 0 };
                let length_index = if offset >= 56 { offset - 56 } else { 0 };
                let value = if position < len { data[safe] }
                    else if position == len { 128 }
                    else if last & (offset >= 56) {
                        length_bytes[length_index]
                    } else { 0 };
                // Four constrained bytes fit in u32; Field arithmetic avoids
                // separate bitwise/overflow gadgets for each intermediate byte.
                packed = packed * 256 + value as Field;
            }
            words[word] = packed as u32;
        }
        state = std::hash::sha256_compression(words, state);
        if last { result = state; }
    }
    let mut output = [0u8;32];
    for word in 0..8 {
        let bytes: [u8;4] = (result[word] as Field).to_be_bytes();
        for byte in 0..4 { output[word*4+byte] = bytes[byte]; }
    }
    output
}
