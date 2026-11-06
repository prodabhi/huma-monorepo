// Bounded byte strings preserve the native UTF-8 and JSONEncoder representation.
pub struct Bytes<let N: u32> {
    pub data: [u8; N],
    pub len: u32,
}

impl<let N: u32> Bytes<N> {
    pub fn empty() -> Self { Self { data: [0; N], len: 0 } }
    pub fn fixed(data: [u8; N]) -> Self { Self { data, len: N } }
    pub fn check(self) {
        assert(self.len <= N);
        for i in 0..N { if i >= self.len { assert(self.data[i] == 0); } }
    }
    pub fn push(mut self, byte: u8) -> Self {
        assert(self.len < N);
        self.data[self.len] = byte;
        self.len += 1;
        self
    }
    pub fn add<let M: u32>(mut self, other: Bytes<M>) -> Self {
        assert(self.len + other.len <= N);
        for i in 0..M { if i < other.len { self.data[self.len + i] = other.data[i]; } }
        self.len += other.len;
        self
    }
    pub fn hash(self) -> [u8;32] { sha256::sha256_var(self.data, self.len) }
    pub fn equals<let M: u32>(self, other: Bytes<M>) -> bool {
        let mut same = self.len == other.len;
        for i in 0..N {
            let active = i < self.len;
            let index = if active & (i < M) { i } else { 0 };
            same &= !active | ((i < M) & (self.data[i] == other.data[index]));
        }
        same
    }
}

pub fn hex(value: [u8;32]) -> Bytes<64> {
    let alphabet = "0123456789abcdef".as_bytes();
    let mut result = [0u8;64];
    for i in 0..32 {
        result[2*i] = alphabet[(value[i] >> 4) as u32];
        result[2*i+1] = alphabet[(value[i] & 15) as u32];
    }
    Bytes::fixed(result)
}

unconstrained fn decimal_hint(value: u64) -> Bytes<20> {
    let mut quotient = value;
    let mut reversed = [0u8;20];
    let mut len = 1;
    for i in 0..20 {
        reversed[i] = (quotient % 10) as u8 + 48;
        if quotient > 0 { len = i + 1; }
        quotient /= 10;
    }
    let mut result = Bytes::<20>::empty();
    for i in 0..20 { if i < len { result = result.push(reversed[len - i - 1]); } }
    result
}

pub fn decimal(value: u64) -> Bytes<20> {
    // Safety: All hint bytes, length, digit ranges, canonical form and decoded
    // value are constrained below. Twenty digits cannot wrap the field modulus.
    let result = unsafe { decimal_hint(value) };
    result.check(); assert(result.len > 0);
    if result.len > 1 { assert(result.data[0] != 48); }
    let mut decoded: Field = 0;
    for i in 0..20 {
        if i < result.len {
            let b = result.data[i]; assert((b >= 48) & (b <= 57));
            decoded = decoded * 10 + (b as Field - 48);
        }
    }
    // At most 20 decimal digits is far below the BN254 modulus, so equality
    // cannot wrap. The hint cannot choose different digits or leading zeroes.
    assert(decoded == value as Field);
    result
}

pub fn boolean(value: bool) -> Bytes<5> {
    if value { Bytes::<5>::empty().add(Bytes::fixed("true".as_bytes())) }
    else { Bytes::fixed("false".as_bytes()) }
}

// A JSON string-array field, including native forward-slash escaping.
pub fn field<let N: u32, let M: u32>(input: Bytes<N>, mut cursor: u32, value: Bytes<M>, first: bool) -> u32 {
    if !first { assert(input.data[cursor] == 44); cursor += 1; }
    assert(input.data[cursor] == 34); cursor += 1;
    for i in 0..M {
        if i < value.len {
            let b = value.data[i];
            if (b == 34) | (b == 92) | (b == 47) {
                assert(input.data[cursor] == 92); assert(input.data[cursor+1] == b); cursor += 2;
            }
            else if (b == 8) | (b == 9) | (b == 10) | (b == 12) | (b == 13) {
                let escaped = if b == 8 { 98 } else if b == 9 { 116 } else if b == 10 { 110 } else if b == 12 { 102 } else { 114 };
                assert(input.data[cursor] == 92); assert(input.data[cursor+1] == escaped); cursor += 2;
            }
            else if b < 32 {
                let alphabet = "0123456789abcdef".as_bytes();
                assert(input.data[cursor] == 92); assert(input.data[cursor+1] == 117);
                assert(input.data[cursor+2] == 48); assert(input.data[cursor+3] == 48);
                assert(input.data[cursor+4] == alphabet[(b >> 4) as u32]);
                assert(input.data[cursor+5] == alphabet[(b & 15) as u32]); cursor += 6;
            } else { assert(input.data[cursor] == b); cursor += 1; }
        }
    }
    assert(input.data[cursor] == 34); cursor + 1
}

pub fn json_start<let N: u32>(input: Bytes<N>) -> u32 {
    input.check(); assert(input.len >= 2); assert(input.data[0] == 91); 1
}

// Derived decimal/hex/boolean/literal fields cannot require JSON escaping.
// Keep the check explicit so accidentally passing arbitrary text fails closed.
pub fn plain_field<let N: u32, let M: u32>(input: Bytes<N>, mut cursor: u32, value: Bytes<M>, first: bool) -> u32 {
    if !first { assert(input.data[cursor] == 44); cursor += 1; }
    assert(input.data[cursor] == 34); cursor += 1;
    for i in 0..M {
        if i < value.len {
            let b = value.data[i];
            assert((b >= 32) & (b != 34) & (b != 47) & (b != 92));
            assert(input.data[cursor+i] == b);
        }
    }
    cursor += value.len;
    assert(input.data[cursor] == 34); cursor + 1
}

pub fn base64_field<let N: u32>(input: Bytes<N>, mut cursor: u32, value: Bytes<88>) -> u32 {
    assert(input.data[cursor] == 44); assert(input.data[cursor+1] == 34); cursor += 2;
    for i in 0..88 {
        let b = value.data[i];
        if b == 47 { assert(input.data[cursor] == 92); assert(input.data[cursor+1] == 47); cursor += 2; }
        else {
            assert((b >= 32) & (b != 34) & (b != 92));
            assert(input.data[cursor] == b); cursor += 1;
        }
    }
    assert(input.data[cursor] == 34); cursor + 1
}
pub fn json_end<let N: u32>(input: Bytes<N>, cursor: u32) {
    assert(cursor + 1 == input.len); assert(input.data[cursor] == 93);
}
pub fn concatenated<let N: u32, let A: u32, let B: u32>(input: Bytes<N>, first: Bytes<A>, second: Bytes<B>) {
    input.check(); assert(input.len == first.len + second.len);
    for i in 0..A { if i < first.len { assert(input.data[i] == first.data[i]); } }
    for i in 0..B { if i < second.len { assert(input.data[first.len+i] == second.data[i]); } }
}

pub fn base64_key(key: [u8;65]) -> Bytes<88> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
    let mut result = Bytes::<88>::empty();
    for i in 0..21 {
        let a = key[i*3]; let b = key[i*3+1]; let c = key[i*3+2];
        result = result.push(alphabet[(a >> 2) as u32])
            .push(alphabet[(((a & 3) << 4) | (b >> 4)) as u32])
            .push(alphabet[(((b & 15) << 2) | (c >> 6)) as u32])
            .push(alphabet[(c & 63) as u32]);
    }
    let a = key[63]; let b = key[64];
    result.push(alphabet[(a >> 2) as u32])
        .push(alphabet[(((a & 3) << 4) | (b >> 4)) as u32])
        .push(alphabet[((b & 15) << 2) as u32]).push(61)
}

pub fn utf8<let N: u32>(value: Bytes<N>) {
    value.check();
    let mut pending = 0u8;
    let mut low = 128u8;
    let mut high = 191u8;
    for i in 0..N {
        if i < value.len {
            let b = value.data[i];
            if pending > 0 {
                assert((b >= low) & (b <= high));
                pending -= 1; low = 128; high = 191;
            } else {
                if b < 128 { pending = 0; }
                else if (b >= 194) & (b <= 223) { pending = 1; }
                else if b == 224 { pending = 2; low = 160; }
                else if (b >= 225) & (b <= 236) { pending = 2; }
                else if b == 237 { pending = 2; high = 159; }
                else if (b >= 238) & (b <= 239) { pending = 2; }
                else if b == 240 { pending = 3; low = 144; }
                else if (b >= 241) & (b <= 243) { pending = 3; }
                else if b == 244 { pending = 3; high = 143; }
                else { assert(false); }
            }
        }
    }
    assert(pending == 0);
}

// Input has already been checked as valid UTF-8. Only codepoint boundaries map.
pub fn utf16_offset<let N: u32>(value: Bytes<N>, location: u32) -> u32 {
    let mut units = 0;
    let mut offset = 0;
    let mut found = false;
    for i in 0..N {
        if i < value.len {
            let b = value.data[i];
            if (b < 128) | (b >= 192) {
                if units == location { offset = i; found = true; }
                units += if b >= 240 { 2 } else { 1 };
            }
        }
    }
    if units == location { offset = value.len; found = true; }
    assert(found);
    offset
}

pub fn replace<let N: u32, let M: u32>(before: Bytes<N>, location: u32, removed: u32, inserted: Bytes<M>) -> Bytes<N> {
    let start = utf16_offset(before, location);
    let end = utf16_offset(before, location + removed);
    assert(start <= end);
    let len = start + inserted.len + before.len - end;
    assert(len <= N);
    let mut data = [0u8;N];
    for i in 0..N {
        if i < len {
            data[i] = if i < start { before.data[i] }
                else if i < start + inserted.len { inserted.data[i - start] }
                else { before.data[end + i - start - inserted.len] };
        }
    }
    Bytes { data, len }
}

pub fn canonical_length<let N: u32>(value: Bytes<N>) -> u32 {
    let mut len = 0;
    for i in 0..N { if (i < value.len) & (value.data[i] != 32) & (value.data[i] != 9) { len = i+1; } }
    len
}
