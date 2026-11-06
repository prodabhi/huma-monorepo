use crate::bytes::Bytes;

fn integer(der: Bytes<72>, start: u32, len: u32) -> [u8;32] {
    assert((len >= 1) & (len <= 33));
    assert(start + len <= der.len);
    let first = der.data[start];
    assert(first < 128);
    if len > 1 { assert((first != 0) | (der.data[start+1] >= 128)); }
    if len == 33 { assert(first == 0); }
    let mut value = [0u8;32];
    for i in 0..32 {
        if len == 33 { value[i] = der.data[start + i + 1]; }
        else if i + len >= 32 { value[i] = der.data[start + i + len - 32]; }
    }
    value
}

// Constrain canonical DER parsing and n-s normalization; the original DER is
// separately hashed into the checkpoint chain, including high-S signatures.
pub fn normalized(der: Bytes<72>) -> [u8;64] {
    der.check();
    assert(der.len >= 8);
    assert((der.data[0] == 48) & (der.data[1] as u32 == der.len - 2) & (der.data[2] == 2));
    let rlen = der.data[3] as u32;
    let r = integer(der, 4, rlen);
    assert(der.data[4+rlen] == 2);
    let slen = der.data[5+rlen] as u32;
    assert(6 + rlen + slen == der.len);
    let s = integer(der, 6+rlen, slen);
    let order: [u8;32] = [255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,
        188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,81];
    let mut negative = [0u8;32];
    let mut borrow = 0u16;
    for j in 0..32 {
        let i = 31-j;
        let v = order[i] as u16 + 256 - s[i] as u16 - borrow;
        negative[i] = (v % 256) as u8;
        borrow = if v < 256 { 1 } else { 0 };
    }
    assert(borrow == 0);
    let mut less = false;
    let mut equal = true;
    for i in 0..32 { less |= equal & (s[i] < negative[i]); equal &= s[i] == negative[i]; }
    let mut raw = [0u8;64];
    for i in 0..32 { raw[i] = r[i]; raw[32+i] = if less { s[i] } else { negative[i] }; }
    raw
}
