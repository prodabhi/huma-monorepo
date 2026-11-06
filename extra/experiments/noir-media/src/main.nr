// Experimental media commitment/membership relation, NOT a scene-liveness policy.
// Mandatory composite verification also checks the signature on sealed_root.
global LEAF_BYTES:u32=3072;
global DEPTH:u32=8;
global SAMPLES:u32=2;
struct Opening {len:u32,bytes:[u8;LEAF_BYTES],siblings:[[u8;32];DEPTH]}
struct Journal {
    kind:u8,profile:u8,nonce:[u8;32],capture_head:[u8;32],encoded_hash:[u8;32],
    decoded_root:[u8;32],edit_root:[u8;32],layout_hash:[u8;32],
    encoded_length:u64,decoded_length:u64,leaf_count:u32,sealed_root:[u8;32],
    challenge:[u8;32],sampled_indices:[u32;SAMPLES],
}
fn be32(value:u32)->[u8;4] {
    let mut out=[0u8;4];
    for i in 0..4 {out[i]=(value>>((3-i)*8)) as u8;}
    out
}
fn be64(value:u64)->[u8;8] {
    let mut out=[0u8;8];
    for i in 0u32..8u32 {out[i]=(value>>(((7-i)*8) as u64)) as u8;}
    out
}
fn sealed(expected:Journal)->[u8;32] {
    let mut bytes=[0u8;233];
    let domain="HUMA_MEDIA_SEAL_V1\0".as_bytes();
    for i in 0..19 {bytes[i]=domain[i];}
    bytes[19]=expected.kind;bytes[20]=expected.profile;
    for i in 0..32 {
        bytes[21+i]=expected.nonce[i];bytes[53+i]=expected.capture_head[i];
        bytes[85+i]=expected.encoded_hash[i];bytes[117+i]=expected.decoded_root[i];
        bytes[149+i]=expected.edit_root[i];bytes[181+i]=expected.layout_hash[i];
    }
    let encoded=be64(expected.encoded_length);let decoded=be64(expected.decoded_length);let count=be32(expected.leaf_count);
    for i in 0..8 {bytes[213+i]=encoded[i];bytes[221+i]=decoded[i];}
    for i in 0..4 {bytes[229+i]=count[i];}
    sha256::digest(bytes)
}
fn index(challenge:[u8;32],root:[u8;32],ordinal:u8,count:u32)->u32 {
    let domain="HUMA_MEDIA_SAMPLE_V1\0".as_bytes();
    let mut bytes=[0u8;86];
    for i in 0..21 {bytes[i]=domain[i];}
    for i in 0..32 {bytes[21+i]=challenge[i];bytes[53+i]=root[i];}
    bytes[85]=ordinal;
    let digest=sha256::digest(bytes);
    // Exact 256-bit reduction. No rounded JS integer or truncated hash hint.
    let mut result=0u32;
    for i in 0..32 {result=(result*256+digest[i] as u32)%count;}
    result
}
fn leaf(kind:u8,profile:u8,index:u32,opening:Opening)->[u8;32] {
    assert((opening.len>0)&(opening.len<=LEAF_BYTES));
    let domain="HUMA_MEDIA_LEAF_V1\0".as_bytes();
    let mut bytes=[0u8;LEAF_BYTES+30];
    bytes[0]=0;
    for i in 0..19 {bytes[1+i]=domain[i];}
    bytes[20]=kind;bytes[21]=profile;
    let position=be32(index);let length=be32(opening.len);
    for i in 0..4 {bytes[22+i]=position[i];bytes[26+i]=length[i];}
    for i in 0..LEAF_BYTES {
        if i>=opening.len {assert(opening.bytes[i]==0);}
        bytes[30+i]=opening.bytes[i];
    }
    sha256::sha256_var(bytes,30+opening.len)
}
fn parent(left:[u8;32],right:[u8;32])->[u8;32] {
    let mut bytes=[0u8;65];bytes[0]=1;
    for i in 0..32 {bytes[1+i]=left[i];bytes[33+i]=right[i];}
    sha256::digest(bytes)
}
fn main(openings:[Opening;SAMPLES],expected:pub Journal) {
    assert((expected.kind>=1)&(expected.kind<=3));
    assert(expected.profile==expected.kind);
    assert((expected.leaf_count>0)&(expected.leaf_count<=(1<<DEPTH)));
    assert((expected.encoded_length>0)&(expected.encoded_length<=536870912));
    assert((expected.decoded_length>=expected.leaf_count as u64)&
        (expected.decoded_length<=expected.leaf_count as u64*LEAF_BYTES as u64));
    assert(sealed(expected)==expected.sealed_root);
    for sample in 0..SAMPLES {
        let position=index(expected.challenge,expected.sealed_root,sample as u8,expected.leaf_count);
        assert(position==expected.sampled_indices[sample]);
        let mut root=leaf(expected.kind,expected.profile,position,openings[sample]);
        for level in 0..DEPTH {
            root=if ((position>>level)&1)==0 {parent(root,openings[sample].siblings[level])}
                else {parent(openings[sample].siblings[level],root)};
        }
        assert(root==expected.decoded_root);
    }
}
