"""Reference for a bounded experimental decoded-leaf membership statement.

Does not attest a sensor, prove decoding, or implement physical liveness checks.
All unsigned claims remain distinct from composite proof+signature acceptance.
"""
import hashlib
import struct

LEAF_BYTES=3072
DEPTH=8
SAMPLES=2
def digest(value): return hashlib.sha256(value).digest()
def leaf(kind,profile,index,data):
    if not 0<=len(data)<=LEAF_BYTES: raise ValueError('Leaf exceeds profile')
    return digest(b'\0HUMA_MEDIA_LEAF_V1\0'+bytes([kind,profile])+struct.pack('>II',index,len(data))+data)
def tree(kind,profile,leaves):
    if not 0<len(leaves)<=2**DEPTH or any(not v for v in leaves): raise ValueError('Invalid leaf count')
    level=[leaf(kind,profile,i,leaves[i] if i<len(leaves) else b'') for i in range(2**DEPTH)]
    levels=[level]
    for _ in range(DEPTH):
        level=[digest(b'\1'+level[i]+level[i+1]) for i in range(0,len(level),2)]
        levels.append(level)
    return levels
def sealed(j):
    fields=[bytes(j[k]) for k in ['nonce','capture_head','encoded_hash','decoded_root','edit_root','layout_hash']]
    return digest(b'HUMA_MEDIA_SEAL_V1\0'+bytes([j['kind'],j['profile']])+b''.join(fields)+
        struct.pack('>QQI',j['encoded_length'],j['decoded_length'],j['leaf_count']))
def indices(j):
    return [int.from_bytes(digest(b'HUMA_MEDIA_SAMPLE_V1\0'+bytes(j['challenge'])+bytes(j['sealed_root'])+bytes([i])),'big')%j['leaf_count'] for i in range(SAMPLES)]
def fixture(kind,encoded,leaves,layout,nonce,challenge):
    levels=tree(kind,kind,leaves)
    journal=dict(kind=kind,profile=kind,nonce=list(nonce),capture_head=list(digest(b'PUBLIC-SYNTHETIC-CAPTURE'+bytes([kind]))),
        encoded_hash=list(digest(encoded)),decoded_root=list(levels[-1][0]),edit_root=list(digest(b'HUMA_MEDIA_EMPTY_EDITS_V1\0')),
        layout_hash=list(digest(layout)),encoded_length=len(encoded),decoded_length=sum(map(len,leaves)),leaf_count=len(leaves))
    journal['sealed_root']=list(sealed(journal));journal['challenge']=list(challenge);journal['sampled_indices']=indices(journal)
    openings=[]
    for position in journal['sampled_indices']:
        data=leaves[position]
        openings.append(dict(len=len(data),bytes=list(data)+[0]*(LEAF_BYTES-len(data)),
            siblings=[list(levels[level][(position>>level)^1]) for level in range(DEPTH)]))
    return dict(openings=openings,expected=journal)
