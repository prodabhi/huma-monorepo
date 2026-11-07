"""Lossless private-op decoding; preserve the V4 signed words and all checks."""
def optimize(source):
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('Review changed replay source before optimizing it')
        source=source.replace(old,new)
    once('struct Op {code:u8,arg:u64}','struct Op {code:u8,lo:u16,mid:u16,hi:u8,top:u16}')
    once('let o=ops[i];let code=o.code;let arg=o.arg;',
        'let o=ops[i];let code=o.code;\n'
        '        let arg=o.lo as Field+(o.mid as Field)*65536+(o.hi as Field)*4294967296+(o.top as Field)*1099511627776;\n'
        '        let sample_delta=o.mid as Field+(o.hi as Field)*65536+(o.top as Field)*16777216;\n'
        '        let scalar=(o.lo as Field+(o.mid as Field)*65536) as u32;')
    once('assert(code<64);(arg as Field).assert_max_bit_size::<56>();',
        '// Typed 16/16/8/16-bit limbs make arg an exact unsigned 56-bit integer.\n        assert(code<64);')
    once('let write=if (code==1)|(code==9) {arg as u32}else{read};',
        'let write=if (code==1)|(code==9) {scalar}else{read};')
    once('let location=(arg&65535) as u32;','let location=o.lo as u32;')
    once('let removed=((arg>>16)&65535) as u32;','let removed=o.mid as u32;')
    once('let next_source=((arg>>32)&255) as u8;','let next_source=o.hi;')
    once('let scalar_ok=(arg<=0x10ffff)&!((arg>=0xd800)&(arg<=0xdfff));',
        'let scalar_ok=(o.hi==0)&(o.top==0)&(scalar<=0x10ffff)&!((scalar>=0xd800)&(scalar<=0xdfff));')
    once('assert(!advance | (arg>0));assert(!flags | (arg<=4294967295));',
        'assert(!advance | (arg!=0));assert(!flags | ((o.hi==0)&(o.top==0)));')
    once('elapsed+=if sample {(arg>>16) as Field}else if begin {(arg>>40) as Field}else if advance {arg as Field}else{0};',
        'elapsed+=if sample {sample_delta}else if begin {o.top as Field}else if advance {arg}else{0};')
    once('let o=ops[t.offset];assert(o.code==if t.up {4}else{3});',
        'let code=ops[t.offset].code;assert(code==if t.up {4}else{3});')
    once('assert(o.arg as Field==(times[t.offset+1]-times[t.offset])*65536+t.key as Field);',
        'assert(words[t.offset]-(code as Field)*72057594037927936==(times[t.offset+1]-times[t.offset])*65536+t.key as Field);')
    return source

def inputs(values):
    for op in values['ops']:
        code=op['code'];arg=int(op['arg'])
        if not 0<=arg<1<<56:raise ValueError('Operation argument exceeds signed word framing')
        op.clear();op.update(code=code,lo=str(arg&65535),mid=str((arg>>16)&65535),hi=str((arg>>32)&255),top=str(arg>>40))
    return values
