"""Keep V4 semantics; avoid rechecking 32-bit overflow on every small update."""
def optimize(source):
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('Review changed geometry before optimizing')
        source=source.replace(old,new)
    once('fn time(previous:Field,delta:u64)->Field',
        '// SCALARS<=65535: gap indices fit 16 bits; UTF-16 counts fit 17.\n'
        '// These checks also reject field underflow before conversion.\n'
        'fn bounded16(v:Field)->u32 {v.assert_max_bit_size::<16>();v as u32}\n'
        'fn bounded17(v:Field)->u32 {v.assert_max_bit_size::<17>();v as u32}\n'
        'fn time(previous:Field,delta:u64)->Field')
    once('left=left+add_scalar+move_right-move_left;',
        'left=bounded16(left as Field+add_scalar as Field+move_right as Field-move_left as Field);')
    once('right=right+move_right+remove-move_left;',
        'right=bounded16(right as Field+move_right as Field+remove as Field-move_left as Field);')
    once('cursor=cursor+add_scalar*width(write)+move_right*width(read)-move_left*width(read);',
        'cursor=bounded17(cursor as Field+(add_scalar as Field)*(width(write) as Field)+(move_right as Field)*(width(read) as Field)-(move_left as Field)*(width(read) as Field));')
    once('total=total+add_scalar*width(write)-remove*width(read);',
        'total=bounded17(total as Field+(add_scalar as Field)*(width(write) as Field)-(remove as Field)*(width(read) as Field));')
    once('remaining-=remove*width(read);',
        'remaining=bounded16(remaining as Field-(remove as Field)*(width(read) as Field));')
    return source
