"""Equivalent gated state-machine predicates, with explicit unsigned bounds."""
import bounded_replay
def optimize(source):
    source=bounded_replay.optimize(source)
    def once(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError('Review changed state machine before optimizing')
        source=source.replace(old,new)
    once('fn time(previous:Field,delta:u64)->Field',
        'fn gated17(active:bool,v:Field) {(if active {v}else{0}).assert_max_bit_size::<17>();}\n'
        'fn time(previous:Field,delta:u64)->Field')
    once('let write=if (code==1)|(code==9) {arg as u32}else{read};',
        'let scalar_op=(code==1)|(code==9);\n'
        '        let scalar_field=if scalar_op {arg as Field}else{0};scalar_field.assert_max_bit_size::<21>();\n'
        '        let scalar=scalar_field as u32;\n'
        '        assert((scalar<=0x10ffff)&!((scalar>=0xd800)&(scalar<=0xdfff)));\n'
        '        let write=if scalar_op {scalar}else{read};')
    old='''        assert(!baseline | ((phase==0)&(left<right)));
        let scalar_ok=(arg<=0x10ffff)&!((arg>=0xd800)&(arg<=0xdfff));
        assert(!(baseline|insertion) | scalar_ok);
        assert(!baseline_done | (phase==0));
        assert(!(baseline_done|move_l|move_r|deletion|end) | (arg==0));
        assert(!(sample|begin|advance|flags) | (phase==1));
        assert(!begin | ((location+removed<=total)&(((next_source>=1)&(next_source<=6))|(next_source==255))));
        assert(!move_l | ((phase==2)&(cursor>target)&(left>0)));
        assert(!move_r | ((phase==2)&(cursor<target)&(right<SCALARS)));
        assert(!deletion | (((phase==2)|(phase==3))&(cursor==target)&(right<SCALARS)&(remaining>=width(read))));
        assert(!insertion | ((phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(cursor==target))&(left<right)));
        assert(!end | ((phase>=2)&(phase<=4)&(remaining==0)&((phase==4)|(cursor==target))));
        assert(!advance | (arg>0));assert(!flags | (arg<=4294967295));'''
    new='''        // phase is constructed from constants 0..4. Gap indices obey
        // left<=right<=SCALARS at entry and after every step.
        let p=phase as Field;let finishing=insertion|end;
        assert(((baseline|baseline_done) as Field)*p==0);
        assert(((sample|begin|advance|flags) as Field)*(p-1)==0);
        assert(((move_l|move_r) as Field)*(p-2)==0);
        assert((deletion as Field)*(p-2)*(p-3)==0);
        assert((finishing as Field)*(p-2)*(p-3)*(p-4)==0);
        assert(((baseline_done|move_l|move_r|deletion|end) as Field)*(arg as Field)==0);
        assert((deletion as Field)*(cursor as Field-target as Field)==0);
        assert((finishing as Field)*(remaining as Field)==0);
        assert((finishing as Field)*(p-4)*(cursor as Field-target as Field)==0);
        assert(!(baseline|insertion) | (left!=right));
        assert(!move_l | (left!=0));
        assert(!(move_r|deletion) | (right!=SCALARS));
        gated17(begin,total as Field-location as Field-removed as Field);
        assert(!begin | (((next_source!=0)&(next_source<=6))|(next_source==255)));
        gated17(move_l,cursor as Field-target as Field-1);
        gated17(move_r,target as Field-cursor as Field-1);
        // Checked unsigned remaining subtraction below enforces deletion capacity.
        assert(!advance | (arg!=0));
        (if flags {arg as Field}else{0}).assert_max_bit_size::<32>();'''
    once(old,new)
    # Safe-index comparisons are equivalent under the gap invariant above.
    source=source.replace('left>0','left!=0').replace('right>0','right!=0')
    source=source.replace('left<SCALARS','left!=SCALARS').replace('right<SCALARS','right!=SCALARS')
    if 'next_times[i]=' in source:
        once('next_times[i]=if (i<op_count)&((code==3)|(code==4)|(code==5))',
            '// Padding has code zero, so no key/edit can occur at i>=op_count.\n'
            '        next_times[i]=if (code==3)|(code==4)|(code==5)')
    return source
