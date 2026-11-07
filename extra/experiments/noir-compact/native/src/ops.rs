use huma_replay_core::Witness;

pub const BASELINE: u8 = 1;
pub const BASELINE_END: u8 = 2;
pub const DOWN: u8 = 3;
pub const UP: u8 = 4;
pub const BEGIN: u8 = 5;
pub const LEFT: u8 = 6;
pub const RIGHT: u8 = 7;
pub const DELETE: u8 = 8;
pub const INSERT: u8 = 9;
pub const END: u8 = 10;
pub const ADVANCE: u8 = 11;
pub const FLAGS_LOW: u8 = 12;
pub const FLAGS_HIGH: u8 = 13;
pub fn word(code: u8, arg: u64) -> u64 {
    assert!(code < 64 && arg < 1u64<<56);
    ((code as u64)<<56)|arg
}
pub fn source(value: &str) -> u8 {
    match value { "typing"=>1,"paste"=>2,"composition"=>3,"dictation"=>4,
                  "replacement"=>5,"import"=>6,_=>255 }
}
fn offset(text: &[char], utf16: usize) -> Result<usize,String> {
    let mut count = 0;
    for (i,c) in text.iter().enumerate() {
        if count == utf16 { return Ok(i); }
        count += c.len_utf16();
    }
    if count == utf16 { Ok(text.len()) } else { Err("Invalid UTF16 boundary".into()) }
}

pub struct Compiled { pub words: Vec<u64>, pub capture_offsets: Vec<usize> }

/// Shared deterministic encoder for new live capture and the public-fixture adapter.
/// A rejected event leaves the complete previous transcript unchanged.
#[derive(Clone)]
pub struct Builder {
    pub words: Vec<u64>,
    pub capture_offsets: Vec<usize>,
    text: Vec<char>,
    cursor: usize,
    elapsed: u64,
    flags: u64,
    scalar_limit: usize,
    operation_limit: usize,
}
impl Builder {
    pub fn new(initial: &str, scalar_limit: usize, operation_limit: usize) -> Result<Self,String> {
        if scalar_limit==0 || scalar_limit>65535 || operation_limit>1<<20 {return Err("Invalid capture limits".into());}
        let text: Vec<char>=initial.chars().collect();
        if text.len()>scalar_limit || text.len()+1>operation_limit {return Err("Initial text exceeds compact profile".into());}
        let mut words: Vec<u64>=text.iter().map(|c|word(BASELINE,*c as u64)).collect();
        words.push(word(BASELINE_END,0));
        Ok(Self {capture_offsets:vec![words.len()],cursor:text.len(),text,words,elapsed:0,flags:0,scalar_limit,operation_limit})
    }
    pub fn text(&self)->String {self.text.iter().collect()}
    pub fn elapsed(&self)->u64 {self.elapsed}
    pub fn captures(&self)->usize {self.capture_offsets.len()-1}
    fn delta(&self,next: u64,limit: u64)->Result<(Vec<u64>,u64),String> {
        let mut delta=next.checked_sub(self.elapsed).ok_or("Capture time moved backwards")?;
        let mut words=Vec::new();
        while delta>limit {
            let advance=(delta-limit).min((1u64<<56)-1);
            words.push(word(ADVANCE,advance));delta-=advance;
        }
        Ok((words,delta))
    }
    fn append(&mut self,words: Vec<u64>,elapsed: u64)->Result<(),String> {
        if words.len()>self.operation_limit-self.words.len() {return Err("Complete capture exceeds compact operation profile".into());}
        self.words.extend(words);self.elapsed=elapsed;self.capture_offsets.push(self.words.len());Ok(())
    }
    pub fn edit(&mut self,location: usize,removed: usize,inserted: &str,input_source: &str,next: u64)->Result<(),String> {
        let location16=u16::try_from(location).map_err(|_|"Edit location exceeds compact range")?;
        let removed16=u16::try_from(removed).map_err(|_|"Edit removal exceeds compact range")?;
        let start=offset(&self.text,location)?;
        let end=offset(&self.text,location.checked_add(removed).ok_or("Edit range overflow")?)?;
        let inserted: Vec<char>=inserted.chars().collect();
        if self.text.len()-(end-start)+inserted.len()>self.scalar_limit {return Err("Complete capture exceeds compact scalar profile".into());}
        let (mut words,delta)=self.delta(next,u16::MAX as u64)?;
        words.push(word(BEGIN,delta<<40 | (source(input_source) as u64)<<32 | (removed16 as u64)<<16 | location16 as u64));
        words.extend(std::iter::repeat_n(word(LEFT,0),self.cursor.saturating_sub(start)));
        words.extend(std::iter::repeat_n(word(RIGHT,0),start.saturating_sub(self.cursor)));
        words.extend(std::iter::repeat_n(word(DELETE,0),end-start));
        words.extend(inserted.iter().map(|c|word(INSERT,*c as u64)));words.push(word(END,0));
        self.append(words,next)?;
        let count=inserted.len();self.text.splice(start..end,inserted);self.cursor=start+count;Ok(())
    }
    pub fn sample(&mut self,kind: &str,key: u16,modifiers: u64,next: u64)->Result<(),String> {
        let code=match kind {"down"=>DOWN,"up"=>UP,_=>return Err("Unknown sample kind".into())};
        let (mut words,delta)=self.delta(next,(1u64<<40)-1)?;
        if self.flags as u32!=modifiers as u32 {words.push(word(FLAGS_LOW,modifiers as u32 as u64));}
        if self.flags>>32!=modifiers>>32 {words.push(word(FLAGS_HIGH,modifiers>>32));}
        words.push(word(code,delta<<16|key as u64));
        self.append(words,next)?;self.flags=modifiers;Ok(())
    }
}

pub fn compile(w: &Witness) -> Result<Compiled,String> {
    // Fixture adapter only: validate the original independent Swift/Rust relation.
    // This does not migrate its old signatures into the new protocol.
    huma_replay_core::replay(w).map_err(str::to_string)?;
    let s = &w.session;
    let mut builder=Builder::new(&s.initial_text,65535,65536)?;
    for record in s.capture_records.as_ref().ok_or("Missing capture records")? {
        if record.kind == "edit" {
            let e = &s.events[record.index];
            builder.edit(e.location,e.removed_length,&e.inserted_text,&e.source,e.elapsed_milliseconds)?;
        } else if record.kind == "key" {
            let sample = &s.input_samples.as_ref().ok_or("Missing samples")?[record.index];
            if sample.origin.is_some() { return Err("V3 compact fixtures cannot omit origin metadata".into()); }
            builder.sample(&sample.kind,sample.key_code,sample.modifiers,sample.elapsed_milliseconds)?;
        } else { return Err("Unsupported V3 compact capture kind".into()); }
    }
    if builder.text().as_bytes() != w.text.as_bytes() { return Err("Native edit replay differs".into()); }
    Ok(Compiled { words:builder.words,capture_offsets:builder.capture_offsets })
}

#[derive(Clone,Debug,PartialEq)]
pub struct Prefix {
    pub phase: u8, pub elapsed: u64, pub edits: u32, pub samples: u32,
    pub typing: u32, pub paste: u32, pub initial_bytes: u32,
}
pub struct Replayed { pub text: String, pub prefixes: Vec<Prefix>, pub baseline_end: usize }
fn need(value: bool) -> Result<(),String> { if value { Ok(()) } else { Err("Invalid compact operation".into()) } }
fn scalar(arg: u64) -> Result<char,String> { u32::try_from(arg).ok().and_then(char::from_u32).ok_or("Invalid scalar".into()) }

pub fn replay(words: &[u64], capacity: usize) -> Result<Replayed,String> {
    let mut buffer = vec!['\0';capacity];
    let (mut left,mut right) = (0usize,capacity);
    let (mut cursor,mut total,mut target,mut remaining) = (0usize,0usize,0usize,0usize);
    let mut p = Prefix { phase:0,elapsed:0,edits:0,samples:0,typing:0,paste:0,initial_bytes:0 };
    let mut prefixes = vec![p.clone()];
    let mut baseline_end = 0;
    let mut edit_source = 0;
    for (i,w) in words.iter().enumerate() {
        need(*w < 1u64<<62)?;
        let code = (w>>56) as u8; let arg = w & ((1u64<<56)-1);
        match code {
            BASELINE => {
                need(p.phase==0 && left<right)?; let c=scalar(arg)?;
                buffer[left]=c;left+=1; cursor+=c.len_utf16();total+=c.len_utf16();
                p.initial_bytes+=c.len_utf8() as u32;
            },
            BASELINE_END => { need(p.phase==0 && arg==0)?;p.phase=1;baseline_end=i+1; },
            DOWN|UP => {
                need(p.phase==1)?;p.elapsed=p.elapsed.checked_add(arg>>16).ok_or("Elapsed overflow")?;p.samples+=1;
            },
            BEGIN => {
                need(p.phase==1)?; target=(arg&65535) as usize;remaining=((arg>>16)&65535) as usize;
                edit_source=((arg>>32)&255) as u8;
                need(target<=total && remaining<=total-target && matches!(edit_source,1..=6|255))?;
                p.elapsed=p.elapsed.checked_add(arg>>40).ok_or("Elapsed overflow")?;p.phase=2;
            },
            LEFT => {
                need(arg==0 && p.phase==2 && cursor>target && left>0)?;
                left-=1;right-=1;buffer[right]=buffer[left];cursor-=buffer[right].len_utf16();
            },
            RIGHT => {
                need(arg==0 && p.phase==2 && cursor<target && right<capacity)?;
                buffer[left]=buffer[right];cursor+=buffer[left].len_utf16();left+=1;right+=1;
            },
            DELETE => {
                need(arg==0 && matches!(p.phase,2|3) && cursor==target && right<capacity)?;
                let width=buffer[right].len_utf16();need(remaining>=width)?;
                remaining-=width;total-=width;right+=1;p.phase=3;
            },
            INSERT => {
                need(matches!(p.phase,2..=4) && remaining==0 && (p.phase==4 || cursor==target) && left<right)?;
                let c=scalar(arg)?;buffer[left]=c;left+=1;cursor+=c.len_utf16();total+=c.len_utf16();p.phase=4;
            },
            END => {
                need(arg==0 && matches!(p.phase,2..=4) && remaining==0 && (p.phase==4 || cursor==target))?;
                p.phase=1;p.edits+=1;p.typing+=u32::from(edit_source==1);p.paste+=u32::from(edit_source==2);
            },
            ADVANCE => { need(p.phase==1 && arg>0)?;p.elapsed=p.elapsed.checked_add(arg).ok_or("Elapsed overflow")?; },
            FLAGS_LOW|FLAGS_HIGH => { need(p.phase==1 && arg<=u32::MAX as u64)?; },
            _ => return Err("Unknown operation".into()),
        }
        prefixes.push(p.clone());
    }
    need(p.phase==1 && baseline_end>0)?;
    let text=buffer[..left].iter().chain(buffer[right..].iter()).collect();
    Ok(Replayed {text,prefixes,baseline_end})
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn gap_replay_handles_unicode_revision_and_import() {
        let words=[word(BASELINE,'a' as u64),word(BASELINE,0x1f600),word(BASELINE,'z' as u64),word(BASELINE_END,0),
            word(BEGIN,1|(2<<16)|(2<<32)),word(LEFT,0),word(LEFT,0),word(DELETE,0),word(INSERT,0x301),word(END,0)];
        let result=replay(&words,8).unwrap();assert_eq!(result.text,"a\u{301}z");
        assert_eq!(result.prefixes.last().unwrap().paste,1);assert_eq!(result.prefixes.last().unwrap().initial_bytes,6);
    }
    #[test] fn invalid_surrogate_boundary_and_partial_edit_reject() {
        let base=[word(BASELINE,0x1f600),word(BASELINE_END,0),word(BEGIN,1|(1<<32)),word(LEFT,0),word(END,0)];
        assert!(replay(&base,8).is_err());assert!(replay(&base[..3],8).is_err());
        assert!(replay(&[word(BASELINE,0xd800),word(BASELINE_END,0)],8).is_err());
    }
    #[test] fn v3_fixture_adapter_cannot_silently_strip_new_assurance_fields() {
        let w: Witness=serde_json::from_str(include_str!("../../../../../backend/zkvm/common/tests/fixtures/presence-typed.json")).unwrap();
        assert!(compile(&w).is_err());
    }
}
