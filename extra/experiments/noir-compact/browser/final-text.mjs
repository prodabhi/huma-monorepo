// Must match finalization_cases.circuit (TEXT_BINDING) and native text_commitment.
// The reader recomputes both commitments from the SAME UTF-8 master bytes it was given;
// a proof's commitment is never trusted on its own.
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DOMAIN=0x48554d410604n;
const fail=message=>{throw new Error(message);};
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}); // a leading BOM is content, not framing
const encoder=new TextEncoder();

export async function hash(input,permute){
  let state=[0n,0n,0n,BigInt(input.length)<<64n];
  const round=async()=>{
    state=await permute(state);
    if(!Array.isArray(state)||state.length!==4||state.some(n=>typeof n!=='bigint'||n<0n||n>=FIELD))fail('Invalid permutation result.');
  };
  for(let block=0;block<Math.floor(input.length/3);block++){
    for(let i=0;i<3;i++)state[i]=(state[i]+input[block*3+i])%FIELD;await round();
  }
  for(let i=0;i<input.length%3;i++)state[i]=(state[i]+input[Math.floor(input.length/3)*3+i])%FIELD;
  await round();return state[0];
}

function commitmentInput(scalars,capacity,canonical,count,bytes){
  const input=[DOMAIN,BigInt(capacity),canonical?1n:0n,BigInt(count),BigInt(bytes)];
  for(let w=0;w<Math.ceil(capacity/12);w++)input.push(0n);
  for(let i=0;i<count;i++)input[5+Math.floor(i/12)]+=BigInt(scalars[i])<<BigInt(21*(i%12));
  return input;
}

// Returns the statement fields a finalization proof must expose for this exact master.
export async function finalTextStatement(master,capacity,permute){
  if(!(master instanceof Uint8Array)||!Number.isInteger(capacity)||capacity<12||capacity>65535||typeof permute!=='function')fail('Invalid final-text request.');
  const text=decoder.decode(master); // throws on any invalid UTF-8
  const scalars=Array.from(text,c=>c.codePointAt(0));
  if(scalars.length>capacity)fail('Master exceeds the proven capacity.');
  let canonicalScalars=scalars.length;
  while(canonicalScalars>0&&(scalars[canonicalScalars-1]===32||scalars[canonicalScalars-1]===9))canonicalScalars--;
  if(canonicalScalars===0)fail('Empty canonical text is never provable.');
  const canonicalBytes=encoder.encode(String.fromCodePoint(...scalars.slice(0,canonicalScalars))).length;
  return {
    raw_scalars:scalars.length,canonical_scalars:canonicalScalars,raw_bytes:master.length,canonical_bytes:canonicalBytes,
    raw_commitment:(await hash(commitmentInput(scalars,capacity,false,scalars.length,master.length),permute)).toString(),
    canonical_commitment:(await hash(commitmentInput(scalars,capacity,true,canonicalScalars,canonicalBytes),permute)).toString(),
  };
}

// exact: the master is byte-for-byte the proven text. canonical: it differs at most in trailing
// ASCII space/tab, which Huma's policy ignores. Anything else does not match.
export async function matchFinalText(master,capacity,proven,permute){
  const mine=await finalTextStatement(master,capacity,permute);
  const canonical=['canonical_scalars','canonical_bytes','canonical_commitment'].every(k=>String(mine[k])===String(proven[k]));
  const exact=canonical&&['raw_scalars','raw_bytes','raw_commitment'].every(k=>String(mine[k])===String(proven[k]));
  return {exact,canonical,match:canonical};
}

export function bbPermute(api){
  const bytes=n=>Uint8Array.from(n.toString(16).padStart(64,'0').match(/../g),x=>parseInt(x,16));
  return async state=>{
    const {outputs}=await api.poseidon2Permutation({inputs:state.map(bytes)});
    return outputs.map(o=>BigInt('0x'+Array.from(o,b=>b.toString(16).padStart(2,'0')).join('')));
  };
}
