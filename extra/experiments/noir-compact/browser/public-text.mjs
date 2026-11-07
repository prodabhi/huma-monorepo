// Must match native/public_text.rs and the pinned circuit's public_text.nr.
// The caller supplies canonical UTF-8 bytes from the SAME text used for SHA-256.
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export async function publicTextCommitment(bytes,permute) {
  if(!(bytes instanceof Uint8Array)||bytes.length<1||bytes.length>1024||typeof permute!=='function')throw Error('Invalid public text.');
  const input=[0x48554d410501n,BigInt(bytes.length)];
  for(let block=0;block<34;block++){
    let word=0n;for(let i=0;i<31;i++)word=word*256n+BigInt(bytes[block*31+i]??0);input.push(word);
  }
  let state=[0n,0n,0n,BigInt(input.length)<<64n];
  async function round(){
    state=await permute(state);
    if(!Array.isArray(state)||state.length!==4||state.some(n=>typeof n!=='bigint'||n<0n||n>=FIELD))throw Error('Invalid permutation result.');
  }
  for(let block=0;block<input.length/3;block++){
    for(let i=0;i<3;i++)state[i]=(state[i]+input[block*3+i])%FIELD;await round();
  }
  // Existing Huma framing ALWAYS has a final permutation, even when N%3==0.
  await round();return state[0].toString();
}
