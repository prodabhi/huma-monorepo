// Experimental replay/behavior/origin component only. The Huma SDK does not
// admit these keys or interpret this bundle as a complete writing proof.
export const CHAIN_KIND='huma-replay-interaction-chain-experiment-v1';
const profiles=Object.freeze({
  'interaction64-ops12-v1':Object.freeze({operations:12,keyHash:'7d8aaa95ab9082418273f656b44ae5a37ee39038c506274a5fa81730b26c6558'}),
  'interaction256-ops12-v1':Object.freeze({operations:12,keyHash:'e4417cf3287a69d79ec01fe858bdecc4dd0d8f9f0c1ee5edaab7f00e020329a8'}),
  'interaction10000-ops120-v1':Object.freeze({operations:120,keyHash:'29a197f58aabc86761f0a1859618c4afbe9565c7d0a1b55ac7f6de44d8985c69'}),
});
const FR=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PROOF_BYTES=14656,INPUT_BYTES=672,MAX_CHUNKS=1024,MAX_JSON=24*1024*1024;
export class ChainError extends Error {
  constructor(code){super(code);this.name='ChainError';this.code=code;}
}
function need(ok,code){if(!ok)throw new ChainError(code);}
function record(value,names){
  need(value!==null&&typeof value==='object'&&!Array.isArray(value),'Format');
  const actual=Object.keys(value).sort(),expected=[...names].sort();
  need(actual.length===expected.length&&actual.every((v,i)=>v===expected[i]),'Format');
}
function base64(value,length){
  need(typeof value==='string'&&value.length===4*Math.ceil(length/3),'Format');
  need(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),'Format');
  const decoded=atob(value);need(decoded.length===length&&btoa(decoded)===value,'Format');
  return Uint8Array.from(decoded,c=>c.charCodeAt(0));
}
function field(bytes,index){
  let value=0n;for(let i=index*32;i<(index+1)*32;i++)value=value*256n+BigInt(bytes[i]);
  need(value<FR,'InvalidStatement');return value;
}
function bit(value){need(value===0n||value===1n,'InvalidStatement');return value===1n;}
function decode(inputs){
  const v=Array.from({length:21},(_,i)=>field(inputs,i));
  need(v[0]<1n<<128n&&v[1]<1n<<128n,'InvalidStatement');
  for(const i of [4,5,19,20])need(v[i]<=65536n,'InvalidStatement');
  const b={nonce:[v[0],v[1]],start:v[4],end:v[5],startRoot:v[2],endRoot:v[3],captureRoot:v[6],
    final:bit(v[7]),originRoot:v[8],rules:v.slice(9,18).map(bit),policy:bit(v[18]),present:v[19],hid:v[20]};
  need(b.start<b.end&&b.start%12n===0n&&b.hid<=b.present&&b.present<=b.end,'InvalidStatement');
  need(b.final?b.policy===b.rules.every(Boolean):!b.policy&&b.rules.every(v=>!v),'InvalidStatement');
  return b;
}
function parse(serialized){
  need(typeof serialized==='string'&&serialized.length>0&&serialized.length<=MAX_JSON,'Format');
  let bundle;try{bundle=JSON.parse(serialized);}catch{throw new ChainError('Format');}
  record(bundle,['kind','profile','chunks']);need(bundle.kind===CHAIN_KIND,'Format');
  need(typeof bundle.profile==='string'&&Object.hasOwn(profiles,bundle.profile),'UntrustedProfile');
  need(Array.isArray(bundle.chunks)&&bundle.chunks.length>0&&bundle.chunks.length<=MAX_CHUNKS,'Format');
  const profile=profiles[bundle.profile],rows=[];
  for(let i=0;i<bundle.chunks.length;i++){
    const item=bundle.chunks[i];record(item,['proof','publicInputs']);
    const proof=base64(item.proof,PROOF_BYTES),inputs=base64(item.publicInputs,INPUT_BYTES),b=decode(inputs);
    need(b.end-b.start<=BigInt(profile.operations),'InvalidStatement');
    need(b.final===(i+1===bundle.chunks.length),'Link');
    if(!b.final)need(b.end-b.start===BigInt(profile.operations),'InvalidStatement');
    if(i===0)need(b.start===0n,'Link');
    else{
      const p=rows[i-1].boundary;
      need(p.end===b.start&&p.endRoot===b.startRoot&&p.nonce.every((n,j)=>n===b.nonce[j]),'Link');
    }
    rows.push({proof,inputs,boundary:b});
  }
  return {profileId:bundle.profile,profile,rows};
}
export async function verifyInteractionChain(serialized,{backend,loadKey}){
  const {profileId,profile,rows}=parse(serialized);
  // loadKey is supplied by the verifier. A key or key hash inside a proof cannot
  // change this allowlist; even a substituted local/downloaded key is rejected.
  const key=await loadKey(profileId);need(key instanceof Uint8Array,'KeyRejected');
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',key));
  const hex=Array.from(digest,n=>n.toString(16).padStart(2,'0')).join('');
  need(hex===profile.keyHash,'KeyRejected');
  for(const row of rows)need(await backend.verify(row.proof,row.inputs,key)===true,'ProofRejected');
  const last=rows.at(-1).boundary;
  return {
    componentVerified:true,scope:'replay-behavior-origin',profile:profileId,chunks:rows.length,
    operations:Number(last.end),nonce:last.nonce.map(String),finalStateRoot:String(last.endRoot),
    captureRoot:String(last.captureRoot),originRoot:String(last.originRoot),rules:last.rules,
    policySatisfied:last.policy,originPresent:Number(last.present),originHid:Number(last.hid),
    checkpointSignaturesVerified:false,hardwareAttestationVerified:false,finalTextVerified:false,
  };
}
