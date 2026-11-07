import { canonicalTextBytes, derToP1363 } from './core.mjs';
import { ASSETS, PROFILES, PROFILE, PROFILE_V5, checkAsset, hex, sha256 } from './assurance-profile.mjs';
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const encoder = new TextEncoder(), fail = () => { throw new Error('Writing-policy evidence rejected.'); };
const join = (...parts) => { const out = new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){out.set(p,i);i+=p.length;}return out; };
const fieldBytes = value => Uint8Array.from(BigInt(value).toString(16).padStart(64,'0').match(/../g),x=>parseInt(x,16));
function base64(value, min, max=min) {
  if(typeof value!=='string'||value.length>4*Math.ceil(max/3)||value.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))fail();
  const raw=atob(value);if(raw.length<min||raw.length>max||btoa(raw)!==value)fail();return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function journal(raw,abi,selected) {
  if(raw.length!==selected.publicBytes)fail();let offset=0;
  function decode(type) {
    if(type.kind==='array')return Array.from({length:type.length},()=>decode(type.type));
    if(type.kind==='struct')return Object.fromEntries(type.fields.map(f=>[f.name,decode(f.type)]));
    if(offset+32>raw.length)fail();const n=BigInt('0x'+hex(raw.subarray(offset,offset+32)));offset+=32;if(n>=FIELD)fail();
    if(type.kind==='field')return n.toString();
    if(type.kind==='boolean'){if(n>1n)fail();return n===1n;}
    if(type.kind!=='integer'||type.sign!=='unsigned'||n>=1n<<BigInt(type.width))fail();return type.width>32?n.toString():Number(n);
  }
  const j=decode(abi),r=j.replay,count=r.checkpoint_count;
  if(offset!==raw.length||count<2||count>selected.checkpoints||j.approved<1||j.approved>j.presence_count||j.presence_count>8||
    j.origin_present>r.samples||j.origin_hid>j.origin_present||j.on_time>j.approved||j.missed!==j.presence_count-j.on_time||
    r.op_count<1||r.op_count>selected.operations||r.byte_length<1||r.raw_byte_length>selected.bytes||r.byte_length>r.raw_byte_length||r.initial_bytes>selected.bytes||
    r.captures!==r.edits+r.samples||r.samples>selected.samples||r.typing+r.paste>r.edits||r.session_nonce.some(n=>BigInt(n)>=1n<<128n)||
    BigInt(r.start_unix)>253402300799999n||BigInt(r.end_unix)>253402300799999n)fail();
  for(const roots of [r.checkpoint_roots,j.checkpoint_roots]){if(roots.length!==selected.checkpoints||roots.slice(count).some(n=>n!=='0'))fail();roots.splice(count);}
  if(j.presence_roots.length!==8||j.presence_roots.slice(j.approved).some(n=>n!=='0'))fail();j.presence_roots.splice(j.approved);
  delete r.checkpoint_count;return j;
}
export async function createAssuranceVerifier({verificationKey,journalABI,verifyZk,version=4,profile}) {
  if(version!==4&&version!==5)fail();
  profile??=version===5?PROFILE_V5:PROFILE;
  const selected=Object.hasOwn(PROFILES,profile)?PROFILES[profile]:undefined;
  if(!selected||selected.version!==version)fail();
  const kind=selected.kind,keyAsset=selected.key;
  verificationKey=await checkAsset(keyAsset,verificationKey.slice());journalABI=await checkAsset(selected.abi,journalABI.slice());
  const abi=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(journalABI));if(typeof verifyZk!=='function')fail();
  return async function verify(source,options={}) {
    if(!options||Array.isArray(options)||typeof options!=='object'||Object.keys(options).some(k=>!['text','expectedKey'].includes(k)))fail();
    if(typeof source!=='string'||source.length>65536||encoder.encode(source).length>65536)fail();
    const f=JSON.parse(source),fields=['kind','profile','proof','publicInputs','publicKey','signatures','presenceSignatures'];
    if(!f||Array.isArray(f)||typeof f!=='object'||fields.some(k=>!Object.hasOwn(f,k))||Object.keys(f).some(k=>![...fields,'text'].includes(k))||f.kind!==kind||f.profile!==profile)fail();
    const proof=base64(f.proof,14656),inputs=base64(f.publicInputs,selected.publicBytes),key=base64(f.publicKey,65),j=journal(inputs,abi,selected);
    if(key[0]!==4)fail();const keyHash=hex(await sha256(key));
    if(Object.hasOwn(options,'expectedKey')&&(typeof options.expectedKey!=='string'||options.expectedKey.length!==64||options.expectedKey!==keyHash))fail();
    let compared=false;
    for(const [o,name] of [[f,'text'],[options,'text']])if(Object.hasOwn(o,name)){
      const bytes=canonicalTextBytes(o[name]);if(bytes.length!==j.replay.byte_length||hex(await sha256(bytes))!==hex(j.replay.text_hash))fail();compared=true;
    }
    const publicKey=await crypto.subtle.importKey('raw',key,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    for(const [roots,signatures,domain] of [[j.checkpoint_roots,f.signatures,'HUMA_COMPACT_ASSURANCE_CHECKPOINT_V4\0'],
      [j.presence_roots,f.presenceSignatures,'HUMA_COMPACT_ASSURANCE_PRESENCE_V4\0']]) {
      if(!Array.isArray(signatures)||signatures.length!==roots.length)fail();
      for(let i=0;i<roots.length;i++)if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,
        derToP1363(base64(signatures[i],8,72)),join(encoder.encode(domain),fieldBytes(roots[i]))))fail();
    }
    if(await verifyZk(proof,inputs,verificationKey)!==true)fail();
    const vk=Uint8Array.from(ASSETS[keyAsset].sha256.match(/../g),x=>parseInt(x,16));
    return {verified:true,experimental:true,version,profile,journal:j,keyHash,programKeyHash:ASSETS[keyAsset].sha256,
      proofIdentity:hex(await sha256(join(encoder.encode('HUMA_COMPACT_ASSURANCE_ID_V'+version+'\0'),vk,inputs,key))),
      signaturesVerified:f.signatures.length,presenceSignaturesVerified:f.presenceSignatures.length,
      textCompared:compared,attestationVerified:false,trustedTime:false,humanAuthorshipProven:false};
  };
}
