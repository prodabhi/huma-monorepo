import { readFile } from 'node:fs/promises';
import { webcrypto, createHash } from 'node:crypto';
import { derToP1363 } from '../noir-compact/browser/core.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
try {
  const bytes=await readFile(process.argv[2]);if(bytes.length>32768)throw new Error();
  const capsule=JSON.parse(bytes);
  if(capsule.kind!=='huma-media-membership-experiment-v1'||Object.keys(capsule).sort().join(',')!=='journal,kind,publicKey,signature')throw new Error();
  const decode=(s,n)=>{if(typeof s!=='string')throw new Error();const b=Buffer.from(s,'base64');if(b.toString('base64')!==s||b.length!==n)throw new Error();return b;};
  const key=decode(capsule.publicKey,65);if(key[0]!==4)throw new Error();
  const der=Buffer.from(capsule.signature,'base64');if(der.toString('base64')!==capsule.signature)throw new Error();
  const signature=derToP1363(new Uint8Array(der));
  const root=capsule.journal.sealed_root;
  if(!Array.isArray(root)||root.length!==32||root.some(n=>!Number.isInteger(n)||n<0||n>255))throw new Error();
  const publicKey=await webcrypto.subtle.importKey('raw',key,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const message=Buffer.concat([Buffer.from('HUMA_MEDIA_SEAL_SIGNATURE_V1\0'),Buffer.from(root)]);
  if(!await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,signature,message))throw new Error();
  process.stdout.write(JSON.stringify({verified:true,keyHash:hash(key)}));
}catch{process.stderr.write('Media seal signature rejected.\n');process.exitCode=1;}
