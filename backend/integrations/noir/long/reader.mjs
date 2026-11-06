// Long-page reader for every format. Adapters supply the Poseidon2 permutation and proof
// verification; producers never supply verifier code.
//   v3 (assurance-long-v3, current): like v1, with one part and final key per text tier and the session
//      nonce bound to the capture key: format and pinned keys, part linkage from genesis to the final
//      state, the nonce, every P-256 signature and the event digest that binds them, the text, then
//      every ZK proof.
//   v1 (assurance-long-v1): the same at one tier for parts, without the nonce binding.
//   v2 (assurance-long-v2, 0.1): one proof. Its final step verifies the folded chain of parts, whose
//      keys it pins, and every capture-key signature in-circuit; the reader checks the event
//      digest, the capture key commitment, the text, and that single proof.
//   v3-passkey: a v3 page whose every approved check-in was also approved by one WebAuthn passkey. The
//      assertions are checked outside ZK, against the proven presence roots, and the writing key signed each
//      one's binding to this passkey (so no one else's passkey can be added later); the statement is v3's.
import { canonicalTextBytes, derToP1363 } from '../../../../extra/experiments/noir-compact/browser/core.mjs';
import { finalTextStatement, hash } from '../../../../extra/experiments/noir-compact/browser/final-text.mjs';

export const KIND = 'huma-long-assurance-public-proof-v1';
export const PROFILE = 'assurance-long-v1';
export const KIND2 = 'huma-long-assurance-public-proof-v2';
export const PROFILE2 = 'assurance-long-v2';
export const KIND3 = 'huma-long-assurance-public-proof-v3';
export const PROFILE3 = 'assurance-long-v3';
export const KIND3P = 'huma-long-assurance-public-proof-v3-passkey';
export const KINDS = [KIND, KIND2, KIND3, KIND3P];
// WebAuthn relying parties whose passkey check-ins a reader accepts unless the caller names others (local dev pages).
export const PASSKEY_RELYING_PARTIES = Object.freeze([Object.freeze({ id: 'huma.social', origin: 'https://huma.social' })]);
export const CAPACITY = 10000;
export const MAX_CHUNKS = 2048;
export const TIERS = [1024, 4096, 10000];
export const KEYS = { chunk: 'b9e817091fcdd28ebbd43c21b068ab9a0e776f6cafa198335e531195ca18dfeb',
  final1024: '42d690d98c77c3ad2b83d986b12a5397bd8a1c634a55a316295c5bcd631c13fd', final4096: '4d6e31a67bf2a1b294b4cce61a31764e589f7d70357b5330fc94c51a63b046df',
  final10000: '842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8' };
// v2 final keys (build/research/noir-long2, prover.mjs build). Each pins the start and fold keys in-circuit.
export const KEYS2 = { final1024: 'ccc8f6538f604edcbc026c2a04b5d7bde7bbcad6652d2184ff5db94b9fafaf51', final4096: '79315d8e8666d5922d49acf9879787c77253cae19ecca3eb7ff78e1b5fce2f16', final10000: '8c7eaff3a810517bd82ed2d7de5747ee8f8fe4f4f57b4f31db3b62f8955e7f77' };
// v3 part and final keys per text tier (build/research/noir-long3, backend/integrations/noir/long3/prover.mjs build).
export const KEYS3 = { chunk1024: '8d8a3bae78664b1b3883b94a1e361d56ee573b7102acc5c18bfd6e721490396b', final1024: 'c9ce374434fdda60af5c436336410bacc83bdadfaef034ac33432d82a1b3cc28',
  chunk4096: 'a73280bcdb84a952e6ca84bc7bcf264dcaea0ee480b3dde00933d7d123782894', final4096: '75414e8be776c623d3eca1177fa1ba2af5f094cd6605427826e0af8c1e5ee95f',
  chunk10000: 'fd0f825f50bfc0312b617bc02141c73a2691df7f444eee5ddd78b219cd3d0ba0', final10000: '842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8' };
const DEVICE = 0x48554d410801n, NONCE = 0x48554d410802n;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PROOF_BYTES = 14656, CHUNK_INPUTS = 96, FINAL_INPUTS = 1408, FINAL_INPUTS2 = 1472;
const DOMAINS = ['HUMA_LONG_ASSURANCE_CHECKPOINT_V1\0', 'HUMA_LONG_ASSURANCE_PRESENCE_V1\0'];
const PASSKEY = 'HUMA_PASSKEY_PRESENCE_V1\0', PASSKEY_BIND = 'HUMA_PASSKEY_BIND_V1\0';
// Public order of `struct Final` in prover.nr: [name, count, type].
const FINAL = [['nonce',2,'field'],['state_root',1,'field'],['capture_root',1,'field'],['origin_root',1,'field'],
  ['presence_root',1,'field'],['bound_root',1,'field'],['op_count',1,32],['raw_scalars',1,32],['canonical_scalars',1,32],
  ['raw_bytes',1,32],['canonical_bytes',1,32],['raw_commitment',1,'field'],['canonical_commitment',1,'field'],['text_capacity',1,32],
  ['initial_bytes',1,32],['edits',1,32],['samples',1,32],['typing',1,32],['paste',1,32],['start_unix',1,64],['end_unix',1,64],
  ['elapsed',1,64],['clock_back',1,'bool'],['checkpoint_count',1,32],['presence_count',1,32],['approved',1,32],['on_time',1,32],
  ['missed',1,32],['median_response',1,64],['longest_gap',1,64],['origin_present',1,32],['origin_hid',1,32],
  ['rules',9,'bool'],['policy_satisfied',1,'bool'],['event_digest',1,'field']];
// v2 appends the capture key commitment and the wallet the proof was made for (0 off-chain).
const FINAL2 = [...FINAL, ['device',1,'field'], ['owner',1,160]];
const encoder = new TextEncoder();

// Poseidon2 (BN254, t=4, d=5, 8 full + 56 partial rounds), the permutation Noir's
// Poseidon2Hasher uses. Constants from taceo-poseidon2 0.2.1 (HorizenLabs parameters).
const DIAG = ['7626475329478847982857743246276194948757851985510858890691733676098590062311','5498568565063849786384470689962419967523752476452646391422913716315471115275','148936322117705719734052984176402258788283488576388928671173547788498414613','15456385653678559339152734484033356164266089951521103188900320352052358038155'].map(BigInt);
const EXTERNAL = ['11633431549750490989983886834189948010834808234699737327785600195936805266405','17353750182810071758476407404624088842693631054828301270920107619055744005334','11575173631114898451293296430061690731976535592475236587664058405912382527658','9724643380371653925020965751082872123058642683375812487991079305063678725624','20936725237749945635418633443468987188819556232926135747685274666391889856770','6427758822462294912934022562310355233516927282963039741999349770315205779230','16782979953202249973699352594809882974187694538612412531558950864304931387798','8979171037234948998646722737761679613767384188475887657669871981433930833742','5428827536651017352121626533783677797977876323745420084354839999137145767736','507241738797493565802569310165979445570507129759637903167193063764556368390','6711578168107599474498163409443059675558516582274824463959700553865920673097','2197359304646916921018958991647650011119043556688567376178243393652789311643','4634703622846121403803831560584049007806112989824652272428991253572845447400','17008376818199175111793852447685303011746023680921106348278379453039148937791','18430784755956196942937899353653692286521408688385681805132578732731487278753','4573768376486344895797915946239137669624900197544620153250805961657870918727','10670120969725161535937685539136065944959698664551200616467222887025111751992','4731853626374224678749618809759140702342195350742653173378450474772131006181','14473527495914528513885847341981310373531349450901830749157165104135412062812','16937191362061486658876740597821783333355021670608822932942683228741190786143','5656559696428674390125424316117443507583679061659043998559560535270557939546','8897648276515725841133578021896617755369443750194849587616503841335248902806','14938684446722672719637788054570691068799510611164812175626676768545923371470','15284149043690546115252102390417391226617211133644099356880071475803043461465','2623479025068612775740107497276979457946709347831661908218182874823658838107','6809791961761836061129379546794905411734858375517368211894790874813684813988','2417620338751920563196799065781703780495622795713803712576790485412779971775','4445143310792944321746901285176579692343442786777464604312772017806735512661','1429019233589939118995503267516676481141938536269008901607126781291273208629','19874283200702583165110559932895904979843482162236139561356679724680604144459','13426632171723830006915194799390005513190035492503509233177687891041405113055','10582332261829184460912611488470654685922576576939233092337240630493625631748'].map(BigInt);
const INTERNAL = ['5624865188680173294191042415227598609140934495743721047183803859030618890703','8228252753786907198149068514193371173033070694924002912950645971088002709521','17586714789554691446538331362711502394998837215506284064347036653995353304693','12985198716830497423350597750558817467658937953000235442251074063454897365701','13480076116139680784838493959937969792577589073830107110893279354229821035984','480609231761423388761863647137314056373740727639536352979673303078459561332','19503345496799249258956440299354839375920540225688429628121751361906635419276','16837818502122887883669221005435922946567532037624537243846974433811447595173','5492108497278641078569490709794391352213168666744080628008171695469579703581','11365311159988448419785032079155356000691294261495515880484003277443744617083','13876891705632851072613751905778242936713392247975808888614530203269491723653','10660388389107698747692475159023710744797290186015856503629656779989214850043','18876318870401623474401728758498150977988613254023317877612912724282285739292','15543349138237018307536452195922365893694804703361435879256942490123776892424','2839988449157209999638903652853828318645773519300826410959678570041742458201','7566039810305694135184226097163626060317478635973510706368412858136696413063','6344830340705033582410486810600848473125256338903726340728639711688240744220','12475357769019880256619207099578191648078162511547701737481203260317463892731','13337401254840718303633782478677852514218549070508887338718446132574012311307','21161869193849404954234950798647336336709035097706159414187214758702055364571','20671052961616073313397254362345395594858011165315285344464242404604146448678','2772189387845778213446441819361180378678387127454165972767013098872140927416','3339032002224218054945450150550795352855387702520990006196627537441898997147','14919705931281848425960108279746818433850049439186607267862213649460469542157','17056699976793486403099510941807022658662936611123286147276760381688934087770','16144580075268719403964467603213740327573316872987042261854346306108421013323','15582343953927413680541644067712456296539774919658221087452235772880573393376','17528510080741946423534916423363640132610906812668323263058626230135522155749','3190600034239022251529646836642735752388641846393941612827022280601486805721','8463814172152682468446984305780323150741498069701538916468821815030498611418','16533435971270903741871235576178437313873873358463959658178441562520661055273','11845696835505436397913764735273748291716405946246049903478361223369666046634','18391057370973634202531308463652130631065370546571735004701144829951670507215','262537877325812689820791215463881982531707709719292538608229687240243203710','2187234489894387585309965540987639130975753519805550941279098789852422770021','19189656350920455659006418422409390013967064310525314160026356916172976152967','15839474183930359560478122372067744245080413846070743460407578046890458719219','1805019124769763805045852541831585930225376844141668951787801647576910524592','323592203814803486950280155834638828455175703393817797003361354810251742052','9780393509796825017346015868945480913627956475147371732521398519483580624282','14009429785059642386335012561867511048847749030947687313594053997432177705759','13749550162460745037234826077137388777330401847577727796245150843898019635981','19497187499283431845443758879472819384797584633472792651343926414232528405311','3708428802547661961864524194762556064568867603968214870300574294082023305587','1339414413482882567499652761996854155383863472782829777976929310155400981782','6396261245879814100794661157306877072718690153118140891315137894471052482309','2069661495404347929962833138824526893650803079024564477269192079629046031674','15793521554502133342917616035884588152451122589545915605459159078589855944361','17053424498357819626596285492499512504457128907932827007302385782133229252374','13658536470391360399708067455536748955260723760813498481671323619545320978896','21546095668130239633971575351786704948662094117932406102037724221634677838565','21411726238386979516934941789127061362496195649331822900487557574597304399109','1944776378988765673004063363506638781964264107780425928778257145151172817981','15590719714223718537172639598316570285163081746016049278954513732528516468773','1351266421179051765004709939353170430290500926943038391678843253157009556309','6772476224477167317130064764757502335545080109882028900432703947986275397548'].map(BigInt);
const mod = x => { x %= FIELD; return x < 0n ? x + FIELD : x; };
const pow5 = x => { const x2 = x * x % FIELD; return x2 * x2 % FIELD * x % FIELD; };
function m4(s) {
  const t0 = s[0] + s[1], t1 = s[2] + s[3], t2 = 2n * s[1] + t1, t3 = 2n * s[3] + t0;
  const t4 = 4n * t1 + t3, t5 = 4n * t0 + t2;
  return [mod(t3 + t5), mod(t5), mod(t2 + t4), mod(t4)];
}
export async function poseidon2Permute(input) {
  let s = m4(input.map(mod));
  const full = r => { s = m4(s.map((v, i) => pow5(mod(v + EXTERNAL[r * 4 + i])))); };
  for (let r = 0; r < 4; r++) full(r);
  for (const c of INTERNAL) {
    s[0] = pow5(mod(s[0] + c)); const sum = mod(s[0] + s[1] + s[2] + s[3]);
    s = s.map((v, i) => mod(v * DIAG[i] + sum));
  }
  for (let r = 4; r < 8; r++) full(r);
  return s;
}
const fail = () => { throw new Error('Long-session evidence rejected.'); };
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const fieldBytes = n => Uint8Array.from(n.toString(16).padStart(64, '0').match(/../g), x => parseInt(x, 16));
const join = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };
function base64(value, min, max = min) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3) || value.length % 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail();
  const raw = atob(value); if (raw.length < min || raw.length > max || btoa(raw) !== value) fail();
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
const base64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const exact = (o, names) => { if (!o || Array.isArray(o) || typeof o !== 'object' || Object.keys(o).length !== names.length || names.some(k => !Object.hasOwn(o, k))) fail(); return o; };
/** WebAuthn challenge for the i-th approved check-in: SHA-256("HUMA_PASSKEY_PRESENCE_V1\0" || 32-byte root). */
export async function passkeyChallenge(root) { return sha256(join(encoder.encode(PASSKEY), fieldBytes(BigInt(root)))); }
/** Message the writing key signs to bind the i-th approval to the passkey: domain || 32-byte root || SHA-256(65-byte passkey key). */
export async function passkeyBinding(root, passkeyKey) { return join(encoder.encode(PASSKEY_BIND), fieldBytes(BigInt(root)), await sha256(passkeyKey)); }
// Top-level member names of a JSON object already parsed (JSON.parse keeps only the last of a repeated name).
function topKeys(text) {
  const keys = []; let depth = 0, key = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { let k = i + 1; while (text[k] !== '"') k += text[k] === '\\' ? 2 : 1; if (depth === 1 && key) { keys.push(JSON.parse(text.slice(i, k + 1))); key = false; } i = k; }
    else if (c === '{' || c === '[') key = ++depth === 1;
    else if (c === '}' || c === ']') depth--;
    else if (c === ',' && depth === 1) key = true;
  }
  return keys;
}
function relyingParties(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 16) fail();
  return Object.freeze(list.map(rp => {
    const { id, origin } = exact(rp, ['id', 'origin']);
    if (typeof id !== 'string' || typeof origin !== 'string' || !/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(id)) fail();
    // An origin exactly as URL would write it (lowercase host, no default port, no path), read without URL: the Mac's
    // engine runs this on bare JavaScriptCore, which has none.
    const [, scheme, host, port] = /^(https|http):\/\/([a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?$/.exec(origin) ?? fail();
    if (!(scheme === 'https' || host === 'localhost') || Number(port) > 65535 || port === (scheme === 'https' ? '443' : '80') ||
        (host !== id && !host.endsWith('.' + id))) fail();
    return Object.freeze({ id, origin });
  }));
}
function fields(raw) {
  const out = []; for (let i = 0; i < raw.length; i += 32) { const n = BigInt('0x' + hex(raw.subarray(i, i + 32))); if (n >= FIELD) fail(); out.push(n); }
  return out;
}
function decimal(value) { if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,76})$/.test(value)) fail(); const n = BigInt(value); if (n >= FIELD) fail(); return n; }
export function decodeFinal(raw) {
  const layout = raw.length === FINAL_INPUTS ? FINAL : raw.length === FINAL_INPUTS2 ? FINAL2 : fail();
  const values = fields(raw); let at = 0; const j = {};
  for (const [name, count, type] of layout) {
    const items = values.slice(at, at + count).map(n => {
      if (type === 'field') return n.toString();
      if (type === 'bool') { if (n > 1n) fail(); return n === 1n; }
      if (n >= 1n << BigInt(type)) fail(); return type === 160 ? '0x' + n.toString(16).padStart(40, '0') : type === 64 ? n.toString() : Number(n);
    });
    at += count; j[name] = count === 1 && name !== 'nonce' ? items[0] : items;
  }
  return j;
}

// Public proof from the worker's signed session summary and the produced proofs (base64).
export function assembleLong(summary, chunks, final) {
  const b64 = h => btoa(String.fromCharCode(...Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))));
  return JSON.stringify({ kind: KIND, profile: PROFILE, publicKey: b64(summary.publicKeyHex),
    chunks: chunks.map(c => c.proof), chunkInputs: chunks.map(c => c.publicInputs), final: final.proof, finalInputs: final.publicInputs,
    events: summary.events, checkpointRoots: summary.checkpointRoots, presenceRoots: summary.presenceRoots,
    signatures: summary.signaturesHex.map(b64), presenceSignatures: summary.presenceSignaturesHex.map(b64), text: summary.text });
}

/** v3 public proof: every part's proof and the final one, the signed roots and their signatures. */
/** With `summary.passkey` (every approval also approved by the passkey) it is the v3-passkey kind with those assertions. */
export function assembleLong3(summary, chunks, final) {
  const f = { ...JSON.parse(assembleLong(summary, chunks, final)), kind: KIND3, profile: PROFILE3 }, p = summary.passkey;
  if (p === undefined || p === null) return JSON.stringify(f);
  return JSON.stringify({ ...f, kind: KIND3P, passkey: { publicKey: p.publicKey,
    assertions: p.assertions.map(({ authenticatorData, clientDataJSON, signature, binding }) => ({ authenticatorData, clientDataJSON, signature, binding })) } });
}
/** v2 public proof: the session's single final proof, its statement and the signed roots for the digest. */
export function assembleLong2(summary, final) {
  const b64 = h => btoa(String.fromCharCode(...Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))));
  return JSON.stringify({ kind: KIND2, profile: PROFILE2, publicKey: b64(summary.publicKeyHex), final: final.proof, finalInputs: final.publicInputs,
    events: summary.events, checkpointRoots: summary.checkpointRoots, presenceRoots: summary.presenceRoots, text: summary.text });
}
/** Commitment to an uncompressed P-256 key, as device_root in prover.nr. */
export async function deviceRoot(key, permute = poseidon2Permute) {
  const half = (from) => BigInt('0x' + hex(key.subarray(from, from + 16)));
  return hash([DEVICE, half(1), half(17), half(33), half(49)], permute);
}
/** Key of the page's on-chain record: keccak256 of its 45 statement fields, given a keccak implementation. */
export function statementBytes(finalInputs) { if (finalInputs.length !== FINAL_INPUTS2) fail(); return finalInputs.subarray(0, 45 * 32); }

export function createLongVerifier({ keys, keys2 = {}, keys3 = {}, verifyZk, permute = poseidon2Permute, passkeyRelyingParties = PASSKEY_RELYING_PARTIES }) {
  if (typeof verifyZk !== 'function' || typeof permute !== 'function' || Object.keys(KEYS).some(k => !keys?.[k])) fail();
  const parties = relyingParties(passkeyRelyingParties);
  return async function verify(source, options = {}) {
    if (!options || Array.isArray(options) || typeof options !== 'object' || Object.keys(options).some(k => !['text', 'expectedKey'].includes(k))) fail();
    if (typeof source !== 'string' || source.length > 32 * 1024 * 1024) fail();
    for (const [name, key] of Object.entries(keys)) if (hex(await sha256(key)) !== KEYS[name]) fail();
    for (const [name, key] of Object.entries(keys2)) if (hex(await sha256(key)) !== KEYS2[name]) fail();
    for (const [name, key] of Object.entries(keys3)) if (hex(await sha256(key)) !== KEYS3[name]) fail();
    const f = JSON.parse(source);
    if (f?.kind === KIND2) return verify2(f, options);
    const v3p = f?.kind === KIND3P, v3 = f?.kind === KIND3 || v3p;
    const required = ['kind', 'profile', 'publicKey', 'chunks', 'chunkInputs', 'final', 'finalInputs', 'events',
      'checkpointRoots', 'presenceRoots', 'signatures', 'presenceSignatures', ...(v3p ? ['passkey'] : [])];
    if (!f || Array.isArray(f) || typeof f !== 'object' || required.some(k => !Object.hasOwn(f, k)) ||
        Object.keys(f).some(k => ![...required, 'text'].includes(k)) || f.kind !== (v3p ? KIND3P : v3 ? KIND3 : KIND) || f.profile !== (v3 ? PROFILE3 : PROFILE)) fail();
    if (!Array.isArray(f.chunks) || !Array.isArray(f.chunkInputs) || f.chunks.length < 1 || f.chunks.length > MAX_CHUNKS ||
        f.chunkInputs.length !== f.chunks.length) fail();
    // 1. Chain: genesis first, each end root starts the next chunk, the last ends at the final state.
    const chunkInputs = f.chunkInputs.map(v => base64(v, CHUNK_INPUTS)), finalInputs = base64(f.finalInputs, FINAL_INPUTS);
    const links = chunkInputs.map(fields);
    links.forEach(([, , genesis], i) => { if (genesis !== (i === 0 ? 1n : 0n)) fail(); });
    for (let i = 1; i < links.length; i++) if (links[i][0] !== links[i - 1][1]) fail();
    const j = decodeFinal(finalInputs);
    if (BigInt(j.state_root) !== links.at(-1)[1] || j.nonce.some(n => BigInt(n) >= 1n << 128n) || j.canonical_scalars < 1 ||
        !TIERS.includes(j.text_capacity) || j.raw_scalars > j.text_capacity || j.canonical_scalars > j.raw_scalars || j.canonical_bytes > j.raw_bytes ||
        j.approved < 1 || j.missed !== j.presence_count - j.on_time || j.checkpoint_count < 2 || j.origin_hid > j.origin_present ||
        j.origin_present > j.samples || BigInt(j.start_unix) > 253402300799999n || BigInt(j.end_unix) > 253402300799999n) fail();
    // 2. Signatures: every signed root, in order, reproduces the circuit's event digest.
    if (typeof f.events !== 'string' || !/^[12]+$/.test(f.events) || !Array.isArray(f.checkpointRoots) || !Array.isArray(f.presenceRoots)) fail();
    const kinds = [...f.events].map(Number);
    const roots = [f.checkpointRoots.map(decimal), f.presenceRoots.map(decimal)];
    if (roots[0].length !== j.checkpoint_count || roots[1].length !== j.approved || kinds.length !== roots[0].length + roots[1].length ||
        kinds.filter(k => k === 1).length !== roots[0].length || kinds.at(-1) !== 1) fail();
    const key = base64(f.publicKey, 65); if (key[0] !== 4) fail();
    const keyHash = hex(await sha256(key));
    if (Object.hasOwn(options, 'expectedKey') && options.expectedKey !== keyHash) fail();
    const publicKey = await crypto.subtle.importKey('raw', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    // v3: the session nonce commits to this key, so these roots can't be signed again by another key and shown as its page.
    if (v3 && BigInt(j.nonce[1]) !== await hash([NONCE, await deviceRoot(key, permute), BigInt(j.nonce[0])], permute) % (1n << 128n)) fail();
    for (const [i, signatures] of [f.signatures, f.presenceSignatures].entries()) {
      if (!Array.isArray(signatures) || signatures.length !== roots[i].length) fail();
      for (let k = 0; k < signatures.length; k++)
        if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, derToP1363(base64(signatures[k], 8, 72)),
          join(encoder.encode(DOMAINS[i]), fieldBytes(roots[i][k])))) fail();
    }
    // v3-passkey: one passkey approved each approved check-in, in order (WebAuthn assertions, all or nothing).
    const passkeyKeyHash = v3p ? await verifyPasskey(f.passkey, roots[1], j.approved, publicKey) : undefined;
    let digest = 0n; const next = [0, 0];
    for (const kind of kinds) digest = await hash([0x48554d410703n, digest, BigInt(kind), roots[kind - 1][next[kind - 1]++]], permute);
    if (digest !== BigInt(j.event_digest)) fail();
    // 3. Text: the reader's own copy (and any embedded copy) must match both commitments.
    let canonicalBytes, compared = false;
    for (const [o, name] of [[f, 'text'], [options, 'text']]) if (Object.hasOwn(o, name)) {
      if (typeof o[name] !== 'string') fail();
      const master = encoder.encode(o[name]), mine = await finalTextStatement(master, j.text_capacity, permute);
      if (mine.canonical_commitment !== j.canonical_commitment || mine.canonical_scalars !== j.canonical_scalars ||
          mine.canonical_bytes !== j.canonical_bytes) fail();
      canonicalBytes = canonicalTextBytes(o[name]); compared = true;
    }
    if (!compared) fail();
    // 4. Every proof, against the pinned keys: v3 parts and final at the statement's text tier.
    const partKey = v3 ? keys3['chunk' + j.text_capacity] : keys.chunk, finalKey = v3 ? keys3['final' + j.text_capacity] : keys['final' + j.text_capacity];
    if (!partKey || !finalKey) fail();
    const proofs = f.chunks.map(p => base64(p, PROOF_BYTES));
    for (let i = 0; i < proofs.length; i++) if (await verifyZk(proofs[i], chunkInputs[i], partKey) !== true) fail();
    if (await verifyZk(base64(f.final, PROOF_BYTES), finalInputs, finalKey) !== true) fail();
    const nonce = join(fieldBytes(BigInt(j.nonce[0])).subarray(16), fieldBytes(BigInt(j.nonce[1])).subarray(16));
    return { verified: true, experimental: true, profile: v3 ? PROFILE3 : PROFILE, journal: j, keyHash, chunks: proofs.length,
      contentHash: hex(await sha256(canonicalBytes)), byteLength: canonicalBytes.length,
      sessionBinding: hex(await sha256(join(encoder.encode('huma-long-session-binding-v1\0'), nonce))),
      checkpointBinding: roots[0].at(-1).toString(16).padStart(64, '0'),
      proofIdentity: hex(await sha256(join(encoder.encode(v3 ? 'HUMA_LONG_ASSURANCE_ID_V3\0' : 'HUMA_LONG_ASSURANCE_ID_V1\0'), fieldBytes(BigInt(j.state_root)), finalInputs, key))),
      signaturesVerified: roots[0].length, presenceSignaturesVerified: roots[1].length, textCompared: true,
      attestationVerified: false, trustedTime: false, humanAuthorshipProven: false, ...(v3p ? { passkeyVerified: true, passkeyKeyHash } : {}) };
  };
  async function verifyPasskey(p, roots, approved, writer) {
    const { publicKey, assertions } = exact(p, ['publicKey', 'assertions']);
    if (!Array.isArray(assertions) || assertions.length !== approved || assertions.length !== roots.length) fail();
    const raw = base64(publicKey, 65); if (raw[0] !== 4) fail();
    const key = await crypto.subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const rpHashes = await Promise.all(parties.map(rp => sha256(encoder.encode(rp.id)).then(hex)));
    let count = 0;
    for (let i = 0; i < roots.length; i++) {
      const a = exact(assertions[i], ['authenticatorData', 'clientDataJSON', 'signature', 'binding']);
      const authData = base64(a.authenticatorData, 37, 1024), clientData = base64(a.clientDataJSON, 2, 4096), signature = base64(a.signature, 8, 72);
      // The writing key bound this approval to this passkey.
      if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, writer, derToP1363(base64(a.binding, 8, 72)), await passkeyBinding(roots[i], raw))) fail();
      let c, names; try { const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(clientData); c = JSON.parse(text); names = topKeys(text); } catch { fail(); }
      if (!c || Array.isArray(c) || typeof c !== 'object' || names.length !== Object.keys(c).length || new Set(names).size !== names.length ||
          c.type !== 'webauthn.get' || typeof c.challenge !== 'string' ||
          c.challenge !== base64url(await passkeyChallenge(roots[i])) || (Object.hasOwn(c, 'crossOrigin') && c.crossOrigin !== false)) fail();
      // The relying party is the one whose origin signed in, and the authenticator scoped the key to that party's id.
      const party = parties.findIndex(rp => rp.origin === c.origin);
      if (party < 0 || hex(authData.subarray(0, 32)) !== rpHashes[party] || (authData[32] & 0x05) !== 0x05) fail();
      // Signature counter, as the recorder enforces it: a non-zero counter must exceed the highest seen so far (0 = none kept).
      const counter = new DataView(authData.buffer, authData.byteOffset, authData.length).getUint32(33);
      if (counter) { if (counter <= count) fail(); count = counter; }
      if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToP1363(signature), join(authData, await sha256(clientData)))) fail();
    }
    return hex(await sha256(raw));
  }
  async function verify2(f, options) {
    const required = ['kind', 'profile', 'publicKey', 'final', 'finalInputs', 'events', 'checkpointRoots', 'presenceRoots'];
    if (!f || Array.isArray(f) || typeof f !== 'object' || required.some(k => !Object.hasOwn(f, k)) ||
        Object.keys(f).some(k => ![...required, 'text'].includes(k)) || f.profile !== PROFILE2) fail();
    const finalInputs = base64(f.finalInputs, FINAL_INPUTS2), j = decodeFinal(finalInputs);
    const key2 = keys2['final' + j.text_capacity]; if (!key2) fail();
    if (j.nonce.some(n => BigInt(n) >= 1n << 128n) || j.canonical_scalars < 1 ||
        !TIERS.includes(j.text_capacity) || j.raw_scalars > j.text_capacity || j.canonical_scalars > j.raw_scalars || j.canonical_bytes > j.raw_bytes ||
        j.approved < 1 || j.missed !== j.presence_count - j.on_time || j.checkpoint_count < 2 || j.origin_hid > j.origin_present ||
        j.origin_present > j.samples || BigInt(j.start_unix) > 253402300799999n || BigInt(j.end_unix) > 253402300799999n) fail();
    // 1. Capture key: the proof's commitment must be this key (its signatures were checked in-circuit).
    const key = base64(f.publicKey, 65); if (key[0] !== 4) fail();
    const keyHash = hex(await sha256(key));
    if (Object.hasOwn(options, 'expectedKey') && options.expectedKey !== keyHash) fail();
    await crypto.subtle.importKey('raw', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']); // a point on the curve
    if (await deviceRoot(key, permute) !== BigInt(j.device)) fail();
    // 2. Signed roots, in order, reproduce the event digest (so the last checkpoint root is known).
    if (typeof f.events !== 'string' || !/^[12]+$/.test(f.events) || !Array.isArray(f.checkpointRoots) || !Array.isArray(f.presenceRoots)) fail();
    const kinds = [...f.events].map(Number), roots = [f.checkpointRoots.map(decimal), f.presenceRoots.map(decimal)];
    if (roots[0].length !== j.checkpoint_count || roots[1].length !== j.approved || kinds.length !== roots[0].length + roots[1].length ||
        kinds.filter(k => k === 1).length !== roots[0].length || kinds.at(-1) !== 1) fail();
    let digest = 0n; const next = [0, 0];
    for (const kind of kinds) digest = await hash([0x48554d410703n, digest, BigInt(kind), roots[kind - 1][next[kind - 1]++]], permute);
    if (digest !== BigInt(j.event_digest)) fail();
    // 3. Text, as v1.
    let canonicalBytes, compared = false;
    for (const [o, name] of [[f, 'text'], [options, 'text']]) if (Object.hasOwn(o, name)) {
      if (typeof o[name] !== 'string') fail();
      const master = encoder.encode(o[name]), mine = await finalTextStatement(master, j.text_capacity, permute);
      if (mine.canonical_commitment !== j.canonical_commitment || mine.canonical_scalars !== j.canonical_scalars ||
          mine.canonical_bytes !== j.canonical_bytes) fail();
      canonicalBytes = canonicalTextBytes(o[name]); compared = true;
    }
    if (!compared) fail();
    // 4. The one proof.
    if (await verifyZk(base64(f.final, PROOF_BYTES), finalInputs, key2) !== true) fail();
    const nonce = join(fieldBytes(BigInt(j.nonce[0])).subarray(16), fieldBytes(BigInt(j.nonce[1])).subarray(16));
    return { verified: true, experimental: true, profile: PROFILE2, journal: j, keyHash, chunks: null,
      contentHash: hex(await sha256(canonicalBytes)), byteLength: canonicalBytes.length,
      sessionBinding: hex(await sha256(join(encoder.encode('huma-long-session-binding-v1\0'), nonce))),
      checkpointBinding: roots[0].at(-1).toString(16).padStart(64, '0'),
      proofIdentity: hex(await sha256(join(encoder.encode('HUMA_LONG_ASSURANCE_ID_V2\0'), fieldBytes(BigInt(j.state_root)), finalInputs, key))),
      signaturesVerified: roots[0].length, presenceSignaturesVerified: roots[1].length, textCompared: true,
      statementKey: statementBytes(finalInputs), attestationVerified: false, trustedTime: false, humanAuthorshipProven: false };
  }
}

// Browser adapter: runs only inside the dedicated verification worker.
// Loading the checker (seven keys and the 10 MB WebAssembly engine) is most of a reader's wait, so a page starts it
// while it's still downloading the proof: prepareLongInline() loads it all at once, and verifyLongInline() uses it.
let prepared;
const inWorker = () => typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
export function prepareLongInline() {
  if (!inWorker()) throw new Error('A dedicated verification worker is required.');
  prepared ??= (async () => {
    const [{ loadAsset }, { loadAsset: loadCrypto }, { createWasmVerifier }] = await Promise.all([
      import('../../../../extra/experiments/noir-compact/browser/assurance-profile.mjs'), import('../../../../extra/experiments/noir-compact/browser/profile.mjs'),
      import('../../../../extra/experiments/noir-compact/browser/wasm.mjs')]);
    const names = Object.keys(KEYS), names2 = Object.keys(KEYS2), names3 = Object.keys(KEYS3);
    const [loaded, loaded2, loaded3, backend] = await Promise.all([Promise.all(names.map(n => loadAsset('long-' + n + '.vk'))),
      Promise.all(names2.map(n => loadAsset('long2-' + n + '.vk'))), Promise.all(names3.map(n => loadAsset('long3-' + n + '.vk'))),
      loadCrypto('g2.dat').then(createWasmVerifier)]);
    return { keys: Object.fromEntries(names.map((n, i) => [n, loaded[i]])), keys2: Object.fromEntries(names2.map((n, i) => [n, loaded2[i]])),
      keys3: Object.fromEntries(names3.map((n, i) => [n, loaded3[i]])), backend };
  })();
  prepared.catch(() => { prepared = undefined; });
  return prepared;
}
export async function verifyLongInline(source, options, { passkeyRelyingParties } = {}) {
  if (!inWorker()) throw new Error('A dedicated verification worker is required.');
  const { keys, keys2, keys3, backend } = await prepareLongInline();
  prepared = undefined; // the engine is closed below, so a later check loads a fresh one
  try { return await createLongVerifier({ keys, keys2, keys3, verifyZk: backend.verify, passkeyRelyingParties })(source, options); }
  finally { await backend.destroy(); }
}

// Node adapter: pinned keys from the reader assets and the single-threaded WASM verifier.
export async function verifyLongNode(source, options, { passkeyRelyingParties } = {}) {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const { createWasmVerifier } = await import('../../../../extra/experiments/noir-compact/browser/wasm.mjs');
  const { checkAsset } = await import('../../../../extra/experiments/noir-compact/browser/profile.mjs');
  const asset = name => new URL('../../../../extra/experiments/noir-compact/browser/assets/' + name, import.meta.url);
  const load = (prefix, names) => Promise.all(names.map(async n => [n, new Uint8Array(await readFile(asset(prefix + n + '.vk')))]));
  const keys = Object.fromEntries(await load('long-', Object.keys(KEYS))), keys2 = Object.fromEntries(await load('long2-', Object.keys(KEYS2)));
  const keys3 = Object.fromEntries(await load('long3-', Object.keys(KEYS3)));
  const g2 = new Uint8Array(await readFile(asset('g2.dat')));
  const wasm = asset('barretenberg-threads.wasm'); await checkAsset('barretenberg-threads.wasm', new Uint8Array(await readFile(wasm)));
  const backend = await createWasmVerifier(g2, fileURLToPath(wasm));
  try { return await createLongVerifier({ keys, keys2, keys3, verifyZk: backend.verify, passkeyRelyingParties })(source, options); }
  finally { await backend.destroy(); }
}
