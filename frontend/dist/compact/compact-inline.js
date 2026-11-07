// profile.mjs
var PROFILE = "cast256-v1";
var KIND = "huma-compact-public-proof-v1";
var MAX_EXPORT_BYTES = 512 * 1024;
var ASSETS = Object.freeze({
  "cast256.vk": { bytes: 3680, sha256: "149d13f114a80bc03df8966aa5b716ba86acc383c48c620e0bdb1afb09f4b600" },
  "journal-abi.json": { bytes: 2611, sha256: "d3ac50086728791ab41503666e4f5454b9bfe30000abf2ddfefd624a7c21c952" },
  "g2.dat": { bytes: 128, sha256: "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f" },
  "barretenberg.wasm": { bytes: 10571126, sha256: "662ed50ca7275398817ae780733a9fc1ad1681776c75615cb81ecd737bca17e6" },
  "barretenberg-threads.wasm": { bytes: 10475904, sha256: "454527654830b95af0c75d639194587119f4f25e20739254c2eb7bc7c5fec5a9" }
});
var hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
var sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
async function checkAsset(name, bytes) {
  const pin = ASSETS[name];
  if (!pin || !(bytes instanceof Uint8Array) || bytes.length !== pin.bytes || hex(await sha256(bytes)) !== pin.sha256)
    throw new Error("Trusted verifier asset does not match its pin.");
  return bytes;
}
async function loadAsset(name) {
  if (!Object.hasOwn(ASSETS, name)) throw new Error("Unknown verifier asset.");
  const response = await fetch(new URL("./assets/" + name, import.meta.url), { credentials: "omit", redirect: "error" });
  if (!response.ok || !response.body) throw new Error("Local verifier asset is unavailable.");
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > ASSETS[name].bytes) throw new Error("Verifier asset exceeds its limit.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return checkAsset(name, bytes);
}

// core.mjs
var FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
var P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
var encode = new TextEncoder();
var fail = (message) => {
  throw new Error(message);
};
var join = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
var integer = (bytes) => BigInt("0x" + hex(bytes));
var fieldBytes = (value) => Uint8Array.from(BigInt(value).toString(16).padStart(64, "0").match(/../g), (x) => parseInt(x, 16));
function base64(value, min, max) {
  if (typeof value !== "string" || value.length > 4 * Math.ceil(max / 3) || value.length % 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail("Invalid public-proof encoding.");
  const raw = atob(value);
  if (raw.length < min || raw.length > max || btoa(raw) !== value) fail("Invalid public-proof length or encoding.");
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
function canonicalTextBytes(text) {
  if (typeof text !== "string" || text.length > 65536) fail("Reader text exceeds its limit.");
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 55296 && c <= 56319) {
      const next = text.charCodeAt(++i);
      if (!(next >= 56320 && next <= 57343)) fail("Text contains an invalid Unicode sequence.");
    } else if (c >= 56320 && c <= 57343) fail("Text contains an invalid Unicode sequence.");
  }
  let end = text.length;
  while (end > 0 && (text.charCodeAt(end - 1) === 32 || text.charCodeAt(end - 1) === 9)) end--;
  const bytes = encode.encode(text.slice(0, end));
  if (bytes.length > 65536) fail("Reader text exceeds its limit.");
  return bytes;
}
function derToP1363(der) {
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > 72 || der[0] !== 48 || der[1] !== der.length - 2) fail("Invalid checkpoint DER signature.");
  let offset = 2;
  const values = [];
  for (let i = 0; i < 2; i++) {
    if (der[offset++] !== 2) fail("Invalid checkpoint DER integer.");
    const size = der[offset++], end = offset + size;
    if (size < 1 || size > 33 || end > der.length || der[offset] & 128 || size > 1 && der[offset] === 0 && !(der[offset + 1] & 128)) fail("Noncanonical checkpoint DER integer.");
    const n = integer(der.subarray(offset, end));
    if (n <= 0n || n >= P256_ORDER) fail("Checkpoint signature scalar is out of range.");
    values.push(fieldBytes(n));
    offset = end;
  }
  if (offset !== der.length) fail("Trailing checkpoint signature bytes.");
  return join(...values);
}
function decodeJournal(raw, abi) {
  if (!(raw instanceof Uint8Array) || raw.length !== 1824) fail("Unexpected public-input length.");
  let offset = 0;
  function decode2(type) {
    if (type.kind === "array") return Array.from({ length: type.length }, () => decode2(type.type));
    if (type.kind === "struct") return Object.fromEntries(type.fields.map((f) => [f.name, decode2(f.type)]));
    if (offset + 32 > raw.length) fail("Truncated public inputs.");
    const n = integer(raw.subarray(offset, offset + 32));
    offset += 32;
    if (n >= FIELD) fail("Noncanonical public field.");
    if (type.kind === "field") return n.toString();
    if (type.kind === "boolean") {
      if (n > 1n) fail("Noncanonical public boolean.");
      return n === 1n;
    }
    if (type.kind !== "integer" || type.sign !== "unsigned" || n >= 1n << BigInt(type.width)) fail("Invalid public integer.");
    return type.width > 32 ? n.toString() : Number(n);
  }
  const journal = decode2(abi);
  if (offset !== raw.length) fail("Unexpected extra public inputs.");
  const count = journal.checkpoint_count;
  if (count < 2 || count > 8 || journal.checkpoint_roots.length !== 8 || journal.checkpoint_roots.slice(count).some((r) => r !== "0")) fail("Invalid checkpoint count or padding.");
  delete journal.checkpoint_count;
  journal.checkpoint_roots = journal.checkpoint_roots.slice(0, count);
  if (journal.session_nonce.some((n) => BigInt(n) >= 1n << 128n) || journal.op_count < 1 || journal.op_count > 1536 || journal.byte_length < 1 || journal.raw_byte_length > 1024 || journal.byte_length > journal.raw_byte_length || journal.initial_bytes > 1024 || journal.captures !== journal.edits + journal.samples || journal.captures > 1536 || journal.typing + journal.paste > journal.edits || BigInt(journal.start_unix) > 253402300799999n || BigInt(journal.end_unix) > 253402300799999n) fail("Public journal exceeds this profile.");
  return journal;
}
function parse(source, abi) {
  if (typeof source !== "string" || source.length > MAX_EXPORT_BYTES || encode.encode(source).length > MAX_EXPORT_BYTES) fail("Public proof exceeds 512 KiB.");
  let file;
  try {
    file = JSON.parse(source);
  } catch {
    fail("Public proof is not valid JSON.");
  }
  if (!file || Array.isArray(file) || typeof file !== "object") fail("Invalid public proof.");
  const allowed = ["kind", "profile", "proof", "publicInputs", "publicKey", "signatures", "text"];
  if (Object.keys(file).some((k) => !allowed.includes(k)) || file.kind !== KIND || file.profile !== PROFILE) fail("Unsupported public-proof format or profile.");
  const proof = base64(file.proof, 14656, 14656), inputs = base64(file.publicInputs, 1824, 1824), key = base64(file.publicKey, 65, 65);
  if (key[0] !== 4) fail("Expected an uncompressed P-256 public key.");
  const journal = decodeJournal(inputs, abi);
  if (!Array.isArray(file.signatures) || file.signatures.length !== journal.checkpoint_roots.length) fail("Every checkpoint needs its signature.");
  const signatures = file.signatures.map((s) => derToP1363(base64(s, 8, 72)));
  const text = Object.hasOwn(file, "text") ? canonicalTextBytes(file.text) : void 0;
  return { proof, inputs, key, journal, signatures, text };
}
async function createCompactVerifier({ verificationKey, journalABI, verifyZk }) {
  verificationKey = verificationKey.slice();
  journalABI = journalABI.slice();
  await checkAsset("cast256.vk", verificationKey);
  await checkAsset("journal-abi.json", journalABI);
  if (typeof verifyZk !== "function") fail("A proof verifier is required.");
  const abi = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(journalABI));
  return async function verify(source, options = {}) {
    if (!options || typeof options !== "object" || Array.isArray(options) || Object.keys(options).some((k) => !["text", "expectedKey"].includes(k))) fail("Unsupported reader option.");
    const { proof, inputs, key, journal, signatures, text } = parse(source, abi);
    const keyHash = hex(await sha256(key));
    if (Object.hasOwn(options, "expectedKey") && (typeof options.expectedKey !== "string" || !/^[a-f0-9]{64}$/.test(options.expectedKey) || options.expectedKey !== keyHash)) fail("Unexpected capture key.");
    const texts = [];
    if (text !== void 0) texts.push(text);
    if (Object.hasOwn(options, "text")) texts.push(canonicalTextBytes(options.text));
    for (const bytes of texts) if (bytes.length !== journal.byte_length || hex(await sha256(bytes)) !== hex(journal.text_hash)) fail("Reader text differs from the proven text.");
    let publicKey;
    try {
      publicKey = await crypto.subtle.importKey("raw", key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    } catch {
      fail("Invalid P-256 capture key.");
    }
    for (let i = 0; i < signatures.length; i++) {
      const message = join(encode.encode("HUMA_COMPACT_EXPERIMENT_CHECKPOINT_V3\0"), fieldBytes(journal.checkpoint_roots[i]));
      if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signatures[i], message)) fail("Checkpoint signature rejected.");
    }
    if (await verifyZk(proof, inputs, verificationKey) !== true) fail("ZK proof rejected.");
    const vkHash = Uint8Array.from(ASSETS["cast256.vk"].sha256.match(/../g), (x) => parseInt(x, 16));
    const identity = hex(await sha256(join(encode.encode("HUMA_COMPACT_EXPERIMENT_ID_V3\0"), vkHash, inputs, key)));
    return {
      verified: true,
      experimental: true,
      profile: PROFILE,
      proofIdentity: identity,
      programKeyHash: ASSETS["cast256.vk"].sha256,
      keyHash,
      journal,
      checkpointCapacity: 8,
      signaturesVerified: signatures.length,
      disclosedPublicKey: true,
      textCompared: texts.length > 0,
      attestationVerified: false,
      trustedTime: false,
      humanAuthorshipProven: false
    };
  };
}

// node_modules/@aztec/bb.js/dest/browser/retry/index.js
function* backoffGenerator() {
  const v = [1, 1, 1, 2, 4, 8, 16, 32, 64];
  let i = 0;
  while (true) {
    yield v[Math.min(i++, v.length - 1)];
  }
}
function* makeBackoff(retries) {
  for (const retry2 of retries) {
    yield retry2;
  }
}
async function retry(fn, backoff = backoffGenerator()) {
  while (true) {
    try {
      return await fn();
    } catch (err2) {
      const s = backoff.next().value;
      if (s === void 0) {
        throw err2;
      }
      await new Promise((resolve) => setTimeout(resolve, s * 1e3));
      continue;
    }
  }
}

// node_modules/@aztec/bb.js/dest/browser/crs/net_crs.js
var CRS_PRIMARY_HOST = "https://crs.aztec-cdn.foundation";
var CRS_FALLBACK_HOST = "https://crs.aztec-labs.com";
async function fetchWithFallback(primaryUrl, fallbackUrl, options) {
  try {
    const response = await fetch(primaryUrl, options);
    if (response.ok || response.status === 206) {
      return response;
    }
    throw new Error(`HTTP ${response.status}`);
  } catch {
    return await fetch(fallbackUrl, options);
  }
}
var NetCrs = class {
  numPoints;
  data;
  g2Data;
  constructor(numPoints) {
    this.numPoints = numPoints;
  }
  /**
   * Download the data.
   */
  async init() {
    await this.downloadG1Data();
    await this.downloadG2Data();
  }
  /**
   * Opens up a ReadableStream to the compressed G1 points data (32 bytes/point).
   */
  async streamG1Data() {
    const response = await this.fetchG1Data();
    return response.body;
  }
  /**
   * Opens up a ReadableStream to the G2 points data
   */
  async streamG2Data() {
    const response = await this.fetchG2Data();
    return response.body;
  }
  /**
   * Download compressed G1 data (32 bytes/point).
   * Decompression happens in C++ via SrsInitSrs.
   */
  async downloadG1Data() {
    const response = await this.fetchG1Data();
    return this.data = new Uint8Array(await response.arrayBuffer());
  }
  /**
   * Download the G2 points data.
   */
  async downloadG2Data() {
    const response2 = await this.fetchG2Data();
    return this.g2Data = new Uint8Array(await response2.arrayBuffer());
  }
  /**
   * G1 points data for prover key (compressed, 32 bytes/point).
   */
  getG1Data() {
    return this.data;
  }
  /**
   * G2 points data for verification key.
   * @returns The points data.
   */
  getG2Data() {
    return this.g2Data;
  }
  /**
   * Download compressed G1 data from CDN with S3 fallback.
   */
  async fetchG1Data() {
    if (this.numPoints === 0) {
      return new Response(new Uint8Array([]));
    }
    const g1End = this.numPoints * 32 - 1;
    const options = {
      headers: { Range: `bytes=0-${g1End}` },
      cache: "force-cache"
    };
    return await fetchWithFallback(`${CRS_PRIMARY_HOST}/g1_compressed.dat`, `${CRS_FALLBACK_HOST}/g1_compressed.dat`, options);
  }
  /**
   * Fetches the appropriate range of points from a remote source
   */
  async fetchG2Data() {
    const options = {
      cache: "force-cache"
    };
    return await retry(() => fetchWithFallback(`${CRS_PRIMARY_HOST}/g2.dat`, `${CRS_FALLBACK_HOST}/g2.dat`, options), makeBackoff([5, 5, 5]));
  }
};
var NetGrumpkinCrs = class {
  numPoints;
  data;
  constructor(numPoints) {
    this.numPoints = numPoints;
  }
  /**
   * Download the data.
   */
  async init() {
    await this.downloadG1Data();
  }
  async downloadG1Data() {
    const response = await this.fetchG1Data();
    return this.data = new Uint8Array(await response.arrayBuffer());
  }
  /**
   * Opens up a ReadableStream to the points data
   */
  async streamG1Data() {
    const response = await this.fetchG1Data();
    return response.body;
  }
  /**
   * G1 points data for prover key.
   * @returns The points data.
   */
  getG1Data() {
    return this.data;
  }
  /**
   * Fetches the appropriate range of points from a remote source
   */
  async fetchG1Data() {
    if (this.numPoints === 0) {
      return new Response(new Uint8Array([]));
    }
    const g1End = this.numPoints * 64 - 1;
    const options = {
      headers: {
        Range: `bytes=0-${g1End}`
      },
      cache: "force-cache"
    };
    return await fetchWithFallback(`${CRS_PRIMARY_HOST}/grumpkin_g1_v2.dat`, `${CRS_FALLBACK_HOST}/grumpkin_g1_v2.dat`, options);
  }
};

// node_modules/idb-keyval/dist/index.js
function promisifyRequest(request) {
  return new Promise((resolve, reject) => {
    request.oncomplete = request.onsuccess = () => resolve(request.result);
    request.onabort = request.onerror = () => reject(request.error);
  });
}
function createStore(dbName, storeName) {
  let dbp;
  const getDB = () => {
    if (dbp)
      return dbp;
    const request = indexedDB.open(dbName);
    request.onupgradeneeded = () => request.result.createObjectStore(storeName);
    dbp = promisifyRequest(request);
    dbp.then((db) => {
      db.onclose = () => dbp = void 0;
    }, () => {
      dbp = void 0;
    });
    return dbp;
  };
  return (txMode, callback) => getDB().then((db) => callback(db.transaction(storeName, txMode).objectStore(storeName)));
}
var defaultGetStoreFunc;
function defaultGetStore() {
  if (!defaultGetStoreFunc) {
    defaultGetStoreFunc = createStore("keyval-store", "keyval");
  }
  return defaultGetStoreFunc;
}
function get(key, customStore = defaultGetStore()) {
  return customStore("readonly", (store) => promisifyRequest(store.get(key)));
}
function set(key, value, customStore = defaultGetStore()) {
  return customStore("readwrite", (store) => {
    store.put(value, key);
    return promisifyRequest(store.transaction);
  });
}

// node_modules/@aztec/bb.js/dest/browser/crs/browser/cached_net_crs.js
var CachedNetCrs = class _CachedNetCrs {
  numPoints;
  g1Data;
  g2Data;
  constructor(numPoints) {
    this.numPoints = numPoints;
  }
  static async new(numPoints) {
    const crs = new _CachedNetCrs(numPoints);
    await crs.init();
    return crs;
  }
  /**
   * Download the data.
   */
  async init() {
    const g2Data = await get("g2Data");
    const g1Uncompressed = await get("g1Data");
    const uncompressedLength = this.numPoints * 64;
    if (g1Uncompressed && g1Uncompressed.length >= uncompressedLength) {
      this.g1Data = g1Uncompressed.length === uncompressedLength ? g1Uncompressed : g1Uncompressed.slice(0, uncompressedLength);
    } else {
      const netCrs = new NetCrs(this.numPoints);
      this.g1Data = await netCrs.downloadG1Data();
    }
    if (!g2Data) {
      const netCrs = new NetCrs(this.numPoints);
      this.g2Data = await netCrs.downloadG2Data();
      await set("g2Data", this.g2Data);
    } else {
      this.g2Data = g2Data;
    }
  }
  /**
   * G1 points data for prover key (compressed or uncompressed).
   */
  getG1Data() {
    return this.g1Data;
  }
  /**
   * Cache uncompressed G1 data in IndexedDB after WASM decompression.
   */
  async cacheUncompressed(data) {
    await set("g1Data", data);
  }
  /**
   * G2 points data for verification key.
   * @returns The points data.
   */
  getG2Data() {
    return this.g2Data;
  }
};
var CachedNetGrumpkinCrs = class _CachedNetGrumpkinCrs {
  numPoints;
  g1Data;
  constructor(numPoints) {
    this.numPoints = numPoints;
  }
  static async new(numPoints) {
    const crs = new _CachedNetGrumpkinCrs(numPoints);
    await crs.init();
    return crs;
  }
  /**
   * Download the data.
   */
  async init() {
    const g1Data = await get("grumpkinG1DataV2");
    const netGrumpkinCrs = new NetGrumpkinCrs(this.numPoints);
    const g1DataLength = this.numPoints * 64;
    if (!g1Data || g1Data.length < g1DataLength) {
      this.g1Data = await netGrumpkinCrs.downloadG1Data();
      await set("grumpkinG1DataV2", this.g1Data);
    } else {
      this.g1Data = g1Data;
    }
  }
  /**
   * G1 points data for prover key.
   * @returns The points data.
   */
  getG1Data() {
    return this.g1Data;
  }
};

// node_modules/msgpackr/unpack.js
var decoder;
try {
  decoder = new TextDecoder();
} catch (error) {
}
var src;
var srcEnd;
var position = 0;
var EMPTY_ARRAY = [];
var strings = EMPTY_ARRAY;
var stringPosition = 0;
var currentUnpackr = {};
var currentStructures;
var srcString;
var srcStringStart = 0;
var srcStringEnd = 0;
var bundledStrings;
var referenceMap;
var currentExtensions = [];
var dataView;
var defaultOptions = {
  useRecords: false,
  mapsAsObjects: true
};
var C1Type = class {
};
var C1 = new C1Type();
C1.name = "MessagePack 0xC1";
var sequentialMode = false;
var inlineObjectReadThreshold = 2;
var readStruct;
var onLoadedStructures;
var onSaveState;
var Unpackr = class _Unpackr {
  constructor(options) {
    if (options) {
      if (options.useRecords === false && options.mapsAsObjects === void 0)
        options.mapsAsObjects = true;
      if (options.sequential && options.trusted !== false) {
        options.trusted = true;
        if (!options.structures && options.useRecords != false) {
          options.structures = [];
          if (!options.maxSharedStructures)
            options.maxSharedStructures = 0;
        }
      }
      if (options.structures)
        options.structures.sharedLength = options.structures.length;
      else if (options.getStructures) {
        (options.structures = []).uninitialized = true;
        options.structures.sharedLength = 0;
      }
      if (options.int64AsNumber) {
        options.int64AsType = "number";
      }
    }
    Object.assign(this, options);
  }
  unpack(source, options) {
    if (src) {
      return saveState(() => {
        clearSource();
        return this ? this.unpack(source, options) : _Unpackr.prototype.unpack.call(defaultOptions, source, options);
      });
    }
    if (!source.buffer && source.constructor === ArrayBuffer)
      source = typeof Buffer !== "undefined" ? Buffer.from(source) : new Uint8Array(source);
    if (typeof options === "object") {
      srcEnd = options.end || source.length;
      position = options.start || 0;
    } else {
      position = 0;
      srcEnd = options > -1 ? options : source.length;
    }
    stringPosition = 0;
    srcStringEnd = 0;
    srcString = null;
    strings = EMPTY_ARRAY;
    bundledStrings = null;
    src = source;
    try {
      dataView = source.dataView || (source.dataView = new DataView(source.buffer, source.byteOffset, source.byteLength));
    } catch (error) {
      src = null;
      if (source instanceof Uint8Array)
        throw error;
      throw new Error("Source must be a Uint8Array or Buffer but was a " + (source && typeof source == "object" ? source.constructor.name : typeof source));
    }
    if (this instanceof _Unpackr) {
      currentUnpackr = this;
      if (this.structures) {
        currentStructures = this.structures;
        return checkedRead(options);
      } else if (!currentStructures || currentStructures.length > 0) {
        currentStructures = [];
      }
    } else {
      currentUnpackr = defaultOptions;
      if (!currentStructures || currentStructures.length > 0)
        currentStructures = [];
    }
    return checkedRead(options);
  }
  unpackMultiple(source, forEach) {
    let values, lastPosition = 0;
    try {
      sequentialMode = true;
      let size = source.length;
      let value = this ? this.unpack(source, size) : defaultUnpackr.unpack(source, size);
      if (forEach) {
        if (forEach(value, lastPosition, position) === false) return;
        while (position < size) {
          lastPosition = position;
          if (forEach(checkedRead(), lastPosition, position) === false) {
            return;
          }
        }
      } else {
        values = [value];
        while (position < size) {
          lastPosition = position;
          values.push(checkedRead());
        }
        return values;
      }
    } catch (error) {
      error.lastPosition = lastPosition;
      error.values = values;
      throw error;
    } finally {
      sequentialMode = false;
      clearSource();
    }
  }
  _mergeStructures(loadedStructures, existingStructures) {
    if (onLoadedStructures)
      loadedStructures = onLoadedStructures.call(this, loadedStructures);
    loadedStructures = loadedStructures || [];
    if (Object.isFrozen(loadedStructures))
      loadedStructures = loadedStructures.map((structure) => structure.slice(0));
    for (let i = 0, l = loadedStructures.length; i < l; i++) {
      let structure = loadedStructures[i];
      if (structure) {
        structure.isShared = true;
        if (i >= 32)
          structure.highByte = i - 32 >> 5;
      }
    }
    loadedStructures.sharedLength = loadedStructures.length;
    for (let id in existingStructures || []) {
      if (id >= 0) {
        let structure = loadedStructures[id];
        let existing = existingStructures[id];
        if (existing) {
          if (structure)
            (loadedStructures.restoreStructures || (loadedStructures.restoreStructures = []))[id] = structure;
          loadedStructures[id] = existing;
        }
      }
    }
    return this.structures = loadedStructures;
  }
  decode(source, options) {
    return this.unpack(source, options);
  }
};
function checkedRead(options) {
  try {
    if (!currentUnpackr.trusted && !sequentialMode) {
      let sharedLength = currentStructures.sharedLength || 0;
      if (sharedLength < currentStructures.length)
        currentStructures.length = sharedLength;
    }
    let result;
    if (currentUnpackr.randomAccessStructure && src[position] < 64 && src[position] >= 32 && readStruct) {
      result = readStruct(src, position, srcEnd, currentUnpackr);
      src = null;
      if (!(options && options.lazy) && result)
        result = result.toJSON();
      position = srcEnd;
    } else
      result = read();
    if (bundledStrings) {
      position = bundledStrings.postBundlePosition;
      bundledStrings = null;
    }
    if (sequentialMode)
      currentStructures.restoreStructures = null;
    if (position == srcEnd) {
      if (currentStructures && currentStructures.restoreStructures)
        restoreStructures();
      currentStructures = null;
      src = null;
      if (referenceMap)
        referenceMap = null;
    } else if (position > srcEnd) {
      throw new Error("Unexpected end of MessagePack data");
    } else if (!sequentialMode) {
      let jsonView;
      try {
        jsonView = JSON.stringify(result, (_, value) => typeof value === "bigint" ? `${value}n` : value).slice(0, 100);
      } catch (error) {
        jsonView = "(JSON view not available " + error + ")";
      }
      throw new Error("Data read, but end of buffer not reached " + jsonView);
    }
    return result;
  } catch (error) {
    if (currentStructures && currentStructures.restoreStructures)
      restoreStructures();
    clearSource();
    if (error instanceof RangeError || error.message.startsWith("Unexpected end of buffer") || position > srcEnd) {
      error.incomplete = true;
    }
    throw error;
  }
}
function restoreStructures() {
  for (let id in currentStructures.restoreStructures) {
    currentStructures[id] = currentStructures.restoreStructures[id];
  }
  currentStructures.restoreStructures = null;
}
function read() {
  let token = src[position++];
  if (token < 160) {
    if (token < 128) {
      if (token < 64)
        return token;
      else {
        let structure = currentStructures[token & 63] || currentUnpackr.getStructures && loadStructures()[token & 63];
        if (structure) {
          if (!structure.read) {
            structure.read = createStructureReader(structure, token & 63);
          }
          return structure.read();
        } else
          return token;
      }
    } else if (token < 144) {
      token -= 128;
      if (currentUnpackr.mapsAsObjects) {
        let object = {};
        for (let i = 0; i < token; i++) {
          let key = readKey();
          if (key === "__proto__")
            key = "__proto_";
          object[key] = read();
        }
        return object;
      } else {
        let map = /* @__PURE__ */ new Map();
        for (let i = 0; i < token; i++) {
          map.set(read(), read());
        }
        return map;
      }
    } else {
      token -= 144;
      let array = new Array(token);
      for (let i = 0; i < token; i++) {
        array[i] = read();
      }
      if (currentUnpackr.freezeData)
        return Object.freeze(array);
      return array;
    }
  } else if (token < 192) {
    let length = token - 160;
    if (srcStringEnd >= position) {
      return srcString.slice(position - srcStringStart, (position += length) - srcStringStart);
    }
    if (srcStringEnd == 0 && srcEnd < 140) {
      let string = length < 16 ? shortStringInJS(length) : longStringInJS(length);
      if (string != null)
        return string;
    }
    return readFixedString(length);
  } else {
    let value;
    switch (token) {
      case 192:
        return null;
      case 193:
        if (bundledStrings) {
          value = read();
          if (value > 0)
            return bundledStrings[1].slice(bundledStrings.position1, bundledStrings.position1 += value);
          else
            return bundledStrings[0].slice(bundledStrings.position0, bundledStrings.position0 -= value);
        }
        return C1;
      // "never-used", return special object to denote that
      case 194:
        return false;
      case 195:
        return true;
      case 196:
        value = src[position++];
        if (value === void 0)
          throw new Error("Unexpected end of buffer");
        return readBin(value);
      case 197:
        value = dataView.getUint16(position);
        position += 2;
        return readBin(value);
      case 198:
        value = dataView.getUint32(position);
        position += 4;
        return readBin(value);
      case 199:
        return readExt(src[position++]);
      case 200:
        value = dataView.getUint16(position);
        position += 2;
        return readExt(value);
      case 201:
        value = dataView.getUint32(position);
        position += 4;
        return readExt(value);
      case 202:
        value = dataView.getFloat32(position);
        if (currentUnpackr.useFloat32 > 2) {
          let multiplier = mult10[(src[position] & 127) << 1 | src[position + 1] >> 7];
          position += 4;
          return (multiplier * value + (value > 0 ? 0.5 : -0.5) >> 0) / multiplier;
        }
        position += 4;
        return value;
      case 203:
        value = dataView.getFloat64(position);
        position += 8;
        return value;
      // uint handlers
      case 204:
        return src[position++];
      case 205:
        value = dataView.getUint16(position);
        position += 2;
        return value;
      case 206:
        value = dataView.getUint32(position);
        position += 4;
        return value;
      case 207:
        if (currentUnpackr.int64AsType === "number") {
          value = dataView.getUint32(position) * 4294967296;
          value += dataView.getUint32(position + 4);
        } else if (currentUnpackr.int64AsType === "string") {
          value = dataView.getBigUint64(position).toString();
        } else if (currentUnpackr.int64AsType === "auto") {
          value = dataView.getBigUint64(position);
          if (value <= BigInt(2) << BigInt(52)) value = Number(value);
        } else
          value = dataView.getBigUint64(position);
        position += 8;
        return value;
      // int handlers
      case 208:
        return dataView.getInt8(position++);
      case 209:
        value = dataView.getInt16(position);
        position += 2;
        return value;
      case 210:
        value = dataView.getInt32(position);
        position += 4;
        return value;
      case 211:
        if (currentUnpackr.int64AsType === "number") {
          value = dataView.getInt32(position) * 4294967296;
          value += dataView.getUint32(position + 4);
        } else if (currentUnpackr.int64AsType === "string") {
          value = dataView.getBigInt64(position).toString();
        } else if (currentUnpackr.int64AsType === "auto") {
          value = dataView.getBigInt64(position);
          if (value >= BigInt(-2) << BigInt(52) && value <= BigInt(2) << BigInt(52)) value = Number(value);
        } else
          value = dataView.getBigInt64(position);
        position += 8;
        return value;
      case 212:
        value = src[position++];
        if (value == 114) {
          return recordDefinition(src[position++] & 63);
        } else {
          let extension = currentExtensions[value];
          if (extension) {
            if (extension.read) {
              position++;
              return extension.read(read());
            } else if (extension.noBuffer) {
              position++;
              return extension();
            } else
              return extension(src.subarray(position, ++position));
          } else
            throw new Error("Unknown extension " + value);
        }
      case 213:
        value = src[position];
        if (value == 114) {
          position++;
          return recordDefinition(src[position++] & 63, src[position++]);
        } else
          return readExt(2);
      case 214:
        return readExt(4);
      case 215:
        return readExt(8);
      case 216:
        return readExt(16);
      case 217:
        value = src[position++];
        if (srcStringEnd >= position) {
          return srcString.slice(position - srcStringStart, (position += value) - srcStringStart);
        }
        return readString8(value);
      case 218:
        value = dataView.getUint16(position);
        position += 2;
        if (srcStringEnd >= position) {
          return srcString.slice(position - srcStringStart, (position += value) - srcStringStart);
        }
        return readString16(value);
      case 219:
        value = dataView.getUint32(position);
        position += 4;
        if (srcStringEnd >= position) {
          return srcString.slice(position - srcStringStart, (position += value) - srcStringStart);
        }
        return readString32(value);
      case 220:
        value = dataView.getUint16(position);
        position += 2;
        return readArray(value);
      case 221:
        value = dataView.getUint32(position);
        position += 4;
        return readArray(value);
      case 222:
        value = dataView.getUint16(position);
        position += 2;
        return readMap(value);
      case 223:
        value = dataView.getUint32(position);
        position += 4;
        return readMap(value);
      default:
        if (token >= 224)
          return token - 256;
        if (token === void 0) {
          let error = new Error("Unexpected end of MessagePack data");
          error.incomplete = true;
          throw error;
        }
        throw new Error("Unknown MessagePack token " + token);
    }
  }
}
var validName = /^[a-zA-Z_$][a-zA-Z\d_$]*$/;
function createStructureReader(structure, firstId) {
  function readObject() {
    if (readObject.count++ > inlineObjectReadThreshold) {
      let optimizedReadObject;
      try {
        optimizedReadObject = structure.read = new Function("r", "return function(){return " + (currentUnpackr.freezeData ? "Object.freeze" : "") + "({" + structure.map((key) => key === "__proto__" ? "__proto_:r()" : validName.test(key) ? key + ":r()" : "[" + JSON.stringify(key) + "]:r()").join(",") + "})}")(read);
      } catch (error) {
        inlineObjectReadThreshold = Infinity;
        return readObject();
      }
      structure.read0 = optimizedReadObject;
      if (structure.highByte === 0)
        structure.read = createSecondByteReader(firstId, structure.read);
      return optimizedReadObject();
    }
    let object = {};
    for (let i = 0, l = structure.length; i < l; i++) {
      let key = structure[i];
      if (key === "__proto__")
        key = "__proto_";
      object[key] = read();
    }
    if (currentUnpackr.freezeData)
      return Object.freeze(object);
    return object;
  }
  readObject.count = 0;
  structure.read0 = readObject;
  if (structure.highByte === 0) {
    return createSecondByteReader(firstId, readObject);
  }
  return readObject;
}
var createSecondByteReader = (firstId, read0) => {
  return function() {
    let highByte = src[position++];
    if (highByte === 0)
      return read0();
    let id = firstId < 32 ? -(firstId + (highByte << 5)) : firstId + (highByte << 5);
    let structure = currentStructures[id] || loadStructures()[id];
    if (!structure) {
      throw new Error("Record id is not defined for " + id);
    }
    if (!structure.read)
      structure.read = createStructureReader(structure, firstId);
    return structure.read();
  };
};
function loadStructures() {
  let loadedStructures = saveState(() => {
    src = null;
    return currentUnpackr.getStructures();
  });
  return currentStructures = currentUnpackr._mergeStructures(loadedStructures, currentStructures);
}
var readFixedString = readStringJS;
var readString8 = readStringJS;
var readString16 = readStringJS;
var readString32 = readStringJS;
function readStringJS(length) {
  let result;
  if (length < 16) {
    if (result = shortStringInJS(length))
      return result;
  }
  if (length > 64 && decoder)
    return decoder.decode(src.subarray(position, position += length));
  const end = position + length;
  const units = [];
  result = "";
  while (position < end) {
    const byte1 = src[position++];
    if ((byte1 & 128) === 0) {
      units.push(byte1);
    } else if ((byte1 & 224) === 192) {
      const byte2 = src[position++] & 63;
      const codePoint = (byte1 & 31) << 6 | byte2;
      if (codePoint < 128) {
        units.push(65533);
      } else {
        units.push(codePoint);
      }
    } else if ((byte1 & 240) === 224) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      const codePoint = (byte1 & 31) << 12 | byte2 << 6 | byte3;
      if (codePoint < 2048 || codePoint >= 55296 && codePoint <= 57343) {
        units.push(65533);
      } else {
        units.push(codePoint);
      }
    } else if ((byte1 & 248) === 240) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      const byte4 = src[position++] & 63;
      let unit = (byte1 & 7) << 18 | byte2 << 12 | byte3 << 6 | byte4;
      if (unit < 65536 || unit > 1114111) {
        units.push(65533);
      } else if (unit > 65535) {
        unit -= 65536;
        units.push(unit >>> 10 & 1023 | 55296);
        unit = 56320 | unit & 1023;
        units.push(unit);
      } else {
        units.push(unit);
      }
    } else {
      units.push(65533);
    }
    if (units.length >= 4096) {
      result += fromCharCode.apply(String, units);
      units.length = 0;
    }
  }
  if (units.length > 0) {
    result += fromCharCode.apply(String, units);
  }
  return result;
}
function readArray(length) {
  let array = new Array(length);
  for (let i = 0; i < length; i++) {
    array[i] = read();
  }
  if (currentUnpackr.freezeData)
    return Object.freeze(array);
  return array;
}
function readMap(length) {
  if (currentUnpackr.mapsAsObjects) {
    let object = {};
    for (let i = 0; i < length; i++) {
      let key = readKey();
      if (key === "__proto__")
        key = "__proto_";
      object[key] = read();
    }
    return object;
  } else {
    let map = /* @__PURE__ */ new Map();
    for (let i = 0; i < length; i++) {
      map.set(read(), read());
    }
    return map;
  }
}
var fromCharCode = String.fromCharCode;
function longStringInJS(length) {
  let start = position;
  let bytes = new Array(length);
  for (let i = 0; i < length; i++) {
    const byte = src[position++];
    if ((byte & 128) > 0) {
      position = start;
      return;
    }
    bytes[i] = byte;
  }
  return fromCharCode.apply(String, bytes);
}
function shortStringInJS(length) {
  if (length < 4) {
    if (length < 2) {
      if (length === 0)
        return "";
      else {
        let a = src[position++];
        if ((a & 128) > 1) {
          position -= 1;
          return;
        }
        return fromCharCode(a);
      }
    } else {
      let a = src[position++];
      let b = src[position++];
      if ((a & 128) > 0 || (b & 128) > 0) {
        position -= 2;
        return;
      }
      if (length < 3)
        return fromCharCode(a, b);
      let c = src[position++];
      if ((c & 128) > 0) {
        position -= 3;
        return;
      }
      return fromCharCode(a, b, c);
    }
  } else {
    let a = src[position++];
    let b = src[position++];
    let c = src[position++];
    let d = src[position++];
    if ((a & 128) > 0 || (b & 128) > 0 || (c & 128) > 0 || (d & 128) > 0) {
      position -= 4;
      return;
    }
    if (length < 6) {
      if (length === 4)
        return fromCharCode(a, b, c, d);
      else {
        let e = src[position++];
        if ((e & 128) > 0) {
          position -= 5;
          return;
        }
        return fromCharCode(a, b, c, d, e);
      }
    } else if (length < 8) {
      let e = src[position++];
      let f = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0) {
        position -= 6;
        return;
      }
      if (length < 7)
        return fromCharCode(a, b, c, d, e, f);
      let g = src[position++];
      if ((g & 128) > 0) {
        position -= 7;
        return;
      }
      return fromCharCode(a, b, c, d, e, f, g);
    } else {
      let e = src[position++];
      let f = src[position++];
      let g = src[position++];
      let h = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0 || (g & 128) > 0 || (h & 128) > 0) {
        position -= 8;
        return;
      }
      if (length < 10) {
        if (length === 8)
          return fromCharCode(a, b, c, d, e, f, g, h);
        else {
          let i = src[position++];
          if ((i & 128) > 0) {
            position -= 9;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i);
        }
      } else if (length < 12) {
        let i = src[position++];
        let j = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0) {
          position -= 10;
          return;
        }
        if (length < 11)
          return fromCharCode(a, b, c, d, e, f, g, h, i, j);
        let k = src[position++];
        if ((k & 128) > 0) {
          position -= 11;
          return;
        }
        return fromCharCode(a, b, c, d, e, f, g, h, i, j, k);
      } else {
        let i = src[position++];
        let j = src[position++];
        let k = src[position++];
        let l = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0 || (k & 128) > 0 || (l & 128) > 0) {
          position -= 12;
          return;
        }
        if (length < 14) {
          if (length === 12)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l);
          else {
            let m = src[position++];
            if ((m & 128) > 0) {
              position -= 13;
              return;
            }
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m);
          }
        } else {
          let m = src[position++];
          let n = src[position++];
          if ((m & 128) > 0 || (n & 128) > 0) {
            position -= 14;
            return;
          }
          if (length < 15)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n);
          let o = src[position++];
          if ((o & 128) > 0) {
            position -= 15;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o);
        }
      }
    }
  }
}
function readOnlyJSString() {
  let token = src[position++];
  let length;
  if (token < 192) {
    length = token - 160;
  } else {
    switch (token) {
      case 217:
        length = src[position++];
        break;
      case 218:
        length = dataView.getUint16(position);
        position += 2;
        break;
      case 219:
        length = dataView.getUint32(position);
        position += 4;
        break;
      default:
        throw new Error("Expected string");
    }
  }
  return readStringJS(length);
}
function readBin(length) {
  return currentUnpackr.copyBuffers ? (
    // specifically use the copying slice (not the node one)
    Uint8Array.prototype.slice.call(src, position, position += length)
  ) : src.subarray(position, position += length);
}
function readExt(length) {
  let type = src[position++];
  if (currentExtensions[type]) {
    let end;
    return currentExtensions[type](src.subarray(position, end = position += length), (readPosition) => {
      position = readPosition;
      try {
        return read();
      } finally {
        position = end;
      }
    });
  } else
    throw new Error("Unknown extension type " + type);
}
var keyCache = new Array(4096);
function readKey() {
  let length = src[position++];
  if (length >= 160 && length < 192) {
    length = length - 160;
    if (srcStringEnd >= position)
      return srcString.slice(position - srcStringStart, (position += length) - srcStringStart);
    else if (!(srcStringEnd == 0 && srcEnd < 180))
      return readFixedString(length);
  } else {
    position--;
    return asSafeString(read());
  }
  let key = (length << 5 ^ (length > 1 ? dataView.getUint16(position) : length > 0 ? src[position] : 0)) & 4095;
  let entry = keyCache[key];
  let checkPosition = position;
  let end = position + length - 3;
  let chunk;
  let i = 0;
  if (entry && entry.bytes == length) {
    while (checkPosition < end) {
      chunk = dataView.getUint32(checkPosition);
      if (chunk != entry[i++]) {
        checkPosition = 1879048192;
        break;
      }
      checkPosition += 4;
    }
    end += 3;
    while (checkPosition < end) {
      chunk = src[checkPosition++];
      if (chunk != entry[i++]) {
        checkPosition = 1879048192;
        break;
      }
    }
    if (checkPosition === end) {
      position = checkPosition;
      return entry.string;
    }
    end -= 3;
    checkPosition = position;
  }
  entry = [];
  keyCache[key] = entry;
  entry.bytes = length;
  while (checkPosition < end) {
    chunk = dataView.getUint32(checkPosition);
    entry.push(chunk);
    checkPosition += 4;
  }
  end += 3;
  while (checkPosition < end) {
    chunk = src[checkPosition++];
    entry.push(chunk);
  }
  let string = length < 16 ? shortStringInJS(length) : longStringInJS(length);
  if (string != null)
    return entry.string = string;
  return entry.string = readFixedString(length);
}
function asSafeString(property) {
  if (typeof property === "string") return property;
  if (typeof property === "number" || typeof property === "boolean" || typeof property === "bigint") return property.toString();
  if (property == null) return property + "";
  if (currentUnpackr.allowArraysInMapKeys && Array.isArray(property) && property.flat().every((item) => ["string", "number", "boolean", "bigint"].includes(typeof item))) {
    return property.flat().toString();
  }
  throw new Error(`Invalid property type for record: ${typeof property}`);
}
var recordDefinition = (id, highByte) => {
  let structure = read().map(asSafeString);
  let firstByte = id;
  if (highByte !== void 0) {
    id = id < 32 ? -((highByte << 5) + id) : (highByte << 5) + id;
    structure.highByte = highByte;
  }
  let existingStructure = currentStructures[id];
  if (existingStructure && (existingStructure.isShared || sequentialMode)) {
    (currentStructures.restoreStructures || (currentStructures.restoreStructures = []))[id] = existingStructure;
  }
  currentStructures[id] = structure;
  structure.read = createStructureReader(structure, firstByte);
  return (structure.read0 || structure.read)();
};
currentExtensions[0] = () => {
};
currentExtensions[0].noBuffer = true;
currentExtensions[66] = (data) => {
  let headLength = data.byteLength % 8 || 8;
  let head = BigInt(data[0] & 128 ? data[0] - 256 : data[0]);
  for (let i = 1; i < headLength; i++) {
    head <<= BigInt(8);
    head += BigInt(data[i]);
  }
  if (data.byteLength !== headLength) {
    let view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let decode2 = (start, end) => {
      let length = end - start;
      if (length <= 40) {
        let out = view.getBigUint64(start);
        for (let i = start + 8; i < end; i += 8) {
          out <<= BigInt(64);
          out |= view.getBigUint64(i);
        }
        return out;
      }
      let middle = start + (length >> 4 << 3);
      let left = decode2(start, middle);
      let right = decode2(middle, end);
      return left << BigInt((end - middle) * 8) | right;
    };
    head = head << BigInt((view.byteLength - headLength) * 8) | decode2(headLength, view.byteLength);
  }
  return head;
};
var errors = {
  Error,
  EvalError,
  RangeError,
  ReferenceError,
  SyntaxError,
  TypeError,
  URIError,
  AggregateError: typeof AggregateError === "function" ? AggregateError : null
};
currentExtensions[101] = () => {
  let data = read();
  if (!errors[data[0]]) {
    let error = Error(data[1], { cause: data[2] });
    error.name = data[0];
    return error;
  }
  return errors[data[0]](data[1], { cause: data[2] });
};
currentExtensions[105] = (data) => {
  if (currentUnpackr.structuredClone === false) throw new Error("Structured clone extension is disabled");
  let id = dataView.getUint32(position - 4);
  if (!referenceMap)
    referenceMap = /* @__PURE__ */ new Map();
  let token = src[position];
  let target2;
  if (token >= 144 && token < 160 || token == 220 || token == 221)
    target2 = [];
  else if (token >= 128 && token < 144 || token == 222 || token == 223)
    target2 = /* @__PURE__ */ new Map();
  else if ((token >= 199 && token <= 201 || token >= 212 && token <= 216) && src[position + 1] === 115)
    target2 = /* @__PURE__ */ new Set();
  else
    target2 = {};
  let refEntry = { target: target2 };
  referenceMap.set(id, refEntry);
  let targetProperties = read();
  if (!refEntry.used) {
    return refEntry.target = targetProperties;
  } else {
    Object.assign(target2, targetProperties);
  }
  if (target2 instanceof Map)
    for (let [k, v] of targetProperties.entries()) target2.set(k, v);
  if (target2 instanceof Set)
    for (let i of Array.from(targetProperties)) target2.add(i);
  return target2;
};
currentExtensions[112] = (data) => {
  if (currentUnpackr.structuredClone === false) throw new Error("Structured clone extension is disabled");
  let id = dataView.getUint32(position - 4);
  let refEntry = referenceMap.get(id);
  refEntry.used = true;
  return refEntry.target;
};
currentExtensions[115] = () => new Set(read());
var typedArrays = ["Int8", "Uint8", "Uint8Clamped", "Int16", "Uint16", "Int32", "Uint32", "Float32", "Float64", "BigInt64", "BigUint64"].map((type) => type + "Array");
var glbl = typeof globalThis === "object" ? globalThis : window;
currentExtensions[116] = (data) => {
  let typeCode = data[0];
  let buffer = Uint8Array.prototype.slice.call(data, 1).buffer;
  let typedArrayName = typedArrays[typeCode];
  if (!typedArrayName) {
    if (typeCode === 16) return buffer;
    if (typeCode === 17) return new DataView(buffer);
    throw new Error("Could not find typed array for code " + typeCode);
  }
  return new glbl[typedArrayName](buffer);
};
currentExtensions[120] = () => {
  let data = read();
  return new RegExp(data[0], data[1]);
};
var TEMP_BUNDLE = [];
currentExtensions[98] = (data) => {
  let dataSize = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
  let dataPosition = position;
  position += dataSize - data.length;
  bundledStrings = TEMP_BUNDLE;
  bundledStrings = [readOnlyJSString(), readOnlyJSString()];
  bundledStrings.position0 = 0;
  bundledStrings.position1 = 0;
  bundledStrings.postBundlePosition = position;
  position = dataPosition;
  return read();
};
currentExtensions[255] = (data) => {
  if (data.length == 4)
    return new Date((data[0] * 16777216 + (data[1] << 16) + (data[2] << 8) + data[3]) * 1e3);
  else if (data.length == 8)
    return new Date(
      ((data[0] << 22) + (data[1] << 14) + (data[2] << 6) + (data[3] >> 2)) / 1e6 + ((data[3] & 3) * 4294967296 + data[4] * 16777216 + (data[5] << 16) + (data[6] << 8) + data[7]) * 1e3
    );
  else if (data.length == 12)
    return new Date(
      ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]) / 1e6 + ((data[4] & 128 ? -281474976710656 : 0) + data[6] * 1099511627776 + data[7] * 4294967296 + data[8] * 16777216 + (data[9] << 16) + (data[10] << 8) + data[11]) * 1e3
    );
  else
    return /* @__PURE__ */ new Date("invalid");
};
function saveState(callback) {
  if (onSaveState)
    onSaveState();
  let savedSrcEnd = srcEnd;
  let savedPosition = position;
  let savedStringPosition = stringPosition;
  let savedSrcStringStart = srcStringStart;
  let savedSrcStringEnd = srcStringEnd;
  let savedSrcString = srcString;
  let savedStrings = strings;
  let savedReferenceMap = referenceMap;
  let savedBundledStrings = bundledStrings;
  let savedSrc = new Uint8Array(src.slice(0, srcEnd));
  let savedStructures = currentStructures;
  let savedStructuresContents = currentStructures.slice(0, currentStructures.length);
  let savedPackr = currentUnpackr;
  let savedSequentialMode = sequentialMode;
  let value = callback();
  srcEnd = savedSrcEnd;
  position = savedPosition;
  stringPosition = savedStringPosition;
  srcStringStart = savedSrcStringStart;
  srcStringEnd = savedSrcStringEnd;
  srcString = savedSrcString;
  strings = savedStrings;
  referenceMap = savedReferenceMap;
  bundledStrings = savedBundledStrings;
  src = savedSrc;
  sequentialMode = savedSequentialMode;
  currentStructures = savedStructures;
  currentStructures.splice(0, currentStructures.length, ...savedStructuresContents);
  currentUnpackr = savedPackr;
  dataView = new DataView(src.buffer, src.byteOffset, src.byteLength);
  return value;
}
function clearSource() {
  src = null;
  referenceMap = null;
  currentStructures = null;
}
var mult10 = new Array(147);
for (let i = 0; i < 256; i++) {
  mult10[i] = +("1e" + Math.floor(45.15 - i * 0.30103));
}
var Decoder = Unpackr;
var defaultUnpackr = new Unpackr({ useRecords: false });
var unpack = defaultUnpackr.unpack;
var unpackMultiple = defaultUnpackr.unpackMultiple;
var decode = defaultUnpackr.unpack;
var FLOAT32_OPTIONS = {
  NEVER: 0,
  ALWAYS: 1,
  DECIMAL_ROUND: 3,
  DECIMAL_FIT: 4
};
var f32Array = new Float32Array(1);
var u8Array = new Uint8Array(f32Array.buffer, 0, 4);

// node_modules/msgpackr/pack.js
var textEncoder;
try {
  textEncoder = new TextEncoder();
} catch (error) {
}
var extensions;
var extensionClasses;
var hasNodeBuffer = typeof Buffer !== "undefined";
var ByteArrayAllocate = hasNodeBuffer ? function(length) {
  return Buffer.allocUnsafeSlow(length);
} : Uint8Array;
var ByteArray = hasNodeBuffer ? Buffer : Uint8Array;
var MAX_BUFFER_SIZE = hasNodeBuffer ? 4294967296 : 2144337920;
var target;
var keysTarget;
var targetView;
var position2 = 0;
var safeEnd;
var bundledStrings2 = null;
var writeStructSlots;
var MAX_BUNDLE_SIZE = 21760;
var hasNonLatin = /[\u0080-\uFFFF]/;
var RECORD_SYMBOL = /* @__PURE__ */ Symbol("record-id");
var Packr = class extends Unpackr {
  constructor(options) {
    super(options);
    this.offset = 0;
    let typeBuffer;
    let start;
    let hasSharedUpdate;
    let structures;
    let referenceMap2;
    let encodeUtf8 = ByteArray.prototype.utf8Write ? function(string, position3) {
      return target.utf8Write(string, position3, target.byteLength - position3);
    } : textEncoder && textEncoder.encodeInto ? function(string, position3) {
      return textEncoder.encodeInto(string, target.subarray(position3)).written;
    } : false;
    let packr = this;
    if (!options)
      options = {};
    let isSequential = options && options.sequential;
    let hasSharedStructures = options.structures || options.saveStructures;
    let maxSharedStructures = options.maxSharedStructures;
    if (maxSharedStructures == null)
      maxSharedStructures = hasSharedStructures ? 32 : 0;
    if (maxSharedStructures > 8160)
      throw new Error("Maximum maxSharedStructure is 8160");
    if (options.structuredClone && options.moreTypes == void 0) {
      this.moreTypes = true;
    }
    let maxOwnStructures = options.maxOwnStructures;
    if (maxOwnStructures == null)
      maxOwnStructures = hasSharedStructures ? 32 : 64;
    if (!this.structures && options.useRecords != false)
      this.structures = [];
    let useTwoByteRecords = maxSharedStructures > 32 || maxOwnStructures + maxSharedStructures > 64;
    let sharedLimitId = maxSharedStructures + 64;
    let maxStructureId = maxSharedStructures + maxOwnStructures + 64;
    if (maxStructureId > 8256) {
      throw new Error("Maximum maxSharedStructure + maxOwnStructure is 8192");
    }
    let recordIdsToRemove = [];
    let transitionsCount = 0;
    let serializationsSinceTransitionRebuild = 0;
    this.pack = this.encode = function(value, encodeOptions) {
      if (!target) {
        target = new ByteArrayAllocate(8192);
        targetView = target.dataView || (target.dataView = new DataView(target.buffer, 0, 8192));
        position2 = 0;
      }
      safeEnd = target.length - 10;
      if (safeEnd - position2 < 2048) {
        target = new ByteArrayAllocate(target.length);
        targetView = target.dataView || (target.dataView = new DataView(target.buffer, 0, target.length));
        safeEnd = target.length - 10;
        position2 = 0;
      } else
        position2 = position2 + 7 & 2147483640;
      start = position2;
      if (encodeOptions & RESERVE_START_SPACE) position2 += encodeOptions & 255;
      referenceMap2 = packr.structuredClone ? /* @__PURE__ */ new Map() : null;
      if (packr.bundleStrings && typeof value !== "string") {
        bundledStrings2 = [];
        bundledStrings2.size = Infinity;
      } else
        bundledStrings2 = null;
      structures = packr.structures;
      if (structures) {
        if (structures.uninitialized)
          structures = packr._mergeStructures(packr.getStructures());
        let sharedLength = structures.sharedLength || 0;
        if (sharedLength > maxSharedStructures) {
          throw new Error("Shared structures is larger than maximum shared structures, try increasing maxSharedStructures to " + structures.sharedLength);
        }
        if (!structures.transitions) {
          structures.transitions = /* @__PURE__ */ Object.create(null);
          for (let i = 0; i < sharedLength; i++) {
            let keys = structures[i];
            if (!keys)
              continue;
            let nextTransition, transition = structures.transitions;
            for (let j = 0, l = keys.length; j < l; j++) {
              let key = keys[j];
              nextTransition = transition[key];
              if (!nextTransition) {
                nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
              }
              transition = nextTransition;
            }
            transition[RECORD_SYMBOL] = i + 64;
          }
          this.lastNamedStructuresLength = sharedLength;
        }
        if (!isSequential) {
          structures.nextId = sharedLength + 64;
        }
      }
      if (hasSharedUpdate)
        hasSharedUpdate = false;
      let encodingError;
      try {
        if (packr.randomAccessStructure && !packr.readOnlyStructures && value && typeof value === "object") {
          if (value.constructor === Object) writeStruct(value);
          else if (value.constructor !== Map && !Array.isArray(value) && !extensionClasses.some((extClass) => value instanceof extClass)) {
            writeStruct(value.toJSON ? value.toJSON() : value);
          } else pack2(value);
        } else
          pack2(value);
        let lastBundle = bundledStrings2;
        if (bundledStrings2)
          writeBundles(start, pack2, 0);
        if (referenceMap2 && referenceMap2.idsToInsert) {
          let idsToInsert = referenceMap2.idsToInsert.sort((a, b) => a.offset > b.offset ? 1 : -1);
          let i = idsToInsert.length;
          let incrementPosition = -1;
          while (lastBundle && i > 0) {
            let insertionPoint = idsToInsert[--i].offset + start;
            if (insertionPoint < lastBundle.stringsPosition + start && incrementPosition === -1)
              incrementPosition = 0;
            if (insertionPoint > lastBundle.position + start) {
              if (incrementPosition >= 0)
                incrementPosition += 6;
            } else {
              if (incrementPosition >= 0) {
                targetView.setUint32(
                  lastBundle.position + start,
                  targetView.getUint32(lastBundle.position + start) + incrementPosition
                );
                incrementPosition = -1;
              }
              lastBundle = lastBundle.previous;
              i++;
            }
          }
          if (incrementPosition >= 0 && lastBundle) {
            targetView.setUint32(
              lastBundle.position + start,
              targetView.getUint32(lastBundle.position + start) + incrementPosition
            );
          }
          position2 += idsToInsert.length * 6;
          if (position2 > safeEnd)
            makeRoom(position2);
          packr.offset = position2;
          let serialized = insertIds(target.subarray(start, position2), idsToInsert);
          referenceMap2 = null;
          return serialized;
        }
        packr.offset = position2;
        if (encodeOptions & REUSE_BUFFER_MODE) {
          target.start = start;
          target.end = position2;
          return target;
        }
        return target.subarray(start, position2);
      } catch (error) {
        encodingError = error;
        throw error;
      } finally {
        if (structures) {
          resetStructures();
          if (hasSharedUpdate && packr.saveStructures) {
            let sharedLength = structures.sharedLength || 0;
            let returnBuffer = target.subarray(start, position2);
            let newSharedData = prepareStructures(structures, packr);
            if (!encodingError) {
              if (packr.saveStructures(newSharedData, newSharedData.isCompatible) === false) {
                structures.uninitialized = true;
                return packr.pack(value, encodeOptions);
              }
              packr.lastNamedStructuresLength = sharedLength;
              if (target.length > 1073741824) target = null;
              return returnBuffer;
            }
          }
        }
        if (target.length > 1073741824) target = null;
        if (encodeOptions & RESET_BUFFER_MODE)
          position2 = start;
      }
    };
    const resetStructures = () => {
      if (serializationsSinceTransitionRebuild < 10)
        serializationsSinceTransitionRebuild++;
      let sharedLength = structures.sharedLength || 0;
      if (structures.length > sharedLength && !isSequential)
        structures.length = sharedLength;
      if (transitionsCount > 1e4) {
        structures.transitions = null;
        serializationsSinceTransitionRebuild = 0;
        transitionsCount = 0;
        if (recordIdsToRemove.length > 0)
          recordIdsToRemove = [];
      } else if (recordIdsToRemove.length > 0 && !isSequential) {
        for (let i = 0, l = recordIdsToRemove.length; i < l; i++) {
          recordIdsToRemove[i][RECORD_SYMBOL] = 0;
        }
        recordIdsToRemove = [];
      }
    };
    const packArray = (value) => {
      var length = value.length;
      if (length < 16) {
        target[position2++] = 144 | length;
      } else if (length < 65536) {
        target[position2++] = 220;
        target[position2++] = length >> 8;
        target[position2++] = length & 255;
      } else {
        target[position2++] = 221;
        targetView.setUint32(position2, length);
        position2 += 4;
      }
      for (let i = 0; i < length; i++) {
        pack2(value[i]);
      }
    };
    const pack2 = (value) => {
      if (position2 > safeEnd)
        target = makeRoom(position2);
      var type = typeof value;
      var length;
      if (type === "string") {
        let strLength = value.length;
        if (bundledStrings2 && strLength >= 4 && strLength < 4096) {
          if ((bundledStrings2.size += strLength) > MAX_BUNDLE_SIZE) {
            let extStart;
            let maxBytes2 = (bundledStrings2[0] ? bundledStrings2[0].length * 3 + bundledStrings2[1].length : 0) + 10;
            if (position2 + maxBytes2 > safeEnd)
              target = makeRoom(position2 + maxBytes2);
            let lastBundle;
            if (bundledStrings2.position) {
              lastBundle = bundledStrings2;
              target[position2] = 200;
              position2 += 3;
              target[position2++] = 98;
              extStart = position2 - start;
              position2 += 4;
              writeBundles(start, pack2, 0);
              targetView.setUint16(extStart + start - 3, position2 - start - extStart);
            } else {
              target[position2++] = 214;
              target[position2++] = 98;
              extStart = position2 - start;
              position2 += 4;
            }
            bundledStrings2 = ["", ""];
            bundledStrings2.previous = lastBundle;
            bundledStrings2.size = 0;
            bundledStrings2.position = extStart;
          }
          let twoByte = hasNonLatin.test(value);
          bundledStrings2[twoByte ? 0 : 1] += value;
          target[position2++] = 193;
          pack2(twoByte ? -strLength : strLength);
          return;
        }
        let headerSize;
        if (strLength < 32) {
          headerSize = 1;
        } else if (strLength < 256) {
          headerSize = 2;
        } else if (strLength < 65536) {
          headerSize = 3;
        } else {
          headerSize = 5;
        }
        let maxBytes = strLength * 3;
        if (position2 + maxBytes > safeEnd)
          target = makeRoom(position2 + maxBytes);
        if (strLength < 64 || !encodeUtf8) {
          let i, c1, c2, strPosition = position2 + headerSize;
          for (i = 0; i < strLength; i++) {
            c1 = value.charCodeAt(i);
            if (c1 < 128) {
              target[strPosition++] = c1;
            } else if (c1 < 2048) {
              target[strPosition++] = c1 >> 6 | 192;
              target[strPosition++] = c1 & 63 | 128;
            } else if ((c1 & 64512) === 55296 && ((c2 = value.charCodeAt(i + 1)) & 64512) === 56320) {
              c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
              i++;
              target[strPosition++] = c1 >> 18 | 240;
              target[strPosition++] = c1 >> 12 & 63 | 128;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            } else {
              target[strPosition++] = c1 >> 12 | 224;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            }
          }
          length = strPosition - position2 - headerSize;
        } else {
          length = encodeUtf8(value, position2 + headerSize);
        }
        if (length < 32) {
          target[position2++] = 160 | length;
        } else if (length < 256) {
          if (headerSize < 2) {
            target.copyWithin(position2 + 2, position2 + 1, position2 + 1 + length);
          }
          target[position2++] = 217;
          target[position2++] = length;
        } else if (length < 65536) {
          if (headerSize < 3) {
            target.copyWithin(position2 + 3, position2 + 2, position2 + 2 + length);
          }
          target[position2++] = 218;
          target[position2++] = length >> 8;
          target[position2++] = length & 255;
        } else {
          if (headerSize < 5) {
            target.copyWithin(position2 + 5, position2 + 3, position2 + 3 + length);
          }
          target[position2++] = 219;
          targetView.setUint32(position2, length);
          position2 += 4;
        }
        position2 += length;
      } else if (type === "number") {
        if (value >>> 0 === value) {
          if (value < 32 || value < 128 && this.useRecords === false || value < 64 && !this.randomAccessStructure) {
            target[position2++] = value;
          } else if (value < 256) {
            target[position2++] = 204;
            target[position2++] = value;
          } else if (value < 65536) {
            target[position2++] = 205;
            target[position2++] = value >> 8;
            target[position2++] = value & 255;
          } else {
            target[position2++] = 206;
            targetView.setUint32(position2, value);
            position2 += 4;
          }
        } else if (value >> 0 === value) {
          if (value >= -32) {
            target[position2++] = 256 + value;
          } else if (value >= -128) {
            target[position2++] = 208;
            target[position2++] = value + 256;
          } else if (value >= -32768) {
            target[position2++] = 209;
            targetView.setInt16(position2, value);
            position2 += 2;
          } else {
            target[position2++] = 210;
            targetView.setInt32(position2, value);
            position2 += 4;
          }
        } else {
          let useFloat32;
          if ((useFloat32 = this.useFloat32) > 0 && value < 4294967296 && value >= -2147483648) {
            target[position2++] = 202;
            targetView.setFloat32(position2, value);
            let xShifted;
            if (useFloat32 < 4 || // this checks for rounding of numbers that were encoded in 32-bit float to nearest significant decimal digit that could be preserved
            (xShifted = value * mult10[(target[position2] & 127) << 1 | target[position2 + 1] >> 7]) >> 0 === xShifted) {
              position2 += 4;
              return;
            } else
              position2--;
          }
          target[position2++] = 203;
          targetView.setFloat64(position2, value);
          position2 += 8;
        }
      } else if (type === "object" || type === "function") {
        if (!value)
          target[position2++] = 192;
        else {
          if (referenceMap2) {
            let referee = referenceMap2.get(value);
            if (referee) {
              if (!referee.id) {
                let idsToInsert = referenceMap2.idsToInsert || (referenceMap2.idsToInsert = []);
                referee.id = idsToInsert.push(referee);
              }
              target[position2++] = 214;
              target[position2++] = 112;
              targetView.setUint32(position2, referee.id);
              position2 += 4;
              return;
            } else
              referenceMap2.set(value, { offset: position2 - start });
          }
          let constructor = value.constructor;
          if (constructor === Object) {
            writeObject(value);
          } else if (constructor === Array) {
            packArray(value);
          } else if (constructor === Map) {
            if (this.mapAsEmptyObject) target[position2++] = 128;
            else {
              length = value.size;
              if (length < 16) {
                target[position2++] = 128 | length;
              } else if (length < 65536) {
                target[position2++] = 222;
                target[position2++] = length >> 8;
                target[position2++] = length & 255;
              } else {
                target[position2++] = 223;
                targetView.setUint32(position2, length);
                position2 += 4;
              }
              for (let [key, entryValue] of value) {
                pack2(key);
                pack2(entryValue);
              }
            }
          } else {
            for (let i = 0, l = extensions.length; i < l; i++) {
              let extensionClass = extensionClasses[i];
              if (value instanceof extensionClass) {
                let extension = extensions[i];
                if (extension.write) {
                  if (extension.type) {
                    target[position2++] = 212;
                    target[position2++] = extension.type;
                    target[position2++] = 0;
                  }
                  let writeResult = extension.write.call(this, value);
                  if (writeResult === value) {
                    if (Array.isArray(value)) {
                      packArray(value);
                    } else {
                      writeObject(value);
                    }
                  } else {
                    pack2(writeResult);
                  }
                  return;
                }
                let currentTarget = target;
                let currentTargetView = targetView;
                let currentPosition = position2;
                target = null;
                let result;
                try {
                  result = extension.pack.call(this, value, (size) => {
                    target = currentTarget;
                    currentTarget = null;
                    position2 += size;
                    if (position2 > safeEnd)
                      makeRoom(position2);
                    return {
                      target,
                      targetView,
                      position: position2 - size
                    };
                  }, pack2);
                } finally {
                  if (currentTarget) {
                    target = currentTarget;
                    targetView = currentTargetView;
                    position2 = currentPosition;
                    safeEnd = target.length - 10;
                  }
                }
                if (result) {
                  if (result.length + position2 > safeEnd)
                    makeRoom(result.length + position2);
                  position2 = writeExtensionData(result, target, position2, extension.type);
                }
                return;
              }
            }
            if (Array.isArray(value)) {
              packArray(value);
            } else {
              if (value.toJSON) {
                const json = value.toJSON();
                if (json !== value)
                  return pack2(json);
              }
              if (type === "function")
                return pack2(this.writeFunction && this.writeFunction(value));
              writeObject(value);
            }
          }
        }
      } else if (type === "boolean") {
        target[position2++] = value ? 195 : 194;
      } else if (type === "bigint") {
        if (value < 9223372036854776e3 && value >= -9223372036854776e3) {
          target[position2++] = 211;
          targetView.setBigInt64(position2, value);
        } else if (value < 18446744073709552e3 && value > 0) {
          target[position2++] = 207;
          targetView.setBigUint64(position2, value);
        } else {
          if (this.largeBigIntToFloat) {
            target[position2++] = 203;
            targetView.setFloat64(position2, Number(value));
          } else if (this.largeBigIntToString) {
            return pack2(value.toString());
          } else if (this.useBigIntExtension || this.moreTypes) {
            let empty = value < 0 ? BigInt(-1) : BigInt(0);
            let array;
            if (value >> BigInt(65536) === empty) {
              let mask = BigInt(18446744073709552e3) - BigInt(1);
              let chunks = [];
              while (true) {
                chunks.push(value & mask);
                if (value >> BigInt(63) === empty) break;
                value >>= BigInt(64);
              }
              array = new Uint8Array(new BigUint64Array(chunks).buffer);
              array.reverse();
            } else {
              let invert = value < 0;
              let string = (invert ? ~value : value).toString(16);
              if (string.length % 2) {
                string = "0" + string;
              } else if (parseInt(string.charAt(0), 16) >= 8) {
                string = "00" + string;
              }
              if (hasNodeBuffer) {
                array = Buffer.from(string, "hex");
              } else {
                array = new Uint8Array(string.length / 2);
                for (let i = 0; i < array.length; i++) {
                  array[i] = parseInt(string.slice(i * 2, i * 2 + 2), 16);
                }
              }
              if (invert) {
                for (let i = 0; i < array.length; i++) array[i] = ~array[i];
              }
            }
            if (array.length + position2 > safeEnd)
              makeRoom(array.length + position2);
            position2 = writeExtensionData(array, target, position2, 66);
            return;
          } else {
            throw new RangeError(value + " was too large to fit in MessagePack 64-bit integer format, use useBigIntExtension, or set largeBigIntToFloat to convert to float-64, or set largeBigIntToString to convert to string");
          }
        }
        position2 += 8;
      } else if (type === "undefined") {
        if (this.encodeUndefinedAsNil)
          target[position2++] = 192;
        else {
          target[position2++] = 212;
          target[position2++] = 0;
          target[position2++] = 0;
        }
      } else {
        throw new Error("Unknown type: " + type);
      }
    };
    const writePlainObject = this.variableMapSize || this.coercibleKeyAsNumber || this.skipValues ? (object) => {
      let keys;
      if (this.skipValues) {
        keys = [];
        for (let key2 in object) {
          if ((typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key2)) && !this.skipValues.includes(object[key2]))
            keys.push(key2);
        }
      } else {
        keys = Object.keys(object);
      }
      let length = keys.length;
      if (length < 16) {
        target[position2++] = 128 | length;
      } else if (length < 65536) {
        target[position2++] = 222;
        target[position2++] = length >> 8;
        target[position2++] = length & 255;
      } else {
        target[position2++] = 223;
        targetView.setUint32(position2, length);
        position2 += 4;
      }
      let key;
      if (this.coercibleKeyAsNumber) {
        for (let i = 0; i < length; i++) {
          key = keys[i];
          let num = Number(key);
          pack2(isNaN(num) ? key : num);
          pack2(object[key]);
        }
      } else {
        for (let i = 0; i < length; i++) {
          pack2(key = keys[i]);
          pack2(object[key]);
        }
      }
    } : (object) => {
      target[position2++] = 222;
      let objectOffset = position2 - start;
      position2 += 2;
      let size = 0;
      for (let key in object) {
        if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          pack2(key);
          pack2(object[key]);
          size++;
        }
      }
      if (size > 65535) {
        throw new Error('Object is too large to serialize with fast 16-bit map size, use the "variableMapSize" option to serialize this object');
      }
      target[objectOffset++ + start] = size >> 8;
      target[objectOffset + start] = size & 255;
    };
    const writeRecord = this.useRecords === false ? writePlainObject : options.progressiveRecords && !useTwoByteRecords ? (
      // this is about 2% faster for highly stable structures, since it only requires one for-in loop (but much more expensive when new structure needs to be written)
      (object) => {
        let nextTransition, transition = structures.transitions || (structures.transitions = /* @__PURE__ */ Object.create(null));
        let objectOffset = position2++ - start;
        let wroteKeys;
        for (let key in object) {
          if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
            nextTransition = transition[key];
            if (nextTransition)
              transition = nextTransition;
            else {
              let keys = Object.keys(object);
              let lastTransition = transition;
              transition = structures.transitions;
              let newTransitions = 0;
              for (let i = 0, l = keys.length; i < l; i++) {
                let key2 = keys[i];
                nextTransition = transition[key2];
                if (!nextTransition) {
                  nextTransition = transition[key2] = /* @__PURE__ */ Object.create(null);
                  newTransitions++;
                }
                transition = nextTransition;
              }
              if (objectOffset + start + 1 == position2) {
                position2--;
                newRecord(transition, keys, newTransitions);
              } else
                insertNewRecord(transition, keys, objectOffset, newTransitions);
              wroteKeys = true;
              transition = lastTransition[key];
            }
            pack2(object[key]);
          }
        }
        if (!wroteKeys) {
          let recordId = transition[RECORD_SYMBOL];
          if (recordId)
            target[objectOffset + start] = recordId;
          else
            insertNewRecord(transition, Object.keys(object), objectOffset, 0);
        }
      }
    ) : (object) => {
      let nextTransition, transition = structures.transitions || (structures.transitions = /* @__PURE__ */ Object.create(null));
      let newTransitions = 0;
      for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
        nextTransition = transition[key];
        if (!nextTransition) {
          nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
          newTransitions++;
        }
        transition = nextTransition;
      }
      let recordId = transition[RECORD_SYMBOL];
      if (recordId) {
        if (recordId >= 96 && useTwoByteRecords) {
          target[position2++] = ((recordId -= 96) & 31) + 96;
          target[position2++] = recordId >> 5;
        } else
          target[position2++] = recordId;
      } else {
        newRecord(transition, transition.__keys__ || Object.keys(object), newTransitions);
      }
      for (let key in object)
        if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          pack2(object[key]);
        }
    };
    const checkUseRecords = typeof this.useRecords == "function" && this.useRecords;
    const writeObject = checkUseRecords ? (object) => {
      checkUseRecords(object) ? writeRecord(object) : writePlainObject(object);
    } : writeRecord;
    const makeRoom = (end) => {
      let newSize;
      if (end > 16777216) {
        if (end - start > MAX_BUFFER_SIZE)
          throw new Error("Packed buffer would be larger than maximum buffer size");
        newSize = Math.min(
          MAX_BUFFER_SIZE,
          Math.round(Math.max((end - start) * (end > 67108864 ? 1.25 : 2), 4194304) / 4096) * 4096
        );
      } else
        newSize = (Math.max(end - start << 2, target.length - 1) >> 12) + 1 << 12;
      let newBuffer = new ByteArrayAllocate(newSize);
      targetView = newBuffer.dataView || (newBuffer.dataView = new DataView(newBuffer.buffer, 0, newSize));
      end = Math.min(end, target.length);
      if (target.copy)
        target.copy(newBuffer, 0, start, end);
      else
        newBuffer.set(target.slice(start, end));
      position2 -= start;
      start = 0;
      safeEnd = newBuffer.length - 10;
      return target = newBuffer;
    };
    const newRecord = (transition, keys, newTransitions) => {
      let recordId = structures.nextId;
      if (!recordId)
        recordId = 64;
      if (recordId < sharedLimitId && this.shouldShareStructure && !this.shouldShareStructure(keys)) {
        recordId = structures.nextOwnId;
        if (!(recordId < maxStructureId))
          recordId = sharedLimitId;
        structures.nextOwnId = recordId + 1;
      } else {
        if (recordId >= maxStructureId)
          recordId = sharedLimitId;
        structures.nextId = recordId + 1;
      }
      let highByte = keys.highByte = recordId >= 96 && useTwoByteRecords ? recordId - 96 >> 5 : -1;
      transition[RECORD_SYMBOL] = recordId;
      transition.__keys__ = keys;
      structures[recordId - 64] = keys;
      if (recordId < sharedLimitId) {
        keys.isShared = true;
        structures.sharedLength = recordId - 63;
        hasSharedUpdate = true;
        if (highByte >= 0) {
          target[position2++] = (recordId & 31) + 96;
          target[position2++] = highByte;
        } else {
          target[position2++] = recordId;
        }
      } else {
        if (highByte >= 0) {
          target[position2++] = 213;
          target[position2++] = 114;
          target[position2++] = (recordId & 31) + 96;
          target[position2++] = highByte;
        } else {
          target[position2++] = 212;
          target[position2++] = 114;
          target[position2++] = recordId;
        }
        if (newTransitions)
          transitionsCount += serializationsSinceTransitionRebuild * newTransitions;
        if (recordIdsToRemove.length >= maxOwnStructures)
          recordIdsToRemove.shift()[RECORD_SYMBOL] = 0;
        recordIdsToRemove.push(transition);
        pack2(keys);
      }
    };
    const insertNewRecord = (transition, keys, insertionOffset, newTransitions) => {
      let mainTarget = target;
      let mainPosition = position2;
      let mainSafeEnd = safeEnd;
      let mainStart = start;
      target = keysTarget;
      position2 = 0;
      start = 0;
      if (!target)
        keysTarget = target = new ByteArrayAllocate(8192);
      safeEnd = target.length - 10;
      newRecord(transition, keys, newTransitions);
      keysTarget = target;
      let keysPosition = position2;
      target = mainTarget;
      position2 = mainPosition;
      safeEnd = mainSafeEnd;
      start = mainStart;
      if (keysPosition > 1) {
        let newEnd = position2 + keysPosition - 1;
        if (newEnd > safeEnd)
          makeRoom(newEnd);
        let insertionPosition = insertionOffset + start;
        target.copyWithin(insertionPosition + keysPosition, insertionPosition + 1, position2);
        target.set(keysTarget.slice(0, keysPosition), insertionPosition);
        position2 = newEnd;
      } else {
        target[insertionOffset + start] = keysTarget[0];
      }
    };
    const writeStruct = (object) => {
      let newPosition = writeStructSlots(object, target, start, position2, structures, makeRoom, (value, newPosition2, notifySharedUpdate) => {
        if (notifySharedUpdate)
          return hasSharedUpdate = true;
        position2 = newPosition2;
        let startTarget = target;
        pack2(value);
        resetStructures();
        if (startTarget !== target) {
          return { position: position2, targetView, target };
        }
        return position2;
      }, this);
      if (newPosition === 0)
        return writeObject(object);
      position2 = newPosition;
    };
  }
  useBuffer(buffer) {
    target = buffer;
    target.dataView || (target.dataView = new DataView(target.buffer, target.byteOffset, target.byteLength));
    targetView = target.dataView;
    position2 = 0;
  }
  set position(value) {
    position2 = value;
  }
  get position() {
    return position2;
  }
  clearSharedData() {
    if (this.structures)
      this.structures = [];
    if (this.typedStructs)
      this.typedStructs = [];
  }
};
extensionClasses = [Date, Set, Error, RegExp, ArrayBuffer, Object.getPrototypeOf(Uint8Array.prototype).constructor, DataView, C1Type];
extensions = [{
  pack(date, allocateForWrite, pack2) {
    let seconds = date.getTime() / 1e3;
    if ((this.useTimestamp32 || date.getMilliseconds() === 0) && seconds >= 0 && seconds < 4294967296) {
      let { target: target2, targetView: targetView2, position: position3 } = allocateForWrite(6);
      target2[position3++] = 214;
      target2[position3++] = 255;
      targetView2.setUint32(position3, seconds);
    } else if (seconds > 0 && seconds < 4294967296) {
      let { target: target2, targetView: targetView2, position: position3 } = allocateForWrite(10);
      target2[position3++] = 215;
      target2[position3++] = 255;
      targetView2.setUint32(position3, date.getMilliseconds() * 4e6 + (seconds / 1e3 / 4294967296 >> 0));
      targetView2.setUint32(position3 + 4, seconds);
    } else if (isNaN(seconds)) {
      if (this.onInvalidDate) {
        allocateForWrite(0);
        return pack2(this.onInvalidDate());
      }
      let { target: target2, targetView: targetView2, position: position3 } = allocateForWrite(3);
      target2[position3++] = 212;
      target2[position3++] = 255;
      target2[position3++] = 255;
    } else {
      let { target: target2, targetView: targetView2, position: position3 } = allocateForWrite(15);
      target2[position3++] = 199;
      target2[position3++] = 12;
      target2[position3++] = 255;
      targetView2.setUint32(position3, date.getMilliseconds() * 1e6);
      targetView2.setBigInt64(position3 + 4, BigInt(Math.floor(seconds)));
    }
  }
}, {
  pack(set2, allocateForWrite, pack2) {
    if (this.setAsEmptyObject) {
      allocateForWrite(0);
      return pack2({});
    }
    let array = Array.from(set2);
    let { target: target2, position: position3 } = allocateForWrite(this.moreTypes ? 3 : 0);
    if (this.moreTypes) {
      target2[position3++] = 212;
      target2[position3++] = 115;
      target2[position3++] = 0;
    }
    pack2(array);
  }
}, {
  pack(error, allocateForWrite, pack2) {
    let { target: target2, position: position3 } = allocateForWrite(this.moreTypes ? 3 : 0);
    if (this.moreTypes) {
      target2[position3++] = 212;
      target2[position3++] = 101;
      target2[position3++] = 0;
    }
    pack2([error.name, error.message, error.cause]);
  }
}, {
  pack(regex, allocateForWrite, pack2) {
    let { target: target2, position: position3 } = allocateForWrite(this.moreTypes ? 3 : 0);
    if (this.moreTypes) {
      target2[position3++] = 212;
      target2[position3++] = 120;
      target2[position3++] = 0;
    }
    pack2([regex.source, regex.flags]);
  }
}, {
  pack(arrayBuffer, allocateForWrite) {
    if (this.moreTypes)
      writeExtBuffer(arrayBuffer, 16, allocateForWrite);
    else
      writeBuffer(hasNodeBuffer ? Buffer.from(arrayBuffer) : new Uint8Array(arrayBuffer), allocateForWrite);
  }
}, {
  pack(typedArray, allocateForWrite) {
    let constructor = typedArray.constructor;
    if (constructor !== ByteArray && this.moreTypes)
      writeExtBuffer(typedArray, typedArrays.indexOf(constructor.name), allocateForWrite);
    else
      writeBuffer(typedArray, allocateForWrite);
  }
}, {
  pack(arrayBuffer, allocateForWrite) {
    if (this.moreTypes)
      writeExtBuffer(arrayBuffer, 17, allocateForWrite);
    else
      writeBuffer(hasNodeBuffer ? Buffer.from(arrayBuffer) : new Uint8Array(arrayBuffer), allocateForWrite);
  }
}, {
  pack(c1, allocateForWrite) {
    let { target: target2, position: position3 } = allocateForWrite(1);
    target2[position3] = 193;
  }
}];
function writeExtBuffer(typedArray, type, allocateForWrite, encode3) {
  let length = typedArray.byteLength;
  if (length + 1 < 256) {
    var { target: target2, position: position3 } = allocateForWrite(4 + length);
    target2[position3++] = 199;
    target2[position3++] = length + 1;
  } else if (length + 1 < 65536) {
    var { target: target2, position: position3 } = allocateForWrite(5 + length);
    target2[position3++] = 200;
    target2[position3++] = length + 1 >> 8;
    target2[position3++] = length + 1 & 255;
  } else {
    var { target: target2, position: position3, targetView: targetView2 } = allocateForWrite(7 + length);
    target2[position3++] = 201;
    targetView2.setUint32(position3, length + 1);
    position3 += 4;
  }
  target2[position3++] = 116;
  target2[position3++] = type;
  if (!typedArray.buffer) typedArray = new Uint8Array(typedArray);
  target2.set(new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength), position3);
}
function writeBuffer(buffer, allocateForWrite) {
  let length = buffer.byteLength;
  var target2, position3;
  if (length < 256) {
    var { target: target2, position: position3 } = allocateForWrite(length + 2);
    target2[position3++] = 196;
    target2[position3++] = length;
  } else if (length < 65536) {
    var { target: target2, position: position3 } = allocateForWrite(length + 3);
    target2[position3++] = 197;
    target2[position3++] = length >> 8;
    target2[position3++] = length & 255;
  } else {
    var { target: target2, position: position3, targetView: targetView2 } = allocateForWrite(length + 5);
    target2[position3++] = 198;
    targetView2.setUint32(position3, length);
    position3 += 4;
  }
  target2.set(buffer, position3);
}
function writeExtensionData(result, target2, position3, type) {
  let length = result.length;
  switch (length) {
    case 1:
      target2[position3++] = 212;
      break;
    case 2:
      target2[position3++] = 213;
      break;
    case 4:
      target2[position3++] = 214;
      break;
    case 8:
      target2[position3++] = 215;
      break;
    case 16:
      target2[position3++] = 216;
      break;
    default:
      if (length < 256) {
        target2[position3++] = 199;
        target2[position3++] = length;
      } else if (length < 65536) {
        target2[position3++] = 200;
        target2[position3++] = length >> 8;
        target2[position3++] = length & 255;
      } else {
        target2[position3++] = 201;
        target2[position3++] = length >> 24;
        target2[position3++] = length >> 16 & 255;
        target2[position3++] = length >> 8 & 255;
        target2[position3++] = length & 255;
      }
  }
  target2[position3++] = type;
  target2.set(result, position3);
  position3 += length;
  return position3;
}
function insertIds(serialized, idsToInsert) {
  let nextId;
  let distanceToMove = idsToInsert.length * 6;
  let lastEnd = serialized.length - distanceToMove;
  while (nextId = idsToInsert.pop()) {
    let offset = nextId.offset;
    let id = nextId.id;
    serialized.copyWithin(offset + distanceToMove, offset, lastEnd);
    distanceToMove -= 6;
    let position3 = offset + distanceToMove;
    serialized[position3++] = 214;
    serialized[position3++] = 105;
    serialized[position3++] = id >> 24;
    serialized[position3++] = id >> 16 & 255;
    serialized[position3++] = id >> 8 & 255;
    serialized[position3++] = id & 255;
    lastEnd = offset;
  }
  return serialized;
}
function writeBundles(start, pack2, incrementPosition) {
  if (bundledStrings2.length > 0) {
    targetView.setUint32(bundledStrings2.position + start, position2 + incrementPosition - bundledStrings2.position - start);
    bundledStrings2.stringsPosition = position2 - start;
    let writeStrings = bundledStrings2;
    bundledStrings2 = null;
    pack2(writeStrings[0]);
    pack2(writeStrings[1]);
  }
}
function prepareStructures(structures, packr) {
  structures.isCompatible = (existingStructures) => {
    let compatible = !existingStructures || (packr.lastNamedStructuresLength || 0) === existingStructures.length;
    if (!compatible)
      packr._mergeStructures(existingStructures);
    return compatible;
  };
  return structures;
}
var defaultPackr = new Packr({ useRecords: false });
var pack = defaultPackr.pack;
var encode2 = defaultPackr.pack;
var Encoder = Packr;
var { NEVER, ALWAYS, DECIMAL_ROUND, DECIMAL_FIT } = FLOAT32_OPTIONS;
var REUSE_BUFFER_MODE = 512;
var RESET_BUFFER_MODE = 1024;
var RESERVE_START_SPACE = 2048;

// node_modules/@aztec/bb.js/dest/browser/bbapi_exception.js
var BBApiException = class _BBApiException extends Error {
  constructor(message) {
    super(message);
    this.name = "BBApiException";
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, _BBApiException);
    }
  }
};

// node_modules/@aztec/bb.js/dest/browser/cbind/generated/api_types.js
function toAvmStat(o) {
  if (o.name === void 0) {
    throw new Error("Expected name in AvmStat deserialization");
  }
  if (o.value_ms === void 0) {
    throw new Error("Expected value_ms in AvmStat deserialization");
  }
  ;
  return {
    name: o.name,
    valueMs: o.value_ms
  };
}
function toCircuitComputeVkResponse(o) {
  if (o.bytes === void 0) {
    throw new Error("Expected bytes in CircuitComputeVkResponse deserialization");
  }
  if (o.fields === void 0) {
    throw new Error("Expected fields in CircuitComputeVkResponse deserialization");
  }
  if (o.hash === void 0) {
    throw new Error("Expected hash in CircuitComputeVkResponse deserialization");
  }
  ;
  return {
    bytes: o.bytes,
    fields: o.fields,
    hash: o.hash
  };
}
function toChonkProof(o) {
  if (o.hiding_oink_proof === void 0) {
    throw new Error("Expected hiding_oink_proof in ChonkProof deserialization");
  }
  if (o.merge_proof === void 0) {
    throw new Error("Expected merge_proof in ChonkProof deserialization");
  }
  if (o.eccvm_proof === void 0) {
    throw new Error("Expected eccvm_proof in ChonkProof deserialization");
  }
  if (o.ipa_proof === void 0) {
    throw new Error("Expected ipa_proof in ChonkProof deserialization");
  }
  if (o.joint_proof === void 0) {
    throw new Error("Expected joint_proof in ChonkProof deserialization");
  }
  ;
  return {
    hidingOinkProof: o.hiding_oink_proof,
    mergeProof: o.merge_proof,
    eccvmProof: o.eccvm_proof,
    ipaProof: o.ipa_proof,
    jointProof: o.joint_proof
  };
}
function toGrumpkinPoint(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in GrumpkinPoint deserialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in GrumpkinPoint deserialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function toSecp256k1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Secp256k1Point deserialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Secp256k1Point deserialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function toBn254G1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Bn254G1Point deserialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Bn254G1Point deserialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function toBn254G2Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Bn254G2Point deserialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Bn254G2Point deserialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function toSecp256r1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Secp256r1Point deserialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Secp256r1Point deserialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function toAvmProveResponse(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in AvmProveResponse deserialization");
  }
  if (o.stats === void 0) {
    throw new Error("Expected stats in AvmProveResponse deserialization");
  }
  ;
  return {
    proof: o.proof,
    stats: o.stats.map((v) => toAvmStat(v))
  };
}
function toAvmVerifyResponse(o) {
  if (o.verified === void 0) {
    throw new Error("Expected verified in AvmVerifyResponse deserialization");
  }
  ;
  return {
    verified: o.verified
  };
}
function toAvmCheckCircuitResponse(o) {
  if (o.passed === void 0) {
    throw new Error("Expected passed in AvmCheckCircuitResponse deserialization");
  }
  if (o.stats === void 0) {
    throw new Error("Expected stats in AvmCheckCircuitResponse deserialization");
  }
  ;
  return {
    passed: o.passed,
    stats: o.stats.map((v) => toAvmStat(v))
  };
}
function toCircuitProveResponse(o) {
  if (o.public_inputs === void 0) {
    throw new Error("Expected public_inputs in CircuitProveResponse deserialization");
  }
  if (o.proof === void 0) {
    throw new Error("Expected proof in CircuitProveResponse deserialization");
  }
  if (o.vk === void 0) {
    throw new Error("Expected vk in CircuitProveResponse deserialization");
  }
  ;
  return {
    publicInputs: o.public_inputs,
    proof: o.proof,
    vk: toCircuitComputeVkResponse(o.vk)
  };
}
function toCircuitInfoResponse(o) {
  if (o.num_gates === void 0) {
    throw new Error("Expected num_gates in CircuitInfoResponse deserialization");
  }
  if (o.num_gates_dyadic === void 0) {
    throw new Error("Expected num_gates_dyadic in CircuitInfoResponse deserialization");
  }
  if (o.num_acir_opcodes === void 0) {
    throw new Error("Expected num_acir_opcodes in CircuitInfoResponse deserialization");
  }
  if (o.gates_per_opcode === void 0) {
    throw new Error("Expected gates_per_opcode in CircuitInfoResponse deserialization");
  }
  ;
  return {
    numGates: o.num_gates,
    numGatesDyadic: o.num_gates_dyadic,
    numAcirOpcodes: o.num_acir_opcodes,
    gatesPerOpcode: o.gates_per_opcode
  };
}
function toCircuitVerifyResponse(o) {
  if (o.verified === void 0) {
    throw new Error("Expected verified in CircuitVerifyResponse deserialization");
  }
  ;
  return {
    verified: o.verified
  };
}
function toChonkComputeVkResponse(o) {
  if (o.bytes === void 0) {
    throw new Error("Expected bytes in ChonkComputeVkResponse deserialization");
  }
  if (o.fields === void 0) {
    throw new Error("Expected fields in ChonkComputeVkResponse deserialization");
  }
  ;
  return {
    bytes: o.bytes,
    fields: o.fields
  };
}
function toChonkStartResponse(o) {
  return {};
}
function toChonkLoadResponse(o) {
  return {};
}
function toChonkAccumulateResponse(o) {
  return {};
}
function toChonkProveResponse(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in ChonkProveResponse deserialization");
  }
  ;
  return {
    proof: toChonkProof(o.proof)
  };
}
function toChonkVerifyResponse(o) {
  if (o.valid === void 0) {
    throw new Error("Expected valid in ChonkVerifyResponse deserialization");
  }
  ;
  return {
    valid: o.valid
  };
}
function toChonkVerifyFromFieldsResponse(o) {
  if (o.valid === void 0) {
    throw new Error("Expected valid in ChonkVerifyFromFieldsResponse deserialization");
  }
  ;
  return {
    valid: o.valid
  };
}
function toChonkBatchVerifyResponse(o) {
  if (o.valid === void 0) {
    throw new Error("Expected valid in ChonkBatchVerifyResponse deserialization");
  }
  ;
  return {
    valid: o.valid
  };
}
function toVkAsFieldsResponse(o) {
  if (o.fields === void 0) {
    throw new Error("Expected fields in VkAsFieldsResponse deserialization");
  }
  ;
  return {
    fields: o.fields
  };
}
function toMegaVkAsFieldsResponse(o) {
  if (o.fields === void 0) {
    throw new Error("Expected fields in MegaVkAsFieldsResponse deserialization");
  }
  ;
  return {
    fields: o.fields
  };
}
function toCircuitWriteSolidityVerifierResponse(o) {
  if (o.solidity_code === void 0) {
    throw new Error("Expected solidity_code in CircuitWriteSolidityVerifierResponse deserialization");
  }
  ;
  return {
    solidityCode: o.solidity_code
  };
}
function toChonkCheckPrecomputedVkResponse(o) {
  if (o.valid === void 0) {
    throw new Error("Expected valid in ChonkCheckPrecomputedVkResponse deserialization");
  }
  if (o.actual_vk === void 0) {
    throw new Error("Expected actual_vk in ChonkCheckPrecomputedVkResponse deserialization");
  }
  ;
  return {
    valid: o.valid,
    actualVk: o.actual_vk
  };
}
function toChonkStatsResponse(o) {
  if (o.acir_opcodes === void 0) {
    throw new Error("Expected acir_opcodes in ChonkStatsResponse deserialization");
  }
  if (o.circuit_size === void 0) {
    throw new Error("Expected circuit_size in ChonkStatsResponse deserialization");
  }
  if (o.gates_per_opcode === void 0) {
    throw new Error("Expected gates_per_opcode in ChonkStatsResponse deserialization");
  }
  ;
  return {
    acirOpcodes: o.acir_opcodes,
    circuitSize: o.circuit_size,
    gatesPerOpcode: o.gates_per_opcode
  };
}
function toChonkCompressProofResponse(o) {
  if (o.compressed_proof === void 0) {
    throw new Error("Expected compressed_proof in ChonkCompressProofResponse deserialization");
  }
  ;
  return {
    compressedProof: o.compressed_proof
  };
}
function toChonkDecompressProofResponse(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in ChonkDecompressProofResponse deserialization");
  }
  ;
  return {
    proof: toChonkProof(o.proof)
  };
}
function toPoseidon2HashResponse(o) {
  if (o.hash === void 0) {
    throw new Error("Expected hash in Poseidon2HashResponse deserialization");
  }
  ;
  return {
    hash: o.hash
  };
}
function toPoseidon2PermutationResponse(o) {
  if (o.outputs === void 0) {
    throw new Error("Expected outputs in Poseidon2PermutationResponse deserialization");
  }
  ;
  return {
    outputs: o.outputs
  };
}
function toPedersenCommitResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in PedersenCommitResponse deserialization");
  }
  ;
  return {
    point: toGrumpkinPoint(o.point)
  };
}
function toPedersenHashResponse(o) {
  if (o.hash === void 0) {
    throw new Error("Expected hash in PedersenHashResponse deserialization");
  }
  ;
  return {
    hash: o.hash
  };
}
function toPedersenHashBufferResponse(o) {
  if (o.hash === void 0) {
    throw new Error("Expected hash in PedersenHashBufferResponse deserialization");
  }
  ;
  return {
    hash: o.hash
  };
}
function toBlake2sResponse(o) {
  if (o.hash === void 0) {
    throw new Error("Expected hash in Blake2sResponse deserialization");
  }
  ;
  return {
    hash: o.hash
  };
}
function toBlake2sToFieldResponse(o) {
  if (o.field === void 0) {
    throw new Error("Expected field in Blake2sToFieldResponse deserialization");
  }
  ;
  return {
    field: o.field
  };
}
function toAesEncryptResponse(o) {
  if (o.ciphertext === void 0) {
    throw new Error("Expected ciphertext in AesEncryptResponse deserialization");
  }
  ;
  return {
    ciphertext: o.ciphertext
  };
}
function toAesDecryptResponse(o) {
  if (o.plaintext === void 0) {
    throw new Error("Expected plaintext in AesDecryptResponse deserialization");
  }
  ;
  return {
    plaintext: o.plaintext
  };
}
function toGrumpkinMulResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in GrumpkinMulResponse deserialization");
  }
  ;
  return {
    point: toGrumpkinPoint(o.point)
  };
}
function toGrumpkinAddResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in GrumpkinAddResponse deserialization");
  }
  ;
  return {
    point: toGrumpkinPoint(o.point)
  };
}
function toGrumpkinBatchMulResponse(o) {
  if (o.points === void 0) {
    throw new Error("Expected points in GrumpkinBatchMulResponse deserialization");
  }
  ;
  return {
    points: o.points.map((v) => toGrumpkinPoint(v))
  };
}
function toGrumpkinGetRandomFrResponse(o) {
  if (o.value === void 0) {
    throw new Error("Expected value in GrumpkinGetRandomFrResponse deserialization");
  }
  ;
  return {
    value: o.value
  };
}
function toGrumpkinReduce512Response(o) {
  if (o.value === void 0) {
    throw new Error("Expected value in GrumpkinReduce512Response deserialization");
  }
  ;
  return {
    value: o.value
  };
}
function toSecp256k1MulResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Secp256k1MulResponse deserialization");
  }
  ;
  return {
    point: toSecp256k1Point(o.point)
  };
}
function toSecp256k1GetRandomFrResponse(o) {
  if (o.value === void 0) {
    throw new Error("Expected value in Secp256k1GetRandomFrResponse deserialization");
  }
  ;
  return {
    value: o.value
  };
}
function toSecp256k1Reduce512Response(o) {
  if (o.value === void 0) {
    throw new Error("Expected value in Secp256k1Reduce512Response deserialization");
  }
  ;
  return {
    value: o.value
  };
}
function toBn254FrSqrtResponse(o) {
  if (o.is_square_root === void 0) {
    throw new Error("Expected is_square_root in Bn254FrSqrtResponse deserialization");
  }
  if (o.value === void 0) {
    throw new Error("Expected value in Bn254FrSqrtResponse deserialization");
  }
  ;
  return {
    isSquareRoot: o.is_square_root,
    value: o.value
  };
}
function toBn254FqSqrtResponse(o) {
  if (o.is_square_root === void 0) {
    throw new Error("Expected is_square_root in Bn254FqSqrtResponse deserialization");
  }
  if (o.value === void 0) {
    throw new Error("Expected value in Bn254FqSqrtResponse deserialization");
  }
  ;
  return {
    isSquareRoot: o.is_square_root,
    value: o.value
  };
}
function toBn254G1MulResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G1MulResponse deserialization");
  }
  ;
  return {
    point: toBn254G1Point(o.point)
  };
}
function toBn254G2MulResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G2MulResponse deserialization");
  }
  ;
  return {
    point: toBn254G2Point(o.point)
  };
}
function toBn254G1IsOnCurveResponse(o) {
  if (o.is_on_curve === void 0) {
    throw new Error("Expected is_on_curve in Bn254G1IsOnCurveResponse deserialization");
  }
  ;
  return {
    isOnCurve: o.is_on_curve
  };
}
function toBn254G1FromCompressedResponse(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G1FromCompressedResponse deserialization");
  }
  ;
  return {
    point: toBn254G1Point(o.point)
  };
}
function toSchnorrComputePublicKeyResponse(o) {
  if (o.public_key === void 0) {
    throw new Error("Expected public_key in SchnorrComputePublicKeyResponse deserialization");
  }
  ;
  return {
    publicKey: toGrumpkinPoint(o.public_key)
  };
}
function toSchnorrConstructSignatureResponse(o) {
  if (o.s === void 0) {
    throw new Error("Expected s in SchnorrConstructSignatureResponse deserialization");
  }
  if (o.e === void 0) {
    throw new Error("Expected e in SchnorrConstructSignatureResponse deserialization");
  }
  ;
  return {
    s: o.s,
    e: o.e
  };
}
function toSchnorrVerifySignatureResponse(o) {
  if (o.verified === void 0) {
    throw new Error("Expected verified in SchnorrVerifySignatureResponse deserialization");
  }
  ;
  return {
    verified: o.verified
  };
}
function toEcdsaSecp256k1ComputePublicKeyResponse(o) {
  if (o.public_key === void 0) {
    throw new Error("Expected public_key in EcdsaSecp256k1ComputePublicKeyResponse deserialization");
  }
  ;
  return {
    publicKey: toSecp256k1Point(o.public_key)
  };
}
function toEcdsaSecp256r1ComputePublicKeyResponse(o) {
  if (o.public_key === void 0) {
    throw new Error("Expected public_key in EcdsaSecp256r1ComputePublicKeyResponse deserialization");
  }
  ;
  return {
    publicKey: toSecp256r1Point(o.public_key)
  };
}
function toEcdsaSecp256k1ConstructSignatureResponse(o) {
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256k1ConstructSignatureResponse deserialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256k1ConstructSignatureResponse deserialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256k1ConstructSignatureResponse deserialization");
  }
  ;
  return {
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function toEcdsaSecp256r1ConstructSignatureResponse(o) {
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256r1ConstructSignatureResponse deserialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256r1ConstructSignatureResponse deserialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256r1ConstructSignatureResponse deserialization");
  }
  ;
  return {
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function toEcdsaSecp256k1RecoverPublicKeyResponse(o) {
  if (o.public_key === void 0) {
    throw new Error("Expected public_key in EcdsaSecp256k1RecoverPublicKeyResponse deserialization");
  }
  ;
  return {
    publicKey: toSecp256k1Point(o.public_key)
  };
}
function toEcdsaSecp256r1RecoverPublicKeyResponse(o) {
  if (o.public_key === void 0) {
    throw new Error("Expected public_key in EcdsaSecp256r1RecoverPublicKeyResponse deserialization");
  }
  ;
  return {
    publicKey: toSecp256r1Point(o.public_key)
  };
}
function toEcdsaSecp256k1VerifySignatureResponse(o) {
  if (o.verified === void 0) {
    throw new Error("Expected verified in EcdsaSecp256k1VerifySignatureResponse deserialization");
  }
  ;
  return {
    verified: o.verified
  };
}
function toEcdsaSecp256r1VerifySignatureResponse(o) {
  if (o.verified === void 0) {
    throw new Error("Expected verified in EcdsaSecp256r1VerifySignatureResponse deserialization");
  }
  ;
  return {
    verified: o.verified
  };
}
function toSrsInitSrsResponse(o) {
  if (o.points_buf === void 0) {
    throw new Error("Expected points_buf in SrsInitSrsResponse deserialization");
  }
  ;
  return {
    pointsBuf: o.points_buf
  };
}
function toChonkBatchVerifierStartResponse(o) {
  return {};
}
function toChonkBatchVerifierQueueResponse(o) {
  return {};
}
function toChonkBatchVerifierStopResponse(o) {
  return {};
}
function toSrsInitGrumpkinSrsResponse(o) {
  if (o.dummy === void 0) {
    throw new Error("Expected dummy in SrsInitGrumpkinSrsResponse deserialization");
  }
  ;
  return {
    dummy: o.dummy
  };
}
function toSetMsmLegacyResponse(o) {
  if (o.enabled === void 0) {
    throw new Error("Expected enabled in SetMsmLegacyResponse deserialization");
  }
  ;
  return {
    enabled: o.enabled
  };
}
function toShutdownResponse(o) {
  return {};
}
function fromAvmProve(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in AvmProve serialization");
  }
  ;
  return {
    inputs: o.inputs
  };
}
function fromAvmVerify(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in AvmVerify serialization");
  }
  if (o.publicInputs === void 0) {
    throw new Error("Expected publicInputs in AvmVerify serialization");
  }
  ;
  return {
    proof: o.proof,
    public_inputs: o.publicInputs
  };
}
function fromAvmCheckCircuit(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in AvmCheckCircuit serialization");
  }
  ;
  return {
    inputs: o.inputs
  };
}
function fromCircuitInput(o) {
  if (o.name === void 0) {
    throw new Error("Expected name in CircuitInput serialization");
  }
  if (o.bytecode === void 0) {
    throw new Error("Expected bytecode in CircuitInput serialization");
  }
  if (o.verificationKey === void 0) {
    throw new Error("Expected verificationKey in CircuitInput serialization");
  }
  ;
  return {
    name: o.name,
    bytecode: o.bytecode,
    verification_key: o.verificationKey
  };
}
function fromProofSystemSettings(o) {
  if (o.ipaAccumulation === void 0) {
    throw new Error("Expected ipaAccumulation in ProofSystemSettings serialization");
  }
  if (o.oracleHashType === void 0) {
    throw new Error("Expected oracleHashType in ProofSystemSettings serialization");
  }
  if (o.disableZk === void 0) {
    throw new Error("Expected disableZk in ProofSystemSettings serialization");
  }
  if (o.optimizedSolidityVerifier === void 0) {
    throw new Error("Expected optimizedSolidityVerifier in ProofSystemSettings serialization");
  }
  ;
  return {
    ipa_accumulation: o.ipaAccumulation,
    oracle_hash_type: o.oracleHashType,
    disable_zk: o.disableZk,
    optimized_solidity_verifier: o.optimizedSolidityVerifier
  };
}
function fromCircuitProve(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in CircuitProve serialization");
  }
  if (o.witness === void 0) {
    throw new Error("Expected witness in CircuitProve serialization");
  }
  if (o.settings === void 0) {
    throw new Error("Expected settings in CircuitProve serialization");
  }
  ;
  return {
    circuit: fromCircuitInput(o.circuit),
    witness: o.witness,
    settings: fromProofSystemSettings(o.settings)
  };
}
function fromCircuitInputNoVK(o) {
  if (o.name === void 0) {
    throw new Error("Expected name in CircuitInputNoVK serialization");
  }
  if (o.bytecode === void 0) {
    throw new Error("Expected bytecode in CircuitInputNoVK serialization");
  }
  ;
  return {
    name: o.name,
    bytecode: o.bytecode
  };
}
function fromCircuitComputeVk(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in CircuitComputeVk serialization");
  }
  if (o.settings === void 0) {
    throw new Error("Expected settings in CircuitComputeVk serialization");
  }
  ;
  return {
    circuit: fromCircuitInputNoVK(o.circuit),
    settings: fromProofSystemSettings(o.settings)
  };
}
function fromCircuitStats(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in CircuitStats serialization");
  }
  if (o.includeGatesPerOpcode === void 0) {
    throw new Error("Expected includeGatesPerOpcode in CircuitStats serialization");
  }
  if (o.settings === void 0) {
    throw new Error("Expected settings in CircuitStats serialization");
  }
  ;
  return {
    circuit: fromCircuitInput(o.circuit),
    include_gates_per_opcode: o.includeGatesPerOpcode,
    settings: fromProofSystemSettings(o.settings)
  };
}
function fromCircuitVerify(o) {
  if (o.verificationKey === void 0) {
    throw new Error("Expected verificationKey in CircuitVerify serialization");
  }
  if (o.publicInputs === void 0) {
    throw new Error("Expected publicInputs in CircuitVerify serialization");
  }
  if (o.proof === void 0) {
    throw new Error("Expected proof in CircuitVerify serialization");
  }
  if (o.settings === void 0) {
    throw new Error("Expected settings in CircuitVerify serialization");
  }
  ;
  return {
    verification_key: o.verificationKey,
    public_inputs: o.publicInputs,
    proof: o.proof,
    settings: fromProofSystemSettings(o.settings)
  };
}
function fromChonkComputeVk(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in ChonkComputeVk serialization");
  }
  if (o.useZkFlavor === void 0) {
    throw new Error("Expected useZkFlavor in ChonkComputeVk serialization");
  }
  ;
  return {
    circuit: fromCircuitInputNoVK(o.circuit),
    use_zk_flavor: o.useZkFlavor
  };
}
function fromChonkStart(o) {
  if (o.numCircuits === void 0) {
    throw new Error("Expected numCircuits in ChonkStart serialization");
  }
  ;
  return {
    num_circuits: o.numCircuits
  };
}
function fromChonkLoad(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in ChonkLoad serialization");
  }
  ;
  return {
    circuit: fromCircuitInput(o.circuit)
  };
}
function fromChonkAccumulate(o) {
  if (o.witness === void 0) {
    throw new Error("Expected witness in ChonkAccumulate serialization");
  }
  ;
  return {
    witness: o.witness
  };
}
function fromChonkProve(o) {
  return {};
}
function fromChonkProof(o) {
  if (o.hidingOinkProof === void 0) {
    throw new Error("Expected hidingOinkProof in ChonkProof serialization");
  }
  if (o.mergeProof === void 0) {
    throw new Error("Expected mergeProof in ChonkProof serialization");
  }
  if (o.eccvmProof === void 0) {
    throw new Error("Expected eccvmProof in ChonkProof serialization");
  }
  if (o.ipaProof === void 0) {
    throw new Error("Expected ipaProof in ChonkProof serialization");
  }
  if (o.jointProof === void 0) {
    throw new Error("Expected jointProof in ChonkProof serialization");
  }
  ;
  return {
    hiding_oink_proof: o.hidingOinkProof,
    merge_proof: o.mergeProof,
    eccvm_proof: o.eccvmProof,
    ipa_proof: o.ipaProof,
    joint_proof: o.jointProof
  };
}
function fromChonkVerify(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in ChonkVerify serialization");
  }
  if (o.vk === void 0) {
    throw new Error("Expected vk in ChonkVerify serialization");
  }
  ;
  return {
    proof: fromChonkProof(o.proof),
    vk: o.vk
  };
}
function fromChonkVerifyFromFields(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in ChonkVerifyFromFields serialization");
  }
  if (o.vk === void 0) {
    throw new Error("Expected vk in ChonkVerifyFromFields serialization");
  }
  ;
  return {
    proof: o.proof,
    vk: o.vk
  };
}
function fromChonkBatchVerify(o) {
  if (o.proofs === void 0) {
    throw new Error("Expected proofs in ChonkBatchVerify serialization");
  }
  if (o.vks === void 0) {
    throw new Error("Expected vks in ChonkBatchVerify serialization");
  }
  ;
  return {
    proofs: o.proofs.map((v) => fromChonkProof(v)),
    vks: o.vks
  };
}
function fromVkAsFields(o) {
  if (o.verificationKey === void 0) {
    throw new Error("Expected verificationKey in VkAsFields serialization");
  }
  ;
  return {
    verification_key: o.verificationKey
  };
}
function fromMegaVkAsFields(o) {
  if (o.verificationKey === void 0) {
    throw new Error("Expected verificationKey in MegaVkAsFields serialization");
  }
  ;
  return {
    verification_key: o.verificationKey
  };
}
function fromCircuitWriteSolidityVerifier(o) {
  if (o.verificationKey === void 0) {
    throw new Error("Expected verificationKey in CircuitWriteSolidityVerifier serialization");
  }
  if (o.settings === void 0) {
    throw new Error("Expected settings in CircuitWriteSolidityVerifier serialization");
  }
  ;
  return {
    verification_key: o.verificationKey,
    settings: fromProofSystemSettings(o.settings)
  };
}
function fromChonkCheckPrecomputedVk(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in ChonkCheckPrecomputedVk serialization");
  }
  if (o.useZkFlavor === void 0) {
    throw new Error("Expected useZkFlavor in ChonkCheckPrecomputedVk serialization");
  }
  ;
  return {
    circuit: fromCircuitInput(o.circuit),
    use_zk_flavor: o.useZkFlavor
  };
}
function fromChonkStats(o) {
  if (o.circuit === void 0) {
    throw new Error("Expected circuit in ChonkStats serialization");
  }
  if (o.includeGatesPerOpcode === void 0) {
    throw new Error("Expected includeGatesPerOpcode in ChonkStats serialization");
  }
  ;
  return {
    circuit: fromCircuitInputNoVK(o.circuit),
    include_gates_per_opcode: o.includeGatesPerOpcode
  };
}
function fromChonkCompressProof(o) {
  if (o.proof === void 0) {
    throw new Error("Expected proof in ChonkCompressProof serialization");
  }
  ;
  return {
    proof: fromChonkProof(o.proof)
  };
}
function fromChonkDecompressProof(o) {
  if (o.compressedProof === void 0) {
    throw new Error("Expected compressedProof in ChonkDecompressProof serialization");
  }
  ;
  return {
    compressed_proof: o.compressedProof
  };
}
function fromPoseidon2Hash(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in Poseidon2Hash serialization");
  }
  ;
  return {
    inputs: o.inputs
  };
}
function fromPoseidon2Permutation(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in Poseidon2Permutation serialization");
  }
  ;
  return {
    inputs: o.inputs
  };
}
function fromPedersenCommit(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in PedersenCommit serialization");
  }
  if (o.hashIndex === void 0) {
    throw new Error("Expected hashIndex in PedersenCommit serialization");
  }
  ;
  return {
    inputs: o.inputs,
    hash_index: o.hashIndex
  };
}
function fromPedersenHash(o) {
  if (o.inputs === void 0) {
    throw new Error("Expected inputs in PedersenHash serialization");
  }
  if (o.hashIndex === void 0) {
    throw new Error("Expected hashIndex in PedersenHash serialization");
  }
  ;
  return {
    inputs: o.inputs,
    hash_index: o.hashIndex
  };
}
function fromPedersenHashBuffer(o) {
  if (o.input === void 0) {
    throw new Error("Expected input in PedersenHashBuffer serialization");
  }
  if (o.hashIndex === void 0) {
    throw new Error("Expected hashIndex in PedersenHashBuffer serialization");
  }
  ;
  return {
    input: o.input,
    hash_index: o.hashIndex
  };
}
function fromBlake2s(o) {
  if (o.data === void 0) {
    throw new Error("Expected data in Blake2s serialization");
  }
  ;
  return {
    data: o.data
  };
}
function fromBlake2sToField(o) {
  if (o.data === void 0) {
    throw new Error("Expected data in Blake2sToField serialization");
  }
  ;
  return {
    data: o.data
  };
}
function fromAesEncrypt(o) {
  if (o.plaintext === void 0) {
    throw new Error("Expected plaintext in AesEncrypt serialization");
  }
  if (o.iv === void 0) {
    throw new Error("Expected iv in AesEncrypt serialization");
  }
  if (o.key === void 0) {
    throw new Error("Expected key in AesEncrypt serialization");
  }
  if (o.length === void 0) {
    throw new Error("Expected length in AesEncrypt serialization");
  }
  ;
  return {
    plaintext: o.plaintext,
    iv: o.iv,
    key: o.key,
    length: o.length
  };
}
function fromAesDecrypt(o) {
  if (o.ciphertext === void 0) {
    throw new Error("Expected ciphertext in AesDecrypt serialization");
  }
  if (o.iv === void 0) {
    throw new Error("Expected iv in AesDecrypt serialization");
  }
  if (o.key === void 0) {
    throw new Error("Expected key in AesDecrypt serialization");
  }
  if (o.length === void 0) {
    throw new Error("Expected length in AesDecrypt serialization");
  }
  ;
  return {
    ciphertext: o.ciphertext,
    iv: o.iv,
    key: o.key,
    length: o.length
  };
}
function fromGrumpkinPoint(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in GrumpkinPoint serialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in GrumpkinPoint serialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function fromGrumpkinMul(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in GrumpkinMul serialization");
  }
  if (o.scalar === void 0) {
    throw new Error("Expected scalar in GrumpkinMul serialization");
  }
  ;
  return {
    point: fromGrumpkinPoint(o.point),
    scalar: o.scalar
  };
}
function fromGrumpkinAdd(o) {
  if (o.pointA === void 0) {
    throw new Error("Expected pointA in GrumpkinAdd serialization");
  }
  if (o.pointB === void 0) {
    throw new Error("Expected pointB in GrumpkinAdd serialization");
  }
  ;
  return {
    point_a: fromGrumpkinPoint(o.pointA),
    point_b: fromGrumpkinPoint(o.pointB)
  };
}
function fromGrumpkinBatchMul(o) {
  if (o.points === void 0) {
    throw new Error("Expected points in GrumpkinBatchMul serialization");
  }
  if (o.scalar === void 0) {
    throw new Error("Expected scalar in GrumpkinBatchMul serialization");
  }
  ;
  return {
    points: o.points.map((v) => fromGrumpkinPoint(v)),
    scalar: o.scalar
  };
}
function fromGrumpkinGetRandomFr(o) {
  if (o.dummy === void 0) {
    throw new Error("Expected dummy in GrumpkinGetRandomFr serialization");
  }
  ;
  return {
    dummy: o.dummy
  };
}
function fromGrumpkinReduce512(o) {
  if (o.input === void 0) {
    throw new Error("Expected input in GrumpkinReduce512 serialization");
  }
  ;
  return {
    input: o.input
  };
}
function fromSecp256k1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Secp256k1Point serialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Secp256k1Point serialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function fromSecp256k1Mul(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Secp256k1Mul serialization");
  }
  if (o.scalar === void 0) {
    throw new Error("Expected scalar in Secp256k1Mul serialization");
  }
  ;
  return {
    point: fromSecp256k1Point(o.point),
    scalar: o.scalar
  };
}
function fromSecp256k1GetRandomFr(o) {
  if (o.dummy === void 0) {
    throw new Error("Expected dummy in Secp256k1GetRandomFr serialization");
  }
  ;
  return {
    dummy: o.dummy
  };
}
function fromSecp256k1Reduce512(o) {
  if (o.input === void 0) {
    throw new Error("Expected input in Secp256k1Reduce512 serialization");
  }
  ;
  return {
    input: o.input
  };
}
function fromBn254FrSqrt(o) {
  if (o.input === void 0) {
    throw new Error("Expected input in Bn254FrSqrt serialization");
  }
  ;
  return {
    input: o.input
  };
}
function fromBn254FqSqrt(o) {
  if (o.input === void 0) {
    throw new Error("Expected input in Bn254FqSqrt serialization");
  }
  ;
  return {
    input: o.input
  };
}
function fromBn254G1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Bn254G1Point serialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Bn254G1Point serialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function fromBn254G1Mul(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G1Mul serialization");
  }
  if (o.scalar === void 0) {
    throw new Error("Expected scalar in Bn254G1Mul serialization");
  }
  ;
  return {
    point: fromBn254G1Point(o.point),
    scalar: o.scalar
  };
}
function fromBn254G2Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Bn254G2Point serialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Bn254G2Point serialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function fromBn254G2Mul(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G2Mul serialization");
  }
  if (o.scalar === void 0) {
    throw new Error("Expected scalar in Bn254G2Mul serialization");
  }
  ;
  return {
    point: fromBn254G2Point(o.point),
    scalar: o.scalar
  };
}
function fromBn254G1IsOnCurve(o) {
  if (o.point === void 0) {
    throw new Error("Expected point in Bn254G1IsOnCurve serialization");
  }
  ;
  return {
    point: fromBn254G1Point(o.point)
  };
}
function fromBn254G1FromCompressed(o) {
  if (o.compressed === void 0) {
    throw new Error("Expected compressed in Bn254G1FromCompressed serialization");
  }
  ;
  return {
    compressed: o.compressed
  };
}
function fromSchnorrComputePublicKey(o) {
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in SchnorrComputePublicKey serialization");
  }
  ;
  return {
    private_key: o.privateKey
  };
}
function fromSchnorrConstructSignature(o) {
  if (o.messageField === void 0) {
    throw new Error("Expected messageField in SchnorrConstructSignature serialization");
  }
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in SchnorrConstructSignature serialization");
  }
  ;
  return {
    message_field: o.messageField,
    private_key: o.privateKey
  };
}
function fromSchnorrVerifySignature(o) {
  if (o.messageField === void 0) {
    throw new Error("Expected messageField in SchnorrVerifySignature serialization");
  }
  if (o.publicKey === void 0) {
    throw new Error("Expected publicKey in SchnorrVerifySignature serialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in SchnorrVerifySignature serialization");
  }
  if (o.e === void 0) {
    throw new Error("Expected e in SchnorrVerifySignature serialization");
  }
  ;
  return {
    message_field: o.messageField,
    public_key: fromGrumpkinPoint(o.publicKey),
    s: o.s,
    e: o.e
  };
}
function fromEcdsaSecp256k1ComputePublicKey(o) {
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in EcdsaSecp256k1ComputePublicKey serialization");
  }
  ;
  return {
    private_key: o.privateKey
  };
}
function fromEcdsaSecp256r1ComputePublicKey(o) {
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in EcdsaSecp256r1ComputePublicKey serialization");
  }
  ;
  return {
    private_key: o.privateKey
  };
}
function fromEcdsaSecp256k1ConstructSignature(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256k1ConstructSignature serialization");
  }
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in EcdsaSecp256k1ConstructSignature serialization");
  }
  ;
  return {
    message: o.message,
    private_key: o.privateKey
  };
}
function fromEcdsaSecp256r1ConstructSignature(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256r1ConstructSignature serialization");
  }
  if (o.privateKey === void 0) {
    throw new Error("Expected privateKey in EcdsaSecp256r1ConstructSignature serialization");
  }
  ;
  return {
    message: o.message,
    private_key: o.privateKey
  };
}
function fromEcdsaSecp256k1RecoverPublicKey(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256k1RecoverPublicKey serialization");
  }
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256k1RecoverPublicKey serialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256k1RecoverPublicKey serialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256k1RecoverPublicKey serialization");
  }
  ;
  return {
    message: o.message,
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function fromEcdsaSecp256r1RecoverPublicKey(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256r1RecoverPublicKey serialization");
  }
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256r1RecoverPublicKey serialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256r1RecoverPublicKey serialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256r1RecoverPublicKey serialization");
  }
  ;
  return {
    message: o.message,
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function fromEcdsaSecp256k1VerifySignature(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256k1VerifySignature serialization");
  }
  if (o.publicKey === void 0) {
    throw new Error("Expected publicKey in EcdsaSecp256k1VerifySignature serialization");
  }
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256k1VerifySignature serialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256k1VerifySignature serialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256k1VerifySignature serialization");
  }
  ;
  return {
    message: o.message,
    public_key: fromSecp256k1Point(o.publicKey),
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function fromSecp256r1Point(o) {
  if (o.x === void 0) {
    throw new Error("Expected x in Secp256r1Point serialization");
  }
  if (o.y === void 0) {
    throw new Error("Expected y in Secp256r1Point serialization");
  }
  ;
  return {
    x: o.x,
    y: o.y
  };
}
function fromEcdsaSecp256r1VerifySignature(o) {
  if (o.message === void 0) {
    throw new Error("Expected message in EcdsaSecp256r1VerifySignature serialization");
  }
  if (o.publicKey === void 0) {
    throw new Error("Expected publicKey in EcdsaSecp256r1VerifySignature serialization");
  }
  if (o.r === void 0) {
    throw new Error("Expected r in EcdsaSecp256r1VerifySignature serialization");
  }
  if (o.s === void 0) {
    throw new Error("Expected s in EcdsaSecp256r1VerifySignature serialization");
  }
  if (o.v === void 0) {
    throw new Error("Expected v in EcdsaSecp256r1VerifySignature serialization");
  }
  ;
  return {
    message: o.message,
    public_key: fromSecp256r1Point(o.publicKey),
    r: o.r,
    s: o.s,
    v: o.v
  };
}
function fromSrsInitSrs(o) {
  if (o.pointsBuf === void 0) {
    throw new Error("Expected pointsBuf in SrsInitSrs serialization");
  }
  if (o.numPoints === void 0) {
    throw new Error("Expected numPoints in SrsInitSrs serialization");
  }
  if (o.g2Point === void 0) {
    throw new Error("Expected g2Point in SrsInitSrs serialization");
  }
  ;
  return {
    points_buf: o.pointsBuf,
    num_points: o.numPoints,
    g2_point: o.g2Point
  };
}
function fromChonkBatchVerifierStart(o) {
  if (o.vks === void 0) {
    throw new Error("Expected vks in ChonkBatchVerifierStart serialization");
  }
  if (o.numCores === void 0) {
    throw new Error("Expected numCores in ChonkBatchVerifierStart serialization");
  }
  if (o.batchSize === void 0) {
    throw new Error("Expected batchSize in ChonkBatchVerifierStart serialization");
  }
  if (o.fifoPath === void 0) {
    throw new Error("Expected fifoPath in ChonkBatchVerifierStart serialization");
  }
  ;
  return {
    vks: o.vks,
    num_cores: o.numCores,
    batch_size: o.batchSize,
    fifo_path: o.fifoPath
  };
}
function fromChonkBatchVerifierQueue(o) {
  if (o.requestId === void 0) {
    throw new Error("Expected requestId in ChonkBatchVerifierQueue serialization");
  }
  if (o.vkIndex === void 0) {
    throw new Error("Expected vkIndex in ChonkBatchVerifierQueue serialization");
  }
  if (o.proofFields === void 0) {
    throw new Error("Expected proofFields in ChonkBatchVerifierQueue serialization");
  }
  ;
  return {
    request_id: o.requestId,
    vk_index: o.vkIndex,
    proof_fields: o.proofFields
  };
}
function fromChonkBatchVerifierStop(o) {
  return {};
}
function fromSrsInitGrumpkinSrs(o) {
  if (o.pointsBuf === void 0) {
    throw new Error("Expected pointsBuf in SrsInitGrumpkinSrs serialization");
  }
  if (o.numPoints === void 0) {
    throw new Error("Expected numPoints in SrsInitGrumpkinSrs serialization");
  }
  ;
  return {
    points_buf: o.pointsBuf,
    num_points: o.numPoints
  };
}
function fromSetMsmLegacy(o) {
  if (o.enabled === void 0) {
    throw new Error("Expected enabled in SetMsmLegacy serialization");
  }
  ;
  return {
    enabled: o.enabled
  };
}
function fromShutdown(o) {
  return {};
}

// node_modules/@aztec/bb.js/dest/browser/cbind/generated/async.js
async function msgpackCall(backend, input) {
  const inputBuffer = new Encoder({ useRecords: false }).pack(input);
  const encodedResult = await backend.call(inputBuffer);
  return new Decoder({ useRecords: false }).unpack(encodedResult);
}
var AsyncApi = class {
  backend;
  constructor(backend) {
    this.backend = backend;
  }
  avmProve(command) {
    const msgpackCommand = fromAvmProve(command);
    return msgpackCall(this.backend, [["AvmProve", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "AvmProveResponse") {
        throw new BBApiException(`Expected variant name 'AvmProveResponse' but got '${variantName}'`);
      }
      return toAvmProveResponse(result);
    });
  }
  avmVerify(command) {
    const msgpackCommand = fromAvmVerify(command);
    return msgpackCall(this.backend, [["AvmVerify", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "AvmVerifyResponse") {
        throw new BBApiException(`Expected variant name 'AvmVerifyResponse' but got '${variantName}'`);
      }
      return toAvmVerifyResponse(result);
    });
  }
  avmCheckCircuit(command) {
    const msgpackCommand = fromAvmCheckCircuit(command);
    return msgpackCall(this.backend, [["AvmCheckCircuit", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "AvmCheckCircuitResponse") {
        throw new BBApiException(`Expected variant name 'AvmCheckCircuitResponse' but got '${variantName}'`);
      }
      return toAvmCheckCircuitResponse(result);
    });
  }
  circuitProve(command) {
    const msgpackCommand = fromCircuitProve(command);
    return msgpackCall(this.backend, [["CircuitProve", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "CircuitProveResponse") {
        throw new BBApiException(`Expected variant name 'CircuitProveResponse' but got '${variantName}'`);
      }
      return toCircuitProveResponse(result);
    });
  }
  circuitComputeVk(command) {
    const msgpackCommand = fromCircuitComputeVk(command);
    return msgpackCall(this.backend, [["CircuitComputeVk", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "CircuitComputeVkResponse") {
        throw new BBApiException(`Expected variant name 'CircuitComputeVkResponse' but got '${variantName}'`);
      }
      return toCircuitComputeVkResponse(result);
    });
  }
  circuitStats(command) {
    const msgpackCommand = fromCircuitStats(command);
    return msgpackCall(this.backend, [["CircuitStats", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "CircuitInfoResponse") {
        throw new BBApiException(`Expected variant name 'CircuitInfoResponse' but got '${variantName}'`);
      }
      return toCircuitInfoResponse(result);
    });
  }
  circuitVerify(command) {
    const msgpackCommand = fromCircuitVerify(command);
    return msgpackCall(this.backend, [["CircuitVerify", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "CircuitVerifyResponse") {
        throw new BBApiException(`Expected variant name 'CircuitVerifyResponse' but got '${variantName}'`);
      }
      return toCircuitVerifyResponse(result);
    });
  }
  chonkComputeVk(command) {
    const msgpackCommand = fromChonkComputeVk(command);
    return msgpackCall(this.backend, [["ChonkComputeVk", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkComputeVkResponse") {
        throw new BBApiException(`Expected variant name 'ChonkComputeVkResponse' but got '${variantName}'`);
      }
      return toChonkComputeVkResponse(result);
    });
  }
  chonkStart(command) {
    const msgpackCommand = fromChonkStart(command);
    return msgpackCall(this.backend, [["ChonkStart", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkStartResponse") {
        throw new BBApiException(`Expected variant name 'ChonkStartResponse' but got '${variantName}'`);
      }
      return toChonkStartResponse(result);
    });
  }
  chonkLoad(command) {
    const msgpackCommand = fromChonkLoad(command);
    return msgpackCall(this.backend, [["ChonkLoad", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkLoadResponse") {
        throw new BBApiException(`Expected variant name 'ChonkLoadResponse' but got '${variantName}'`);
      }
      return toChonkLoadResponse(result);
    });
  }
  chonkAccumulate(command) {
    const msgpackCommand = fromChonkAccumulate(command);
    return msgpackCall(this.backend, [["ChonkAccumulate", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkAccumulateResponse") {
        throw new BBApiException(`Expected variant name 'ChonkAccumulateResponse' but got '${variantName}'`);
      }
      return toChonkAccumulateResponse(result);
    });
  }
  chonkProve(command) {
    const msgpackCommand = fromChonkProve(command);
    return msgpackCall(this.backend, [["ChonkProve", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkProveResponse") {
        throw new BBApiException(`Expected variant name 'ChonkProveResponse' but got '${variantName}'`);
      }
      return toChonkProveResponse(result);
    });
  }
  chonkVerify(command) {
    const msgpackCommand = fromChonkVerify(command);
    return msgpackCall(this.backend, [["ChonkVerify", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkVerifyResponse") {
        throw new BBApiException(`Expected variant name 'ChonkVerifyResponse' but got '${variantName}'`);
      }
      return toChonkVerifyResponse(result);
    });
  }
  chonkVerifyFromFields(command) {
    const msgpackCommand = fromChonkVerifyFromFields(command);
    return msgpackCall(this.backend, [["ChonkVerifyFromFields", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkVerifyFromFieldsResponse") {
        throw new BBApiException(`Expected variant name 'ChonkVerifyFromFieldsResponse' but got '${variantName}'`);
      }
      return toChonkVerifyFromFieldsResponse(result);
    });
  }
  chonkBatchVerify(command) {
    const msgpackCommand = fromChonkBatchVerify(command);
    return msgpackCall(this.backend, [["ChonkBatchVerify", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkBatchVerifyResponse") {
        throw new BBApiException(`Expected variant name 'ChonkBatchVerifyResponse' but got '${variantName}'`);
      }
      return toChonkBatchVerifyResponse(result);
    });
  }
  vkAsFields(command) {
    const msgpackCommand = fromVkAsFields(command);
    return msgpackCall(this.backend, [["VkAsFields", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "VkAsFieldsResponse") {
        throw new BBApiException(`Expected variant name 'VkAsFieldsResponse' but got '${variantName}'`);
      }
      return toVkAsFieldsResponse(result);
    });
  }
  megaVkAsFields(command) {
    const msgpackCommand = fromMegaVkAsFields(command);
    return msgpackCall(this.backend, [["MegaVkAsFields", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "MegaVkAsFieldsResponse") {
        throw new BBApiException(`Expected variant name 'MegaVkAsFieldsResponse' but got '${variantName}'`);
      }
      return toMegaVkAsFieldsResponse(result);
    });
  }
  circuitWriteSolidityVerifier(command) {
    const msgpackCommand = fromCircuitWriteSolidityVerifier(command);
    return msgpackCall(this.backend, [["CircuitWriteSolidityVerifier", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "CircuitWriteSolidityVerifierResponse") {
        throw new BBApiException(`Expected variant name 'CircuitWriteSolidityVerifierResponse' but got '${variantName}'`);
      }
      return toCircuitWriteSolidityVerifierResponse(result);
    });
  }
  chonkCheckPrecomputedVk(command) {
    const msgpackCommand = fromChonkCheckPrecomputedVk(command);
    return msgpackCall(this.backend, [["ChonkCheckPrecomputedVk", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkCheckPrecomputedVkResponse") {
        throw new BBApiException(`Expected variant name 'ChonkCheckPrecomputedVkResponse' but got '${variantName}'`);
      }
      return toChonkCheckPrecomputedVkResponse(result);
    });
  }
  chonkStats(command) {
    const msgpackCommand = fromChonkStats(command);
    return msgpackCall(this.backend, [["ChonkStats", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkStatsResponse") {
        throw new BBApiException(`Expected variant name 'ChonkStatsResponse' but got '${variantName}'`);
      }
      return toChonkStatsResponse(result);
    });
  }
  chonkCompressProof(command) {
    const msgpackCommand = fromChonkCompressProof(command);
    return msgpackCall(this.backend, [["ChonkCompressProof", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkCompressProofResponse") {
        throw new BBApiException(`Expected variant name 'ChonkCompressProofResponse' but got '${variantName}'`);
      }
      return toChonkCompressProofResponse(result);
    });
  }
  chonkDecompressProof(command) {
    const msgpackCommand = fromChonkDecompressProof(command);
    return msgpackCall(this.backend, [["ChonkDecompressProof", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkDecompressProofResponse") {
        throw new BBApiException(`Expected variant name 'ChonkDecompressProofResponse' but got '${variantName}'`);
      }
      return toChonkDecompressProofResponse(result);
    });
  }
  poseidon2Hash(command) {
    const msgpackCommand = fromPoseidon2Hash(command);
    return msgpackCall(this.backend, [["Poseidon2Hash", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Poseidon2HashResponse") {
        throw new BBApiException(`Expected variant name 'Poseidon2HashResponse' but got '${variantName}'`);
      }
      return toPoseidon2HashResponse(result);
    });
  }
  poseidon2Permutation(command) {
    const msgpackCommand = fromPoseidon2Permutation(command);
    return msgpackCall(this.backend, [["Poseidon2Permutation", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Poseidon2PermutationResponse") {
        throw new BBApiException(`Expected variant name 'Poseidon2PermutationResponse' but got '${variantName}'`);
      }
      return toPoseidon2PermutationResponse(result);
    });
  }
  pedersenCommit(command) {
    const msgpackCommand = fromPedersenCommit(command);
    return msgpackCall(this.backend, [["PedersenCommit", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "PedersenCommitResponse") {
        throw new BBApiException(`Expected variant name 'PedersenCommitResponse' but got '${variantName}'`);
      }
      return toPedersenCommitResponse(result);
    });
  }
  pedersenHash(command) {
    const msgpackCommand = fromPedersenHash(command);
    return msgpackCall(this.backend, [["PedersenHash", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "PedersenHashResponse") {
        throw new BBApiException(`Expected variant name 'PedersenHashResponse' but got '${variantName}'`);
      }
      return toPedersenHashResponse(result);
    });
  }
  pedersenHashBuffer(command) {
    const msgpackCommand = fromPedersenHashBuffer(command);
    return msgpackCall(this.backend, [["PedersenHashBuffer", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "PedersenHashBufferResponse") {
        throw new BBApiException(`Expected variant name 'PedersenHashBufferResponse' but got '${variantName}'`);
      }
      return toPedersenHashBufferResponse(result);
    });
  }
  blake2s(command) {
    const msgpackCommand = fromBlake2s(command);
    return msgpackCall(this.backend, [["Blake2s", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Blake2sResponse") {
        throw new BBApiException(`Expected variant name 'Blake2sResponse' but got '${variantName}'`);
      }
      return toBlake2sResponse(result);
    });
  }
  blake2sToField(command) {
    const msgpackCommand = fromBlake2sToField(command);
    return msgpackCall(this.backend, [["Blake2sToField", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Blake2sToFieldResponse") {
        throw new BBApiException(`Expected variant name 'Blake2sToFieldResponse' but got '${variantName}'`);
      }
      return toBlake2sToFieldResponse(result);
    });
  }
  aesEncrypt(command) {
    const msgpackCommand = fromAesEncrypt(command);
    return msgpackCall(this.backend, [["AesEncrypt", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "AesEncryptResponse") {
        throw new BBApiException(`Expected variant name 'AesEncryptResponse' but got '${variantName}'`);
      }
      return toAesEncryptResponse(result);
    });
  }
  aesDecrypt(command) {
    const msgpackCommand = fromAesDecrypt(command);
    return msgpackCall(this.backend, [["AesDecrypt", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "AesDecryptResponse") {
        throw new BBApiException(`Expected variant name 'AesDecryptResponse' but got '${variantName}'`);
      }
      return toAesDecryptResponse(result);
    });
  }
  grumpkinMul(command) {
    const msgpackCommand = fromGrumpkinMul(command);
    return msgpackCall(this.backend, [["GrumpkinMul", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "GrumpkinMulResponse") {
        throw new BBApiException(`Expected variant name 'GrumpkinMulResponse' but got '${variantName}'`);
      }
      return toGrumpkinMulResponse(result);
    });
  }
  grumpkinAdd(command) {
    const msgpackCommand = fromGrumpkinAdd(command);
    return msgpackCall(this.backend, [["GrumpkinAdd", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "GrumpkinAddResponse") {
        throw new BBApiException(`Expected variant name 'GrumpkinAddResponse' but got '${variantName}'`);
      }
      return toGrumpkinAddResponse(result);
    });
  }
  grumpkinBatchMul(command) {
    const msgpackCommand = fromGrumpkinBatchMul(command);
    return msgpackCall(this.backend, [["GrumpkinBatchMul", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "GrumpkinBatchMulResponse") {
        throw new BBApiException(`Expected variant name 'GrumpkinBatchMulResponse' but got '${variantName}'`);
      }
      return toGrumpkinBatchMulResponse(result);
    });
  }
  grumpkinGetRandomFr(command) {
    const msgpackCommand = fromGrumpkinGetRandomFr(command);
    return msgpackCall(this.backend, [["GrumpkinGetRandomFr", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "GrumpkinGetRandomFrResponse") {
        throw new BBApiException(`Expected variant name 'GrumpkinGetRandomFrResponse' but got '${variantName}'`);
      }
      return toGrumpkinGetRandomFrResponse(result);
    });
  }
  grumpkinReduce512(command) {
    const msgpackCommand = fromGrumpkinReduce512(command);
    return msgpackCall(this.backend, [["GrumpkinReduce512", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "GrumpkinReduce512Response") {
        throw new BBApiException(`Expected variant name 'GrumpkinReduce512Response' but got '${variantName}'`);
      }
      return toGrumpkinReduce512Response(result);
    });
  }
  secp256k1Mul(command) {
    const msgpackCommand = fromSecp256k1Mul(command);
    return msgpackCall(this.backend, [["Secp256k1Mul", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Secp256k1MulResponse") {
        throw new BBApiException(`Expected variant name 'Secp256k1MulResponse' but got '${variantName}'`);
      }
      return toSecp256k1MulResponse(result);
    });
  }
  secp256k1GetRandomFr(command) {
    const msgpackCommand = fromSecp256k1GetRandomFr(command);
    return msgpackCall(this.backend, [["Secp256k1GetRandomFr", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Secp256k1GetRandomFrResponse") {
        throw new BBApiException(`Expected variant name 'Secp256k1GetRandomFrResponse' but got '${variantName}'`);
      }
      return toSecp256k1GetRandomFrResponse(result);
    });
  }
  secp256k1Reduce512(command) {
    const msgpackCommand = fromSecp256k1Reduce512(command);
    return msgpackCall(this.backend, [["Secp256k1Reduce512", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Secp256k1Reduce512Response") {
        throw new BBApiException(`Expected variant name 'Secp256k1Reduce512Response' but got '${variantName}'`);
      }
      return toSecp256k1Reduce512Response(result);
    });
  }
  bn254FrSqrt(command) {
    const msgpackCommand = fromBn254FrSqrt(command);
    return msgpackCall(this.backend, [["Bn254FrSqrt", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254FrSqrtResponse") {
        throw new BBApiException(`Expected variant name 'Bn254FrSqrtResponse' but got '${variantName}'`);
      }
      return toBn254FrSqrtResponse(result);
    });
  }
  bn254FqSqrt(command) {
    const msgpackCommand = fromBn254FqSqrt(command);
    return msgpackCall(this.backend, [["Bn254FqSqrt", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254FqSqrtResponse") {
        throw new BBApiException(`Expected variant name 'Bn254FqSqrtResponse' but got '${variantName}'`);
      }
      return toBn254FqSqrtResponse(result);
    });
  }
  bn254G1Mul(command) {
    const msgpackCommand = fromBn254G1Mul(command);
    return msgpackCall(this.backend, [["Bn254G1Mul", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254G1MulResponse") {
        throw new BBApiException(`Expected variant name 'Bn254G1MulResponse' but got '${variantName}'`);
      }
      return toBn254G1MulResponse(result);
    });
  }
  bn254G2Mul(command) {
    const msgpackCommand = fromBn254G2Mul(command);
    return msgpackCall(this.backend, [["Bn254G2Mul", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254G2MulResponse") {
        throw new BBApiException(`Expected variant name 'Bn254G2MulResponse' but got '${variantName}'`);
      }
      return toBn254G2MulResponse(result);
    });
  }
  bn254G1IsOnCurve(command) {
    const msgpackCommand = fromBn254G1IsOnCurve(command);
    return msgpackCall(this.backend, [["Bn254G1IsOnCurve", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254G1IsOnCurveResponse") {
        throw new BBApiException(`Expected variant name 'Bn254G1IsOnCurveResponse' but got '${variantName}'`);
      }
      return toBn254G1IsOnCurveResponse(result);
    });
  }
  bn254G1FromCompressed(command) {
    const msgpackCommand = fromBn254G1FromCompressed(command);
    return msgpackCall(this.backend, [["Bn254G1FromCompressed", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "Bn254G1FromCompressedResponse") {
        throw new BBApiException(`Expected variant name 'Bn254G1FromCompressedResponse' but got '${variantName}'`);
      }
      return toBn254G1FromCompressedResponse(result);
    });
  }
  schnorrComputePublicKey(command) {
    const msgpackCommand = fromSchnorrComputePublicKey(command);
    return msgpackCall(this.backend, [["SchnorrComputePublicKey", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SchnorrComputePublicKeyResponse") {
        throw new BBApiException(`Expected variant name 'SchnorrComputePublicKeyResponse' but got '${variantName}'`);
      }
      return toSchnorrComputePublicKeyResponse(result);
    });
  }
  schnorrConstructSignature(command) {
    const msgpackCommand = fromSchnorrConstructSignature(command);
    return msgpackCall(this.backend, [["SchnorrConstructSignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SchnorrConstructSignatureResponse") {
        throw new BBApiException(`Expected variant name 'SchnorrConstructSignatureResponse' but got '${variantName}'`);
      }
      return toSchnorrConstructSignatureResponse(result);
    });
  }
  schnorrVerifySignature(command) {
    const msgpackCommand = fromSchnorrVerifySignature(command);
    return msgpackCall(this.backend, [["SchnorrVerifySignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SchnorrVerifySignatureResponse") {
        throw new BBApiException(`Expected variant name 'SchnorrVerifySignatureResponse' but got '${variantName}'`);
      }
      return toSchnorrVerifySignatureResponse(result);
    });
  }
  ecdsaSecp256k1ComputePublicKey(command) {
    const msgpackCommand = fromEcdsaSecp256k1ComputePublicKey(command);
    return msgpackCall(this.backend, [["EcdsaSecp256k1ComputePublicKey", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256k1ComputePublicKeyResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256k1ComputePublicKeyResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256k1ComputePublicKeyResponse(result);
    });
  }
  ecdsaSecp256r1ComputePublicKey(command) {
    const msgpackCommand = fromEcdsaSecp256r1ComputePublicKey(command);
    return msgpackCall(this.backend, [["EcdsaSecp256r1ComputePublicKey", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256r1ComputePublicKeyResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256r1ComputePublicKeyResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256r1ComputePublicKeyResponse(result);
    });
  }
  ecdsaSecp256k1ConstructSignature(command) {
    const msgpackCommand = fromEcdsaSecp256k1ConstructSignature(command);
    return msgpackCall(this.backend, [["EcdsaSecp256k1ConstructSignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256k1ConstructSignatureResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256k1ConstructSignatureResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256k1ConstructSignatureResponse(result);
    });
  }
  ecdsaSecp256r1ConstructSignature(command) {
    const msgpackCommand = fromEcdsaSecp256r1ConstructSignature(command);
    return msgpackCall(this.backend, [["EcdsaSecp256r1ConstructSignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256r1ConstructSignatureResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256r1ConstructSignatureResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256r1ConstructSignatureResponse(result);
    });
  }
  ecdsaSecp256k1RecoverPublicKey(command) {
    const msgpackCommand = fromEcdsaSecp256k1RecoverPublicKey(command);
    return msgpackCall(this.backend, [["EcdsaSecp256k1RecoverPublicKey", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256k1RecoverPublicKeyResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256k1RecoverPublicKeyResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256k1RecoverPublicKeyResponse(result);
    });
  }
  ecdsaSecp256r1RecoverPublicKey(command) {
    const msgpackCommand = fromEcdsaSecp256r1RecoverPublicKey(command);
    return msgpackCall(this.backend, [["EcdsaSecp256r1RecoverPublicKey", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256r1RecoverPublicKeyResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256r1RecoverPublicKeyResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256r1RecoverPublicKeyResponse(result);
    });
  }
  ecdsaSecp256k1VerifySignature(command) {
    const msgpackCommand = fromEcdsaSecp256k1VerifySignature(command);
    return msgpackCall(this.backend, [["EcdsaSecp256k1VerifySignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256k1VerifySignatureResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256k1VerifySignatureResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256k1VerifySignatureResponse(result);
    });
  }
  ecdsaSecp256r1VerifySignature(command) {
    const msgpackCommand = fromEcdsaSecp256r1VerifySignature(command);
    return msgpackCall(this.backend, [["EcdsaSecp256r1VerifySignature", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "EcdsaSecp256r1VerifySignatureResponse") {
        throw new BBApiException(`Expected variant name 'EcdsaSecp256r1VerifySignatureResponse' but got '${variantName}'`);
      }
      return toEcdsaSecp256r1VerifySignatureResponse(result);
    });
  }
  srsInitSrs(command) {
    const msgpackCommand = fromSrsInitSrs(command);
    return msgpackCall(this.backend, [["SrsInitSrs", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SrsInitSrsResponse") {
        throw new BBApiException(`Expected variant name 'SrsInitSrsResponse' but got '${variantName}'`);
      }
      return toSrsInitSrsResponse(result);
    });
  }
  chonkBatchVerifierStart(command) {
    const msgpackCommand = fromChonkBatchVerifierStart(command);
    return msgpackCall(this.backend, [["ChonkBatchVerifierStart", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkBatchVerifierStartResponse") {
        throw new BBApiException(`Expected variant name 'ChonkBatchVerifierStartResponse' but got '${variantName}'`);
      }
      return toChonkBatchVerifierStartResponse(result);
    });
  }
  chonkBatchVerifierQueue(command) {
    const msgpackCommand = fromChonkBatchVerifierQueue(command);
    return msgpackCall(this.backend, [["ChonkBatchVerifierQueue", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkBatchVerifierQueueResponse") {
        throw new BBApiException(`Expected variant name 'ChonkBatchVerifierQueueResponse' but got '${variantName}'`);
      }
      return toChonkBatchVerifierQueueResponse(result);
    });
  }
  chonkBatchVerifierStop(command) {
    const msgpackCommand = fromChonkBatchVerifierStop(command);
    return msgpackCall(this.backend, [["ChonkBatchVerifierStop", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ChonkBatchVerifierStopResponse") {
        throw new BBApiException(`Expected variant name 'ChonkBatchVerifierStopResponse' but got '${variantName}'`);
      }
      return toChonkBatchVerifierStopResponse(result);
    });
  }
  srsInitGrumpkinSrs(command) {
    const msgpackCommand = fromSrsInitGrumpkinSrs(command);
    return msgpackCall(this.backend, [["SrsInitGrumpkinSrs", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SrsInitGrumpkinSrsResponse") {
        throw new BBApiException(`Expected variant name 'SrsInitGrumpkinSrsResponse' but got '${variantName}'`);
      }
      return toSrsInitGrumpkinSrsResponse(result);
    });
  }
  setMsmLegacy(command) {
    const msgpackCommand = fromSetMsmLegacy(command);
    return msgpackCall(this.backend, [["SetMsmLegacy", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "SetMsmLegacyResponse") {
        throw new BBApiException(`Expected variant name 'SetMsmLegacyResponse' but got '${variantName}'`);
      }
      return toSetMsmLegacyResponse(result);
    });
  }
  shutdown(command) {
    const msgpackCommand = fromShutdown(command);
    return msgpackCall(this.backend, [["Shutdown", msgpackCommand]]).then(([variantName, result]) => {
      if (variantName === "ErrorResponse") {
        throw new BBApiException(result.message || "Unknown error from barretenberg");
      }
      if (variantName !== "ShutdownResponse") {
        throw new BBApiException(`Expected variant name 'ShutdownResponse' but got '${variantName}'`);
      }
      return toShutdownResponse(result);
    });
  }
  destroy() {
    return this.backend.destroy ? this.backend.destroy() : Promise.resolve();
  }
};

// node_modules/@aztec/bb.js/dest/browser/bb_backends/index.js
var BackendType;
(function(BackendType2) {
  BackendType2["Wasm"] = "Wasm";
  BackendType2["WasmWorker"] = "WasmWorker";
  BackendType2["NativeUnixSocket"] = "NativeUnixSocket";
  BackendType2["NativeSharedMemory"] = "NativeSharedMemory";
})(BackendType || (BackendType = {}));

// node_modules/comlink/dist/esm/comlink.mjs
var proxyMarker = /* @__PURE__ */ Symbol("Comlink.proxy");
var createEndpoint = /* @__PURE__ */ Symbol("Comlink.endpoint");
var releaseProxy = /* @__PURE__ */ Symbol("Comlink.releaseProxy");
var finalizer = /* @__PURE__ */ Symbol("Comlink.finalizer");
var throwMarker = /* @__PURE__ */ Symbol("Comlink.thrown");
var isObject = (val) => typeof val === "object" && val !== null || typeof val === "function";
var proxyTransferHandler = {
  canHandle: (val) => isObject(val) && val[proxyMarker],
  serialize(obj) {
    const { port1, port2 } = new MessageChannel();
    expose(obj, port1);
    return [port2, [port2]];
  },
  deserialize(port) {
    port.start();
    return wrap(port);
  }
};
var throwTransferHandler = {
  canHandle: (value) => isObject(value) && throwMarker in value,
  serialize({ value }) {
    let serialized;
    if (value instanceof Error) {
      serialized = {
        isError: true,
        value: {
          message: value.message,
          name: value.name,
          stack: value.stack
        }
      };
    } else {
      serialized = { isError: false, value };
    }
    return [serialized, []];
  },
  deserialize(serialized) {
    if (serialized.isError) {
      throw Object.assign(new Error(serialized.value.message), serialized.value);
    }
    throw serialized.value;
  }
};
var transferHandlers = /* @__PURE__ */ new Map([
  ["proxy", proxyTransferHandler],
  ["throw", throwTransferHandler]
]);
function isAllowedOrigin(allowedOrigins, origin) {
  for (const allowedOrigin of allowedOrigins) {
    if (origin === allowedOrigin || allowedOrigin === "*") {
      return true;
    }
    if (allowedOrigin instanceof RegExp && allowedOrigin.test(origin)) {
      return true;
    }
  }
  return false;
}
function expose(obj, ep = globalThis, allowedOrigins = ["*"]) {
  ep.addEventListener("message", function callback(ev) {
    if (!ev || !ev.data) {
      return;
    }
    if (!isAllowedOrigin(allowedOrigins, ev.origin)) {
      console.warn(`Invalid origin '${ev.origin}' for comlink proxy`);
      return;
    }
    const { id, type, path } = Object.assign({ path: [] }, ev.data);
    const argumentList = (ev.data.argumentList || []).map(fromWireValue);
    let returnValue;
    try {
      const parent = path.slice(0, -1).reduce((obj2, prop) => obj2[prop], obj);
      const rawValue = path.reduce((obj2, prop) => obj2[prop], obj);
      switch (type) {
        case "GET":
          {
            returnValue = rawValue;
          }
          break;
        case "SET":
          {
            parent[path.slice(-1)[0]] = fromWireValue(ev.data.value);
            returnValue = true;
          }
          break;
        case "APPLY":
          {
            returnValue = rawValue.apply(parent, argumentList);
          }
          break;
        case "CONSTRUCT":
          {
            const value = new rawValue(...argumentList);
            returnValue = proxy(value);
          }
          break;
        case "ENDPOINT":
          {
            const { port1, port2 } = new MessageChannel();
            expose(obj, port2);
            returnValue = transfer(port1, [port1]);
          }
          break;
        case "RELEASE":
          {
            returnValue = void 0;
          }
          break;
        default:
          return;
      }
    } catch (value) {
      returnValue = { value, [throwMarker]: 0 };
    }
    Promise.resolve(returnValue).catch((value) => {
      return { value, [throwMarker]: 0 };
    }).then((returnValue2) => {
      const [wireValue, transferables] = toWireValue(returnValue2);
      ep.postMessage(Object.assign(Object.assign({}, wireValue), { id }), transferables);
      if (type === "RELEASE") {
        ep.removeEventListener("message", callback);
        closeEndPoint(ep);
        if (finalizer in obj && typeof obj[finalizer] === "function") {
          obj[finalizer]();
        }
      }
    }).catch((error) => {
      const [wireValue, transferables] = toWireValue({
        value: new TypeError("Unserializable return value"),
        [throwMarker]: 0
      });
      ep.postMessage(Object.assign(Object.assign({}, wireValue), { id }), transferables);
    });
  });
  if (ep.start) {
    ep.start();
  }
}
function isMessagePort(endpoint) {
  return endpoint.constructor.name === "MessagePort";
}
function closeEndPoint(endpoint) {
  if (isMessagePort(endpoint))
    endpoint.close();
}
function wrap(ep, target2) {
  const pendingListeners = /* @__PURE__ */ new Map();
  ep.addEventListener("message", function handleMessage(ev) {
    const { data } = ev;
    if (!data || !data.id) {
      return;
    }
    const resolver = pendingListeners.get(data.id);
    if (!resolver) {
      return;
    }
    try {
      resolver(data);
    } finally {
      pendingListeners.delete(data.id);
    }
  });
  return createProxy(ep, pendingListeners, [], target2);
}
function throwIfProxyReleased(isReleased) {
  if (isReleased) {
    throw new Error("Proxy has been released and is not useable");
  }
}
function releaseEndpoint(ep) {
  return requestResponseMessage(ep, /* @__PURE__ */ new Map(), {
    type: "RELEASE"
  }).then(() => {
    closeEndPoint(ep);
  });
}
var proxyCounter = /* @__PURE__ */ new WeakMap();
var proxyFinalizers = "FinalizationRegistry" in globalThis && new FinalizationRegistry((ep) => {
  const newCount = (proxyCounter.get(ep) || 0) - 1;
  proxyCounter.set(ep, newCount);
  if (newCount === 0) {
    releaseEndpoint(ep);
  }
});
function registerProxy(proxy2, ep) {
  const newCount = (proxyCounter.get(ep) || 0) + 1;
  proxyCounter.set(ep, newCount);
  if (proxyFinalizers) {
    proxyFinalizers.register(proxy2, ep, proxy2);
  }
}
function unregisterProxy(proxy2) {
  if (proxyFinalizers) {
    proxyFinalizers.unregister(proxy2);
  }
}
function createProxy(ep, pendingListeners, path = [], target2 = function() {
}) {
  let isProxyReleased = false;
  const proxy2 = new Proxy(target2, {
    get(_target, prop) {
      throwIfProxyReleased(isProxyReleased);
      if (prop === releaseProxy) {
        return () => {
          unregisterProxy(proxy2);
          releaseEndpoint(ep);
          pendingListeners.clear();
          isProxyReleased = true;
        };
      }
      if (prop === "then") {
        if (path.length === 0) {
          return { then: () => proxy2 };
        }
        const r = requestResponseMessage(ep, pendingListeners, {
          type: "GET",
          path: path.map((p) => p.toString())
        }).then(fromWireValue);
        return r.then.bind(r);
      }
      return createProxy(ep, pendingListeners, [...path, prop]);
    },
    set(_target, prop, rawValue) {
      throwIfProxyReleased(isProxyReleased);
      const [value, transferables] = toWireValue(rawValue);
      return requestResponseMessage(ep, pendingListeners, {
        type: "SET",
        path: [...path, prop].map((p) => p.toString()),
        value
      }, transferables).then(fromWireValue);
    },
    apply(_target, _thisArg, rawArgumentList) {
      throwIfProxyReleased(isProxyReleased);
      const last = path[path.length - 1];
      if (last === createEndpoint) {
        return requestResponseMessage(ep, pendingListeners, {
          type: "ENDPOINT"
        }).then(fromWireValue);
      }
      if (last === "bind") {
        return createProxy(ep, pendingListeners, path.slice(0, -1));
      }
      const [argumentList, transferables] = processArguments(rawArgumentList);
      return requestResponseMessage(ep, pendingListeners, {
        type: "APPLY",
        path: path.map((p) => p.toString()),
        argumentList
      }, transferables).then(fromWireValue);
    },
    construct(_target, rawArgumentList) {
      throwIfProxyReleased(isProxyReleased);
      const [argumentList, transferables] = processArguments(rawArgumentList);
      return requestResponseMessage(ep, pendingListeners, {
        type: "CONSTRUCT",
        path: path.map((p) => p.toString()),
        argumentList
      }, transferables).then(fromWireValue);
    }
  });
  registerProxy(proxy2, ep);
  return proxy2;
}
function myFlat(arr) {
  return Array.prototype.concat.apply([], arr);
}
function processArguments(argumentList) {
  const processed = argumentList.map(toWireValue);
  return [processed.map((v) => v[0]), myFlat(processed.map((v) => v[1]))];
}
var transferCache = /* @__PURE__ */ new WeakMap();
function transfer(obj, transfers) {
  transferCache.set(obj, transfers);
  return obj;
}
function proxy(obj) {
  return Object.assign(obj, { [proxyMarker]: true });
}
function toWireValue(value) {
  for (const [name, handler] of transferHandlers) {
    if (handler.canHandle(value)) {
      const [serializedValue, transferables] = handler.serialize(value);
      return [
        {
          type: "HANDLER",
          name,
          value: serializedValue
        },
        transferables
      ];
    }
  }
  return [
    {
      type: "RAW",
      value
    },
    transferCache.get(value) || []
  ];
}
function fromWireValue(value) {
  switch (value.type) {
    case "HANDLER":
      return transferHandlers.get(value.name).deserialize(value.value);
    case "RAW":
      return value.value;
  }
}
function requestResponseMessage(ep, pendingListeners, msg, transfers) {
  return new Promise((resolve) => {
    const id = generateUUID();
    pendingListeners.set(id, resolve);
    if (ep.start) {
      ep.start();
    }
    ep.postMessage(Object.assign({ id }, msg), transfers);
  });
}
function generateUUID() {
  return new Array(4).fill(0).map(() => Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16)).join("-");
}

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/helpers/browser/index.js
function getSharedMemoryAvailable() {
  const globalScope = typeof window !== "undefined" ? window : globalThis;
  return typeof SharedArrayBuffer !== "undefined" && globalScope.crossOriginIsolated;
}
function getRemoteBarretenbergWasm(worker) {
  return wrap(worker);
}
function getNumCpu() {
  return navigator.hardwareConcurrency;
}
function getAvailableThreads(logger) {
  if (typeof navigator !== "undefined" && navigator.hardwareConcurrency) {
    return navigator.hardwareConcurrency;
  } else {
    logger(`Could not detect environment to query number of threads. Falling back to one thread.`);
    return 1;
  }
}
function readinessListener(worker, callback) {
  worker.addEventListener("message", function ready(event) {
    if (!!event.data && event.data.ready === true) {
      worker.removeEventListener("message", ready);
      callback();
    }
  });
}

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/barretenberg_wasm_thread/factory/browser/index.js
async function createThreadWorker() {
  const worker = new Worker(new URL("./thread.worker.js", import.meta.url), { type: "module" });
  await new Promise((resolve) => readinessListener(worker, resolve));
  return worker;
}

// node_modules/@aztec/bb.js/dest/browser/random/browser/index.js
var randomBytes = (len) => {
  const getWebCrypto = () => {
    if (typeof window !== "undefined" && window.crypto)
      return window.crypto;
    if (typeof globalThis !== "undefined" && globalThis.crypto)
      return globalThis.crypto;
    return void 0;
  };
  const crypto2 = getWebCrypto();
  if (!crypto2) {
    throw new Error("randomBytes UnsupportedEnvironment");
  }
  const buf = new Uint8Array(len);
  const MAX_BYTES = 65536;
  if (len > MAX_BYTES) {
    for (let generated = 0; generated < len; generated += MAX_BYTES) {
      crypto2.getRandomValues(buf.subarray(generated, generated + MAX_BYTES));
    }
  } else {
    crypto2.getRandomValues(buf);
  }
  return buf;
};

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/barretenberg_wasm_base/index.js
var BarretenbergWasmBase = class {
  memory;
  instance;
  logger = () => {
  };
  getImportObj(memory) {
    const importObj = {
      // We need to implement a part of the wasi api:
      // https://github.com/WebAssembly/WASI/blob/main/phases/snapshot/docs.md
      // We literally only need to support random_get, everything else is noop implementated in barretenberg.wasm.
      wasi_snapshot_preview1: {
        random_get: (out, length) => {
          out = out >>> 0;
          const randomData = randomBytes(length);
          const mem = this.getMemory();
          mem.set(randomData, out);
        },
        clock_time_get: (a1, a2, out) => {
          out = out >>> 0;
          const ts = BigInt((/* @__PURE__ */ new Date()).getTime()) * 1000000n;
          const view = new DataView(this.getMemory().buffer);
          view.setBigUint64(out, ts, true);
        },
        proc_exit: () => {
          this.logger("PANIC: proc_exit was called.");
          throw new Error();
        }
      },
      // These are functions implementations for imports we've defined are needed.
      // The native C++ build defines these in a module called "env". We must implement TypeScript versions here.
      env: {
        /**
         * The 'info' call we use for logging in C++, calls this under the hood.
         * The native code will just print to std:err (to avoid std::cout which is used for IPC).
         * Here we just emit the log line for the client to decide what to do with.
         */
        logstr: (addr) => {
          const str = this.stringFromAddress(addr);
          const m = this.getMemory();
          const str2 = `${str} (mem: ${(m.length / (1024 * 1024)).toFixed(2)}MiB)`;
          this.logger(str2);
        },
        throw_or_abort_impl: (addr) => {
          const str = this.stringFromAddress(addr);
          throw new Error(str);
        },
        memory
      }
    };
    return importObj;
  }
  exports() {
    return this.instance.exports;
  }
  /**
   * When returning values from the WASM, use >>> operator to convert signed representation to unsigned representation.
   */
  call(name, ...args) {
    if (!this.exports()[name]) {
      throw new Error(`WASM function ${name} not found.`);
    }
    try {
      return this.exports()[name](...args) >>> 0;
    } catch (err2) {
      const message = `WASM function ${name} aborted, error: ${err2}`;
      this.logger(message);
      this.logger(err2.stack);
      throw err2;
    }
  }
  memSize() {
    return this.getMemory().length;
  }
  /**
   * Returns a copy of the data, not a view.
   */
  getMemorySlice(start, end) {
    return this.getMemory().subarray(start, end).slice();
  }
  writeMemory(offset, arr) {
    const mem = this.getMemory();
    mem.set(arr, offset);
  }
  getMemory() {
    return new Uint8Array(this.memory.buffer);
  }
  // PRIVATE METHODS
  stringFromAddress(addr) {
    addr = addr >>> 0;
    const m = this.getMemory();
    let i = addr;
    for (; m[i] !== 0; ++i)
      ;
    const textDecoder = new TextDecoder("ascii");
    return textDecoder.decode(m.slice(addr, i));
  }
};

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/barretenberg_wasm_main/heap_allocator.js
var HeapAllocator = class {
  wasm;
  allocs = [];
  inScratchPtr = 0;
  // Next input starts here, grows UP
  outScratchPtr = 1024;
  // Next output ends here, grows DOWN
  constructor(wasm) {
    this.wasm = wasm;
  }
  getInputs(buffers) {
    return buffers.map((bufOrNum) => {
      if (typeof bufOrNum === "object") {
        const size = bufOrNum.length;
        if (this.inScratchPtr + size <= this.outScratchPtr) {
          const ptr = this.inScratchPtr;
          this.inScratchPtr += size;
          this.wasm.writeMemory(ptr, bufOrNum);
          return ptr;
        } else {
          const ptr = this.wasm.call("bbmalloc", size);
          this.wasm.writeMemory(ptr, bufOrNum);
          this.allocs.push(ptr);
          return ptr;
        }
      } else {
        return bufOrNum;
      }
    });
  }
  getOutputPtrs(outLens) {
    return outLens.map((len) => {
      const size = len || 4;
      if (this.inScratchPtr + size <= this.outScratchPtr) {
        this.outScratchPtr -= size;
        return this.outScratchPtr;
      } else {
        const ptr = this.wasm.call("bbmalloc", size);
        this.allocs.push(ptr);
        return ptr;
      }
    });
  }
  addOutputPtr(ptr) {
    if (ptr >= 1024) {
      this.allocs.push(ptr);
    }
  }
  freeAll() {
    for (const ptr of this.allocs) {
      this.wasm.call("bbfree", ptr);
    }
  }
};

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/barretenberg_wasm_main/index.js
var BarretenbergWasmMain = class _BarretenbergWasmMain extends BarretenbergWasmBase {
  static MAX_THREADS = 32;
  workers = [];
  remoteWasms = [];
  nextWorker = 0;
  nextThreadId = 1;
  useCustomLogger = false;
  // Pre-allocated scratch buffers for msgpack I/O to avoid malloc/free overhead
  msgpackInputScratch = 0;
  // 8MB input buffer
  msgpackOutputScratch = 0;
  // 8MB output buffer
  MSGPACK_SCRATCH_SIZE = 1024 * 1024 * 8;
  // 8MB
  getNumThreads() {
    return this.workers.length + 1;
  }
  /**
   * Init as main thread. Spawn child threads.
   */
  async init(module, threads = Math.min(getNumCpu(), _BarretenbergWasmMain.MAX_THREADS), logger, initial = 37, maximum = this.getDefaultMaximumMemoryPages(), unref = false) {
    this.useCustomLogger = logger !== void 0;
    this.logger = logger ?? (() => {
    });
    const initialMb = initial * 2 ** 16 / (1024 * 1024);
    const maxMb = maximum * 2 ** 16 / (1024 * 1024);
    const shared = getSharedMemoryAvailable();
    this.logger(`Initializing bb wasm: initial memory ${initial} pages ${initialMb}MiB; max memory: ${maximum} pages, ${maxMb}MiB; threads: ${threads}; shared memory: ${shared}`);
    this.memory = new WebAssembly.Memory({ initial, maximum, shared });
    const instance = await WebAssembly.instantiate(module, this.getImportObj(this.memory));
    this.instance = instance;
    this.call("_initialize");
    this.msgpackInputScratch = this.call("bbmalloc", this.MSGPACK_SCRATCH_SIZE);
    this.msgpackOutputScratch = this.call("bbmalloc", this.MSGPACK_SCRATCH_SIZE);
    this.logger(`Allocated msgpack scratch buffers: input @ ${this.msgpackInputScratch}, output @ ${this.msgpackOutputScratch} (${this.MSGPACK_SCRATCH_SIZE} bytes each)`);
    if (threads > 1) {
      this.logger(`Creating ${threads} worker threads`);
      this.workers = await Promise.all(Array.from({ length: threads - 1 }).map(createThreadWorker));
      if (this.useCustomLogger) {
        this.workers.forEach((worker) => this.setupWorkerLogForwarding(worker));
      }
      this.remoteWasms = await Promise.all(this.workers.map(getRemoteBarretenbergWasm));
      await Promise.all(this.remoteWasms.map((w) => w.initThread(module, this.memory, this.useCustomLogger)));
      if (unref) {
        for (const worker of this.workers) {
          worker.unref();
        }
      }
    }
  }
  getDefaultMaximumMemoryPages() {
    if (typeof self !== "undefined" && typeof self.navigator !== "undefined" && /iPad|iPhone/.test(self.navigator.userAgent)) {
      return 2 ** 14;
    }
    return 2 ** 16;
  }
  /**
   * Set up forwarding of log messages from worker threads to our logger.
   * Workers post messages with { type: 'log', msg: string } which we intercept here.
   */
  setupWorkerLogForwarding(worker) {
    const handler = (data) => {
      if (data && typeof data === "object" && "type" in data && data.type === "log" && "msg" in data) {
        this.logger(data.msg);
      }
    };
    if ("on" in worker && typeof worker.on === "function") {
      worker.on("message", handler);
    } else if ("addEventListener" in worker) {
      worker.addEventListener("message", (event) => {
        handler(event.data);
      });
    }
  }
  /**
   * Called on main thread. Signals child threads to gracefully exit.
   */
  async destroy() {
    await Promise.all(this.workers.map((w) => w.terminate()));
  }
  getImportObj(memory) {
    const baseImports = super.getImportObj(memory);
    return {
      ...baseImports,
      wasi: {
        "thread-spawn": (arg) => {
          arg = arg >>> 0;
          const id = this.nextThreadId++;
          const worker = this.nextWorker++ % this.remoteWasms.length;
          this.remoteWasms[worker].call("wasi_thread_start", id, arg).catch(this.logger);
          return id;
        }
      },
      env: {
        ...baseImports.env,
        env_hardware_concurrency: () => {
          return this.remoteWasms.length + 1;
        }
      }
    };
  }
  callWasmExport(funcName, inArgs, outLens) {
    const alloc = new HeapAllocator(this);
    const inPtrs = alloc.getInputs(inArgs);
    const outPtrs = alloc.getOutputPtrs(outLens);
    this.call(funcName, ...inPtrs, ...outPtrs);
    const outArgs = this.getOutputArgs(outLens, outPtrs, alloc);
    alloc.freeAll();
    return outArgs;
  }
  getOutputArgs(outLens, outPtrs, alloc) {
    return outLens.map((len, i) => {
      if (len) {
        return this.getMemorySlice(outPtrs[i], outPtrs[i] + len);
      }
      const slice = this.getMemorySlice(outPtrs[i], outPtrs[i] + 4);
      const ptr = new DataView(slice.buffer, slice.byteOffset, slice.byteLength).getUint32(0, true);
      alloc.addOutputPtr(ptr);
      const lslice = this.getMemorySlice(ptr, ptr + 4);
      const length = new DataView(lslice.buffer, lslice.byteOffset, lslice.byteLength).getUint32(0, false);
      return this.getMemorySlice(ptr + 4, ptr + 4 + length);
    });
  }
  cbindCall(cbind, inputBuffer) {
    const needsCustomInputBuffer = inputBuffer.length > this.MSGPACK_SCRATCH_SIZE;
    let inputPtr;
    if (needsCustomInputBuffer) {
      inputPtr = this.call("bbmalloc", inputBuffer.length);
    } else {
      inputPtr = this.msgpackInputScratch;
    }
    this.writeMemory(inputPtr, inputBuffer);
    const METADATA_SIZE = 8;
    const outputPtrLocation = this.msgpackOutputScratch;
    const outputSizeLocation = this.msgpackOutputScratch + 4;
    const scratchDataPtr = this.msgpackOutputScratch + METADATA_SIZE;
    const scratchDataSize = this.MSGPACK_SCRATCH_SIZE - METADATA_SIZE;
    let mem = this.getMemory();
    let view = new DataView(mem.buffer);
    view.setUint32(outputPtrLocation, scratchDataPtr, true);
    view.setUint32(outputSizeLocation, scratchDataSize, true);
    this.call(cbind, inputPtr, inputBuffer.length, outputPtrLocation, outputSizeLocation);
    if (needsCustomInputBuffer) {
      this.call("bbfree", inputPtr);
    }
    mem = this.getMemory();
    view = new DataView(mem.buffer);
    const outputDataPtr = view.getUint32(outputPtrLocation, true);
    const outputSize = view.getUint32(outputSizeLocation, true);
    const usedScratch = outputDataPtr === scratchDataPtr;
    const encodedResult = this.getMemorySlice(outputDataPtr, outputDataPtr + outputSize);
    if (!usedScratch) {
      this.call("bbfree", outputDataPtr);
    }
    return encodedResult;
  }
};

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/fetch_code/browser/index.js
async function fetchCode(shared, wasmPath) {
  if (wasmPath !== void 0) throw new Error("A proof cannot choose a WASM URL.");
  return loadAsset(shared ? "barretenberg-threads.wasm" : "barretenberg.wasm");
}

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/index.js
async function fetchModuleAndThreads(desiredThreads = 32, wasmPath, logger = () => {
}) {
  const shared = getSharedMemoryAvailable();
  const availableThreads = shared ? await getAvailableThreads(logger) : 1;
  const limitedThreads = Math.min(desiredThreads, availableThreads, 32);
  logger(`Fetching bb wasm from ${wasmPath ?? "default location"}`);
  const code = await fetchCode(shared, wasmPath);
  logger(`Compiling bb wasm of ${code.byteLength} bytes`);
  const module = await WebAssembly.compile(code);
  logger("Compilation of bb wasm complete");
  return { module, threads: limitedThreads };
}

// node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm/barretenberg_wasm_main/factory/browser/index.js
async function createMainWorker() {
  const worker = new Worker(new URL("./main.worker.js", import.meta.url), { type: "module" });
  await new Promise((resolve) => readinessListener(worker, resolve));
  return worker;
}

// node_modules/@aztec/bb.js/dest/browser/bb_backends/wasm.js
var BarretenbergWasmAsyncBackend = class _BarretenbergWasmAsyncBackend {
  wasm;
  worker;
  constructor(wasm, worker) {
    this.wasm = wasm;
    this.worker = worker;
  }
  /**
   * Create and initialize an asynchronous WASM backend.
   * @param options.threads Number of threads (defaults to hardware max, up to 32 for parallel proving)
   * @param options.wasmPath Optional path to WASM files
   * @param options.logger Optional logging function
   * @param options.memory Optional initial and maximum memory configuration
   * @param options.useWorker Run on worker thread (default: true for browser safety)
   * @param options.unref Unref worker handles so they don't prevent process exit
   */
  static async new(options = {}) {
    const useWorker = options.useWorker ?? true;
    if (useWorker) {
      const worker = await createMainWorker();
      const wasm = getRemoteBarretenbergWasm(worker);
      const { module, threads } = await fetchModuleAndThreads(options.threads, options.wasmPath, options.logger);
      await wasm.init(module, threads, proxy(options.logger ?? (() => {
      })), options.memory?.initial, options.memory?.maximum);
      if (options.unref) {
        worker.unref();
      }
      return new _BarretenbergWasmAsyncBackend(wasm, worker);
    } else {
      const wasm = new BarretenbergWasmMain();
      const { module, threads } = await fetchModuleAndThreads(options.threads, options.wasmPath, options.logger);
      await wasm.init(module, threads, options.logger, options.memory?.initial, options.memory?.maximum, options.unref);
      return new _BarretenbergWasmAsyncBackend(wasm);
    }
  }
  async call(inputBuffer) {
    return this.wasm.cbindCall("bbapi", inputBuffer);
  }
  async destroy() {
    await this.wasm.destroy();
    if (this.worker) {
      await this.worker.terminate();
    }
  }
};

// node_modules/@aztec/bb.js/dest/browser/bb_backends/browser/index.js
async function createAsyncBackend(type, options, logger) {
  switch (type) {
    case BackendType.Wasm:
    case BackendType.WasmWorker: {
      const useWorker = type === BackendType.WasmWorker;
      logger(`Using WASM backend (worker: ${useWorker})`);
      const wasm = await BarretenbergWasmAsyncBackend.new({
        threads: options.threads,
        wasmPath: options.wasmPath,
        logger,
        memory: options.memory,
        useWorker
      });
      return new Barretenberg(wasm, options);
    }
    default:
      throw new Error(`Unknown backend type: ${type}`);
  }
}

// node_modules/@aztec/bb.js/dest/browser/proof/index.js
function hexToUint8Array(hex2) {
  const sanitizedHex = BigInt(hex2).toString(16).padStart(64, "0");
  const len = sanitizedHex.length / 2;
  const u8 = new Uint8Array(len);
  let i = 0;
  let j = 0;
  while (i < len) {
    u8[i] = parseInt(sanitizedHex.slice(j, j + 2), 16);
    i += 1;
    j += 2;
  }
  return u8;
}

// node_modules/pako/dist/pako.esm.mjs
var Z_FIXED$1 = 4;
var Z_BINARY = 0;
var Z_TEXT = 1;
var Z_UNKNOWN$1 = 2;
function zero$1(buf) {
  let len = buf.length;
  while (--len >= 0) {
    buf[len] = 0;
  }
}
var STORED_BLOCK = 0;
var STATIC_TREES = 1;
var DYN_TREES = 2;
var MIN_MATCH$1 = 3;
var MAX_MATCH$1 = 258;
var LENGTH_CODES$1 = 29;
var LITERALS$1 = 256;
var L_CODES$1 = LITERALS$1 + 1 + LENGTH_CODES$1;
var D_CODES$1 = 30;
var BL_CODES$1 = 19;
var HEAP_SIZE$1 = 2 * L_CODES$1 + 1;
var MAX_BITS$1 = 15;
var Buf_size = 16;
var MAX_BL_BITS = 7;
var END_BLOCK = 256;
var REP_3_6 = 16;
var REPZ_3_10 = 17;
var REPZ_11_138 = 18;
var extra_lbits = (
  /* extra bits for each length code */
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0])
);
var extra_dbits = (
  /* extra bits for each distance code */
  new Uint8Array([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13])
);
var extra_blbits = (
  /* extra bits for each bit length code */
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7])
);
var bl_order = new Uint8Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
var DIST_CODE_LEN = 512;
var static_ltree = new Array((L_CODES$1 + 2) * 2);
zero$1(static_ltree);
var static_dtree = new Array(D_CODES$1 * 2);
zero$1(static_dtree);
var _dist_code = new Array(DIST_CODE_LEN);
zero$1(_dist_code);
var _length_code = new Array(MAX_MATCH$1 - MIN_MATCH$1 + 1);
zero$1(_length_code);
var base_length = new Array(LENGTH_CODES$1);
zero$1(base_length);
var base_dist = new Array(D_CODES$1);
zero$1(base_dist);
function StaticTreeDesc(static_tree, extra_bits, extra_base, elems, max_length) {
  this.static_tree = static_tree;
  this.extra_bits = extra_bits;
  this.extra_base = extra_base;
  this.elems = elems;
  this.max_length = max_length;
  this.has_stree = static_tree && static_tree.length;
}
var static_l_desc;
var static_d_desc;
var static_bl_desc;
function TreeDesc(dyn_tree, stat_desc) {
  this.dyn_tree = dyn_tree;
  this.max_code = 0;
  this.stat_desc = stat_desc;
}
var d_code = (dist) => {
  return dist < 256 ? _dist_code[dist] : _dist_code[256 + (dist >>> 7)];
};
var put_short = (s, w) => {
  s.pending_buf[s.pending++] = w & 255;
  s.pending_buf[s.pending++] = w >>> 8 & 255;
};
var send_bits = (s, value, length) => {
  if (s.bi_valid > Buf_size - length) {
    s.bi_buf |= value << s.bi_valid & 65535;
    put_short(s, s.bi_buf);
    s.bi_buf = value >> Buf_size - s.bi_valid;
    s.bi_valid += length - Buf_size;
  } else {
    s.bi_buf |= value << s.bi_valid & 65535;
    s.bi_valid += length;
  }
};
var send_code = (s, c, tree) => {
  send_bits(
    s,
    tree[c * 2],
    tree[c * 2 + 1]
    /*.Len*/
  );
};
var bi_reverse = (code, len) => {
  let res = 0;
  do {
    res |= code & 1;
    code >>>= 1;
    res <<= 1;
  } while (--len > 0);
  return res >>> 1;
};
var bi_flush = (s) => {
  if (s.bi_valid === 16) {
    put_short(s, s.bi_buf);
    s.bi_buf = 0;
    s.bi_valid = 0;
  } else if (s.bi_valid >= 8) {
    s.pending_buf[s.pending++] = s.bi_buf & 255;
    s.bi_buf >>= 8;
    s.bi_valid -= 8;
  }
};
var gen_bitlen = (s, desc) => {
  const tree = desc.dyn_tree;
  const max_code = desc.max_code;
  const stree = desc.stat_desc.static_tree;
  const has_stree = desc.stat_desc.has_stree;
  const extra = desc.stat_desc.extra_bits;
  const base = desc.stat_desc.extra_base;
  const max_length = desc.stat_desc.max_length;
  let h;
  let n, m;
  let bits;
  let xbits;
  let f;
  let overflow = 0;
  for (bits = 0; bits <= MAX_BITS$1; bits++) {
    s.bl_count[bits] = 0;
  }
  tree[s.heap[s.heap_max] * 2 + 1] = 0;
  for (h = s.heap_max + 1; h < HEAP_SIZE$1; h++) {
    n = s.heap[h];
    bits = tree[tree[n * 2 + 1] * 2 + 1] + 1;
    if (bits > max_length) {
      bits = max_length;
      overflow++;
    }
    tree[n * 2 + 1] = bits;
    if (n > max_code) {
      continue;
    }
    s.bl_count[bits]++;
    xbits = 0;
    if (n >= base) {
      xbits = extra[n - base];
    }
    f = tree[n * 2];
    s.opt_len += f * (bits + xbits);
    if (has_stree) {
      s.static_len += f * (stree[n * 2 + 1] + xbits);
    }
  }
  if (overflow === 0) {
    return;
  }
  do {
    bits = max_length - 1;
    while (s.bl_count[bits] === 0) {
      bits--;
    }
    s.bl_count[bits]--;
    s.bl_count[bits + 1] += 2;
    s.bl_count[max_length]--;
    overflow -= 2;
  } while (overflow > 0);
  for (bits = max_length; bits !== 0; bits--) {
    n = s.bl_count[bits];
    while (n !== 0) {
      m = s.heap[--h];
      if (m > max_code) {
        continue;
      }
      if (tree[m * 2 + 1] !== bits) {
        s.opt_len += (bits - tree[m * 2 + 1]) * tree[m * 2];
        tree[m * 2 + 1] = bits;
      }
      n--;
    }
  }
};
var gen_codes = (tree, max_code, bl_count) => {
  const next_code = new Array(MAX_BITS$1 + 1);
  let code = 0;
  let bits;
  let n;
  for (bits = 1; bits <= MAX_BITS$1; bits++) {
    code = code + bl_count[bits - 1] << 1;
    next_code[bits] = code;
  }
  for (n = 0; n <= max_code; n++) {
    let len = tree[n * 2 + 1];
    if (len === 0) {
      continue;
    }
    tree[n * 2] = bi_reverse(next_code[len]++, len);
  }
};
var tr_static_init = () => {
  let n;
  let bits;
  let length;
  let code;
  let dist;
  const bl_count = new Array(MAX_BITS$1 + 1);
  length = 0;
  for (code = 0; code < LENGTH_CODES$1 - 1; code++) {
    base_length[code] = length;
    for (n = 0; n < 1 << extra_lbits[code]; n++) {
      _length_code[length++] = code;
    }
  }
  _length_code[length - 1] = code;
  dist = 0;
  for (code = 0; code < 16; code++) {
    base_dist[code] = dist;
    for (n = 0; n < 1 << extra_dbits[code]; n++) {
      _dist_code[dist++] = code;
    }
  }
  dist >>= 7;
  for (; code < D_CODES$1; code++) {
    base_dist[code] = dist << 7;
    for (n = 0; n < 1 << extra_dbits[code] - 7; n++) {
      _dist_code[256 + dist++] = code;
    }
  }
  for (bits = 0; bits <= MAX_BITS$1; bits++) {
    bl_count[bits] = 0;
  }
  n = 0;
  while (n <= 143) {
    static_ltree[n * 2 + 1] = 8;
    n++;
    bl_count[8]++;
  }
  while (n <= 255) {
    static_ltree[n * 2 + 1] = 9;
    n++;
    bl_count[9]++;
  }
  while (n <= 279) {
    static_ltree[n * 2 + 1] = 7;
    n++;
    bl_count[7]++;
  }
  while (n <= 287) {
    static_ltree[n * 2 + 1] = 8;
    n++;
    bl_count[8]++;
  }
  gen_codes(static_ltree, L_CODES$1 + 1, bl_count);
  for (n = 0; n < D_CODES$1; n++) {
    static_dtree[n * 2 + 1] = 5;
    static_dtree[n * 2] = bi_reverse(n, 5);
  }
  static_l_desc = new StaticTreeDesc(static_ltree, extra_lbits, LITERALS$1 + 1, L_CODES$1, MAX_BITS$1);
  static_d_desc = new StaticTreeDesc(static_dtree, extra_dbits, 0, D_CODES$1, MAX_BITS$1);
  static_bl_desc = new StaticTreeDesc(new Array(0), extra_blbits, 0, BL_CODES$1, MAX_BL_BITS);
};
var init_block = (s) => {
  let n;
  for (n = 0; n < L_CODES$1; n++) {
    s.dyn_ltree[n * 2] = 0;
  }
  for (n = 0; n < D_CODES$1; n++) {
    s.dyn_dtree[n * 2] = 0;
  }
  for (n = 0; n < BL_CODES$1; n++) {
    s.bl_tree[n * 2] = 0;
  }
  s.dyn_ltree[END_BLOCK * 2] = 1;
  s.opt_len = s.static_len = 0;
  s.sym_next = s.matches = 0;
};
var bi_windup = (s) => {
  if (s.bi_valid > 8) {
    put_short(s, s.bi_buf);
  } else if (s.bi_valid > 0) {
    s.pending_buf[s.pending++] = s.bi_buf;
  }
  s.bi_buf = 0;
  s.bi_valid = 0;
};
var smaller = (tree, n, m, depth) => {
  const _n2 = n * 2;
  const _m2 = m * 2;
  return tree[_n2] < tree[_m2] || tree[_n2] === tree[_m2] && depth[n] <= depth[m];
};
var pqdownheap = (s, tree, k) => {
  const v = s.heap[k];
  let j = k << 1;
  while (j <= s.heap_len) {
    if (j < s.heap_len && smaller(tree, s.heap[j + 1], s.heap[j], s.depth)) {
      j++;
    }
    if (smaller(tree, v, s.heap[j], s.depth)) {
      break;
    }
    s.heap[k] = s.heap[j];
    k = j;
    j <<= 1;
  }
  s.heap[k] = v;
};
var compress_block = (s, ltree, dtree) => {
  let dist;
  let lc;
  let sx = 0;
  let code;
  let extra;
  if (s.sym_next !== 0) {
    do {
      dist = s.pending_buf[s.sym_buf + sx++] & 255;
      dist += (s.pending_buf[s.sym_buf + sx++] & 255) << 8;
      lc = s.pending_buf[s.sym_buf + sx++];
      if (dist === 0) {
        send_code(s, lc, ltree);
      } else {
        code = _length_code[lc];
        send_code(s, code + LITERALS$1 + 1, ltree);
        extra = extra_lbits[code];
        if (extra !== 0) {
          lc -= base_length[code];
          send_bits(s, lc, extra);
        }
        dist--;
        code = d_code(dist);
        send_code(s, code, dtree);
        extra = extra_dbits[code];
        if (extra !== 0) {
          dist -= base_dist[code];
          send_bits(s, dist, extra);
        }
      }
    } while (sx < s.sym_next);
  }
  send_code(s, END_BLOCK, ltree);
};
var build_tree = (s, desc) => {
  const tree = desc.dyn_tree;
  const stree = desc.stat_desc.static_tree;
  const has_stree = desc.stat_desc.has_stree;
  const elems = desc.stat_desc.elems;
  let n, m;
  let max_code = -1;
  let node;
  s.heap_len = 0;
  s.heap_max = HEAP_SIZE$1;
  for (n = 0; n < elems; n++) {
    if (tree[n * 2] !== 0) {
      s.heap[++s.heap_len] = max_code = n;
      s.depth[n] = 0;
    } else {
      tree[n * 2 + 1] = 0;
    }
  }
  while (s.heap_len < 2) {
    node = s.heap[++s.heap_len] = max_code < 2 ? ++max_code : 0;
    tree[node * 2] = 1;
    s.depth[node] = 0;
    s.opt_len--;
    if (has_stree) {
      s.static_len -= stree[node * 2 + 1];
    }
  }
  desc.max_code = max_code;
  for (n = s.heap_len >> 1; n >= 1; n--) {
    pqdownheap(s, tree, n);
  }
  node = elems;
  do {
    n = s.heap[
      1
      /*SMALLEST*/
    ];
    s.heap[
      1
      /*SMALLEST*/
    ] = s.heap[s.heap_len--];
    pqdownheap(
      s,
      tree,
      1
      /*SMALLEST*/
    );
    m = s.heap[
      1
      /*SMALLEST*/
    ];
    s.heap[--s.heap_max] = n;
    s.heap[--s.heap_max] = m;
    tree[node * 2] = tree[n * 2] + tree[m * 2];
    s.depth[node] = (s.depth[n] >= s.depth[m] ? s.depth[n] : s.depth[m]) + 1;
    tree[n * 2 + 1] = tree[m * 2 + 1] = node;
    s.heap[
      1
      /*SMALLEST*/
    ] = node++;
    pqdownheap(
      s,
      tree,
      1
      /*SMALLEST*/
    );
  } while (s.heap_len >= 2);
  s.heap[--s.heap_max] = s.heap[
    1
    /*SMALLEST*/
  ];
  gen_bitlen(s, desc);
  gen_codes(tree, max_code, s.bl_count);
};
var scan_tree = (s, tree, max_code) => {
  let n;
  let prevlen = -1;
  let curlen;
  let nextlen = tree[0 * 2 + 1];
  let count = 0;
  let max_count = 7;
  let min_count = 4;
  if (nextlen === 0) {
    max_count = 138;
    min_count = 3;
  }
  tree[(max_code + 1) * 2 + 1] = 65535;
  for (n = 0; n <= max_code; n++) {
    curlen = nextlen;
    nextlen = tree[(n + 1) * 2 + 1];
    if (++count < max_count && curlen === nextlen) {
      continue;
    } else if (count < min_count) {
      s.bl_tree[curlen * 2] += count;
    } else if (curlen !== 0) {
      if (curlen !== prevlen) {
        s.bl_tree[curlen * 2]++;
      }
      s.bl_tree[REP_3_6 * 2]++;
    } else if (count <= 10) {
      s.bl_tree[REPZ_3_10 * 2]++;
    } else {
      s.bl_tree[REPZ_11_138 * 2]++;
    }
    count = 0;
    prevlen = curlen;
    if (nextlen === 0) {
      max_count = 138;
      min_count = 3;
    } else if (curlen === nextlen) {
      max_count = 6;
      min_count = 3;
    } else {
      max_count = 7;
      min_count = 4;
    }
  }
};
var send_tree = (s, tree, max_code) => {
  let n;
  let prevlen = -1;
  let curlen;
  let nextlen = tree[0 * 2 + 1];
  let count = 0;
  let max_count = 7;
  let min_count = 4;
  if (nextlen === 0) {
    max_count = 138;
    min_count = 3;
  }
  for (n = 0; n <= max_code; n++) {
    curlen = nextlen;
    nextlen = tree[(n + 1) * 2 + 1];
    if (++count < max_count && curlen === nextlen) {
      continue;
    } else if (count < min_count) {
      do {
        send_code(s, curlen, s.bl_tree);
      } while (--count !== 0);
    } else if (curlen !== 0) {
      if (curlen !== prevlen) {
        send_code(s, curlen, s.bl_tree);
        count--;
      }
      send_code(s, REP_3_6, s.bl_tree);
      send_bits(s, count - 3, 2);
    } else if (count <= 10) {
      send_code(s, REPZ_3_10, s.bl_tree);
      send_bits(s, count - 3, 3);
    } else {
      send_code(s, REPZ_11_138, s.bl_tree);
      send_bits(s, count - 11, 7);
    }
    count = 0;
    prevlen = curlen;
    if (nextlen === 0) {
      max_count = 138;
      min_count = 3;
    } else if (curlen === nextlen) {
      max_count = 6;
      min_count = 3;
    } else {
      max_count = 7;
      min_count = 4;
    }
  }
};
var build_bl_tree = (s) => {
  let max_blindex;
  scan_tree(s, s.dyn_ltree, s.l_desc.max_code);
  scan_tree(s, s.dyn_dtree, s.d_desc.max_code);
  build_tree(s, s.bl_desc);
  for (max_blindex = BL_CODES$1 - 1; max_blindex >= 3; max_blindex--) {
    if (s.bl_tree[bl_order[max_blindex] * 2 + 1] !== 0) {
      break;
    }
  }
  s.opt_len += 3 * (max_blindex + 1) + 5 + 5 + 4;
  return max_blindex;
};
var send_all_trees = (s, lcodes, dcodes, blcodes) => {
  let rank2;
  send_bits(s, lcodes - 257, 5);
  send_bits(s, dcodes - 1, 5);
  send_bits(s, blcodes - 4, 4);
  for (rank2 = 0; rank2 < blcodes; rank2++) {
    send_bits(s, s.bl_tree[bl_order[rank2] * 2 + 1], 3);
  }
  send_tree(s, s.dyn_ltree, lcodes - 1);
  send_tree(s, s.dyn_dtree, dcodes - 1);
};
var detect_data_type = (s) => {
  let block_mask = 4093624447;
  let n;
  for (n = 0; n <= 31; n++, block_mask >>>= 1) {
    if (block_mask & 1 && s.dyn_ltree[n * 2] !== 0) {
      return Z_BINARY;
    }
  }
  if (s.dyn_ltree[9 * 2] !== 0 || s.dyn_ltree[10 * 2] !== 0 || s.dyn_ltree[13 * 2] !== 0) {
    return Z_TEXT;
  }
  for (n = 32; n < LITERALS$1; n++) {
    if (s.dyn_ltree[n * 2] !== 0) {
      return Z_TEXT;
    }
  }
  return Z_BINARY;
};
var static_init_done = false;
var _tr_init$1 = (s) => {
  if (!static_init_done) {
    tr_static_init();
    static_init_done = true;
  }
  s.l_desc = new TreeDesc(s.dyn_ltree, static_l_desc);
  s.d_desc = new TreeDesc(s.dyn_dtree, static_d_desc);
  s.bl_desc = new TreeDesc(s.bl_tree, static_bl_desc);
  s.bi_buf = 0;
  s.bi_valid = 0;
  init_block(s);
};
var _tr_stored_block$1 = (s, buf, stored_len, last) => {
  send_bits(s, (STORED_BLOCK << 1) + (last ? 1 : 0), 3);
  bi_windup(s);
  put_short(s, stored_len);
  put_short(s, ~stored_len);
  if (stored_len) {
    s.pending_buf.set(s.window.subarray(buf, buf + stored_len), s.pending);
  }
  s.pending += stored_len;
};
var _tr_align$1 = (s) => {
  send_bits(s, STATIC_TREES << 1, 3);
  send_code(s, END_BLOCK, static_ltree);
  bi_flush(s);
};
var _tr_flush_block$1 = (s, buf, stored_len, last) => {
  let opt_lenb, static_lenb;
  let max_blindex = 0;
  if (s.level > 0) {
    if (s.strm.data_type === Z_UNKNOWN$1) {
      s.strm.data_type = detect_data_type(s);
    }
    build_tree(s, s.l_desc);
    build_tree(s, s.d_desc);
    max_blindex = build_bl_tree(s);
    opt_lenb = s.opt_len + 3 + 7 >>> 3;
    static_lenb = s.static_len + 3 + 7 >>> 3;
    if (static_lenb <= opt_lenb) {
      opt_lenb = static_lenb;
    }
  } else {
    opt_lenb = static_lenb = stored_len + 5;
  }
  if (stored_len + 4 <= opt_lenb && buf !== -1) {
    _tr_stored_block$1(s, buf, stored_len, last);
  } else if (s.strategy === Z_FIXED$1 || static_lenb === opt_lenb) {
    send_bits(s, (STATIC_TREES << 1) + (last ? 1 : 0), 3);
    compress_block(s, static_ltree, static_dtree);
  } else {
    send_bits(s, (DYN_TREES << 1) + (last ? 1 : 0), 3);
    send_all_trees(s, s.l_desc.max_code + 1, s.d_desc.max_code + 1, max_blindex + 1);
    compress_block(s, s.dyn_ltree, s.dyn_dtree);
  }
  init_block(s);
  if (last) {
    bi_windup(s);
  }
};
var _tr_tally$1 = (s, dist, lc) => {
  s.pending_buf[s.sym_buf + s.sym_next++] = dist;
  s.pending_buf[s.sym_buf + s.sym_next++] = dist >> 8;
  s.pending_buf[s.sym_buf + s.sym_next++] = lc;
  if (dist === 0) {
    s.dyn_ltree[lc * 2]++;
  } else {
    s.matches++;
    dist--;
    s.dyn_ltree[(_length_code[lc] + LITERALS$1 + 1) * 2]++;
    s.dyn_dtree[d_code(dist) * 2]++;
  }
  return s.sym_next === s.sym_end;
};
var _tr_init_1 = _tr_init$1;
var _tr_stored_block_1 = _tr_stored_block$1;
var _tr_flush_block_1 = _tr_flush_block$1;
var _tr_tally_1 = _tr_tally$1;
var _tr_align_1 = _tr_align$1;
var trees = {
  _tr_init: _tr_init_1,
  _tr_stored_block: _tr_stored_block_1,
  _tr_flush_block: _tr_flush_block_1,
  _tr_tally: _tr_tally_1,
  _tr_align: _tr_align_1
};
var adler32 = (adler, buf, len, pos) => {
  let s1 = adler & 65535 | 0, s2 = adler >>> 16 & 65535 | 0, n = 0;
  while (len !== 0) {
    n = len > 2e3 ? 2e3 : len;
    len -= n;
    do {
      s1 = s1 + buf[pos++] | 0;
      s2 = s2 + s1 | 0;
    } while (--n);
    s1 %= 65521;
    s2 %= 65521;
  }
  return s1 | s2 << 16 | 0;
};
var adler32_1 = adler32;
var makeTable = () => {
  let c, table = [];
  for (var n = 0; n < 256; n++) {
    c = n;
    for (var k = 0; k < 8; k++) {
      c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
    }
    table[n] = c;
  }
  return table;
};
var crcTable = new Uint32Array(makeTable());
var crc32 = (crc, buf, len, pos) => {
  const t = crcTable;
  const end = pos + len;
  crc ^= -1;
  for (let i = pos; i < end; i++) {
    crc = crc >>> 8 ^ t[(crc ^ buf[i]) & 255];
  }
  return crc ^ -1;
};
var crc32_1 = crc32;
var messages = {
  2: "need dictionary",
  /* Z_NEED_DICT       2  */
  1: "stream end",
  /* Z_STREAM_END      1  */
  0: "",
  /* Z_OK              0  */
  "-1": "file error",
  /* Z_ERRNO         (-1) */
  "-2": "stream error",
  /* Z_STREAM_ERROR  (-2) */
  "-3": "data error",
  /* Z_DATA_ERROR    (-3) */
  "-4": "insufficient memory",
  /* Z_MEM_ERROR     (-4) */
  "-5": "buffer error",
  /* Z_BUF_ERROR     (-5) */
  "-6": "incompatible version"
  /* Z_VERSION_ERROR (-6) */
};
var constants$2 = {
  /* Allowed flush values; see deflate() and inflate() below for details */
  Z_NO_FLUSH: 0,
  Z_PARTIAL_FLUSH: 1,
  Z_SYNC_FLUSH: 2,
  Z_FULL_FLUSH: 3,
  Z_FINISH: 4,
  Z_BLOCK: 5,
  Z_TREES: 6,
  /* Return codes for the compression/decompression functions. Negative values
  * are errors, positive values are used for special but normal events.
  */
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_NEED_DICT: 2,
  Z_ERRNO: -1,
  Z_STREAM_ERROR: -2,
  Z_DATA_ERROR: -3,
  Z_MEM_ERROR: -4,
  Z_BUF_ERROR: -5,
  //Z_VERSION_ERROR: -6,
  /* compression levels */
  Z_NO_COMPRESSION: 0,
  Z_BEST_SPEED: 1,
  Z_BEST_COMPRESSION: 9,
  Z_DEFAULT_COMPRESSION: -1,
  Z_FILTERED: 1,
  Z_HUFFMAN_ONLY: 2,
  Z_RLE: 3,
  Z_FIXED: 4,
  Z_DEFAULT_STRATEGY: 0,
  /* Possible values of the data_type field (though see inflate()) */
  Z_BINARY: 0,
  Z_TEXT: 1,
  //Z_ASCII:                1, // = Z_TEXT (deprecated)
  Z_UNKNOWN: 2,
  /* The deflate compression method */
  Z_DEFLATED: 8
  //Z_NULL:                 null // Use -1 or null inline, depending on var type
};
var { _tr_init, _tr_stored_block, _tr_flush_block, _tr_tally, _tr_align } = trees;
var {
  Z_NO_FLUSH: Z_NO_FLUSH$2,
  Z_PARTIAL_FLUSH,
  Z_FULL_FLUSH: Z_FULL_FLUSH$1,
  Z_FINISH: Z_FINISH$3,
  Z_BLOCK: Z_BLOCK$1,
  Z_OK: Z_OK$3,
  Z_STREAM_END: Z_STREAM_END$3,
  Z_STREAM_ERROR: Z_STREAM_ERROR$2,
  Z_DATA_ERROR: Z_DATA_ERROR$2,
  Z_BUF_ERROR: Z_BUF_ERROR$2,
  Z_DEFAULT_COMPRESSION: Z_DEFAULT_COMPRESSION$1,
  Z_FILTERED,
  Z_HUFFMAN_ONLY,
  Z_RLE,
  Z_FIXED,
  Z_DEFAULT_STRATEGY: Z_DEFAULT_STRATEGY$1,
  Z_UNKNOWN,
  Z_DEFLATED: Z_DEFLATED$2
} = constants$2;
var MAX_MEM_LEVEL = 9;
var MAX_WBITS$1 = 15;
var DEF_MEM_LEVEL = 8;
var LENGTH_CODES = 29;
var LITERALS = 256;
var L_CODES = LITERALS + 1 + LENGTH_CODES;
var D_CODES = 30;
var BL_CODES = 19;
var HEAP_SIZE = 2 * L_CODES + 1;
var MAX_BITS = 15;
var MIN_MATCH = 3;
var MAX_MATCH = 258;
var MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1;
var PRESET_DICT = 32;
var INIT_STATE = 42;
var GZIP_STATE = 57;
var EXTRA_STATE = 69;
var NAME_STATE = 73;
var COMMENT_STATE = 91;
var HCRC_STATE = 103;
var BUSY_STATE = 113;
var FINISH_STATE = 666;
var BS_NEED_MORE = 1;
var BS_BLOCK_DONE = 2;
var BS_FINISH_STARTED = 3;
var BS_FINISH_DONE = 4;
var OS_CODE = 3;
var err = (strm, errorCode) => {
  strm.msg = messages[errorCode];
  return errorCode;
};
var rank = (f) => {
  return f * 2 - (f > 4 ? 9 : 0);
};
var zero = (buf) => {
  let len = buf.length;
  while (--len >= 0) {
    buf[len] = 0;
  }
};
var slide_hash = (s) => {
  let n, m;
  let p;
  let wsize = s.w_size;
  n = s.hash_size;
  p = n;
  do {
    m = s.head[--p];
    s.head[p] = m >= wsize ? m - wsize : 0;
  } while (--n);
  n = wsize;
  p = n;
  do {
    m = s.prev[--p];
    s.prev[p] = m >= wsize ? m - wsize : 0;
  } while (--n);
};
var HASH = (s, prev, data) => (prev << s.hash_shift ^ data) & s.hash_mask;
var INSERT_STRING = (s, str) => {
  let h;
  if (s.legacy_hash) {
    h = s.ins_h = HASH(s, s.ins_h, s.window[str + MIN_MATCH - 1]);
  } else {
    const w = s.window;
    const value = w[str] | w[str + 1] << 8 | w[str + 2] << 16 | w[str + 3] << 24;
    h = s.ins_h = Math.imul(value, 66521) + 66521 >>> 16 & s.hash_mask;
  }
  const hash_head = s.prev[str & s.w_mask] = s.head[h];
  s.head[h] = str;
  return hash_head;
};
var flush_pending = (strm) => {
  const s = strm.state;
  let len = s.pending;
  if (len > strm.avail_out) {
    len = strm.avail_out;
  }
  if (len === 0) {
    return;
  }
  strm.output.set(s.pending_buf.subarray(s.pending_out, s.pending_out + len), strm.next_out);
  strm.next_out += len;
  s.pending_out += len;
  strm.total_out += len;
  strm.avail_out -= len;
  s.pending -= len;
  if (s.pending === 0) {
    s.pending_out = 0;
  }
};
var flush_block_only = (s, last) => {
  _tr_flush_block(s, s.block_start >= 0 ? s.block_start : -1, s.strstart - s.block_start, last);
  s.block_start = s.strstart;
  flush_pending(s.strm);
};
var put_byte = (s, b) => {
  s.pending_buf[s.pending++] = b;
};
var putShortMSB = (s, b) => {
  s.pending_buf[s.pending++] = b >>> 8 & 255;
  s.pending_buf[s.pending++] = b & 255;
};
var read_buf = (strm, buf, start, size) => {
  let len = strm.avail_in;
  if (len > size) {
    len = size;
  }
  if (len === 0) {
    return 0;
  }
  strm.avail_in -= len;
  buf.set(strm.input.subarray(strm.next_in, strm.next_in + len), start);
  if (strm.state.wrap === 1) {
    strm.adler = adler32_1(strm.adler, buf, len, start);
  } else if (strm.state.wrap === 2) {
    strm.adler = crc32_1(strm.adler, buf, len, start);
  }
  strm.next_in += len;
  strm.total_in += len;
  return len;
};
var longest_match = (s, cur_match) => {
  let chain_length = s.max_chain_length;
  let scan = s.strstart;
  let match;
  let len;
  let best_len = s.prev_length;
  let nice_match = s.nice_match;
  const limit = s.strstart > s.w_size - MIN_LOOKAHEAD ? s.strstart - (s.w_size - MIN_LOOKAHEAD) : 0;
  const _win = s.window;
  const wmask = s.w_mask;
  const prev = s.prev;
  const strend = s.strstart + MAX_MATCH;
  let scan_end1 = _win[scan + best_len - 1];
  let scan_end = _win[scan + best_len];
  if (s.prev_length >= s.good_match) {
    chain_length >>= 2;
  }
  if (nice_match > s.lookahead) {
    nice_match = s.lookahead;
  }
  do {
    match = cur_match;
    if (_win[match + best_len] !== scan_end || _win[match + best_len - 1] !== scan_end1 || _win[match] !== _win[scan] || _win[++match] !== _win[scan + 1]) {
      continue;
    }
    scan += 2;
    match++;
    do {
    } while (_win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && _win[++scan] === _win[++match] && scan < strend);
    len = MAX_MATCH - (strend - scan);
    scan = strend - MAX_MATCH;
    if (len > best_len) {
      s.match_start = cur_match;
      best_len = len;
      if (len >= nice_match) {
        break;
      }
      scan_end1 = _win[scan + best_len - 1];
      scan_end = _win[scan + best_len];
    }
  } while ((cur_match = prev[cur_match & wmask]) > limit && --chain_length !== 0);
  if (best_len <= s.lookahead) {
    return best_len;
  }
  return s.lookahead;
};
var fill_window = (s) => {
  const _w_size = s.w_size;
  let n, more, str;
  do {
    more = s.window_size - s.lookahead - s.strstart;
    if (s.strstart >= _w_size + (_w_size - MIN_LOOKAHEAD)) {
      s.window.set(s.window.subarray(_w_size, _w_size + _w_size - more), 0);
      s.match_start -= _w_size;
      s.strstart -= _w_size;
      s.block_start -= _w_size;
      if (s.insert > s.strstart) {
        s.insert = s.strstart;
      }
      slide_hash(s);
      more += _w_size;
    }
    if (s.strm.avail_in === 0) {
      break;
    }
    n = read_buf(s.strm, s.window, s.strstart + s.lookahead, more);
    s.lookahead += n;
    if (!s.legacy_hash) {
      if (s.lookahead + s.insert > MIN_MATCH) {
        str = s.strstart - s.insert;
        while (s.insert) {
          INSERT_STRING(s, str);
          str++;
          s.insert--;
          if (s.lookahead + s.insert <= MIN_MATCH) {
            break;
          }
        }
      }
    } else if (s.lookahead + s.insert >= MIN_MATCH) {
      str = s.strstart - s.insert;
      s.ins_h = s.window[str];
      s.ins_h = HASH(s, s.ins_h, s.window[str + 1]);
      while (s.insert) {
        INSERT_STRING(s, str);
        str++;
        s.insert--;
        if (s.lookahead + s.insert < MIN_MATCH) {
          break;
        }
      }
    }
  } while (s.lookahead < MIN_LOOKAHEAD && s.strm.avail_in !== 0);
};
var deflate_stored = (s, flush) => {
  let min_block = s.pending_buf_size - 5 > s.w_size ? s.w_size : s.pending_buf_size - 5;
  let len, left, have, last = 0;
  let used = s.strm.avail_in;
  do {
    len = 65535;
    have = s.bi_valid + 42 >> 3;
    if (s.strm.avail_out < have) {
      break;
    }
    have = s.strm.avail_out - have;
    left = s.strstart - s.block_start;
    if (len > left + s.strm.avail_in) {
      len = left + s.strm.avail_in;
    }
    if (len > have) {
      len = have;
    }
    if (len < min_block && (len === 0 && flush !== Z_FINISH$3 || flush === Z_NO_FLUSH$2 || len !== left + s.strm.avail_in)) {
      break;
    }
    last = flush === Z_FINISH$3 && len === left + s.strm.avail_in ? 1 : 0;
    _tr_stored_block(s, 0, 0, last);
    s.pending_buf[s.pending - 4] = len;
    s.pending_buf[s.pending - 3] = len >> 8;
    s.pending_buf[s.pending - 2] = ~len;
    s.pending_buf[s.pending - 1] = ~len >> 8;
    flush_pending(s.strm);
    if (left) {
      if (left > len) {
        left = len;
      }
      s.strm.output.set(s.window.subarray(s.block_start, s.block_start + left), s.strm.next_out);
      s.strm.next_out += left;
      s.strm.avail_out -= left;
      s.strm.total_out += left;
      s.block_start += left;
      len -= left;
    }
    if (len) {
      read_buf(s.strm, s.strm.output, s.strm.next_out, len);
      s.strm.next_out += len;
      s.strm.avail_out -= len;
      s.strm.total_out += len;
    }
  } while (last === 0);
  used -= s.strm.avail_in;
  if (used) {
    if (used >= s.w_size) {
      s.matches = 2;
      s.window.set(s.strm.input.subarray(s.strm.next_in - s.w_size, s.strm.next_in), 0);
      s.strstart = s.w_size;
      s.insert = s.strstart;
    } else {
      if (s.window_size - s.strstart <= used) {
        s.strstart -= s.w_size;
        s.window.set(s.window.subarray(s.w_size, s.w_size + s.strstart), 0);
        if (s.matches < 2) {
          s.matches++;
        }
        if (s.insert > s.strstart) {
          s.insert = s.strstart;
        }
      }
      s.window.set(s.strm.input.subarray(s.strm.next_in - used, s.strm.next_in), s.strstart);
      s.strstart += used;
      s.insert += used > s.w_size - s.insert ? s.w_size - s.insert : used;
    }
    s.block_start = s.strstart;
  }
  if (s.high_water < s.strstart) {
    s.high_water = s.strstart;
  }
  if (last) {
    return BS_FINISH_DONE;
  }
  if (flush !== Z_NO_FLUSH$2 && flush !== Z_FINISH$3 && s.strm.avail_in === 0 && s.strstart === s.block_start) {
    return BS_BLOCK_DONE;
  }
  have = s.window_size - s.strstart;
  if (s.strm.avail_in > have && s.block_start >= s.w_size) {
    s.block_start -= s.w_size;
    s.strstart -= s.w_size;
    s.window.set(s.window.subarray(s.w_size, s.w_size + s.strstart), 0);
    if (s.matches < 2) {
      s.matches++;
    }
    have += s.w_size;
    if (s.insert > s.strstart) {
      s.insert = s.strstart;
    }
  }
  if (have > s.strm.avail_in) {
    have = s.strm.avail_in;
  }
  if (have) {
    read_buf(s.strm, s.window, s.strstart, have);
    s.strstart += have;
    s.insert += have > s.w_size - s.insert ? s.w_size - s.insert : have;
  }
  if (s.high_water < s.strstart) {
    s.high_water = s.strstart;
  }
  have = s.bi_valid + 42 >> 3;
  have = s.pending_buf_size - have > 65535 ? 65535 : s.pending_buf_size - have;
  min_block = have > s.w_size ? s.w_size : have;
  left = s.strstart - s.block_start;
  if (left >= min_block || (left || flush === Z_FINISH$3) && flush !== Z_NO_FLUSH$2 && s.strm.avail_in === 0 && left <= have) {
    len = left > have ? have : left;
    last = flush === Z_FINISH$3 && s.strm.avail_in === 0 && len === left ? 1 : 0;
    _tr_stored_block(s, s.block_start, len, last);
    s.block_start += len;
    flush_pending(s.strm);
  }
  return last ? BS_FINISH_STARTED : BS_NEED_MORE;
};
var deflate_fast = (s, flush) => {
  let hash_head;
  let bflush;
  for (; ; ) {
    if (s.lookahead < MIN_LOOKAHEAD) {
      fill_window(s);
      if (s.lookahead < MIN_LOOKAHEAD && flush === Z_NO_FLUSH$2) {
        return BS_NEED_MORE;
      }
      if (s.lookahead === 0) {
        break;
      }
    }
    hash_head = 0;
    if (s.lookahead >= MIN_MATCH) {
      hash_head = INSERT_STRING(s, s.strstart);
    }
    if (hash_head !== 0 && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD) {
      s.match_length = longest_match(s, hash_head);
    }
    if (s.match_length >= MIN_MATCH) {
      bflush = _tr_tally(s, s.strstart - s.match_start, s.match_length - MIN_MATCH);
      s.lookahead -= s.match_length;
      if (s.match_length <= s.max_lazy_match && s.lookahead >= MIN_MATCH) {
        s.match_length--;
        do {
          s.strstart++;
          hash_head = INSERT_STRING(s, s.strstart);
        } while (--s.match_length !== 0);
        s.strstart++;
      } else {
        s.strstart += s.match_length;
        s.match_length = 0;
        if (s.legacy_hash) {
          s.ins_h = s.window[s.strstart];
          s.ins_h = HASH(s, s.ins_h, s.window[s.strstart + 1]);
        }
      }
    } else {
      bflush = _tr_tally(s, 0, s.window[s.strstart]);
      s.lookahead--;
      s.strstart++;
    }
    if (bflush) {
      flush_block_only(s, false);
      if (s.strm.avail_out === 0) {
        return BS_NEED_MORE;
      }
    }
  }
  s.insert = s.strstart < MIN_MATCH - 1 ? s.strstart : MIN_MATCH - 1;
  if (flush === Z_FINISH$3) {
    flush_block_only(s, true);
    if (s.strm.avail_out === 0) {
      return BS_FINISH_STARTED;
    }
    return BS_FINISH_DONE;
  }
  if (s.sym_next) {
    flush_block_only(s, false);
    if (s.strm.avail_out === 0) {
      return BS_NEED_MORE;
    }
  }
  return BS_BLOCK_DONE;
};
var deflate_slow = (s, flush) => {
  let hash_head;
  let bflush;
  let max_insert;
  for (; ; ) {
    if (s.lookahead < MIN_LOOKAHEAD) {
      fill_window(s);
      if (s.lookahead < MIN_LOOKAHEAD && flush === Z_NO_FLUSH$2) {
        return BS_NEED_MORE;
      }
      if (s.lookahead === 0) {
        break;
      }
    }
    hash_head = 0;
    if (s.lookahead >= MIN_MATCH) {
      hash_head = INSERT_STRING(s, s.strstart);
    }
    s.prev_length = s.match_length;
    s.prev_match = s.match_start;
    s.match_length = MIN_MATCH - 1;
    if (hash_head !== 0 && s.prev_length < s.max_lazy_match && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD) {
      s.match_length = longest_match(s, hash_head);
      if (s.match_length <= 5 && (s.strategy === Z_FILTERED || s.match_length === MIN_MATCH && s.strstart - s.match_start > 4096)) {
        s.match_length = MIN_MATCH - 1;
      }
    }
    if (s.prev_length >= MIN_MATCH && s.match_length <= s.prev_length) {
      max_insert = s.strstart + s.lookahead - MIN_MATCH;
      bflush = _tr_tally(s, s.strstart - 1 - s.prev_match, s.prev_length - MIN_MATCH);
      s.lookahead -= s.prev_length - 1;
      s.prev_length -= 2;
      do {
        if (++s.strstart <= max_insert) {
          hash_head = INSERT_STRING(s, s.strstart);
        }
      } while (--s.prev_length !== 0);
      s.match_available = 0;
      s.match_length = MIN_MATCH - 1;
      s.strstart++;
      if (bflush) {
        flush_block_only(s, false);
        if (s.strm.avail_out === 0) {
          return BS_NEED_MORE;
        }
      }
    } else if (s.match_available) {
      bflush = _tr_tally(s, 0, s.window[s.strstart - 1]);
      if (bflush) {
        flush_block_only(s, false);
      }
      s.strstart++;
      s.lookahead--;
      if (s.strm.avail_out === 0) {
        return BS_NEED_MORE;
      }
    } else {
      s.match_available = 1;
      s.strstart++;
      s.lookahead--;
    }
  }
  if (s.match_available) {
    bflush = _tr_tally(s, 0, s.window[s.strstart - 1]);
    s.match_available = 0;
  }
  s.insert = s.strstart < MIN_MATCH - 1 ? s.strstart : MIN_MATCH - 1;
  if (flush === Z_FINISH$3) {
    flush_block_only(s, true);
    if (s.strm.avail_out === 0) {
      return BS_FINISH_STARTED;
    }
    return BS_FINISH_DONE;
  }
  if (s.sym_next) {
    flush_block_only(s, false);
    if (s.strm.avail_out === 0) {
      return BS_NEED_MORE;
    }
  }
  return BS_BLOCK_DONE;
};
var deflate_rle = (s, flush) => {
  let bflush;
  let prev;
  let scan, strend;
  const _win = s.window;
  for (; ; ) {
    if (s.lookahead <= MAX_MATCH) {
      fill_window(s);
      if (s.lookahead <= MAX_MATCH && flush === Z_NO_FLUSH$2) {
        return BS_NEED_MORE;
      }
      if (s.lookahead === 0) {
        break;
      }
    }
    s.match_length = 0;
    if (s.lookahead >= MIN_MATCH && s.strstart > 0) {
      scan = s.strstart - 1;
      prev = _win[scan];
      if (prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan]) {
        strend = s.strstart + MAX_MATCH;
        do {
        } while (prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && prev === _win[++scan] && scan < strend);
        s.match_length = MAX_MATCH - (strend - scan);
        if (s.match_length > s.lookahead) {
          s.match_length = s.lookahead;
        }
      }
    }
    if (s.match_length >= MIN_MATCH) {
      bflush = _tr_tally(s, 1, s.match_length - MIN_MATCH);
      s.lookahead -= s.match_length;
      s.strstart += s.match_length;
      s.match_length = 0;
    } else {
      bflush = _tr_tally(s, 0, s.window[s.strstart]);
      s.lookahead--;
      s.strstart++;
    }
    if (bflush) {
      flush_block_only(s, false);
      if (s.strm.avail_out === 0) {
        return BS_NEED_MORE;
      }
    }
  }
  s.insert = 0;
  if (flush === Z_FINISH$3) {
    flush_block_only(s, true);
    if (s.strm.avail_out === 0) {
      return BS_FINISH_STARTED;
    }
    return BS_FINISH_DONE;
  }
  if (s.sym_next) {
    flush_block_only(s, false);
    if (s.strm.avail_out === 0) {
      return BS_NEED_MORE;
    }
  }
  return BS_BLOCK_DONE;
};
var deflate_huff = (s, flush) => {
  let bflush;
  for (; ; ) {
    if (s.lookahead === 0) {
      fill_window(s);
      if (s.lookahead === 0) {
        if (flush === Z_NO_FLUSH$2) {
          return BS_NEED_MORE;
        }
        break;
      }
    }
    s.match_length = 0;
    bflush = _tr_tally(s, 0, s.window[s.strstart]);
    s.lookahead--;
    s.strstart++;
    if (bflush) {
      flush_block_only(s, false);
      if (s.strm.avail_out === 0) {
        return BS_NEED_MORE;
      }
    }
  }
  s.insert = 0;
  if (flush === Z_FINISH$3) {
    flush_block_only(s, true);
    if (s.strm.avail_out === 0) {
      return BS_FINISH_STARTED;
    }
    return BS_FINISH_DONE;
  }
  if (s.sym_next) {
    flush_block_only(s, false);
    if (s.strm.avail_out === 0) {
      return BS_NEED_MORE;
    }
  }
  return BS_BLOCK_DONE;
};
function Config(good_length, max_lazy, nice_length, max_chain, func) {
  this.good_length = good_length;
  this.max_lazy = max_lazy;
  this.nice_length = nice_length;
  this.max_chain = max_chain;
  this.func = func;
}
var configuration_table = [
  /*      good lazy nice chain */
  new Config(0, 0, 0, 0, deflate_stored),
  /* 0 store only */
  new Config(4, 4, 8, 4, deflate_fast),
  /* 1 max speed, no lazy matches */
  new Config(4, 5, 16, 8, deflate_fast),
  /* 2 */
  new Config(4, 6, 32, 32, deflate_fast),
  /* 3 */
  new Config(4, 4, 16, 16, deflate_slow),
  /* 4 lazy matches */
  new Config(8, 16, 32, 32, deflate_slow),
  /* 5 */
  new Config(8, 16, 128, 128, deflate_slow),
  /* 6 */
  new Config(8, 32, 128, 256, deflate_slow),
  /* 7 */
  new Config(32, 128, 258, 1024, deflate_slow),
  /* 8 */
  new Config(32, 258, 258, 4096, deflate_slow)
  /* 9 max compression */
];
var lm_init = (s) => {
  s.window_size = 2 * s.w_size;
  zero(s.head);
  s.max_lazy_match = configuration_table[s.level].max_lazy;
  s.good_match = configuration_table[s.level].good_length;
  s.nice_match = configuration_table[s.level].nice_length;
  s.max_chain_length = configuration_table[s.level].max_chain;
  s.strstart = 0;
  s.block_start = 0;
  s.lookahead = 0;
  s.insert = 0;
  s.match_length = s.prev_length = MIN_MATCH - 1;
  s.match_available = 0;
  s.ins_h = 0;
};
function DeflateState() {
  this.strm = null;
  this.status = 0;
  this.pending_buf = null;
  this.pending_buf_size = 0;
  this.pending_out = 0;
  this.pending = 0;
  this.wrap = 0;
  this.gzhead = null;
  this.gzindex = 0;
  this.method = Z_DEFLATED$2;
  this.last_flush = -1;
  this.w_size = 0;
  this.w_bits = 0;
  this.w_mask = 0;
  this.window = null;
  this.window_size = 0;
  this.prev = null;
  this.head = null;
  this.ins_h = 0;
  this.legacy_hash = 0;
  this.hash_size = 0;
  this.hash_bits = 0;
  this.hash_mask = 0;
  this.hash_shift = 0;
  this.block_start = 0;
  this.match_length = 0;
  this.prev_match = 0;
  this.match_available = 0;
  this.strstart = 0;
  this.match_start = 0;
  this.lookahead = 0;
  this.prev_length = 0;
  this.max_chain_length = 0;
  this.max_lazy_match = 0;
  this.level = 0;
  this.strategy = 0;
  this.good_match = 0;
  this.nice_match = 0;
  this.dyn_ltree = new Uint16Array(HEAP_SIZE * 2);
  this.dyn_dtree = new Uint16Array((2 * D_CODES + 1) * 2);
  this.bl_tree = new Uint16Array((2 * BL_CODES + 1) * 2);
  zero(this.dyn_ltree);
  zero(this.dyn_dtree);
  zero(this.bl_tree);
  this.l_desc = null;
  this.d_desc = null;
  this.bl_desc = null;
  this.bl_count = new Uint16Array(MAX_BITS + 1);
  this.heap = new Uint16Array(2 * L_CODES + 1);
  zero(this.heap);
  this.heap_len = 0;
  this.heap_max = 0;
  this.depth = new Uint16Array(2 * L_CODES + 1);
  zero(this.depth);
  this.sym_buf = 0;
  this.lit_bufsize = 0;
  this.sym_next = 0;
  this.sym_end = 0;
  this.opt_len = 0;
  this.static_len = 0;
  this.matches = 0;
  this.insert = 0;
  this.bi_buf = 0;
  this.bi_valid = 0;
}
var deflateStateCheck = (strm) => {
  if (!strm) {
    return 1;
  }
  const s = strm.state;
  if (!s || s.strm !== strm || s.status !== INIT_STATE && //#ifdef GZIP
  s.status !== GZIP_STATE && //#endif
  s.status !== EXTRA_STATE && s.status !== NAME_STATE && s.status !== COMMENT_STATE && s.status !== HCRC_STATE && s.status !== BUSY_STATE && s.status !== FINISH_STATE) {
    return 1;
  }
  return 0;
};
var deflateResetKeep = (strm) => {
  if (deflateStateCheck(strm)) {
    return err(strm, Z_STREAM_ERROR$2);
  }
  strm.total_in = strm.total_out = 0;
  strm.data_type = Z_UNKNOWN;
  const s = strm.state;
  s.pending = 0;
  s.pending_out = 0;
  if (s.wrap < 0) {
    s.wrap = -s.wrap;
  }
  s.status = //#ifdef GZIP
  s.wrap === 2 ? GZIP_STATE : (
    //#endif
    s.wrap ? INIT_STATE : BUSY_STATE
  );
  strm.adler = s.wrap === 2 ? 0 : 1;
  s.last_flush = -2;
  _tr_init(s);
  return Z_OK$3;
};
var deflateReset = (strm) => {
  const ret = deflateResetKeep(strm);
  if (ret === Z_OK$3) {
    lm_init(strm.state);
  }
  return ret;
};
var deflateSetHeader = (strm, head) => {
  if (deflateStateCheck(strm) || strm.state.wrap !== 2) {
    return Z_STREAM_ERROR$2;
  }
  strm.state.gzhead = head;
  return Z_OK$3;
};
var deflateInit2 = (strm, level, method, windowBits, memLevel, strategy, legacyHash) => {
  if (!strm) {
    return Z_STREAM_ERROR$2;
  }
  let wrap2 = 1;
  if (level === Z_DEFAULT_COMPRESSION$1) {
    level = 6;
  }
  if (windowBits < 0) {
    wrap2 = 0;
    windowBits = -windowBits;
  } else if (windowBits > 15) {
    wrap2 = 2;
    windowBits -= 16;
  }
  if (memLevel < 1 || memLevel > MAX_MEM_LEVEL || method !== Z_DEFLATED$2 || windowBits < 8 || windowBits > 15 || level < 0 || level > 9 || strategy < 0 || strategy > Z_FIXED || windowBits === 8 && wrap2 !== 1) {
    return err(strm, Z_STREAM_ERROR$2);
  }
  if (windowBits === 8) {
    windowBits = 9;
  }
  const s = new DeflateState();
  strm.state = s;
  s.strm = strm;
  s.status = INIT_STATE;
  s.wrap = wrap2;
  s.gzhead = null;
  s.w_bits = windowBits;
  s.w_size = 1 << s.w_bits;
  s.w_mask = s.w_size - 1;
  s.legacy_hash = legacyHash ? 1 : 0;
  s.hash_bits = memLevel + 7;
  if (!s.legacy_hash && s.hash_bits < 15) {
    s.hash_bits = 15;
  }
  s.hash_size = 1 << s.hash_bits;
  s.hash_mask = s.hash_size - 1;
  s.hash_shift = ~~((s.hash_bits + MIN_MATCH - 1) / MIN_MATCH);
  s.window = new Uint8Array(s.w_size * 2);
  s.head = new Uint16Array(s.hash_size);
  s.prev = new Uint16Array(s.w_size);
  s.lit_bufsize = 1 << memLevel + 6;
  s.pending_buf_size = s.lit_bufsize * 4;
  s.pending_buf = new Uint8Array(s.pending_buf_size);
  s.sym_buf = s.lit_bufsize;
  s.sym_end = (s.lit_bufsize - 1) * 3;
  s.level = level;
  s.strategy = strategy;
  s.method = method;
  return deflateReset(strm);
};
var deflateInit = (strm, level) => {
  return deflateInit2(strm, level, Z_DEFLATED$2, MAX_WBITS$1, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY$1);
};
var deflate$2 = (strm, flush) => {
  if (deflateStateCheck(strm) || flush > Z_BLOCK$1 || flush < 0) {
    return strm ? err(strm, Z_STREAM_ERROR$2) : Z_STREAM_ERROR$2;
  }
  const s = strm.state;
  if (!strm.output || strm.avail_in !== 0 && !strm.input || s.status === FINISH_STATE && flush !== Z_FINISH$3) {
    return err(strm, strm.avail_out === 0 ? Z_BUF_ERROR$2 : Z_STREAM_ERROR$2);
  }
  const old_flush = s.last_flush;
  s.last_flush = flush;
  if (s.pending !== 0) {
    flush_pending(strm);
    if (strm.avail_out === 0) {
      s.last_flush = -1;
      return Z_OK$3;
    }
  } else if (strm.avail_in === 0 && rank(flush) <= rank(old_flush) && flush !== Z_FINISH$3) {
    return err(strm, Z_BUF_ERROR$2);
  }
  if (s.status === FINISH_STATE && strm.avail_in !== 0) {
    return err(strm, Z_BUF_ERROR$2);
  }
  if (s.status === INIT_STATE && s.wrap === 0) {
    s.status = BUSY_STATE;
  }
  if (s.status === INIT_STATE) {
    let header = Z_DEFLATED$2 + (s.w_bits - 8 << 4) << 8;
    let level_flags = -1;
    if (s.strategy >= Z_HUFFMAN_ONLY || s.level < 2) {
      level_flags = 0;
    } else if (s.level < 6) {
      level_flags = 1;
    } else if (s.level === 6) {
      level_flags = 2;
    } else {
      level_flags = 3;
    }
    header |= level_flags << 6;
    if (s.strstart !== 0) {
      header |= PRESET_DICT;
    }
    header += 31 - header % 31;
    putShortMSB(s, header);
    if (s.strstart !== 0) {
      putShortMSB(s, strm.adler >>> 16);
      putShortMSB(s, strm.adler & 65535);
    }
    strm.adler = 1;
    s.status = BUSY_STATE;
    flush_pending(strm);
    if (s.pending !== 0) {
      s.last_flush = -1;
      return Z_OK$3;
    }
  }
  if (s.status === GZIP_STATE) {
    strm.adler = 0;
    put_byte(s, 31);
    put_byte(s, 139);
    put_byte(s, 8);
    if (!s.gzhead) {
      put_byte(s, 0);
      put_byte(s, 0);
      put_byte(s, 0);
      put_byte(s, 0);
      put_byte(s, 0);
      put_byte(s, s.level === 9 ? 2 : s.strategy >= Z_HUFFMAN_ONLY || s.level < 2 ? 4 : 0);
      put_byte(s, OS_CODE);
      s.status = BUSY_STATE;
      flush_pending(strm);
      if (s.pending !== 0) {
        s.last_flush = -1;
        return Z_OK$3;
      }
    } else {
      put_byte(
        s,
        (s.gzhead.text ? 1 : 0) + (s.gzhead.hcrc ? 2 : 0) + (!s.gzhead.extra ? 0 : 4) + (!s.gzhead.name ? 0 : 8) + (!s.gzhead.comment ? 0 : 16)
      );
      put_byte(s, s.gzhead.time & 255);
      put_byte(s, s.gzhead.time >> 8 & 255);
      put_byte(s, s.gzhead.time >> 16 & 255);
      put_byte(s, s.gzhead.time >> 24 & 255);
      put_byte(s, s.level === 9 ? 2 : s.strategy >= Z_HUFFMAN_ONLY || s.level < 2 ? 4 : 0);
      put_byte(s, s.gzhead.os & 255);
      if (s.gzhead.extra && s.gzhead.extra.length) {
        put_byte(s, s.gzhead.extra.length & 255);
        put_byte(s, s.gzhead.extra.length >> 8 & 255);
      }
      if (s.gzhead.hcrc) {
        strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending, 0);
      }
      s.gzindex = 0;
      s.status = EXTRA_STATE;
    }
  }
  if (s.status === EXTRA_STATE) {
    if (s.gzhead.extra) {
      let beg = s.pending;
      let left = (s.gzhead.extra.length & 65535) - s.gzindex;
      while (s.pending + left > s.pending_buf_size) {
        let copy = s.pending_buf_size - s.pending;
        s.pending_buf.set(s.gzhead.extra.subarray(s.gzindex, s.gzindex + copy), s.pending);
        s.pending = s.pending_buf_size;
        if (s.gzhead.hcrc && s.pending > beg) {
          strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
        }
        s.gzindex += copy;
        flush_pending(strm);
        if (s.pending !== 0) {
          s.last_flush = -1;
          return Z_OK$3;
        }
        beg = 0;
        left -= copy;
      }
      let gzhead_extra = new Uint8Array(s.gzhead.extra);
      s.pending_buf.set(gzhead_extra.subarray(s.gzindex, s.gzindex + left), s.pending);
      s.pending += left;
      if (s.gzhead.hcrc && s.pending > beg) {
        strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
      }
      s.gzindex = 0;
    }
    s.status = NAME_STATE;
  }
  if (s.status === NAME_STATE) {
    if (s.gzhead.name) {
      let beg = s.pending;
      let val;
      do {
        if (s.pending === s.pending_buf_size) {
          if (s.gzhead.hcrc && s.pending > beg) {
            strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
          }
          flush_pending(strm);
          if (s.pending !== 0) {
            s.last_flush = -1;
            return Z_OK$3;
          }
          beg = 0;
        }
        if (s.gzindex < s.gzhead.name.length) {
          val = s.gzhead.name.charCodeAt(s.gzindex++) & 255;
        } else {
          val = 0;
        }
        put_byte(s, val);
      } while (val !== 0);
      if (s.gzhead.hcrc && s.pending > beg) {
        strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
      }
      s.gzindex = 0;
    }
    s.status = COMMENT_STATE;
  }
  if (s.status === COMMENT_STATE) {
    if (s.gzhead.comment) {
      let beg = s.pending;
      let val;
      do {
        if (s.pending === s.pending_buf_size) {
          if (s.gzhead.hcrc && s.pending > beg) {
            strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
          }
          flush_pending(strm);
          if (s.pending !== 0) {
            s.last_flush = -1;
            return Z_OK$3;
          }
          beg = 0;
        }
        if (s.gzindex < s.gzhead.comment.length) {
          val = s.gzhead.comment.charCodeAt(s.gzindex++) & 255;
        } else {
          val = 0;
        }
        put_byte(s, val);
      } while (val !== 0);
      if (s.gzhead.hcrc && s.pending > beg) {
        strm.adler = crc32_1(strm.adler, s.pending_buf, s.pending - beg, beg);
      }
    }
    s.status = HCRC_STATE;
  }
  if (s.status === HCRC_STATE) {
    if (s.gzhead.hcrc) {
      if (s.pending + 2 > s.pending_buf_size) {
        flush_pending(strm);
        if (s.pending !== 0) {
          s.last_flush = -1;
          return Z_OK$3;
        }
      }
      put_byte(s, strm.adler & 255);
      put_byte(s, strm.adler >> 8 & 255);
      strm.adler = 0;
    }
    s.status = BUSY_STATE;
    flush_pending(strm);
    if (s.pending !== 0) {
      s.last_flush = -1;
      return Z_OK$3;
    }
  }
  if (strm.avail_in !== 0 || s.lookahead !== 0 || flush !== Z_NO_FLUSH$2 && s.status !== FINISH_STATE) {
    let bstate = s.level === 0 ? deflate_stored(s, flush) : s.strategy === Z_HUFFMAN_ONLY ? deflate_huff(s, flush) : s.strategy === Z_RLE ? deflate_rle(s, flush) : configuration_table[s.level].func(s, flush);
    if (bstate === BS_FINISH_STARTED || bstate === BS_FINISH_DONE) {
      s.status = FINISH_STATE;
    }
    if (bstate === BS_NEED_MORE || bstate === BS_FINISH_STARTED) {
      if (strm.avail_out === 0) {
        s.last_flush = -1;
      }
      return Z_OK$3;
    }
    if (bstate === BS_BLOCK_DONE) {
      if (flush === Z_PARTIAL_FLUSH) {
        _tr_align(s);
      } else if (flush !== Z_BLOCK$1) {
        _tr_stored_block(s, 0, 0, false);
        if (flush === Z_FULL_FLUSH$1) {
          zero(s.head);
          if (s.lookahead === 0) {
            s.strstart = 0;
            s.block_start = 0;
            s.insert = 0;
          }
        }
      }
      flush_pending(strm);
      if (strm.avail_out === 0) {
        s.last_flush = -1;
        return Z_OK$3;
      }
    }
  }
  if (flush !== Z_FINISH$3) {
    return Z_OK$3;
  }
  if (s.wrap <= 0) {
    return Z_STREAM_END$3;
  }
  if (s.wrap === 2) {
    put_byte(s, strm.adler & 255);
    put_byte(s, strm.adler >> 8 & 255);
    put_byte(s, strm.adler >> 16 & 255);
    put_byte(s, strm.adler >> 24 & 255);
    put_byte(s, strm.total_in & 255);
    put_byte(s, strm.total_in >> 8 & 255);
    put_byte(s, strm.total_in >> 16 & 255);
    put_byte(s, strm.total_in >> 24 & 255);
  } else {
    putShortMSB(s, strm.adler >>> 16);
    putShortMSB(s, strm.adler & 65535);
  }
  flush_pending(strm);
  if (s.wrap > 0) {
    s.wrap = -s.wrap;
  }
  return s.pending !== 0 ? Z_OK$3 : Z_STREAM_END$3;
};
var deflateEnd = (strm) => {
  if (deflateStateCheck(strm)) {
    return Z_STREAM_ERROR$2;
  }
  const status = strm.state.status;
  strm.state = null;
  return status === BUSY_STATE ? err(strm, Z_DATA_ERROR$2) : Z_OK$3;
};
var deflateSetDictionary = (strm, dictionary) => {
  let dictLength = dictionary.length;
  if (deflateStateCheck(strm)) {
    return Z_STREAM_ERROR$2;
  }
  const s = strm.state;
  const wrap2 = s.wrap;
  if (wrap2 === 2 || wrap2 === 1 && s.status !== INIT_STATE || s.lookahead) {
    return Z_STREAM_ERROR$2;
  }
  if (wrap2 === 1) {
    strm.adler = adler32_1(strm.adler, dictionary, dictLength, 0);
  }
  s.wrap = 0;
  if (dictLength >= s.w_size) {
    if (wrap2 === 0) {
      zero(s.head);
      s.strstart = 0;
      s.block_start = 0;
      s.insert = 0;
    }
    let tmpDict = new Uint8Array(s.w_size);
    tmpDict.set(dictionary.subarray(dictLength - s.w_size, dictLength), 0);
    dictionary = tmpDict;
    dictLength = s.w_size;
  }
  const avail = strm.avail_in;
  const next = strm.next_in;
  const input = strm.input;
  strm.avail_in = dictLength;
  strm.next_in = 0;
  strm.input = dictionary;
  fill_window(s);
  while (s.lookahead >= MIN_MATCH) {
    let str = s.strstart;
    let n = s.lookahead - (MIN_MATCH - 1);
    do {
      INSERT_STRING(s, str);
      str++;
    } while (--n);
    s.strstart = str;
    s.lookahead = MIN_MATCH - 1;
    fill_window(s);
  }
  s.strstart += s.lookahead;
  s.block_start = s.strstart;
  s.insert = s.lookahead;
  s.lookahead = 0;
  s.match_length = s.prev_length = MIN_MATCH - 1;
  s.match_available = 0;
  strm.next_in = next;
  strm.input = input;
  strm.avail_in = avail;
  s.wrap = wrap2;
  return Z_OK$3;
};
var deflateInit_1 = deflateInit;
var deflateInit2_1 = deflateInit2;
var deflateReset_1 = deflateReset;
var deflateResetKeep_1 = deflateResetKeep;
var deflateSetHeader_1 = deflateSetHeader;
var deflate_2$1 = deflate$2;
var deflateEnd_1 = deflateEnd;
var deflateSetDictionary_1 = deflateSetDictionary;
var deflateInfo = "pako deflate (from Nodeca project)";
var deflate_1$2 = {
  deflateInit: deflateInit_1,
  deflateInit2: deflateInit2_1,
  deflateReset: deflateReset_1,
  deflateResetKeep: deflateResetKeep_1,
  deflateSetHeader: deflateSetHeader_1,
  deflate: deflate_2$1,
  deflateEnd: deflateEnd_1,
  deflateSetDictionary: deflateSetDictionary_1,
  deflateInfo
};
var _has = (obj, key) => {
  return Object.prototype.hasOwnProperty.call(obj, key);
};
var assign = function(obj) {
  const sources = Array.prototype.slice.call(arguments, 1);
  while (sources.length) {
    const source = sources.shift();
    if (!source) {
      continue;
    }
    if (typeof source !== "object") {
      throw new TypeError(source + "must be non-object");
    }
    for (const p in source) {
      if (_has(source, p)) {
        obj[p] = source[p];
      }
    }
  }
  return obj;
};
var flattenChunks = (chunks) => {
  let len = 0;
  for (let i = 0, l = chunks.length; i < l; i++) {
    len += chunks[i].length;
  }
  const result = new Uint8Array(len);
  for (let i = 0, pos = 0, l = chunks.length; i < l; i++) {
    let chunk = chunks[i];
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
};
var common = {
  assign,
  flattenChunks
};
var STR_APPLY_UIA_OK = true;
try {
  String.fromCharCode.apply(null, new Uint8Array(1));
} catch (__) {
  STR_APPLY_UIA_OK = false;
}
var _utf8len = new Uint8Array(256);
for (let q = 0; q < 256; q++) {
  _utf8len[q] = q >= 252 ? 6 : q >= 248 ? 5 : q >= 240 ? 4 : q >= 224 ? 3 : q >= 192 ? 2 : 1;
}
_utf8len[254] = _utf8len[255] = 1;
var string2buf = (str) => {
  if (typeof TextEncoder === "function" && TextEncoder.prototype.encode) {
    return new TextEncoder().encode(str);
  }
  let buf, c, c2, m_pos, i, str_len = str.length, buf_len = 0;
  for (m_pos = 0; m_pos < str_len; m_pos++) {
    c = str.charCodeAt(m_pos);
    if ((c & 64512) === 55296 && m_pos + 1 < str_len) {
      c2 = str.charCodeAt(m_pos + 1);
      if ((c2 & 64512) === 56320) {
        c = 65536 + (c - 55296 << 10) + (c2 - 56320);
        m_pos++;
      }
    }
    buf_len += c < 128 ? 1 : c < 2048 ? 2 : c < 65536 ? 3 : 4;
  }
  buf = new Uint8Array(buf_len);
  for (i = 0, m_pos = 0; i < buf_len; m_pos++) {
    c = str.charCodeAt(m_pos);
    if ((c & 64512) === 55296 && m_pos + 1 < str_len) {
      c2 = str.charCodeAt(m_pos + 1);
      if ((c2 & 64512) === 56320) {
        c = 65536 + (c - 55296 << 10) + (c2 - 56320);
        m_pos++;
      }
    }
    if (c < 128) {
      buf[i++] = c;
    } else if (c < 2048) {
      buf[i++] = 192 | c >>> 6;
      buf[i++] = 128 | c & 63;
    } else if (c < 65536) {
      buf[i++] = 224 | c >>> 12;
      buf[i++] = 128 | c >>> 6 & 63;
      buf[i++] = 128 | c & 63;
    } else {
      buf[i++] = 240 | c >>> 18;
      buf[i++] = 128 | c >>> 12 & 63;
      buf[i++] = 128 | c >>> 6 & 63;
      buf[i++] = 128 | c & 63;
    }
  }
  return buf;
};
var buf2binstring = (buf, len) => {
  if (len < 65534) {
    if (buf.subarray && STR_APPLY_UIA_OK) {
      return String.fromCharCode.apply(null, buf.length === len ? buf : buf.subarray(0, len));
    }
  }
  let result = "";
  for (let i = 0; i < len; i++) {
    result += String.fromCharCode(buf[i]);
  }
  return result;
};
var buf2string = (buf, max) => {
  const len = max || buf.length;
  if (typeof TextDecoder === "function" && TextDecoder.prototype.decode) {
    return new TextDecoder().decode(buf.subarray(0, max));
  }
  let i, out;
  const utf16buf = new Array(len * 2);
  for (out = 0, i = 0; i < len; ) {
    let c = buf[i++];
    if (c < 128) {
      utf16buf[out++] = c;
      continue;
    }
    let c_len = _utf8len[c];
    if (c_len > 4) {
      utf16buf[out++] = 65533;
      i += c_len - 1;
      continue;
    }
    c &= c_len === 2 ? 31 : c_len === 3 ? 15 : 7;
    while (c_len > 1 && i < len) {
      c = c << 6 | buf[i++] & 63;
      c_len--;
    }
    if (c_len > 1) {
      utf16buf[out++] = 65533;
      continue;
    }
    if (c < 65536) {
      utf16buf[out++] = c;
    } else {
      c -= 65536;
      utf16buf[out++] = 55296 | c >> 10 & 1023;
      utf16buf[out++] = 56320 | c & 1023;
    }
  }
  return buf2binstring(utf16buf, out);
};
var utf8border = (buf, max) => {
  max = max || buf.length;
  if (max > buf.length) {
    max = buf.length;
  }
  let pos = max - 1;
  while (pos >= 0 && (buf[pos] & 192) === 128) {
    pos--;
  }
  if (pos < 0) {
    return max;
  }
  if (pos === 0) {
    return max;
  }
  return pos + _utf8len[buf[pos]] > max ? pos : max;
};
var strings2 = {
  string2buf,
  buf2string,
  utf8border
};
function ZStream() {
  this.input = null;
  this.next_in = 0;
  this.avail_in = 0;
  this.total_in = 0;
  this.output = null;
  this.next_out = 0;
  this.avail_out = 0;
  this.total_out = 0;
  this.msg = "";
  this.state = null;
  this.data_type = 2;
  this.adler = 0;
}
var zstream = ZStream;
var toString$1 = Object.prototype.toString;
var {
  Z_NO_FLUSH: Z_NO_FLUSH$1,
  Z_SYNC_FLUSH,
  Z_FULL_FLUSH,
  Z_FINISH: Z_FINISH$2,
  Z_OK: Z_OK$2,
  Z_STREAM_END: Z_STREAM_END$2,
  Z_DEFAULT_COMPRESSION,
  Z_DEFAULT_STRATEGY,
  Z_DEFLATED: Z_DEFLATED$1
} = constants$2;
var defaultOptions$1 = {
  level: Z_DEFAULT_COMPRESSION,
  method: Z_DEFLATED$1,
  chunkSize: 16384,
  windowBits: 15,
  memLevel: 8,
  strategy: Z_DEFAULT_STRATEGY,
  legacyHash: true
};
function Deflate$1(options) {
  this.options = common.assign({}, defaultOptions$1, options || {});
  let opt = this.options;
  if (opt.raw && opt.windowBits > 0) {
    opt.windowBits = -opt.windowBits;
  } else if (opt.gzip && opt.windowBits > 0 && opt.windowBits < 16) {
    opt.windowBits += 16;
  }
  this.err = 0;
  this.msg = "";
  this.ended = false;
  this.chunks = [];
  this.strm = new zstream();
  this.strm.avail_out = 0;
  let status = deflate_1$2.deflateInit2(
    this.strm,
    opt.level,
    opt.method,
    opt.windowBits,
    opt.memLevel,
    opt.strategy,
    opt.legacyHash
  );
  if (status !== Z_OK$2) {
    throw new Error(messages[status]);
  }
  if (opt.header) {
    deflate_1$2.deflateSetHeader(this.strm, opt.header);
  }
  if (opt.dictionary) {
    let dict;
    if (typeof opt.dictionary === "string") {
      dict = strings2.string2buf(opt.dictionary);
    } else if (toString$1.call(opt.dictionary) === "[object ArrayBuffer]") {
      dict = new Uint8Array(opt.dictionary);
    } else {
      dict = opt.dictionary;
    }
    status = deflate_1$2.deflateSetDictionary(this.strm, dict);
    if (status !== Z_OK$2) {
      throw new Error(messages[status]);
    }
    this._dict_set = true;
  }
}
Deflate$1.prototype.push = function(data, flush_mode) {
  const strm = this.strm;
  const chunkSize = this.options.chunkSize;
  let status, _flush_mode;
  if (this.ended) {
    return false;
  }
  if (flush_mode === ~~flush_mode) _flush_mode = flush_mode;
  else _flush_mode = flush_mode === true ? Z_FINISH$2 : Z_NO_FLUSH$1;
  if (typeof data === "string") {
    strm.input = strings2.string2buf(data);
  } else if (toString$1.call(data) === "[object ArrayBuffer]") {
    strm.input = new Uint8Array(data);
  } else {
    strm.input = data;
  }
  strm.next_in = 0;
  strm.avail_in = strm.input.length;
  for (; ; ) {
    if (strm.avail_out === 0) {
      strm.output = new Uint8Array(chunkSize);
      strm.next_out = 0;
      strm.avail_out = chunkSize;
    }
    if ((_flush_mode === Z_SYNC_FLUSH || _flush_mode === Z_FULL_FLUSH) && strm.avail_out <= 6) {
      this.onData(strm.output.subarray(0, strm.next_out));
      strm.avail_out = 0;
      continue;
    }
    status = deflate_1$2.deflate(strm, _flush_mode);
    if (status === Z_STREAM_END$2) {
      if (strm.next_out > 0) {
        this.onData(strm.output.subarray(0, strm.next_out));
      }
      status = deflate_1$2.deflateEnd(this.strm);
      this.onEnd(status);
      this.ended = true;
      return status === Z_OK$2;
    }
    if (strm.avail_out === 0) {
      this.onData(strm.output);
      continue;
    }
    if (_flush_mode > 0 && strm.next_out > 0) {
      this.onData(strm.output.subarray(0, strm.next_out));
      strm.avail_out = 0;
      continue;
    }
    if (strm.avail_in === 0) break;
  }
  return true;
};
Deflate$1.prototype.onData = function(chunk) {
  this.chunks.push(chunk);
};
Deflate$1.prototype.onEnd = function(status) {
  if (status === Z_OK$2) {
    this.result = common.flattenChunks(this.chunks);
  }
  this.chunks = [];
  this.err = status;
  this.msg = this.strm.msg;
};
function deflate$1(input, options) {
  const deflator = new Deflate$1(options);
  deflator.push(input, true);
  if (deflator.err) {
    throw deflator.msg || messages[deflator.err];
  }
  return deflator.result;
}
function deflateRaw$1(input, options) {
  options = options || {};
  options.raw = true;
  return deflate$1(input, options);
}
function gzip$1(input, options) {
  options = options || {};
  options.gzip = true;
  return deflate$1(input, options);
}
var Deflate_1$1 = Deflate$1;
var deflate_2 = deflate$1;
var deflateRaw_1$1 = deflateRaw$1;
var gzip_1$1 = gzip$1;
var constants$1 = constants$2;
var deflate_1$1 = {
  Deflate: Deflate_1$1,
  deflate: deflate_2,
  deflateRaw: deflateRaw_1$1,
  gzip: gzip_1$1,
  constants: constants$1
};
var BAD$1 = 16209;
var TYPE$1 = 16191;
var inffast = function inflate_fast(strm, start) {
  let _in;
  let last;
  let _out;
  let beg;
  let end;
  let dmax;
  let wsize;
  let whave;
  let wnext;
  let s_window;
  let hold;
  let bits;
  let lcode;
  let dcode;
  let lmask;
  let dmask;
  let here;
  let op;
  let len;
  let dist;
  let from;
  let from_source;
  let input, output;
  const state = strm.state;
  _in = strm.next_in;
  input = strm.input;
  last = _in + (strm.avail_in - 5);
  _out = strm.next_out;
  output = strm.output;
  beg = _out - (start - strm.avail_out);
  end = _out + (strm.avail_out - 257);
  dmax = state.dmax;
  wsize = state.wsize;
  whave = state.whave;
  wnext = state.wnext;
  s_window = state.window;
  hold = state.hold;
  bits = state.bits;
  lcode = state.lencode;
  dcode = state.distcode;
  lmask = (1 << state.lenbits) - 1;
  dmask = (1 << state.distbits) - 1;
  top:
    do {
      if (bits < 15) {
        hold += input[_in++] << bits;
        bits += 8;
        hold += input[_in++] << bits;
        bits += 8;
      }
      here = lcode[hold & lmask];
      dolen:
        for (; ; ) {
          op = here >>> 24;
          hold >>>= op;
          bits -= op;
          op = here >>> 16 & 255;
          if (op === 0) {
            output[_out++] = here & 65535;
          } else if (op & 16) {
            len = here & 65535;
            op &= 15;
            if (op) {
              if (bits < op) {
                hold += input[_in++] << bits;
                bits += 8;
              }
              len += hold & (1 << op) - 1;
              hold >>>= op;
              bits -= op;
            }
            if (bits < 15) {
              hold += input[_in++] << bits;
              bits += 8;
              hold += input[_in++] << bits;
              bits += 8;
            }
            here = dcode[hold & dmask];
            dodist:
              for (; ; ) {
                op = here >>> 24;
                hold >>>= op;
                bits -= op;
                op = here >>> 16 & 255;
                if (op & 16) {
                  dist = here & 65535;
                  op &= 15;
                  if (bits < op) {
                    hold += input[_in++] << bits;
                    bits += 8;
                    if (bits < op) {
                      hold += input[_in++] << bits;
                      bits += 8;
                    }
                  }
                  dist += hold & (1 << op) - 1;
                  if (dist > dmax) {
                    strm.msg = "invalid distance too far back";
                    state.mode = BAD$1;
                    break top;
                  }
                  hold >>>= op;
                  bits -= op;
                  op = _out - beg;
                  if (dist > op) {
                    op = dist - op;
                    if (op > whave) {
                      if (state.sane) {
                        strm.msg = "invalid distance too far back";
                        state.mode = BAD$1;
                        break top;
                      }
                    }
                    from = 0;
                    from_source = s_window;
                    if (wnext === 0) {
                      from += wsize - op;
                      if (op < len) {
                        len -= op;
                        do {
                          output[_out++] = s_window[from++];
                        } while (--op);
                        from = _out - dist;
                        from_source = output;
                      }
                    } else if (wnext < op) {
                      from += wsize + wnext - op;
                      op -= wnext;
                      if (op < len) {
                        len -= op;
                        do {
                          output[_out++] = s_window[from++];
                        } while (--op);
                        from = 0;
                        if (wnext < len) {
                          op = wnext;
                          len -= op;
                          do {
                            output[_out++] = s_window[from++];
                          } while (--op);
                          from = _out - dist;
                          from_source = output;
                        }
                      }
                    } else {
                      from += wnext - op;
                      if (op < len) {
                        len -= op;
                        do {
                          output[_out++] = s_window[from++];
                        } while (--op);
                        from = _out - dist;
                        from_source = output;
                      }
                    }
                    while (len > 2) {
                      output[_out++] = from_source[from++];
                      output[_out++] = from_source[from++];
                      output[_out++] = from_source[from++];
                      len -= 3;
                    }
                    if (len) {
                      output[_out++] = from_source[from++];
                      if (len > 1) {
                        output[_out++] = from_source[from++];
                      }
                    }
                  } else {
                    from = _out - dist;
                    do {
                      output[_out++] = output[from++];
                      output[_out++] = output[from++];
                      output[_out++] = output[from++];
                      len -= 3;
                    } while (len > 2);
                    if (len) {
                      output[_out++] = output[from++];
                      if (len > 1) {
                        output[_out++] = output[from++];
                      }
                    }
                  }
                } else if ((op & 64) === 0) {
                  here = dcode[(here & 65535) + (hold & (1 << op) - 1)];
                  continue dodist;
                } else {
                  strm.msg = "invalid distance code";
                  state.mode = BAD$1;
                  break top;
                }
                break;
              }
          } else if ((op & 64) === 0) {
            here = lcode[(here & 65535) + (hold & (1 << op) - 1)];
            continue dolen;
          } else if (op & 32) {
            state.mode = TYPE$1;
            break top;
          } else {
            strm.msg = "invalid literal/length code";
            state.mode = BAD$1;
            break top;
          }
          break;
        }
    } while (_in < last && _out < end);
  len = bits >> 3;
  _in -= len;
  bits -= len << 3;
  hold &= (1 << bits) - 1;
  strm.next_in = _in;
  strm.next_out = _out;
  strm.avail_in = _in < last ? 5 + (last - _in) : 5 - (_in - last);
  strm.avail_out = _out < end ? 257 + (end - _out) : 257 - (_out - end);
  state.hold = hold;
  state.bits = bits;
  return;
};
var MAXBITS = 15;
var ENOUGH_LENS$1 = 852;
var ENOUGH_DISTS$1 = 592;
var CODES$1 = 0;
var LENS$1 = 1;
var DISTS$1 = 2;
var lbase = new Uint16Array([
  /* Length codes 257..285 base */
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  13,
  15,
  17,
  19,
  23,
  27,
  31,
  35,
  43,
  51,
  59,
  67,
  83,
  99,
  115,
  131,
  163,
  195,
  227,
  258,
  0,
  0
]);
var lext = new Uint8Array([
  /* Length codes 257..285 extra */
  16,
  16,
  16,
  16,
  16,
  16,
  16,
  16,
  17,
  17,
  17,
  17,
  18,
  18,
  18,
  18,
  19,
  19,
  19,
  19,
  20,
  20,
  20,
  20,
  21,
  21,
  21,
  21,
  16,
  199,
  75
]);
var dbase = new Uint16Array([
  /* Distance codes 0..29 base */
  1,
  2,
  3,
  4,
  5,
  7,
  9,
  13,
  17,
  25,
  33,
  49,
  65,
  97,
  129,
  193,
  257,
  385,
  513,
  769,
  1025,
  1537,
  2049,
  3073,
  4097,
  6145,
  8193,
  12289,
  16385,
  24577,
  0,
  0
]);
var dext = new Uint8Array([
  /* Distance codes 0..29 extra */
  16,
  16,
  16,
  16,
  17,
  17,
  18,
  18,
  19,
  19,
  20,
  20,
  21,
  21,
  22,
  22,
  23,
  23,
  24,
  24,
  25,
  25,
  26,
  26,
  27,
  27,
  28,
  28,
  29,
  29,
  64,
  64
]);
var inflate_table = (type, lens, lens_index, codes, table, table_index, work, opts) => {
  const bits = opts.bits;
  let len = 0;
  let sym = 0;
  let min = 0, max = 0;
  let root = 0;
  let curr = 0;
  let drop = 0;
  let left = 0;
  let used = 0;
  let huff = 0;
  let incr;
  let fill;
  let low;
  let mask;
  let next;
  let base = null;
  let match;
  const count = new Uint16Array(MAXBITS + 1);
  const offs = new Uint16Array(MAXBITS + 1);
  let extra = null;
  let here_bits, here_op, here_val;
  for (len = 0; len <= MAXBITS; len++) {
    count[len] = 0;
  }
  for (sym = 0; sym < codes; sym++) {
    count[lens[lens_index + sym]]++;
  }
  root = bits;
  for (max = MAXBITS; max >= 1; max--) {
    if (count[max] !== 0) {
      break;
    }
  }
  if (root > max) {
    root = max;
  }
  if (max === 0) {
    table[table_index++] = 1 << 24 | 64 << 16 | 0;
    table[table_index++] = 1 << 24 | 64 << 16 | 0;
    opts.bits = 1;
    return 0;
  }
  for (min = 1; min < max; min++) {
    if (count[min] !== 0) {
      break;
    }
  }
  if (root < min) {
    root = min;
  }
  left = 1;
  for (len = 1; len <= MAXBITS; len++) {
    left <<= 1;
    left -= count[len];
    if (left < 0) {
      return -1;
    }
  }
  if (left > 0 && (type === CODES$1 || max !== 1)) {
    return -1;
  }
  offs[1] = 0;
  for (len = 1; len < MAXBITS; len++) {
    offs[len + 1] = offs[len] + count[len];
  }
  for (sym = 0; sym < codes; sym++) {
    if (lens[lens_index + sym] !== 0) {
      work[offs[lens[lens_index + sym]]++] = sym;
    }
  }
  if (type === CODES$1) {
    base = extra = work;
    match = 20;
  } else if (type === LENS$1) {
    base = lbase;
    extra = lext;
    match = 257;
  } else {
    base = dbase;
    extra = dext;
    match = 0;
  }
  huff = 0;
  sym = 0;
  len = min;
  next = table_index;
  curr = root;
  drop = 0;
  low = -1;
  used = 1 << root;
  mask = used - 1;
  if (type === LENS$1 && used > ENOUGH_LENS$1 || type === DISTS$1 && used > ENOUGH_DISTS$1) {
    return 1;
  }
  for (; ; ) {
    here_bits = len - drop;
    if (work[sym] + 1 < match) {
      here_op = 0;
      here_val = work[sym];
    } else if (work[sym] >= match) {
      here_op = extra[work[sym] - match];
      here_val = base[work[sym] - match];
    } else {
      here_op = 32 + 64;
      here_val = 0;
    }
    incr = 1 << len - drop;
    fill = 1 << curr;
    min = fill;
    do {
      fill -= incr;
      table[next + (huff >> drop) + fill] = here_bits << 24 | here_op << 16 | here_val | 0;
    } while (fill !== 0);
    incr = 1 << len - 1;
    while (huff & incr) {
      incr >>= 1;
    }
    if (incr !== 0) {
      huff &= incr - 1;
      huff += incr;
    } else {
      huff = 0;
    }
    sym++;
    if (--count[len] === 0) {
      if (len === max) {
        break;
      }
      len = lens[lens_index + work[sym]];
    }
    if (len > root && (huff & mask) !== low) {
      if (drop === 0) {
        drop = root;
      }
      next += min;
      curr = len - drop;
      left = 1 << curr;
      while (curr + drop < max) {
        left -= count[curr + drop];
        if (left <= 0) {
          break;
        }
        curr++;
        left <<= 1;
      }
      used += 1 << curr;
      if (type === LENS$1 && used > ENOUGH_LENS$1 || type === DISTS$1 && used > ENOUGH_DISTS$1) {
        return 1;
      }
      low = huff & mask;
      table[low] = root << 24 | curr << 16 | next - table_index | 0;
    }
  }
  if (huff !== 0) {
    table[next + huff] = len - drop << 24 | 64 << 16 | 0;
  }
  opts.bits = root;
  return 0;
};
var inftrees = inflate_table;
var CODES = 0;
var LENS = 1;
var DISTS = 2;
var {
  Z_FINISH: Z_FINISH$1,
  Z_BLOCK,
  Z_TREES,
  Z_OK: Z_OK$1,
  Z_STREAM_END: Z_STREAM_END$1,
  Z_NEED_DICT: Z_NEED_DICT$1,
  Z_STREAM_ERROR: Z_STREAM_ERROR$1,
  Z_DATA_ERROR: Z_DATA_ERROR$1,
  Z_MEM_ERROR: Z_MEM_ERROR$1,
  Z_BUF_ERROR: Z_BUF_ERROR$1,
  Z_DEFLATED
} = constants$2;
var HEAD = 16180;
var FLAGS = 16181;
var TIME = 16182;
var OS = 16183;
var EXLEN = 16184;
var EXTRA = 16185;
var NAME = 16186;
var COMMENT = 16187;
var HCRC = 16188;
var DICTID = 16189;
var DICT = 16190;
var TYPE = 16191;
var TYPEDO = 16192;
var STORED = 16193;
var COPY_ = 16194;
var COPY = 16195;
var TABLE = 16196;
var LENLENS = 16197;
var CODELENS = 16198;
var LEN_ = 16199;
var LEN = 16200;
var LENEXT = 16201;
var DIST = 16202;
var DISTEXT = 16203;
var MATCH = 16204;
var LIT = 16205;
var CHECK = 16206;
var LENGTH = 16207;
var DONE = 16208;
var BAD = 16209;
var MEM = 16210;
var SYNC = 16211;
var ENOUGH_LENS = 852;
var ENOUGH_DISTS = 592;
var MAX_WBITS = 15;
var DEF_WBITS = MAX_WBITS;
var zswap32 = (q) => {
  return (q >>> 24 & 255) + (q >>> 8 & 65280) + ((q & 65280) << 8) + ((q & 255) << 24);
};
function InflateState() {
  this.strm = null;
  this.mode = 0;
  this.last = false;
  this.wrap = 0;
  this.havedict = false;
  this.flags = 0;
  this.dmax = 0;
  this.check = 0;
  this.total = 0;
  this.head = null;
  this.wbits = 0;
  this.wsize = 0;
  this.whave = 0;
  this.wnext = 0;
  this.window = null;
  this.hold = 0;
  this.bits = 0;
  this.length = 0;
  this.offset = 0;
  this.extra = 0;
  this.lencode = null;
  this.distcode = null;
  this.lenbits = 0;
  this.distbits = 0;
  this.ncode = 0;
  this.nlen = 0;
  this.ndist = 0;
  this.have = 0;
  this.next = null;
  this.lens = new Uint16Array(320);
  this.work = new Uint16Array(288);
  this.lendyn = null;
  this.distdyn = null;
  this.sane = 0;
  this.back = 0;
  this.was = 0;
}
var inflateStateCheck = (strm) => {
  if (!strm) {
    return 1;
  }
  const state = strm.state;
  if (!state || state.strm !== strm || state.mode < HEAD || state.mode > SYNC) {
    return 1;
  }
  return 0;
};
var inflateResetKeep = (strm) => {
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  const state = strm.state;
  strm.total_in = strm.total_out = state.total = 0;
  strm.msg = "";
  if (state.wrap) {
    strm.adler = state.wrap & 1;
  }
  state.mode = HEAD;
  state.last = 0;
  state.havedict = 0;
  state.flags = -1;
  state.dmax = 32768;
  state.head = null;
  state.hold = 0;
  state.bits = 0;
  state.lencode = state.lendyn = new Int32Array(ENOUGH_LENS);
  state.distcode = state.distdyn = new Int32Array(ENOUGH_DISTS);
  state.sane = 1;
  state.back = -1;
  return Z_OK$1;
};
var inflateReset = (strm) => {
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  const state = strm.state;
  state.wsize = 0;
  state.whave = 0;
  state.wnext = 0;
  return inflateResetKeep(strm);
};
var inflateReset2 = (strm, windowBits) => {
  let wrap2;
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  const state = strm.state;
  if (windowBits < 0) {
    wrap2 = 0;
    windowBits = -windowBits;
  } else {
    wrap2 = (windowBits >> 4) + 5;
    if (windowBits < 48) {
      windowBits &= 15;
    }
  }
  if (windowBits && (windowBits < 8 || windowBits > 15)) {
    return Z_STREAM_ERROR$1;
  }
  if (state.window !== null && state.wbits !== windowBits) {
    state.window = null;
  }
  state.wrap = wrap2;
  state.wbits = windowBits;
  return inflateReset(strm);
};
var inflateInit2 = (strm, windowBits) => {
  if (!strm) {
    return Z_STREAM_ERROR$1;
  }
  const state = new InflateState();
  strm.state = state;
  state.strm = strm;
  state.window = null;
  state.mode = HEAD;
  const ret = inflateReset2(strm, windowBits);
  if (ret !== Z_OK$1) {
    strm.state = null;
  }
  return ret;
};
var inflateInit = (strm) => {
  return inflateInit2(strm, DEF_WBITS);
};
var virgin = true;
var lenfix;
var distfix;
var fixedtables = (state) => {
  if (virgin) {
    lenfix = new Int32Array(512);
    distfix = new Int32Array(32);
    let sym = 0;
    while (sym < 144) {
      state.lens[sym++] = 8;
    }
    while (sym < 256) {
      state.lens[sym++] = 9;
    }
    while (sym < 280) {
      state.lens[sym++] = 7;
    }
    while (sym < 288) {
      state.lens[sym++] = 8;
    }
    inftrees(LENS, state.lens, 0, 288, lenfix, 0, state.work, { bits: 9 });
    sym = 0;
    while (sym < 32) {
      state.lens[sym++] = 5;
    }
    inftrees(DISTS, state.lens, 0, 32, distfix, 0, state.work, { bits: 5 });
    virgin = false;
  }
  state.lencode = lenfix;
  state.lenbits = 9;
  state.distcode = distfix;
  state.distbits = 5;
};
var updatewindow = (strm, src2, end, copy) => {
  let dist;
  const state = strm.state;
  if (state.window === null) {
    state.window = new Uint8Array(1 << state.wbits);
  }
  if (state.wsize === 0) {
    state.wsize = 1 << state.wbits;
    state.wnext = 0;
    state.whave = 0;
  }
  if (copy >= state.wsize) {
    state.window.set(src2.subarray(end - state.wsize, end), 0);
    state.wnext = 0;
    state.whave = state.wsize;
  } else {
    dist = state.wsize - state.wnext;
    if (dist > copy) {
      dist = copy;
    }
    state.window.set(src2.subarray(end - copy, end - copy + dist), state.wnext);
    copy -= dist;
    if (copy) {
      state.window.set(src2.subarray(end - copy, end), 0);
      state.wnext = copy;
      state.whave = state.wsize;
    } else {
      state.wnext += dist;
      if (state.wnext === state.wsize) {
        state.wnext = 0;
      }
      if (state.whave < state.wsize) {
        state.whave += dist;
      }
    }
  }
  return 0;
};
var inflate$2 = (strm, flush) => {
  let state;
  let input, output;
  let next;
  let put;
  let have, left;
  let hold;
  let bits;
  let _in, _out;
  let copy;
  let from;
  let from_source;
  let here = 0;
  let here_bits, here_op, here_val;
  let last_bits, last_op, last_val;
  let len;
  let ret;
  const hbuf = new Uint8Array(4);
  let opts;
  let n;
  const order = (
    /* permutation of code lengths */
    new Uint8Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15])
  );
  if (inflateStateCheck(strm) || !strm.output || !strm.input && strm.avail_in !== 0) {
    return Z_STREAM_ERROR$1;
  }
  state = strm.state;
  if (state.mode === TYPE) {
    state.mode = TYPEDO;
  }
  put = strm.next_out;
  output = strm.output;
  left = strm.avail_out;
  next = strm.next_in;
  input = strm.input;
  have = strm.avail_in;
  hold = state.hold;
  bits = state.bits;
  _in = have;
  _out = left;
  ret = Z_OK$1;
  inf_leave:
    for (; ; ) {
      switch (state.mode) {
        case HEAD:
          if (state.wrap === 0) {
            state.mode = TYPEDO;
            break;
          }
          while (bits < 16) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if (state.wrap & 2 && hold === 35615) {
            if (state.wbits === 0) {
              state.wbits = 15;
            }
            state.check = 0;
            hbuf[0] = hold & 255;
            hbuf[1] = hold >>> 8 & 255;
            state.check = crc32_1(state.check, hbuf, 2, 0);
            hold = 0;
            bits = 0;
            state.mode = FLAGS;
            break;
          }
          if (state.head) {
            state.head.done = false;
          }
          if (!(state.wrap & 1) || /* check if zlib header allowed */
          (((hold & 255) << 8) + (hold >> 8)) % 31) {
            strm.msg = "incorrect header check";
            state.mode = BAD;
            break;
          }
          if ((hold & 15) !== Z_DEFLATED) {
            strm.msg = "unknown compression method";
            state.mode = BAD;
            break;
          }
          hold >>>= 4;
          bits -= 4;
          len = (hold & 15) + 8;
          if (state.wbits === 0) {
            state.wbits = len;
          }
          if (len > 15 || len > state.wbits) {
            strm.msg = "invalid window size";
            state.mode = BAD;
            break;
          }
          state.dmax = 1 << state.wbits;
          state.flags = 0;
          strm.adler = state.check = 1;
          state.mode = hold & 512 ? DICTID : TYPE;
          hold = 0;
          bits = 0;
          break;
        case FLAGS:
          while (bits < 16) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          state.flags = hold;
          if ((state.flags & 255) !== Z_DEFLATED) {
            strm.msg = "unknown compression method";
            state.mode = BAD;
            break;
          }
          if (state.flags & 57344) {
            strm.msg = "unknown header flags set";
            state.mode = BAD;
            break;
          }
          if (state.head) {
            state.head.text = hold >> 8 & 1;
          }
          if (state.flags & 512 && state.wrap & 4) {
            hbuf[0] = hold & 255;
            hbuf[1] = hold >>> 8 & 255;
            state.check = crc32_1(state.check, hbuf, 2, 0);
          }
          hold = 0;
          bits = 0;
          state.mode = TIME;
        /* falls through */
        case TIME:
          while (bits < 32) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if (state.head) {
            state.head.time = hold;
          }
          if (state.flags & 512 && state.wrap & 4) {
            hbuf[0] = hold & 255;
            hbuf[1] = hold >>> 8 & 255;
            hbuf[2] = hold >>> 16 & 255;
            hbuf[3] = hold >>> 24 & 255;
            state.check = crc32_1(state.check, hbuf, 4, 0);
          }
          hold = 0;
          bits = 0;
          state.mode = OS;
        /* falls through */
        case OS:
          while (bits < 16) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if (state.head) {
            state.head.xflags = hold & 255;
            state.head.os = hold >> 8;
          }
          if (state.flags & 512 && state.wrap & 4) {
            hbuf[0] = hold & 255;
            hbuf[1] = hold >>> 8 & 255;
            state.check = crc32_1(state.check, hbuf, 2, 0);
          }
          hold = 0;
          bits = 0;
          state.mode = EXLEN;
        /* falls through */
        case EXLEN:
          if (state.flags & 1024) {
            while (bits < 16) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            state.length = hold;
            if (state.head) {
              state.head.extra_len = hold;
            }
            if (state.flags & 512 && state.wrap & 4) {
              hbuf[0] = hold & 255;
              hbuf[1] = hold >>> 8 & 255;
              state.check = crc32_1(state.check, hbuf, 2, 0);
            }
            hold = 0;
            bits = 0;
          } else if (state.head) {
            state.head.extra = null;
          }
          state.mode = EXTRA;
        /* falls through */
        case EXTRA:
          if (state.flags & 1024) {
            copy = state.length;
            if (copy > have) {
              copy = have;
            }
            if (copy) {
              if (state.head) {
                len = state.head.extra_len - state.length;
                if (!state.head.extra) {
                  state.head.extra = new Uint8Array(state.head.extra_len);
                }
                state.head.extra.set(
                  input.subarray(
                    next,
                    // extra field is limited to 65536 bytes
                    // - no need for additional size check
                    next + copy
                  ),
                  /*len + copy > state.head.extra_max - len ? state.head.extra_max : copy,*/
                  len
                );
              }
              if (state.flags & 512 && state.wrap & 4) {
                state.check = crc32_1(state.check, input, copy, next);
              }
              have -= copy;
              next += copy;
              state.length -= copy;
            }
            if (state.length) {
              break inf_leave;
            }
          }
          state.length = 0;
          state.mode = NAME;
        /* falls through */
        case NAME:
          if (state.flags & 2048) {
            if (have === 0) {
              break inf_leave;
            }
            copy = 0;
            do {
              len = input[next + copy++];
              if (state.head && len && state.length < 65536) {
                state.head.name += String.fromCharCode(len);
              }
            } while (len && copy < have);
            if (state.flags & 512 && state.wrap & 4) {
              state.check = crc32_1(state.check, input, copy, next);
            }
            have -= copy;
            next += copy;
            if (len) {
              break inf_leave;
            }
          } else if (state.head) {
            state.head.name = null;
          }
          state.length = 0;
          state.mode = COMMENT;
        /* falls through */
        case COMMENT:
          if (state.flags & 4096) {
            if (have === 0) {
              break inf_leave;
            }
            copy = 0;
            do {
              len = input[next + copy++];
              if (state.head && len && state.length < 65536) {
                state.head.comment += String.fromCharCode(len);
              }
            } while (len && copy < have);
            if (state.flags & 512 && state.wrap & 4) {
              state.check = crc32_1(state.check, input, copy, next);
            }
            have -= copy;
            next += copy;
            if (len) {
              break inf_leave;
            }
          } else if (state.head) {
            state.head.comment = null;
          }
          state.mode = HCRC;
        /* falls through */
        case HCRC:
          if (state.flags & 512) {
            while (bits < 16) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            if (state.wrap & 4 && hold !== (state.check & 65535)) {
              strm.msg = "header crc mismatch";
              state.mode = BAD;
              break;
            }
            hold = 0;
            bits = 0;
          }
          if (state.head) {
            state.head.hcrc = state.flags >> 9 & 1;
            state.head.done = true;
          }
          strm.adler = state.check = 0;
          state.mode = TYPE;
          break;
        case DICTID:
          while (bits < 32) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          strm.adler = state.check = zswap32(hold);
          hold = 0;
          bits = 0;
          state.mode = DICT;
        /* falls through */
        case DICT:
          if (state.havedict === 0) {
            strm.next_out = put;
            strm.avail_out = left;
            strm.next_in = next;
            strm.avail_in = have;
            state.hold = hold;
            state.bits = bits;
            return Z_NEED_DICT$1;
          }
          strm.adler = state.check = 1;
          state.mode = TYPE;
        /* falls through */
        case TYPE:
          if (flush === Z_BLOCK || flush === Z_TREES) {
            break inf_leave;
          }
        /* falls through */
        case TYPEDO:
          if (state.last) {
            hold >>>= bits & 7;
            bits -= bits & 7;
            state.mode = CHECK;
            break;
          }
          while (bits < 3) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          state.last = hold & 1;
          hold >>>= 1;
          bits -= 1;
          switch (hold & 3) {
            case 0:
              state.mode = STORED;
              break;
            case 1:
              fixedtables(state);
              state.mode = LEN_;
              if (flush === Z_TREES) {
                hold >>>= 2;
                bits -= 2;
                break inf_leave;
              }
              break;
            case 2:
              state.mode = TABLE;
              break;
            case 3:
              strm.msg = "invalid block type";
              state.mode = BAD;
          }
          hold >>>= 2;
          bits -= 2;
          break;
        case STORED:
          hold >>>= bits & 7;
          bits -= bits & 7;
          while (bits < 32) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if ((hold & 65535) !== (hold >>> 16 ^ 65535)) {
            strm.msg = "invalid stored block lengths";
            state.mode = BAD;
            break;
          }
          state.length = hold & 65535;
          hold = 0;
          bits = 0;
          state.mode = COPY_;
          if (flush === Z_TREES) {
            break inf_leave;
          }
        /* falls through */
        case COPY_:
          state.mode = COPY;
        /* falls through */
        case COPY:
          copy = state.length;
          if (copy) {
            if (copy > have) {
              copy = have;
            }
            if (copy > left) {
              copy = left;
            }
            if (copy === 0) {
              break inf_leave;
            }
            output.set(input.subarray(next, next + copy), put);
            have -= copy;
            next += copy;
            left -= copy;
            put += copy;
            state.length -= copy;
            break;
          }
          state.mode = TYPE;
          break;
        case TABLE:
          while (bits < 14) {
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          state.nlen = (hold & 31) + 257;
          hold >>>= 5;
          bits -= 5;
          state.ndist = (hold & 31) + 1;
          hold >>>= 5;
          bits -= 5;
          state.ncode = (hold & 15) + 4;
          hold >>>= 4;
          bits -= 4;
          if (state.nlen > 286 || state.ndist > 30) {
            strm.msg = "too many length or distance symbols";
            state.mode = BAD;
            break;
          }
          state.have = 0;
          state.mode = LENLENS;
        /* falls through */
        case LENLENS:
          while (state.have < state.ncode) {
            while (bits < 3) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            state.lens[order[state.have++]] = hold & 7;
            hold >>>= 3;
            bits -= 3;
          }
          while (state.have < 19) {
            state.lens[order[state.have++]] = 0;
          }
          state.lencode = state.lendyn;
          state.lenbits = 7;
          opts = { bits: state.lenbits };
          ret = inftrees(CODES, state.lens, 0, 19, state.lencode, 0, state.work, opts);
          state.lenbits = opts.bits;
          if (ret) {
            strm.msg = "invalid code lengths set";
            state.mode = BAD;
            break;
          }
          state.have = 0;
          state.mode = CODELENS;
        /* falls through */
        case CODELENS:
          while (state.have < state.nlen + state.ndist) {
            for (; ; ) {
              here = state.lencode[hold & (1 << state.lenbits) - 1];
              here_bits = here >>> 24;
              here_op = here >>> 16 & 255;
              here_val = here & 65535;
              if (here_bits <= bits) {
                break;
              }
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            if (here_val < 16) {
              hold >>>= here_bits;
              bits -= here_bits;
              state.lens[state.have++] = here_val;
            } else {
              if (here_val === 16) {
                n = here_bits + 2;
                while (bits < n) {
                  if (have === 0) {
                    break inf_leave;
                  }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                hold >>>= here_bits;
                bits -= here_bits;
                if (state.have === 0) {
                  strm.msg = "invalid bit length repeat";
                  state.mode = BAD;
                  break;
                }
                len = state.lens[state.have - 1];
                copy = 3 + (hold & 3);
                hold >>>= 2;
                bits -= 2;
              } else if (here_val === 17) {
                n = here_bits + 3;
                while (bits < n) {
                  if (have === 0) {
                    break inf_leave;
                  }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                hold >>>= here_bits;
                bits -= here_bits;
                len = 0;
                copy = 3 + (hold & 7);
                hold >>>= 3;
                bits -= 3;
              } else {
                n = here_bits + 7;
                while (bits < n) {
                  if (have === 0) {
                    break inf_leave;
                  }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                hold >>>= here_bits;
                bits -= here_bits;
                len = 0;
                copy = 11 + (hold & 127);
                hold >>>= 7;
                bits -= 7;
              }
              if (state.have + copy > state.nlen + state.ndist) {
                strm.msg = "invalid bit length repeat";
                state.mode = BAD;
                break;
              }
              while (copy--) {
                state.lens[state.have++] = len;
              }
            }
          }
          if (state.mode === BAD) {
            break;
          }
          if (state.lens[256] === 0) {
            strm.msg = "invalid code -- missing end-of-block";
            state.mode = BAD;
            break;
          }
          state.lenbits = 9;
          opts = { bits: state.lenbits };
          ret = inftrees(LENS, state.lens, 0, state.nlen, state.lencode, 0, state.work, opts);
          state.lenbits = opts.bits;
          if (ret) {
            strm.msg = "invalid literal/lengths set";
            state.mode = BAD;
            break;
          }
          state.distbits = 6;
          state.distcode = state.distdyn;
          opts = { bits: state.distbits };
          ret = inftrees(DISTS, state.lens, state.nlen, state.ndist, state.distcode, 0, state.work, opts);
          state.distbits = opts.bits;
          if (ret) {
            strm.msg = "invalid distances set";
            state.mode = BAD;
            break;
          }
          state.mode = LEN_;
          if (flush === Z_TREES) {
            break inf_leave;
          }
        /* falls through */
        case LEN_:
          state.mode = LEN;
        /* falls through */
        case LEN:
          if (have >= 6 && left >= 258) {
            strm.next_out = put;
            strm.avail_out = left;
            strm.next_in = next;
            strm.avail_in = have;
            state.hold = hold;
            state.bits = bits;
            inffast(strm, _out);
            put = strm.next_out;
            output = strm.output;
            left = strm.avail_out;
            next = strm.next_in;
            input = strm.input;
            have = strm.avail_in;
            hold = state.hold;
            bits = state.bits;
            if (state.mode === TYPE) {
              state.back = -1;
            }
            break;
          }
          state.back = 0;
          for (; ; ) {
            here = state.lencode[hold & (1 << state.lenbits) - 1];
            here_bits = here >>> 24;
            here_op = here >>> 16 & 255;
            here_val = here & 65535;
            if (here_bits <= bits) {
              break;
            }
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if (here_op && (here_op & 240) === 0) {
            last_bits = here_bits;
            last_op = here_op;
            last_val = here_val;
            for (; ; ) {
              here = state.lencode[last_val + ((hold & (1 << last_bits + last_op) - 1) >> last_bits)];
              here_bits = here >>> 24;
              here_op = here >>> 16 & 255;
              here_val = here & 65535;
              if (last_bits + here_bits <= bits) {
                break;
              }
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            hold >>>= last_bits;
            bits -= last_bits;
            state.back += last_bits;
          }
          hold >>>= here_bits;
          bits -= here_bits;
          state.back += here_bits;
          state.length = here_val;
          if (here_op === 0) {
            state.mode = LIT;
            break;
          }
          if (here_op & 32) {
            state.back = -1;
            state.mode = TYPE;
            break;
          }
          if (here_op & 64) {
            strm.msg = "invalid literal/length code";
            state.mode = BAD;
            break;
          }
          state.extra = here_op & 15;
          state.mode = LENEXT;
        /* falls through */
        case LENEXT:
          if (state.extra) {
            n = state.extra;
            while (bits < n) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            state.length += hold & (1 << state.extra) - 1;
            hold >>>= state.extra;
            bits -= state.extra;
            state.back += state.extra;
          }
          state.was = state.length;
          state.mode = DIST;
        /* falls through */
        case DIST:
          for (; ; ) {
            here = state.distcode[hold & (1 << state.distbits) - 1];
            here_bits = here >>> 24;
            here_op = here >>> 16 & 255;
            here_val = here & 65535;
            if (here_bits <= bits) {
              break;
            }
            if (have === 0) {
              break inf_leave;
            }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          if ((here_op & 240) === 0) {
            last_bits = here_bits;
            last_op = here_op;
            last_val = here_val;
            for (; ; ) {
              here = state.distcode[last_val + ((hold & (1 << last_bits + last_op) - 1) >> last_bits)];
              here_bits = here >>> 24;
              here_op = here >>> 16 & 255;
              here_val = here & 65535;
              if (last_bits + here_bits <= bits) {
                break;
              }
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            hold >>>= last_bits;
            bits -= last_bits;
            state.back += last_bits;
          }
          hold >>>= here_bits;
          bits -= here_bits;
          state.back += here_bits;
          if (here_op & 64) {
            strm.msg = "invalid distance code";
            state.mode = BAD;
            break;
          }
          state.offset = here_val;
          state.extra = here_op & 15;
          state.mode = DISTEXT;
        /* falls through */
        case DISTEXT:
          if (state.extra) {
            n = state.extra;
            while (bits < n) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            state.offset += hold & (1 << state.extra) - 1;
            hold >>>= state.extra;
            bits -= state.extra;
            state.back += state.extra;
          }
          if (state.offset > state.dmax) {
            strm.msg = "invalid distance too far back";
            state.mode = BAD;
            break;
          }
          state.mode = MATCH;
        /* falls through */
        case MATCH:
          if (left === 0) {
            break inf_leave;
          }
          copy = _out - left;
          if (state.offset > copy) {
            copy = state.offset - copy;
            if (copy > state.whave) {
              if (state.sane) {
                strm.msg = "invalid distance too far back";
                state.mode = BAD;
                break;
              }
            }
            if (copy > state.wnext) {
              copy -= state.wnext;
              from = state.wsize - copy;
            } else {
              from = state.wnext - copy;
            }
            if (copy > state.length) {
              copy = state.length;
            }
            from_source = state.window;
          } else {
            from_source = output;
            from = put - state.offset;
            copy = state.length;
          }
          if (copy > left) {
            copy = left;
          }
          left -= copy;
          state.length -= copy;
          do {
            output[put++] = from_source[from++];
          } while (--copy);
          if (state.length === 0) {
            state.mode = LEN;
          }
          break;
        case LIT:
          if (left === 0) {
            break inf_leave;
          }
          output[put++] = state.length;
          left--;
          state.mode = LEN;
          break;
        case CHECK:
          if (state.wrap) {
            while (bits < 32) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold |= input[next++] << bits;
              bits += 8;
            }
            _out -= left;
            strm.total_out += _out;
            state.total += _out;
            if (state.wrap & 4 && _out) {
              strm.adler = state.check = /*UPDATE_CHECK(state.check, put - _out, _out);*/
              state.flags ? crc32_1(state.check, output, _out, put - _out) : adler32_1(state.check, output, _out, put - _out);
            }
            _out = left;
            if (state.wrap & 4 && (state.flags ? hold : zswap32(hold)) !== state.check) {
              strm.msg = "incorrect data check";
              state.mode = BAD;
              break;
            }
            hold = 0;
            bits = 0;
          }
          state.mode = LENGTH;
        /* falls through */
        case LENGTH:
          if (state.wrap && state.flags) {
            while (bits < 32) {
              if (have === 0) {
                break inf_leave;
              }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            if (state.wrap & 4 && hold !== (state.total & 4294967295)) {
              strm.msg = "incorrect length check";
              state.mode = BAD;
              break;
            }
            hold = 0;
            bits = 0;
          }
          state.mode = DONE;
        /* falls through */
        case DONE:
          ret = Z_STREAM_END$1;
          break inf_leave;
        case BAD:
          ret = Z_DATA_ERROR$1;
          break inf_leave;
        case MEM:
          return Z_MEM_ERROR$1;
        case SYNC:
        /* falls through */
        default:
          return Z_STREAM_ERROR$1;
      }
    }
  strm.next_out = put;
  strm.avail_out = left;
  strm.next_in = next;
  strm.avail_in = have;
  state.hold = hold;
  state.bits = bits;
  if (state.wsize || _out !== strm.avail_out && state.mode < BAD && (state.mode < CHECK || flush !== Z_FINISH$1)) {
    if (updatewindow(strm, strm.output, strm.next_out, _out - strm.avail_out)) ;
  }
  _in -= strm.avail_in;
  _out -= strm.avail_out;
  strm.total_in += _in;
  strm.total_out += _out;
  state.total += _out;
  if (state.wrap & 4 && _out) {
    strm.adler = state.check = /*UPDATE_CHECK(state.check, strm.next_out - _out, _out);*/
    state.flags ? crc32_1(state.check, output, _out, strm.next_out - _out) : adler32_1(state.check, output, _out, strm.next_out - _out);
  }
  strm.data_type = state.bits + (state.last ? 64 : 0) + (state.mode === TYPE ? 128 : 0) + (state.mode === LEN_ || state.mode === COPY_ ? 256 : 0);
  if ((_in === 0 && _out === 0 || flush === Z_FINISH$1) && ret === Z_OK$1) {
    ret = Z_BUF_ERROR$1;
  }
  return ret;
};
var inflateEnd = (strm) => {
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  let state = strm.state;
  if (state.window) {
    state.window = null;
  }
  strm.state = null;
  return Z_OK$1;
};
var inflateGetHeader = (strm, head) => {
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  const state = strm.state;
  if ((state.wrap & 2) === 0) {
    return Z_STREAM_ERROR$1;
  }
  state.head = head;
  head.done = false;
  return Z_OK$1;
};
var inflateSetDictionary = (strm, dictionary) => {
  const dictLength = dictionary.length;
  let state;
  let dictid;
  let ret;
  if (inflateStateCheck(strm)) {
    return Z_STREAM_ERROR$1;
  }
  state = strm.state;
  if (state.wrap !== 0 && state.mode !== DICT) {
    return Z_STREAM_ERROR$1;
  }
  if (state.mode === DICT) {
    dictid = 1;
    dictid = adler32_1(dictid, dictionary, dictLength, 0);
    if (dictid !== state.check) {
      return Z_DATA_ERROR$1;
    }
  }
  ret = updatewindow(strm, dictionary, dictLength, dictLength);
  if (ret) {
    state.mode = MEM;
    return Z_MEM_ERROR$1;
  }
  state.havedict = 1;
  return Z_OK$1;
};
var inflateReset_1 = inflateReset;
var inflateReset2_1 = inflateReset2;
var inflateResetKeep_1 = inflateResetKeep;
var inflateInit_1 = inflateInit;
var inflateInit2_1 = inflateInit2;
var inflate_2$1 = inflate$2;
var inflateEnd_1 = inflateEnd;
var inflateGetHeader_1 = inflateGetHeader;
var inflateSetDictionary_1 = inflateSetDictionary;
var inflateInfo = "pako inflate (from Nodeca project)";
var inflate_1$2 = {
  inflateReset: inflateReset_1,
  inflateReset2: inflateReset2_1,
  inflateResetKeep: inflateResetKeep_1,
  inflateInit: inflateInit_1,
  inflateInit2: inflateInit2_1,
  inflate: inflate_2$1,
  inflateEnd: inflateEnd_1,
  inflateGetHeader: inflateGetHeader_1,
  inflateSetDictionary: inflateSetDictionary_1,
  inflateInfo
};
function GZheader() {
  this.text = 0;
  this.time = 0;
  this.xflags = 0;
  this.os = 0;
  this.extra = null;
  this.extra_len = 0;
  this.name = "";
  this.comment = "";
  this.hcrc = 0;
  this.done = false;
}
var gzheader = GZheader;
var toString = Object.prototype.toString;
var {
  Z_NO_FLUSH,
  Z_FINISH,
  Z_OK,
  Z_STREAM_END,
  Z_NEED_DICT,
  Z_STREAM_ERROR,
  Z_DATA_ERROR,
  Z_MEM_ERROR,
  Z_BUF_ERROR
} = constants$2;
var defaultOptions2 = {
  chunkSize: 1024 * 64,
  windowBits: 15,
  to: ""
};
function Inflate$1(options) {
  this.options = common.assign({}, defaultOptions2, options || {});
  const opt = this.options;
  if (opt.raw && opt.windowBits >= 0 && opt.windowBits < 16) {
    opt.windowBits = -opt.windowBits;
    if (opt.windowBits === 0) {
      opt.windowBits = -15;
    }
  }
  if (opt.windowBits >= 0 && opt.windowBits < 16 && !(options && options.windowBits)) {
    opt.windowBits += 32;
  }
  if (opt.windowBits > 15 && opt.windowBits < 48) {
    if ((opt.windowBits & 15) === 0) {
      opt.windowBits |= 15;
    }
  }
  this.err = 0;
  this.msg = "";
  this.ended = false;
  this.chunks = [];
  this.strm = new zstream();
  this.strm.avail_out = 0;
  let status = inflate_1$2.inflateInit2(
    this.strm,
    opt.windowBits
  );
  if (status !== Z_OK) {
    throw new Error(messages[status]);
  }
  this.header = new gzheader();
  inflate_1$2.inflateGetHeader(this.strm, this.header);
  if (opt.dictionary) {
    if (typeof opt.dictionary === "string") {
      opt.dictionary = strings2.string2buf(opt.dictionary);
    } else if (toString.call(opt.dictionary) === "[object ArrayBuffer]") {
      opt.dictionary = new Uint8Array(opt.dictionary);
    }
    if (opt.raw) {
      status = inflate_1$2.inflateSetDictionary(this.strm, opt.dictionary);
      if (status !== Z_OK) {
        throw new Error(messages[status]);
      }
    }
  }
}
Inflate$1.prototype.push = function(data, flush_mode) {
  const strm = this.strm;
  const chunkSize = this.options.chunkSize;
  const dictionary = this.options.dictionary;
  let status, _flush_mode, last_avail_out;
  if (this.ended) return false;
  if (flush_mode === ~~flush_mode) _flush_mode = flush_mode;
  else _flush_mode = flush_mode === true ? Z_FINISH : Z_NO_FLUSH;
  if (toString.call(data) === "[object ArrayBuffer]") {
    strm.input = new Uint8Array(data);
  } else {
    strm.input = data;
  }
  strm.next_in = 0;
  strm.avail_in = strm.input.length;
  for (; ; ) {
    if (strm.avail_out === 0) {
      strm.output = new Uint8Array(chunkSize);
      strm.next_out = 0;
      strm.avail_out = chunkSize;
    }
    status = inflate_1$2.inflate(strm, _flush_mode);
    if (status === Z_NEED_DICT && dictionary) {
      status = inflate_1$2.inflateSetDictionary(strm, dictionary);
      if (status === Z_OK) {
        status = inflate_1$2.inflate(strm, _flush_mode);
      } else if (status === Z_DATA_ERROR) {
        status = Z_NEED_DICT;
      }
    }
    while (strm.avail_in > 0 && status === Z_STREAM_END && strm.state.wrap & 2 && strm.state.flags !== 0 && strm.input[strm.next_in] !== 0) {
      inflate_1$2.inflateReset(strm);
      status = inflate_1$2.inflate(strm, _flush_mode);
    }
    switch (status) {
      case Z_STREAM_ERROR:
      case Z_DATA_ERROR:
      case Z_NEED_DICT:
      case Z_MEM_ERROR:
        this.onEnd(status);
        this.ended = true;
        return false;
    }
    last_avail_out = strm.avail_out;
    if (strm.next_out) {
      if (strm.avail_out === 0 || status === Z_STREAM_END || _flush_mode > 0) {
        if (this.options.to === "string") {
          let next_out_utf8 = strings2.utf8border(strm.output, strm.next_out);
          let tail = strm.next_out - next_out_utf8;
          let utf8str = strings2.buf2string(strm.output, next_out_utf8);
          strm.next_out = tail;
          strm.avail_out = chunkSize - tail;
          if (tail) strm.output.set(strm.output.subarray(next_out_utf8, next_out_utf8 + tail), 0);
          this.onData(utf8str);
        } else {
          this.onData(strm.output.length === strm.next_out ? strm.output : strm.output.subarray(0, strm.next_out));
          strm.avail_out = 0;
          strm.next_out = 0;
        }
      }
    }
    if ((status === Z_OK || status === Z_BUF_ERROR) && last_avail_out === 0) continue;
    if (status === Z_STREAM_END) {
      status = inflate_1$2.inflateEnd(this.strm);
      this.onEnd(status);
      this.ended = true;
      return true;
    }
    if (strm.avail_in === 0) {
      if (_flush_mode === Z_FINISH) {
        status = inflate_1$2.inflateEnd(this.strm);
        this.onEnd(status === Z_OK ? Z_BUF_ERROR : status);
        this.ended = true;
        return false;
      }
      break;
    }
  }
  return true;
};
Inflate$1.prototype.onData = function(chunk) {
  this.chunks.push(chunk);
};
Inflate$1.prototype.onEnd = function(status) {
  if (status === Z_OK) {
    if (this.options.to === "string") {
      this.result = this.chunks.join("");
    } else {
      this.result = common.flattenChunks(this.chunks);
    }
  }
  this.chunks = [];
  this.err = status;
  this.msg = this.strm.msg;
};
function inflate$1(input, options) {
  const inflator = new Inflate$1(options);
  inflator.push(input, true);
  if (inflator.err) throw inflator.msg || messages[inflator.err];
  return inflator.result;
}
function inflateRaw$1(input, options) {
  options = options || {};
  options.raw = true;
  return inflate$1(input, options);
}
var Inflate_1$1 = Inflate$1;
var inflate_2 = inflate$1;
var inflateRaw_1$1 = inflateRaw$1;
var ungzip$1 = inflate$1;
var constants = constants$2;
var inflate_1$1 = {
  Inflate: Inflate_1$1,
  inflate: inflate_2,
  inflateRaw: inflateRaw_1$1,
  ungzip: ungzip$1,
  constants
};
var { Deflate, deflate, deflateRaw, gzip } = deflate_1$1;
var { Inflate, inflate, inflateRaw, ungzip } = inflate_1$1;

// node_modules/@aztec/bb.js/dest/browser/barretenberg/backend.js
function getProofSettingsFromOptions(options) {
  if (options?.verifierTarget) {
    const legacyOptions = [options.keccak, options.keccakZK, options.starknet, options.starknetZK].filter(Boolean);
    if (legacyOptions.length > 0) {
      throw new Error("Cannot use verifierTarget with legacy options (keccak, keccakZK, starknet, starknetZK). Use verifierTarget alone.");
    }
    switch (options.verifierTarget) {
      case "evm":
        return { ipaAccumulation: false, oracleHashType: "keccak", disableZk: false, optimizedSolidityVerifier: false };
      case "evm-no-zk":
        return { ipaAccumulation: false, oracleHashType: "keccak", disableZk: true, optimizedSolidityVerifier: false };
      case "noir-recursive":
        return {
          ipaAccumulation: false,
          oracleHashType: "poseidon2",
          disableZk: false,
          optimizedSolidityVerifier: false
        };
      case "noir-recursive-no-zk":
        return {
          ipaAccumulation: false,
          oracleHashType: "poseidon2",
          disableZk: true,
          optimizedSolidityVerifier: false
        };
      case "noir-rollup":
        return {
          ipaAccumulation: true,
          oracleHashType: "poseidon2",
          disableZk: false,
          optimizedSolidityVerifier: false
        };
      case "noir-rollup-no-zk":
        return {
          ipaAccumulation: true,
          oracleHashType: "poseidon2",
          disableZk: true,
          optimizedSolidityVerifier: false
        };
      case "starknet":
        return {
          ipaAccumulation: false,
          oracleHashType: "starknet",
          disableZk: false,
          optimizedSolidityVerifier: false
        };
      case "starknet-no-zk":
        return {
          ipaAccumulation: false,
          oracleHashType: "starknet",
          disableZk: true,
          optimizedSolidityVerifier: false
        };
    }
  }
  return {
    ipaAccumulation: false,
    oracleHashType: options?.keccak || options?.keccakZK ? "keccak" : options?.starknet || options?.starknetZK ? "starknet" : "poseidon2",
    disableZk: options?.keccak || options?.starknet ? true : false,
    optimizedSolidityVerifier: false
  };
}
var UltraHonkVerifierBackend = class {
  api;
  constructor(api) {
    this.api = api;
  }
  async verifyProof(proofData, options) {
    const proofFrs = [];
    for (let i = 0; i < proofData.proof.length; i += 32) {
      proofFrs.push(proofData.proof.slice(i, i + 32));
    }
    const { verified } = await this.api.circuitVerify({
      verificationKey: proofData.verificationKey,
      publicInputs: proofData.publicInputs.map(hexToUint8Array),
      proof: proofFrs,
      settings: getProofSettingsFromOptions(options)
    });
    return verified;
  }
};

// node_modules/@aztec/bb.js/dest/browser/barretenberg/index.js
var DEFAULT_BB_CRS_SIZE = 2 ** 19;
var IOS_BB_CRS_SIZE = 2 ** 18;
var Barretenberg = class _Barretenberg extends AsyncApi {
  options;
  constructor(backend, options) {
    super(backend);
    this.options = options;
  }
  /**
   * Constructs an instance of Barretenberg.
   *
   * If options.backend is set: uses that specific backend (throws if unavailable)
   * If options.backend is unset: tries backends in order with fallback:
   *   1. NativeUnixSocket (if bb binary available)
   *   2. WasmWorker (in browser) or Wasm (in Node.js)
   */
  static async new(options = {}) {
    const logger = options.logger ?? (() => {
    });
    if (options.backend) {
      const backend = await createAsyncBackend(options.backend, options, logger);
      await configureMsmBackend(backend, options);
      if (!options.skipSrsInit && (options.backend === BackendType.Wasm || options.backend === BackendType.WasmWorker)) {
        await backend.initSRSChonk(options.srsSize);
      }
      return backend;
    }
    if (typeof window === "undefined") {
      try {
        const backend = await createAsyncBackend(BackendType.NativeUnixSocket, options, logger);
        await configureMsmBackend(backend, options);
        return backend;
      } catch (err2) {
        logger(`Unix socket unavailable (${err2.message}), falling back to WASM`);
        const backend = await createAsyncBackend(BackendType.Wasm, options, logger);
        await configureMsmBackend(backend, options);
        if (!options.skipSrsInit) {
          await backend.initSRSChonk(options.srsSize);
        }
        return backend;
      }
    } else {
      logger(`In browser, using WASM over worker backend.`);
      const backend = await createAsyncBackend(BackendType.WasmWorker, options, logger);
      await configureMsmBackend(backend, options);
      if (!options.skipSrsInit) {
        await backend.initSRSChonk(options.srsSize);
      }
      return backend;
    }
  }
  async initSRSChonk(srsSize = this.getDefaultSrsSize()) {
    const crs = await CachedNetCrs.new(srsSize, this.options.crsPath, this.options.logger);
    const grumpkinCrs = await CachedNetGrumpkinCrs.new(2 ** 16, this.options.crsPath, this.options.logger);
    const response = await this.srsInitSrs({
      pointsBuf: crs.getG1Data(),
      numPoints: crs.numPoints,
      g2Point: crs.getG2Data()
    });
    if (response.pointsBuf.length > 0) {
      await crs.cacheUncompressed(response.pointsBuf);
    }
    await this.srsInitGrumpkinSrs({ pointsBuf: grumpkinCrs.getG1Data(), numPoints: grumpkinCrs.numPoints });
  }
  getDefaultSrsSize() {
    if (typeof self !== "undefined" && typeof self.navigator !== "undefined" && /iPad|iPhone/.test(self.navigator.userAgent)) {
      return IOS_BB_CRS_SIZE;
    }
    return DEFAULT_BB_CRS_SIZE;
  }
  async acirGetCircuitSizes(bytecode, recursive, honkRecursion) {
    const response = await this.circuitStats({
      circuit: { name: "", bytecode, verificationKey: new Uint8Array() },
      includeGatesPerOpcode: false,
      settings: {
        ipaAccumulation: false,
        oracleHashType: honkRecursion ? "poseidon2" : "keccak",
        disableZk: !recursive,
        optimizedSolidityVerifier: false
      }
    });
    return [response.numGates, response.numGatesDyadic];
  }
  async destroy() {
    return super.destroy();
  }
  /**
   * Initialize the singleton instance of Barretenberg.
   * @param options Backend configuration options
   */
  static async initSingleton(options = {}) {
    if (!barretenbergSingletonPromise) {
      barretenbergSingletonPromise = _Barretenberg.new({ ...options, unref: true });
    }
    try {
      barretenbergSingleton = await barretenbergSingletonPromise;
      return barretenbergSingleton;
    } catch (error) {
      barretenbergSingleton = void 0;
      barretenbergSingletonPromise = void 0;
      throw error;
    }
  }
  static async destroySingleton() {
    if (barretenbergSingleton) {
      await barretenbergSingleton.destroy();
      barretenbergSingleton = void 0;
      barretenbergSingletonPromise = void 0;
    }
  }
  /**
   * Get the singleton instance of Barretenberg.
   * Must call initSingleton() first.
   */
  static getSingleton() {
    if (!barretenbergSingleton) {
      throw new Error("First call Barretenberg.initSingleton() on @aztec/bb.js module.");
    }
    return barretenbergSingleton;
  }
};
var barretenbergSingletonPromise;
var barretenbergSingleton;
async function configureMsmBackend(backend, options) {
  if (options.legacyMsm !== void 0) {
    await backend.setMsmLegacy({ enabled: options.legacyMsm });
  }
}

// node_modules/@aztec/bb.js/dest/browser/cbind/generated/curve_constants.js
var BN254_G1_GENERATOR = {
  x: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
  y: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
};
var BN254_G2_GENERATOR = {
  x: [new Uint8Array([24, 0, 222, 239, 18, 31, 30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92, 217, 146, 246, 237]), new Uint8Array([25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194])],
  y: [new Uint8Array([18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227, 209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170]), new Uint8Array([9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149, 188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91])]
};
var GRUMPKIN_G1_GENERATOR = {
  x: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
  y: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 2, 207, 19, 94, 117, 6, 164, 93, 99, 45, 39, 13, 69, 241, 24, 18, 148, 131, 63, 196, 141, 130, 63, 39, 44])
};
var SECP256K1_G1_GENERATOR = {
  x: new Uint8Array([121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152]),
  y: new Uint8Array([72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184])
};
var SECP256R1_G1_GENERATOR = {
  x: new Uint8Array([107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129, 45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150]),
  y: new Uint8Array([79, 227, 66, 226, 254, 26, 127, 155, 142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55, 191, 81, 245])
};

// wasm.mjs
async function createWasmVerifier(g2Point, wasmPath) {
  await checkAsset("g2.dat", g2Point);
  const api = await Barretenberg.new({
    backend: BackendType.Wasm,
    threads: 1,
    skipSrsInit: true,
    ...wasmPath === void 0 ? {} : { wasmPath },
    memory: { initial: 37, maximum: 2048 }
    // 128 MiB ceiling; verifier only.
  });
  try {
    const generator = new Uint8Array(64);
    generator[31] = 1;
    generator[63] = 2;
    await api.srsInitSrs({ pointsBuf: generator, numPoints: 1, g2Point });
  } catch (error) {
    await api.destroy();
    throw error;
  }
  const verifier = new UltraHonkVerifierBackend(api);
  return {
    verify: (proof, inputs, verificationKey) => verifier.verifyProof({
      proof,
      verificationKey,
      publicInputs: Array.from({ length: inputs.length / 32 }, (_, i) => "0x" + hex(inputs.subarray(i * 32, i * 32 + 32)))
    }, { verifierTarget: "noir-recursive" }),
    api,
    destroy: () => api.destroy()
  };
}

// inline.mjs
async function verifyCompactInline(source, options) {
  if (typeof WorkerGlobalScope === "undefined" || !(self instanceof WorkerGlobalScope)) throw new Error("A dedicated verification worker is required.");
  const [verificationKey, journalABI, g2] = await Promise.all(["cast256.vk", "journal-abi.json", "g2.dat"].map(loadAsset));
  const backend = await createWasmVerifier(g2);
  try {
    const verify = await createCompactVerifier({ verificationKey, journalABI, verifyZk: backend.verify });
    return await verify(source, options);
  } finally {
    await backend.destroy();
  }
}
export {
  verifyCompactInline
};
/*! Bundled license information:

comlink/dist/esm/comlink.mjs:
  (**
   * @license
   * Copyright 2019 Google LLC
   * SPDX-License-Identifier: Apache-2.0
   *)

pako/dist/pako.esm.mjs:
  (*! pako 2.2.0 https://github.com/nodeca/pako @license (MIT AND Zlib) *)
*/
