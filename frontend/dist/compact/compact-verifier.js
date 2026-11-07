// profile.mjs
var MAX_EXPORT_BYTES = 512 * 1024;
var ASSETS = Object.freeze({
  "cast256.vk": { bytes: 3680, sha256: "149d13f114a80bc03df8966aa5b716ba86acc383c48c620e0bdb1afb09f4b600" },
  "journal-abi.json": { bytes: 2611, sha256: "d3ac50086728791ab41503666e4f5454b9bfe30000abf2ddfefd624a7c21c952" },
  "g2.dat": { bytes: 128, sha256: "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f" },
  "barretenberg.wasm": { bytes: 10571126, sha256: "662ed50ca7275398817ae780733a9fc1ad1681776c75615cb81ecd737bca17e6" },
  "barretenberg-threads.wasm": { bytes: 10475904, sha256: "454527654830b95af0c75d639194587119f4f25e20739254c2eb7bc7c5fec5a9" }
});

// client.mjs
var active = false;
function verifyCompactProof(source, options = {}, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (active) return reject(new Error("A local proof check is already running."));
    if (typeof source !== "string" || source.length > MAX_EXPORT_BYTES) return reject(new Error("Public proof exceeds 512 KiB."));
    if (signal?.aborted) return reject(new DOMException("Verification cancelled.", "AbortError"));
    const worker = new Worker(new URL("./compact-worker.js", import.meta.url), { type: "module" });
    active = true;
    let done = false;
    const finish = (error, result) => {
      if (done) return;
      done = true;
      active = false;
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancel);
      worker.terminate();
      if (error) reject(error);
      else resolve(result);
    };
    const cancel = () => finish(new DOMException("Verification cancelled.", "AbortError"));
    const timer = setTimeout(() => finish(new Error("Verification exceeded its 20-second limit.")), 2e4);
    signal?.addEventListener("abort", cancel, { once: true });
    worker.onmessage = ({ data }) => {
      if (data?.error) finish(new Error(data.error));
      else if (data?.result?.verified === true) finish(null, data.result);
      else finish(new Error("Invalid verifier response."));
    };
    worker.onerror = () => finish(new Error("Local verifier stopped before completion."));
    worker.onmessageerror = () => finish(new Error("Invalid verifier response."));
    try {
      worker.postMessage({ source, options });
    } catch (error) {
      finish(error);
    }
  });
}
export {
  verifyCompactProof
};
