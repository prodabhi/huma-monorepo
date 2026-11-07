import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { checkAsset, hex } from './profile.mjs';

export async function createWasmVerifier(g2Point, wasmPath) {
  await checkAsset('g2.dat', g2Point);
  const api = await Barretenberg.new({
    backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    ...(wasmPath === undefined ? {} : { wasmPath }),
    memory: { initial: 37, maximum: 2048 }, // 128 MiB ceiling; verifier only.
  });
  try {
    // The API requires one G1 point even though verification only uses G2.
    // BN254's public generator is (1,2); no proving SRS is downloaded.
    const generator = new Uint8Array(64); generator[31] = 1; generator[63] = 2;
    await api.srsInitSrs({ pointsBuf: generator, numPoints: 1, g2Point });
  } catch (error) { await api.destroy(); throw error; }
  const verifier = new UltraHonkVerifierBackend(api);
  return {
    verify: (proof, inputs, verificationKey) => verifier.verifyProof({
      proof, verificationKey,
      publicInputs: Array.from({ length: inputs.length / 32 }, (_, i) => '0x' + hex(inputs.subarray(i * 32, i * 32 + 32))),
    }, { verifierTarget: 'noir-recursive' }),
    api,
    destroy: () => api.destroy(),
  };
}
