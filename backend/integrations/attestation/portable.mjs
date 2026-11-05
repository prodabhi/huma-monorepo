import { base64 } from './service.mjs';
import { digest, verifyArchivedAttestation, verifyAssertion } from './apple.mjs';
import { portableVerifier } from './portable-core.mjs';
export { readerPolicy } from './portable-core.mjs';
const verifier = portableVerifier({ base64, digest: bytes => digest(Buffer.from(bytes)),
    verifyArchivedAttestation, verifyAssertion });
export const { verifyReplayDeviceBinding, verifyPortableDeviceEvidence } = verifier;
