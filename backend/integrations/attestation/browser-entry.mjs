import { appleWebVerifier, base64, digest } from './apple-web.mjs';
import { portableVerifier, readerPolicy } from './portable-core.mjs';
// Build-time constants contain the same repository-pinned Apple roots as the CLI.
const apple = appleWebVerifier(base64(APPLE_ATTESTATION_ROOT), base64(APPLE_RECEIPT_ROOT));
const { verifyPortableDeviceEvidence } = portableVerifier({ base64, digest, ...apple });
export { readerPolicy, verifyPortableDeviceEvidence };
