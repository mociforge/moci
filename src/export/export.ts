import { MociError } from "../core/errors.js";
import type { MociIdentityManager } from "../core/identity.js";
import type { ExportPackage } from "../core/types.js";
import { keccak256 } from "../crypto/keccak.js";
import { encrypt } from "../crypto/aes.js";

/**
 * Export an identity as an encrypted package for cross-device transfer.
 *
 * The filename is an opaque hash (no MOCI ID leakage).
 * The HMAC key is included inside the encrypted payload so the importing
 * device can re-sign all memory entries with a fresh key.
 *
 * @param manager - Identity manager with a loaded identity.
 * @param exportPassphrase - Passphrase to encrypt the export package.
 * @param hmacKey - Current HMAC key used for memory entry signatures.
 * @returns Object with an opaque filename and the encrypted data as a JSON string.
 * @throws MociError with code IDENTITY_NOT_FOUND if no identity is loaded.
 * @throws MociError with code EXPORT_MISSING_RING3 if Ring 3 chain is empty.
 * @throws MociError with code EXPORT_FAILED on unexpected errors.
 */
export function exportIdentity(
  manager: MociIdentityManager,
  exportPassphrase: string,
  hmacKey: string,
): { filename: string; encryptedData: string } {
  const identity = manager.identity;
  if (!identity) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded to export");
  }
  if (identity.memory.ring3_chain.length === 0) {
    throw new MociError("EXPORT_MISSING_RING3", "Ring 3 chain is empty — cannot export");
  }

  try {
    const pkg: ExportPackage & { hmac_key: string } = {
      moci_id: identity.moci_id,
      layer0_hash: identity.layer0_hash,
      memory: structuredClone(identity.memory),
      meta: structuredClone(identity.meta),
      created_at: identity.created_at,
      exported_at: Date.now(),
      version: identity.version,
      hmac_key: hmacKey,
    };

    const hash = keccak256(identity.layer0_hash).slice(0, 8);
    const filename = `moci-export-${hash}.enc`;

    const encrypted = encrypt(JSON.stringify(pkg), exportPassphrase);
    return { filename, encryptedData: JSON.stringify(encrypted) };
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("EXPORT_FAILED", `Export failed: ${(e as Error).message}`);
  }
}
