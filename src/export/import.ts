import crypto from "node:crypto";
import { MociError } from "../core/errors.js";
import type { MociIdentity, MemoryEntry } from "../core/types.js";
import { decrypt } from "../crypto/aes.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { verifyRing3Chain } from "../core/verify.js";
import { isTombstoned } from "../storage/tombstone.js";

/**
 * Import a previously exported identity, verify its integrity, and re-sign
 * all memory HMACs with a freshly generated device key.
 *
 * Steps: decrypt → verify Ring 3 chain → check tombstone → re-sign → return.
 *
 * @param encryptedData - The encrypted export data string (JSON of EncryptedPayload).
 * @param exportPassphrase - The passphrase used during export.
 * @param newBasePath - Override base directory for tombstone checks (testing).
 * @returns The re-signed identity and the new HMAC key.
 * @throws MociError with code DECRYPT_FAILED if passphrase is wrong.
 * @throws MociError with code IMPORT_MISSING_RING3 if Ring 3 chain is missing.
 * @throws MociError with code IMPORT_MISSING_META if meta field is absent.
 * @throws MociError with code IMPORT_CHAIN_INVALID if Ring 3 chain is broken.
 * @throws MociError with code IMPORT_FAILED if identity is tombstoned.
 */
export function importIdentity(
  encryptedData: string,
  exportPassphrase: string,
  newBasePath?: string,
): { identity: MociIdentity; hmacKey: string } {
  const pkg = decryptExport(encryptedData, exportPassphrase);
  validateExportFields(pkg);

  const identity = buildIdentity(pkg);

  if (!verifyRing3Chain(identity)) {
    throw new MociError("IMPORT_CHAIN_INVALID", "Ring 3 chain verification failed");
  }
  if (isTombstoned(identity.moci_id, newBasePath)) {
    throw new MociError("IMPORT_FAILED", "Identity is tombstoned and cannot be imported");
  }

  const newHmacKey = crypto.randomBytes(32).toString("hex");
  resignAllRings(identity, newHmacKey);

  return { identity, hmacKey: newHmacKey };
}

/** Decrypt the export payload and parse the inner JSON. */
function decryptExport(
  encryptedData: string,
  passphrase: string,
): Record<string, unknown> {
  let plaintext: string;
  try {
    const payload = JSON.parse(encryptedData);
    plaintext = decrypt(payload, passphrase);
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("IMPORT_FAILED", `Failed to decrypt export: ${(e as Error).message}`);
  }
  try {
    return JSON.parse(plaintext);
  } catch {
    throw new MociError("IMPORT_FAILED", "Corrupted export data");
  }
}

/** Ensure required fields are present in the decrypted package. */
function validateExportFields(pkg: Record<string, unknown>): void {
  const mem = pkg.memory as Record<string, unknown> | undefined;
  if (!mem?.ring3_chain || !Array.isArray(mem.ring3_chain) || mem.ring3_chain.length === 0) {
    throw new MociError("IMPORT_MISSING_RING3", "Export package has no Ring 3 chain");
  }
  if (!pkg.meta) {
    throw new MociError("IMPORT_MISSING_META", "Export package has no meta field");
  }
}

/** Reconstruct a MociIdentity from the raw decrypted fields. */
function buildIdentity(pkg: Record<string, unknown>): MociIdentity {
  return {
    moci_id: pkg.moci_id as string,
    layer0_hash: pkg.layer0_hash as string,
    memory: structuredClone(pkg.memory as MociIdentity["memory"]),
    meta: structuredClone(pkg.meta as MociIdentity["meta"]),
    created_at: pkg.created_at as number,
    version: pkg.version as string,
  };
}

/** Re-sign every memory entry in all three rings with a new HMAC key. */
function resignAllRings(identity: MociIdentity, hmacKey: string): void {
  const resign = (entry: MemoryEntry): void => {
    entry.hmac = hmacSha256(
      entry.content + (entry.source ?? "") + entry.timestamp + entry.seq,
      hmacKey,
    );
  };
  identity.memory.ring0.forEach(resign);
  identity.memory.ring1.forEach(resign);
  identity.memory.ring2.forEach(resign);
}
