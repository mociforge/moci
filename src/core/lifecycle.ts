import fs from "node:fs";
import crypto from "node:crypto";
import { MociError } from "./errors.js";
import { REVOCATION_TERMINATOR } from "./constants.js";
import { keccak256 } from "../crypto/keccak.js";
import { addTombstone } from "../storage/tombstone.js";
import {
  getIdentityFilePath,
  getIdentityBackupPath,
  getIdentityDir,
} from "../storage/paths.js";
import type { MociIdentityManager } from "./identity.js";
import type { AuditLogger } from "./types.js";

/**
 * Suspend an active identity. Sets status to "suspended" and logs an audit event.
 *
 * @param manager - Identity manager with a loaded identity.
 * @param auditLogger - Logger for recording the lifecycle event.
 * @throws MociError with code IDENTITY_NOT_FOUND if no identity is loaded.
 * @throws MociError with code IDENTITY_NOT_ACTIVE if identity is not active.
 */
export function suspend(
  manager: MociIdentityManager,
  auditLogger: AuditLogger,
): void {
  const identity = manager.identity;
  if (!identity) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded");
  }
  if (identity.meta.status !== "active") {
    throw new MociError(
      "IDENTITY_NOT_ACTIVE",
      `Cannot suspend: identity is ${identity.meta.status}`,
    );
  }
  identity.meta.status = "suspended";
  auditLogger.log("identity_suspended", identity.moci_id, {});
}

/**
 * Resume a suspended identity. Sets status back to "active" and logs an audit event.
 *
 * @param manager - Identity manager with a loaded identity.
 * @param auditLogger - Logger for recording the lifecycle event.
 * @throws MociError with code IDENTITY_NOT_FOUND if no identity is loaded.
 * @throws MociError with code IDENTITY_SUSPENDED if identity is not suspended.
 */
export function resume(
  manager: MociIdentityManager,
  auditLogger: AuditLogger,
): void {
  const identity = manager.identity;
  if (!identity) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded");
  }
  if (identity.meta.status !== "suspended") {
    throw new MociError(
      "IDENTITY_SUSPENDED",
      `Cannot resume: identity is ${identity.meta.status}`,
    );
  }
  identity.meta.status = "active";
  auditLogger.log("identity_resumed", identity.moci_id, {});
}

/**
 * Revoke an identity permanently. Appends a REVOKED terminator hash to Ring 3,
 * writes a tombstone, and logs an audit event.
 *
 * The terminator hash is keccak256(last_ring3_hash + "REVOKED|" + timestamp),
 * making the revocation cryptographically chained to the identity's history.
 *
 * @param manager - Identity manager with a loaded identity.
 * @param auditLogger - Logger for recording the lifecycle event.
 * @throws MociError with code IDENTITY_NOT_FOUND if no identity is loaded.
 */
export function revoke(
  manager: MociIdentityManager,
  auditLogger: AuditLogger,
): void {
  const identity = manager.identity;
  if (!identity) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded");
  }

  identity.meta.status = "revoked";

  const chain = identity.memory.ring3_chain;
  const lastHash = chain[chain.length - 1].hash;
  const timestamp = Date.now();
  const terminatorInput = `${REVOCATION_TERMINATOR}|${timestamp}`;
  const terminatorHash = keccak256(lastHash + terminatorInput);

  chain.push({
    hash: terminatorHash,
    input_digest: terminatorInput,
    promoted_at: timestamp,
  });

  addTombstone(identity.moci_id, manager.basePath);
  auditLogger.log("identity_revoked", identity.moci_id, {});
}

/**
 * Permanently delete a revoked identity. Overwrites identity files with random
 * data 3 times before unlinking to resist forensic recovery. Tombstone is preserved.
 *
 * @param manager - Identity manager with a loaded identity.
 * @param auditLogger - Logger for recording the lifecycle event.
 * @throws MociError with code IDENTITY_NOT_FOUND if no identity is loaded.
 * @throws MociError with code IDENTITY_REVOKED if identity is not in revoked state.
 */
export function deletePermanent(
  manager: MociIdentityManager,
  auditLogger: AuditLogger,
): void {
  const identity = manager.identity;
  if (!identity) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded");
  }
  if (identity.meta.status !== "revoked") {
    throw new MociError(
      "IDENTITY_REVOKED",
      `Cannot delete: identity must be revoked first (current: ${identity.meta.status})`,
    );
  }

  const primaryPath = getIdentityFilePath(identity.moci_id, manager.basePath);
  const backupPath = getIdentityBackupPath(identity.moci_id, manager.basePath);

  secureWipe(primaryPath);
  secureWipe(backupPath);

  const dirPath = getIdentityDir(identity.moci_id, manager.basePath);
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true });
  }

  identity.meta.status = "deleted";
  auditLogger.log("identity_deleted_permanent", identity.moci_id, {});
}

/**
 * Overwrite a file with random data 3 times, fsync each pass, then unlink.
 */
function secureWipe(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  const size = fs.statSync(filePath).size;
  for (let i = 0; i < 3; i++) {
    const randomData = crypto.randomBytes(size);
    fs.writeFileSync(filePath, randomData, { mode: 0o600 });
    const fd = fs.openSync(filePath, "r");
    try {
      fs.fdatasyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }
  fs.unlinkSync(filePath);
}
