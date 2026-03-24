import path from "node:path";
import os from "node:os";

const DEFAULT_BASE = path.join(os.homedir(), ".openclaw");

/**
 * Resolve the base directory for all MOCI data.
 * Override with `basePath` for testing — never touch ~/.openclaw/ in tests.
 *
 * @param basePath - Override base directory (defaults to ~/.openclaw/).
 * @returns Absolute path to the MOCI data root.
 */
export function getBaseDir(basePath?: string): string {
  return basePath ?? DEFAULT_BASE;
}

/**
 * @param basePath - Override base directory.
 * @returns Path to the identities parent directory.
 */
export function getIdentitiesDir(basePath?: string): string {
  return path.join(getBaseDir(basePath), "identities");
}

/**
 * @param mociId - The MOCI identity ID.
 * @param basePath - Override base directory.
 * @returns Path to a specific identity's directory.
 */
export function getIdentityDir(mociId: string, basePath?: string): string {
  return path.join(getIdentitiesDir(basePath), mociId);
}

/**
 * @param mociId - The MOCI identity ID.
 * @param basePath - Override base directory.
 * @returns Path to the encrypted identity file.
 */
export function getIdentityFilePath(mociId: string, basePath?: string): string {
  return path.join(getIdentityDir(mociId, basePath), "identity.enc");
}

/**
 * @param mociId - The MOCI identity ID.
 * @param basePath - Override base directory.
 * @returns Path to the backup identity file.
 */
export function getIdentityBackupPath(mociId: string, basePath?: string): string {
  return path.join(getIdentityDir(mociId, basePath), "identity.enc.bak");
}

/**
 * @param basePath - Override base directory.
 * @returns Path to the device salt file.
 */
export function getDeviceSaltPath(basePath?: string): string {
  return path.join(getBaseDir(basePath), ".moci-device-salt");
}

/**
 * @param basePath - Override base directory.
 * @returns Path to the monotonic promotion counter (breadcrumb).
 */
export function getCounterPath(basePath?: string): string {
  return path.join(getBaseDir(basePath), ".moci-counter");
}

/**
 * @param basePath - Override base directory.
 * @returns Path to the tombstone list file.
 */
export function getTombstonePath(basePath?: string): string {
  return path.join(getBaseDir(basePath), ".moci-tombstones");
}

/**
 * @param basePath - Override base directory.
 * @returns Path to the audit log file.
 */
export function getAuditLogPath(basePath?: string): string {
  return path.join(getBaseDir(basePath), ".moci-audit.jsonl");
}
