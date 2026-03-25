import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { MociIdentityManager } from "../core/identity.js";
import { AuditLogger } from "../audit/logger.js";
import { getIdentitiesDir } from "../storage/paths.js";
import { deriveDeviceFingerprint, deriveLegacyDeviceFingerprint } from "../storage/salt.js";
import { deriveKeyPair } from "../crypto/pbkdf2.js";
import { MociError } from "../core/errors.js";

/**
 * Read a passphrase from an env var (non-interactive fallback).
 * In a production CLI this would use a TTY prompt; env-var is used for v0.
 *
 * @param envVar - Environment variable name.
 * @returns The passphrase string, or undefined if not set.
 */
export function readPassphraseFromEnv(envVar = "MOCI_PASSPHRASE"): string | undefined {
  return process.env[envVar] || undefined;
}

/**
 * Derive the HMAC + audit keys for a loaded identity.
 * Tier 1 (device key) → derives from device fingerprint.
 * Tier 2 (passphrase) → derives from passphrase + PBKDF2.
 *
 * @param mociId - The MOCI identity string.
 * @param tier - Security tier (1 or 2).
 * @param passphrase - User passphrase (required for tier 2).
 * @returns hmacKey and auditKey strings.
 */
export function deriveKeys(
  mociId: string,
  tier: 1 | 2 | 3,
  passphrase?: string,
): { hmacKey: string; auditKey: string } {
  if (tier >= 2 && passphrase) {
    const salt = Buffer.from(mociId, "utf8");
    const pair = deriveKeyPair(passphrase, salt);
    return { hmacKey: pair.hmacKey, auditKey: crypto.createHash("sha256").update(pair.hmacKey + "audit").digest("hex") };
  }
  const fp = deriveDeviceFingerprint(mociId);
  const hmacKey = crypto.createHash("sha256").update(fp + "hmac").digest("hex");
  const auditKey = crypto.createHash("sha256").update(fp + "audit").digest("hex");
  return { hmacKey, auditKey };
}

/**
 * Load the first identity found in the identities directory,
 * or a specific one if mociId is provided.
 *
 * @param mociId - Optional specific MOCI ID.
 * @param passphrase - Decryption passphrase.
 * @returns Loaded manager, identity, and derived keys.
 */
export function loadIdentity(
  mociId?: string,
  passphrase?: string,
): { manager: MociIdentityManager; mociId: string; hmacKey: string; auditKey: string } {
  const manager = new MociIdentityManager();
  const resolvedId = mociId ?? findFirstIdentity();
  const secret = passphrase ?? deriveDeviceFingerprint(resolvedId);
  const legacySecret = passphrase ? undefined : deriveLegacyDeviceFingerprint(resolvedId);
  manager.load(resolvedId, secret, legacySecret);

  if (manager.usedLegacyFingerprint) {
    info("Identity uses legacy fingerprint. Run: moci migrate-fingerprint");
  }

  const identity = manager.identity!;
  const keys = deriveKeys(resolvedId, identity.meta.security_tier, passphrase);
  return { manager, mociId: resolvedId, ...keys };
}

/**
 * Find the first identity directory name under ~/.openclaw/identities/.
 *
 * @returns The MOCI ID string from the directory name.
 * @throws MociError if no identities exist.
 */
export function findFirstIdentity(): string {
  const dir = getIdentitiesDir();
  if (!fs.existsSync(dir)) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identities directory found");
  }
  const entries = fs.readdirSync(dir).filter((e) => {
    const full = path.join(dir, e);
    return fs.statSync(full).isDirectory() && e.startsWith("CW-");
  });
  if (entries.length === 0) {
    throw new MociError("IDENTITY_NOT_FOUND", "No identities found");
  }
  return entries[0];
}

/**
 * Create an AuditLogger for the given key.
 */
export function createAuditLogger(auditKey: string): AuditLogger {
  return new AuditLogger(auditKey);
}

/**
 * Print a success message.
 */
export function ok(msg: string): void {
  console.log(`✓ ${msg}`);
}

/**
 * Print a failure message and exit.
 */
export function fail(msg: string): never {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

/**
 * Print an indented info line.
 */
export function info(msg: string): void {
  console.log(`  ${msg}`);
}
