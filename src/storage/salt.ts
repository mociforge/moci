import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import { MociError } from "../core/errors.js";
import { keccak256 } from "../crypto/keccak.js";
import { getBaseDir, getDeviceSaltPath } from "./paths.js";

/**
 * Ensure the device salt file exists; create it on first run.
 * The salt is a 256-bit CSPRNG value stored as hex (mode 0o600).
 *
 * @param basePath - Override base directory (for testing).
 * @returns The device salt as a hex string (64 chars).
 * @throws MociError with code DEVICE_SALT_WRITE_FAILED or DEVICE_SALT_READ_FAILED.
 */
export function ensureDeviceSalt(basePath?: string): string {
  const baseDir = getBaseDir(basePath);
  const saltPath = getDeviceSaltPath(basePath);

  if (!fs.existsSync(baseDir)) {
    try {
      fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    } catch (e) {
      throw new MociError(
        "DEVICE_SALT_WRITE_FAILED",
        `Cannot create directory ${baseDir}: ${(e as Error).message}`,
      );
    }
  }

  if (!fs.existsSync(saltPath)) {
    try {
      const salt = crypto.randomBytes(32).toString("hex");
      fs.writeFileSync(saltPath, salt, { mode: 0o600 });
    } catch (e) {
      throw new MociError(
        "DEVICE_SALT_WRITE_FAILED",
        `Cannot write device salt: ${(e as Error).message}`,
      );
    }
  }

  try {
    return fs.readFileSync(saltPath, "utf8").trim();
  } catch (e) {
    throw new MociError(
      "DEVICE_SALT_READ_FAILED",
      `Cannot read device salt: ${(e as Error).message}`,
    );
  }
}

/**
 * Derive a device-specific fingerprint for a MOCI identity.
 * Combines the device salt with host-specific attributes and the MOCI ID.
 *
 * @param mociId - The MOCI identity string.
 * @param basePath - Override base directory (for testing).
 * @returns Keccak-256 hex hash of the combined fingerprint material.
 */
export function deriveDeviceFingerprint(mociId: string, basePath?: string): string {
  const salt = ensureDeviceSalt(basePath);
  const material = [
    salt,
    os.hostname(),
    os.homedir(),
    os.platform() + os.arch(),
    mociId,
  ].join("|");
  return keccak256(material);
}
