import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
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
 * Attempt to read a hardware-bound machine identifier from the OS.
 *
 * Priority:
 *   Linux  → /etc/machine-id, then /var/lib/dbus/machine-id
 *   macOS  → IOPlatformSerialNumber via ioreg
 *   Win32  → HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid via reg query
 *
 * Returns "" when no hardware ID can be obtained (Docker, CI, unsupported OS).
 *
 * @returns Trimmed hardware ID string, or "" on failure.
 */
export function getHardwareMachineId(): string {
  const platform = os.platform();

  try {
    if (platform === "linux") {
      for (const p of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
        if (fs.existsSync(p)) return fs.readFileSync(p, "utf8").trim();
      }
      return "";
    }

    if (platform === "darwin") {
      const out = execSync("ioreg -rd1 -c IOPlatformExpertDevice", {
        encoding: "utf8",
        timeout: 5000,
      });
      const match = /"IOPlatformSerialNumber"\s*=\s*"([^"]+)"/.exec(out);
      return match ? match[1].trim() : "";
    }

    if (platform === "win32") {
      const out = execSync(
        "reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid",
        { encoding: "utf8", timeout: 5000 },
      );
      const match = /MachineGuid\s+REG_SZ\s+(\S+)/.exec(out);
      return match ? match[1].trim() : "";
    }
  } catch {
    // Hardware ID unavailable — silent fallback.
  }

  return "";
}

/**
 * Derive a device-specific fingerprint for a MOCI identity.
 * Combines the device salt with host-specific attributes, a hardware
 * machine ID (when available), and the MOCI ID.
 *
 * When getHardwareMachineId() returns "", the fingerprint degrades to the
 * same inputs as the v0.1.0 legacy fingerprint (backward-compatible).
 *
 * @param mociId - The MOCI identity string.
 * @param basePath - Override base directory (for testing).
 * @returns Keccak-256 hex hash of the combined fingerprint material.
 */
export function deriveDeviceFingerprint(mociId: string, basePath?: string): string {
  const salt = ensureDeviceSalt(basePath);
  const machineId = getHardwareMachineId();
  const material = [
    salt,
    os.hostname(),
    os.homedir(),
    os.platform() + os.arch(),
    machineId,
    mociId,
  ].join("|");
  return keccak256(material);
}

/**
 * Derive the legacy (v0.1.0) device fingerprint that does NOT include
 * a hardware machine ID. Used for backward-compatible decryption of
 * identities created before the hardware-binding upgrade.
 *
 * @param mociId - The MOCI identity string.
 * @param basePath - Override base directory (for testing).
 * @returns Keccak-256 hex hash using the original v0.1.0 material.
 */
export function deriveLegacyDeviceFingerprint(mociId: string, basePath?: string): string {
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
