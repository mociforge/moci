import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { MociError } from "../core/errors.js";
import { keccak256 } from "../crypto/keccak.js";
import { timingSafeEqual } from "../crypto/timing.js";

/**
 * Generate a 32-byte random HMAC key for a skill and persist it to disk.
 *
 * @param skillName - Name of the skill (used as the key filename).
 * @param skillDir - Directory to write the key file into.
 * @returns The generated key as a hex string (64 characters).
 * @throws MociError with code KEY_GENERATION_FAILED on I/O errors.
 */
export function generateSkillKey(skillName: string, skillDir: string): string {
  try {
    if (!fs.existsSync(skillDir)) {
      fs.mkdirSync(skillDir, { recursive: true, mode: 0o700 });
    }
    const key = crypto.randomBytes(32).toString("hex");
    const keyPath = path.join(skillDir, `${skillName}.key`);
    writeSecure(keyPath, key);
    return key;
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError(
      "KEY_GENERATION_FAILED",
      `Failed to generate skill key: ${(e as Error).message}`,
    );
  }
}

/**
 * Verify a key against a stored pin using Trust On First Use (TOFU).
 * On first use the key hash is stored as the pin; subsequent calls compare
 * the current key hash against the stored value.
 *
 * @param verifyKey - The key to verify.
 * @param pinPath - Path to the pin file.
 * @returns True if the key matches the stored pin (or if this is the first use).
 * @throws MociError with code KEY_PIN_WRITE_FAILED if the pin cannot be stored.
 * @throws MociError with code KEY_PIN_MISMATCH if the pin cannot be read.
 */
export function verifyKeyPin(verifyKey: string, pinPath: string): boolean {
  const currentPin = keccak256(verifyKey);

  if (!fs.existsSync(pinPath)) {
    try {
      const dir = path.dirname(pinPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      writeSecure(pinPath, currentPin);
    } catch (e) {
      if (e instanceof MociError) throw e;
      throw new MociError(
        "KEY_PIN_WRITE_FAILED",
        `Cannot write key pin: ${(e as Error).message}`,
      );
    }
    return true;
  }

  try {
    const storedPin = fs.readFileSync(pinPath, "utf8").trim();
    return timingSafeEqual(currentPin, storedPin);
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError(
      "KEY_PIN_MISMATCH",
      `Cannot read key pin: ${(e as Error).message}`,
    );
  }
}

/** Write a small file atomically via temp + rename, tolerating platforms without fdatasync. */
function writeSecure(filepath: string, content: string): void {
  const tmpPath = filepath + ".tmp." + crypto.randomBytes(4).toString("hex");
  try {
    fs.writeFileSync(tmpPath, content, { mode: 0o600 });
    try {
      const fd = fs.openSync(tmpPath, "r+");
      try { fs.fdatasyncSync(fd); } finally { fs.closeSync(fd); }
    } catch { /* fdatasync unsupported on some platforms — proceed */ }
    fs.renameSync(tmpPath, filepath);
  } catch (e) {
    try { fs.unlinkSync(tmpPath); } catch { /* best-effort */ }
    throw e;
  }
}
