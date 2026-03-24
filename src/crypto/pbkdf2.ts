import crypto from "node:crypto";

const DEFAULT_ITERATIONS = 100_000;
const KEY_LENGTH = 32;
const DIGEST = "sha256";

/**
 * Derive a symmetric key from a passphrase using PBKDF2-SHA256.
 *
 * @param passphrase - The user-provided passphrase.
 * @param salt - Random salt (should be at least 32 bytes).
 * @param iterations - Iteration count (default 100,000).
 * @returns 32-byte derived key as a Buffer.
 */
export function deriveKey(
  passphrase: string,
  salt: Buffer,
  iterations: number = DEFAULT_ITERATIONS,
): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, iterations, KEY_LENGTH, DIGEST);
}

/**
 * Derive two independent keys (HMAC + encryption) from a single passphrase
 * by using domain-separated salts.
 *
 * @param passphrase - The user-provided passphrase.
 * @param salt - Base salt (at least 32 bytes).
 * @returns An object with `hmacKey` and `encryptionKey` as hex strings.
 */
export function deriveKeyPair(
  passphrase: string,
  salt: Buffer,
): { hmacKey: string; encryptionKey: string } {
  const hmacSalt = Buffer.concat([Buffer.from("hmac:"), salt]);
  const encSalt = Buffer.concat([Buffer.from("enc:"), salt]);

  const hmacKey = deriveKey(passphrase, hmacSalt).toString("hex");
  const encryptionKey = deriveKey(passphrase, encSalt).toString("hex");

  return { hmacKey, encryptionKey };
}
