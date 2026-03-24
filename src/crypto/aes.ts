import crypto from "node:crypto";
import { MociError } from "../core/errors.js";
import { deriveKey } from "./pbkdf2.js";

const AES_ALGO = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100_000;

/**
 * Encrypted payload containing all data needed for decryption.
 */
export interface EncryptedPayload {
  iv: string;
  salt: string;
  tag: string;
  ciphertext: string;
}

/**
 * Encrypt a plaintext string with AES-256-GCM using a passphrase-derived key.
 *
 * @param plaintext - The string to encrypt.
 * @param passphrase - The passphrase used for key derivation.
 * @returns An EncryptedPayload with all fields as hex strings.
 * @throws MociError with code ENCRYPT_FAILED on unexpected errors.
 */
export function encrypt(plaintext: string, passphrase: string): EncryptedPayload {
  try {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(AES_ALGO, key, iv, { authTagLength: TAG_LENGTH });
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      iv: iv.toString("hex"),
      salt: salt.toString("hex"),
      tag: tag.toString("hex"),
      ciphertext: encrypted.toString("hex"),
    };
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("ENCRYPT_FAILED", `Encryption failed: ${(e as Error).message}`);
  }
}

/**
 * Decrypt an EncryptedPayload back to plaintext using the original passphrase.
 *
 * @param payload - The encrypted payload produced by encrypt().
 * @param passphrase - The passphrase used during encryption.
 * @returns The original plaintext string.
 * @throws MociError with code DECRYPT_FAILED if passphrase is wrong or data is corrupted.
 */
export function decrypt(payload: EncryptedPayload, passphrase: string): string {
  try {
    const salt = Buffer.from(payload.salt, "hex");
    const iv = Buffer.from(payload.iv, "hex");
    const tag = Buffer.from(payload.tag, "hex");
    const ciphertext = Buffer.from(payload.ciphertext, "hex");

    const key = deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
    const decipher = crypto.createDecipheriv(AES_ALGO, key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("DECRYPT_FAILED", "Decryption failed: wrong passphrase or corrupted data");
  }
}
