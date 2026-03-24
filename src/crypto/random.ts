import crypto from "node:crypto";
import { B32 } from "../core/constants.js";

/**
 * Generate a random Crockford Base32 string using rejection sampling.
 * Bytes >= 224 are discarded to eliminate modulo bias (224 = 32 * 7).
 *
 * @param length - Number of Base32 characters to generate.
 * @returns A string of `length` Crockford Base32 characters.
 */
export function randomBase32(length: number): string {
  const result: string[] = [];
  while (result.length < length) {
    const byte = crypto.randomBytes(1)[0];
    if (byte < 224) {
      result.push(B32[byte % 32]);
    }
  }
  return result.join("");
}

/**
 * Generate a random hex string.
 *
 * @param bytes - Number of random bytes (output will be 2× this in hex chars).
 * @returns Lowercase hex string.
 */
export function randomHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString("hex");
}
