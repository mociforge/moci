import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Compute keccak-256 hash of a UTF-8 string.
 * This is SYNCHRONOUS — never use await with it.
 *
 * @param input - The string to hash.
 * @returns Lowercase hex string (64 characters).
 */
export function keccak256(input: string): string {
  const data = new TextEncoder().encode(input);
  return bytesToHex(keccak_256(data));
}
