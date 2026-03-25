import { keccak_256, bytesToHex } from "./vendor/noble-keccak.js";

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

// Well-known keccak-256 reference digests used for the self-test.
const KECCAK_EMPTY_HASH = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const KECCAK_HELLO_HASH = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

/**
 * Verify that the keccak-256 implementation produces correct output for two
 * known inputs. Called at startup to detect tampering or accidental corruption
 * of the vendored crypto library.
 *
 * @returns True when both reference digests match; false if either deviates.
 */
export function verifyCryptoIntegrity(): boolean {
  return (
    keccak256("") === KECCAK_EMPTY_HASH &&
    keccak256("hello") === KECCAK_HELLO_HASH
  );
}
