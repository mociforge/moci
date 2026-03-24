import { keccak256 } from "../crypto/keccak.js";
import { timingSafeEqual } from "../crypto/timing.js";
import type { MociIdentity, VerificationResult } from "./types.js";

/**
 * Verify an identity's layer-0 hash and Ring 3 chain head against expected values.
 * All comparisons use constant-time equality to prevent timing side-channels.
 *
 * @param identity - The identity to verify.
 * @param expectedLayer0 - Expected layer-0 hash (hex).
 * @param expectedRing3Head - Expected Ring 3 chain head hash (hex).
 * @returns VerificationResult with authentication status and fork detection.
 */
export function verifyIdentity(
  identity: MociIdentity,
  expectedLayer0: string,
  expectedRing3Head: string,
): VerificationResult {
  const keyValid = timingSafeEqual(identity.layer0_hash, expectedLayer0);
  const chain = identity.memory.ring3_chain;
  const head = chain[chain.length - 1].hash;
  const memoryMatch = timingSafeEqual(head, expectedRing3Head);

  return {
    authenticated: keyValid && memoryMatch,
    keyValid,
    memoryMatch,
    forkDetected: keyValid && !memoryMatch,
  };
}

/**
 * Recompute every hash in the Ring 3 chain and verify integrity.
 * This is NOT a format check — it actually re-derives each hash from the
 * previous entry's hash + the current entry's input_digest.
 *
 * @param identity - The identity whose Ring 3 chain to verify.
 * @returns True if the entire chain is intact.
 */
export function verifyRing3Chain(identity: MociIdentity): boolean {
  const chain = identity.memory.ring3_chain;
  if (chain.length === 0) return false;
  if (!chain[0].hash || chain[0].hash.length !== 64) return false;

  for (let i = 1; i < chain.length; i++) {
    const entry = chain[i];
    if (!entry.hash || entry.hash.length !== 64 || !entry.input_digest) {
      return false;
    }
    const recomputed = keccak256(chain[i - 1].hash + entry.input_digest);
    if (!timingSafeEqual(recomputed, entry.hash)) return false;
  }

  return true;
}
