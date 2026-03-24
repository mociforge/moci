import type { IdentityMeta } from "./types.js";

/**
 * Return a monotonically increasing timestamp.
 * If the system clock has drifted backwards, advance from the last known time
 * to prevent sequence violations in the memory chain.
 *
 * Mutates `meta.last_write_timestamp` as a side effect.
 *
 * @param meta - The identity's metadata (mutated in-place).
 * @returns A timestamp guaranteed to be >= the previous call's value.
 */
export function getMonotonicTimestamp(meta: IdentityMeta): number {
  const now = Date.now();
  if (now >= meta.last_write_timestamp) {
    meta.last_write_timestamp = now;
    return now;
  }
  const corrected = meta.last_write_timestamp + 1;
  meta.last_write_timestamp = corrected;
  return corrected;
}
