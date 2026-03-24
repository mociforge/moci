/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * Must be used for ALL hash, HMAC, and signature comparisons.
 *
 * @param a - First string.
 * @param b - Second string.
 * @returns True if strings are identical.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
