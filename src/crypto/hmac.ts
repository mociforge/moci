import crypto from "node:crypto";

/**
 * Compute HMAC-SHA256 of a message with a secret key.
 *
 * @param message - The message to authenticate.
 * @param secret - The HMAC secret key.
 * @returns Lowercase hex string (64 characters).
 */
export function hmacSha256(message: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(message).digest("hex");
}
