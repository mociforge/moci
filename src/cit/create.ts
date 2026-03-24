import { MociError } from "../core/errors.js";
import { CIT_DEFAULT_TTL_MS, CIT_MAX_TTL_MS } from "../core/constants.js";
import type { MociIdentity, CITPayload, DelegationLink } from "../core/types.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { keccak256 } from "../crypto/keccak.js";
import { randomBase32 } from "../crypto/random.js";

export interface CreateCITOptions {
  ttlMs?: number;
  sessionId?: string;
  requestBody?: string;
  delegationChain?: DelegationLink[];
}

/**
 * Create a signed MOCI Identity Token (CIT) for skill authorization.
 * The identity must be in "active" status; TTL is clamped to [60s, 300s].
 *
 * @param identity - The active MOCI identity issuing the token.
 * @param skillTarget - Target skill identifier the token is scoped to.
 * @param trustScore - Current trust score of the identity.
 * @param signingKey - HMAC key used to sign the token payload.
 * @param options - Optional TTL override, session ID, request body hash, delegation chain.
 * @returns Base64-encoded token string and its HMAC signature.
 * @throws MociError with code CIT_ISSUANCE_BLOCKED if identity is not active.
 */
export function createCIT(
  identity: MociIdentity,
  skillTarget: string,
  trustScore: number,
  signingKey: string,
  options?: CreateCITOptions,
): { token: string; sig: string } {
  if (identity.meta.status !== "active") {
    throw new MociError(
      "CIT_ISSUANCE_BLOCKED",
      `Cannot issue CIT: identity is ${identity.meta.status}`,
    );
  }

  const now = Date.now();
  const rawTtl = options?.ttlMs ?? CIT_DEFAULT_TTL_MS;
  const ttl = Math.max(CIT_DEFAULT_TTL_MS, Math.min(rawTtl, CIT_MAX_TTL_MS));

  const chain = identity.memory.ring3_chain;
  const payload: CITPayload = {
    moci_id: identity.moci_id,
    ring3_head: chain[chain.length - 1].hash,
    trust_score: trustScore,
    issued_at: now,
    expires_at: now + ttl,
    nonce: randomBase32(12),
    skill_target: skillTarget,
  };

  if (options?.sessionId) payload.session_id = options.sessionId;
  if (options?.requestBody) payload.request_hash = keccak256(options.requestBody);
  if (options?.delegationChain) payload.delegation_chain = options.delegationChain;

  const payloadStr = JSON.stringify(payload);
  const sig = hmacSha256(payloadStr, signingKey);
  return { token: Buffer.from(payloadStr).toString("base64"), sig };
}
