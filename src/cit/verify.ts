import {
  CIT_MAX_TTL_MS,
  CIT_MAX_NONCE_CACHE,
  MAX_DELEGATION_DEPTH,
} from "../core/constants.js";
import type { CITPayload, CITResult, CITOptions } from "../core/types.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { timingSafeEqual } from "../crypto/timing.js";
import { validateMociId } from "../core/validate.js";
import { verifyKeyPin } from "./keypin.js";

/**
 * Verify a received CIT token against a set of security checks.
 *
 * Verification order (short-circuit on first failure):
 * key pinning → decode → signature (timingSafeEqual) → expiry → TTL cap →
 * skill target → nonce replay → MOCI format → delegation chain depth.
 *
 * @param tokenB64 - Base64-encoded CIT token.
 * @param sig - HMAC signature of the token.
 * @param options - Verification parameters (skill ID, verify key, nonce cache, pin path).
 * @returns CITResult with validity flag and extracted identity fields.
 */
export function verifyCIT(
  tokenB64: string,
  sig: string,
  options: CITOptions,
): CITResult {
  if (options.keyPinPath) {
    if (!verifyKeyPin(options.verifyKey, options.keyPinPath)) {
      return { valid: false, error: "Verify key changed — run: openclaw moci repin-key" };
    }
  }

  let payload: CITPayload;
  try {
    payload = JSON.parse(Buffer.from(tokenB64, "base64").toString("utf8"));
  } catch {
    return { valid: false, error: "Malformed token" };
  }

  const expectedSig = hmacSha256(JSON.stringify(payload), options.verifyKey);
  if (!timingSafeEqual(sig, expectedSig)) {
    return { valid: false, error: "Invalid signature" };
  }

  if (Date.now() > payload.expires_at) {
    return { valid: false, error: "Token expired" };
  }

  if (payload.expires_at - payload.issued_at > CIT_MAX_TTL_MS) {
    return { valid: false, error: "TTL exceeds maximum" };
  }

  if (payload.skill_target !== options.mySkillId) {
    return { valid: false, error: "Token not for this skill" };
  }

  return verifyNonceAndFormat(payload, options);
}

/**
 * Nonce replay check, MOCI format validation, and delegation depth guard.
 * Split from verifyCIT to keep each function under 50 lines.
 */
function verifyNonceAndFormat(
  payload: CITPayload,
  options: CITOptions,
): CITResult {
  if (options.seenNonces) {
    if (options.seenNonces.has(payload.nonce)) {
      return { valid: false, error: "Nonce reused (replay)" };
    }
    options.seenNonces.add(payload.nonce);
    if (options.seenNonces.size > CIT_MAX_NONCE_CACHE) {
      const first = options.seenNonces.values().next().value;
      if (first) options.seenNonces.delete(first);
    }
  }

  const idCheck = validateMociId(payload.moci_id);
  if (!idCheck.valid) {
    return { valid: false, error: "Invalid MOCI in token" };
  }

  const maxDepth = options.maxDelegationDepth ?? MAX_DELEGATION_DEPTH;
  if (payload.delegation_chain && payload.delegation_chain.length > maxDepth) {
    return {
      valid: false,
      error: `Delegation chain too deep: ${payload.delegation_chain.length} > ${maxDepth}`,
    };
  }

  return {
    valid: true,
    mociId: payload.moci_id,
    ring3Head: payload.ring3_head,
    trustScore: payload.trust_score,
    delegationChain: payload.delegation_chain,
  };
}
