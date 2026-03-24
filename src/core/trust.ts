import {
  TRUST_BASE,
  TRUST_AGE_BONUS_MAX,
  TRUST_CONTINUITY_BONUS_MAX,
  TRUST_VERIFICATION_BONUS_MAX,
  TRUST_MAX,
} from "./constants.js";
import type { MociIdentity } from "./types.js";

/**
 * Compute the trust score for an identity based on age, continuity, and verification tier.
 *
 * Scoring breakdown:
 * - Base: 10 (everyone starts here)
 * - Age bonus: up to 30, linearly scaled over 365 days
 * - Continuity bonus: up to 40, based on promotion_counter (12 promotions = full bonus)
 * - Verification bonus: up to 20, based on security_tier (tier 1=0, tier 2=10, tier 3=20)
 *
 * @param identity - The identity to score.
 * @returns Trust score in the range [10, 100].
 */
export function computeTrustScore(identity: MociIdentity): number {
  const ageDays =
    (Date.now() - identity.created_at) / (24 * 60 * 60 * 1000);
  const ageBonus = Math.min(
    TRUST_AGE_BONUS_MAX,
    Math.floor((ageDays / 365) * TRUST_AGE_BONUS_MAX),
  );

  const continuityBonus = Math.min(
    TRUST_CONTINUITY_BONUS_MAX,
    Math.floor(
      (identity.meta.promotion_counter / 12) * TRUST_CONTINUITY_BONUS_MAX,
    ),
  );

  let verificationBonus: number;
  switch (identity.meta.security_tier) {
    case 1:
      verificationBonus = 0;
      break;
    case 2:
      verificationBonus = Math.floor(TRUST_VERIFICATION_BONUS_MAX / 2);
      break;
    case 3:
      verificationBonus = TRUST_VERIFICATION_BONUS_MAX;
      break;
  }

  return Math.min(
    TRUST_MAX,
    TRUST_BASE + ageBonus + continuityBonus + verificationBonus,
  );
}
