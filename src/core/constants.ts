/**
 * MOCI system constants — ring limits, memory budgets, rate limits,
 * allowed callers, and name validation patterns.
 */

// Crockford Base32 alphabet (no O, I, L, U — avoids visual ambiguity).
export const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// Ring age thresholds (milliseconds).
export const RING0_MAX_AGE_MS = 24 * 60 * 60 * 1000;
export const RING1_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const RING2_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000;

// Ring entry count caps.
export const RING1_MAX_ENTRIES = 30;
export const RING2_MAX_ENTRIES = 50;

// Memory budget caps (bytes).
export const MEMORY_BUDGET_BYTES = 32 * 1024;
export const MEMORY_BUDGET_BYTES_HIGH = 64 * 1024;

// Ring 0 write constraints.
export const RING0_MAX_ENTRIES_PER_HOUR = 60;
export const RING0_MAX_BYTES_PER_ENTRY = 1024;
export const RING0_MAX_TOTAL_BYTES = 8192;
export const RING0_OVERFLOW_THRESHOLD = 0.9;  // 90% capacity triggers overflow handling

// Per-entry byte caps for promoted rings.
export const RING1_MAX_BYTES_PER_ENTRY = 512;
export const RING2_MAX_BYTES_PER_ENTRY = 256;

// Cooldown imposed after a rate-limit breach.
export const COOLDOWN_ON_BREACH_MS = 300_000;  // 5 minutes

// Callers permitted to write to Ring 0.
export const ALLOWED_WRITERS: readonly string[] = ["gateway", "heartbeat", "skill:moci"];

// CIT (MOCI Identity Token) timing.
export const CIT_DEFAULT_TTL_MS = 60_000;    // 60 seconds
export const CIT_MAX_TTL_MS = 300_000;       // 5 minutes hard cap
export const CIT_MAX_NONCE_CACHE = 1000;     // max nonces held in memory per skill instance

// Caller token expiry window.
export const CALLER_TOKEN_MAX_AGE_MS = 300_000;  // 5 minutes

// Disk headroom: enter read-only emergency mode when free space drops below this.
export const DISK_SPACE_MIN_BYTES = 1_048_576;   // 1 MB

// Audit log rotation threshold.
export const AUDIT_LOG_MAX_BYTES = 1_048_576;    // 1 MB

// Current identity format version.
export const IDENTITY_VERSION = "0.1.0";

// MOCI ID format constants.
export const MOCI_PREFIX = "CW";
export const NAME_MIN_LENGTH = 2;
export const NAME_MAX_LENGTH = 12;
export const SUFFIX_LENGTH = 6;
export const CRC_LENGTH = 2;

// Delegation chain depth limit.
export const MAX_DELEGATION_DEPTH = 5;

// Trust score boundaries.
export const TRUST_BASE = 10;
export const TRUST_AGE_BONUS_MAX = 30;
export const TRUST_CONTINUITY_BONUS_MAX = 40;
export const TRUST_VERIFICATION_BONUS_MAX = 20;
export const TRUST_MAX = 100;

// Blocked name patterns: profanity, system-reserved, and programming keywords.
export const BLOCKED_NAME_PATTERNS: readonly RegExp[] = [
  /^(FUCK|SHIT|NAZI|PORN|DEAD|KILL|HATE|DAMN|HELL|CUNT|DICK|COCK|SLUT|RAPE)/i,
  /^(ADMIN|ROOT|SYSTEM|OPENCLAW|GATEWAY|SERVER|OFFICIAL|SUPPORT|STAFF)/i,
  /^(NULL|UNDEFINED|NAN|TRUE|FALSE|TEST)$/i,
];

// Prompt-injection detection patterns for memory sanitization.
export const INJECTION_PATTERNS: readonly RegExp[] = [
  /ignore\s+(all|previous|above|everything)/gi,
  /forget\s+(all|everything|previous)/gi,
  /system\s*:/gi,
  /you\s+are\s+now/gi,
  /your\s+(new\s+)?role\s+is/gi,
  /disregard\s+(all|previous)/gi,
  /override\s+(instructions|rules|policy)/gi,
  /act\s+as\s+(if|though|an?\s)/gi,
  /<script[\s>]/gi,
  /<\/?\w+[\s>]/gi,
];

// Privilege-escalation patterns for post-summarization output validation.
export const ESCALATION_PATTERNS: readonly RegExp[] = [
  /\b(admin|administrator|root|superuser|owner)\b/gi,
  /\b(full\s+access|all\s+permissions|unlimited)\b/gi,
  /\b(promoted|elevated|granted|upgraded)\s+(to|as|with)\b/gi,
  /\b(I\s+am\s+now|my\s+role\s+is|I\s+have\s+been)\b/gi,
  /\b(you\s+must|always\s+do|never\s+question)\b/gi,
];

// Regex patterns for redacting MOCI IDs from agent tool outputs.
export const MOCI_REDACTION_PATTERN =
  /CW-[0-9A-HJ-KM-NP-QRSTV-XYZ]{2,12}(?:\.[0-9A-HJ-KM-NP-QRSTV-XYZ]{4,6})?-[0-9A-HJ-KM-NP-QRSTV-XYZ]{2}/g;

// Monotonic clock: maximum clock-skew tolerance before correcting forward.
export const CLOCK_MAX_SKEW_MS = 5000;

// Promotion retry policy.
export const PROMOTION_RETRY_DELAYS_MS: readonly number[] = [1_000, 5_000, 30_000, 300_000];
export const PROMOTION_MAX_RETRIES = 3;
export const PROMOTION_OVERDUE_THRESHOLD_MS = 48 * 60 * 60 * 1000;  // 48 hours

// Ring 3 genesis prefix — included in the genesis hash input to domain-separate it.
export const GENESIS_PREFIX = "genesis";

// Revocation terminator — appended to Ring 3 chain when identity is revoked.
export const REVOCATION_TERMINATOR = "REVOKED";
