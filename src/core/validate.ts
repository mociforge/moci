import { B32, BLOCKED_NAME_PATTERNS, NAME_MIN_LENGTH, NAME_MAX_LENGTH } from "./constants.js";
import type { ValidationResult, NameValidation } from "./types.js";

/**
 * CRC-8/CCITT checksum over a string.
 * Used for typo detection in MOCI IDs — NOT for security.
 *
 * @param str - Input string.
 * @returns 8-bit CRC value.
 */
export function crc8(str: string): number {
  let crc = 0;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      crc = (crc & 0x80) ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff;
    }
  }
  return crc;
}

/**
 * Encode a CRC-8 value as two Crockford Base32 characters.
 *
 * @param crc - 8-bit CRC value.
 * @returns Two-character Base32 string.
 */
export function crcToBase32(crc: number): string {
  return B32[(crc >> 5) & 31] + B32[crc & 31];
}

/**
 * Normalize a user-input string to Crockford Base32 form.
 * Replaces ambiguous characters (O→0, I/L→1, U→V) and strips invalids.
 *
 * @param input - Raw user input.
 * @returns Normalized uppercase Base32 string.
 */
export function normalizeBase32(input: string): string {
  return input
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/I|L/g, "1")
    .replace(/U/g, "V")
    .replace(/[^0-9A-HJ-KM-NP-QRSTV-XYZ]/g, "");
}

/**
 * Validate a user-chosen name for MOCI identity registration.
 * Only uppercases and strips non-alphanumeric characters.
 * No Crockford Base32 normalization — O, I, L, U are kept as-is.
 * Checks length bounds (2-12) and blocked-name patterns.
 *
 * @param input - Raw name string from the user.
 * @returns Validation result with uppercased name on success.
 */
export function validateName(input: string): NameValidation {
  const n = input.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (n.length < NAME_MIN_LENGTH) {
    return { valid: false, error: "Name must be at least 2 characters" };
  }
  if (n.length > NAME_MAX_LENGTH) {
    return { valid: false, error: "Name must be 12 characters or fewer" };
  }
  for (const p of BLOCKED_NAME_PATTERNS) {
    if (p.test(n)) {
      return { valid: false, error: "Name contains a restricted term" };
    }
  }
  return { valid: true, normalized: n };
}

/**
 * Validate a full MOCI ID string.
 * Supports both open-tier (CW-NAME.SUFFIX-CRC) and premium (CW-NAME-CRC) formats.
 * CRC mismatch messages never reveal the expected checksum.
 *
 * @param id - The MOCI ID string to validate.
 * @returns Validation result with parsed segments on success.
 */
export function validateMociId(id: string): ValidationResult {
  // NAME: A-Z 0-9 (full alphanumeric, user-chosen)
  // SUFFIX + CRC: Crockford Base32 only (system-generated)
  const B32_CHARS = "0-9A-HJ-KM-NP-QRSTV-XYZ";
  const openPat = new RegExp(
    `^CW-([A-Z0-9]{2,12})\\.([${B32_CHARS}]{4,6})-([${B32_CHARS}]{2})$`,
  );
  const premPat = new RegExp(
    `^CW-([A-Z0-9]{2,12})-([${B32_CHARS}]{2})$`,
  );

  let match = id.match(openPat);
  let isPremium = false;
  if (!match) {
    match = id.match(premPat);
    isPremium = true;
  }
  if (!match) {
    return { valid: false, error: "Invalid MOCI format" };
  }

  const name = match[1];
  const suffix = isPremium ? "" : match[2];
  const givenCrc = isPremium ? match[2] : match[3];

  if (isPremium && name.length > 6) {
    for (let s = 2; s <= name.length - 4; s++) {
      const pn = name.slice(0, s);
      const ps = name.slice(s);
      if (ps.length >= 4 && ps.length <= 6) {
        if (crcToBase32(crc8(`CW-${pn}.${ps}`)) === givenCrc) {
          return {
            valid: false,
            error: `Did you mean CW-${pn}.${ps}-${givenCrc}? (missing dot)`,
          };
        }
      }
    }
  }

  const body = isPremium ? `CW-${name}` : `CW-${name}.${suffix}`;
  if (crcToBase32(crc8(body)) !== givenCrc) {
    return { valid: false, error: "Invalid MOCI" };
  }

  return {
    valid: true,
    parsed: { prefix: "CW", name, suffix, checksum: givenCrc, isPremium },
  };
}
