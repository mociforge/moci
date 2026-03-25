/**
 * MOCI error codes covering all failure scenarios across the system.
 */
export type MociErrorCode =
  // Identity generation and validation
  | "INVALID_NAME"
  | "INVALID_ID_FORMAT"
  | "CRC_MISMATCH"
  | "NAME_BLOCKED"
  | "NAME_TOO_SHORT"
  | "NAME_TOO_LONG"

  // Identity lifecycle
  | "IDENTITY_NOT_FOUND"
  | "IDENTITY_CORRUPTED"
  | "IDENTITY_NOT_ACTIVE"
  | "IDENTITY_SUSPENDED"
  | "IDENTITY_REVOKED"
  | "IDENTITY_DELETED"
  | "IDENTITY_ALREADY_EXISTS"

  // Memory / ring operations
  | "MEMORY_WRITE_UNAUTHORIZED"
  | "MEMORY_WRITE_RATE_LIMITED"
  | "MEMORY_WRITE_COOLDOWN"
  | "MEMORY_ENTRY_TOO_LARGE"
  | "MEMORY_RING0_FULL"
  | "MEMORY_REPLAY_DETECTED"
  | "MEMORY_HMAC_INVALID"
  | "MEMORY_SEQ_BROKEN"
  | "MEMORY_BUDGET_EXCEEDED"

  // Ring 3 chain integrity
  | "RING3_CHAIN_EMPTY"
  | "RING3_CHAIN_BROKEN"
  | "RING3_HASH_INVALID"

  // Verification
  | "VERIFICATION_FAILED"
  | "FORK_DETECTED"
  | "CALLER_TOKEN_INVALID"
  | "CALLER_TOKEN_EXPIRED"
  | "CALLER_NOT_ALLOWED"

  // CIT (MOCI Identity Token)
  | "CIT_MALFORMED"
  | "CIT_SIGNATURE_INVALID"
  | "CIT_EXPIRED"
  | "CIT_TTL_EXCEEDED"
  | "CIT_WRONG_SKILL"
  | "CIT_NONCE_REUSED"
  | "CIT_INVALID_MOCI"
  | "CIT_DELEGATION_TOO_DEEP"
  | "CIT_KEY_CHANGED"
  | "CIT_ISSUANCE_BLOCKED"

  // Storage / file I/O
  | "FILE_NOT_FOUND"
  | "FILE_READ_FAILED"
  | "FILE_WRITE_FAILED"
  | "FILE_PARSE_FAILED"
  | "FILE_PERMISSION_DENIED"
  | "DISK_FULL"
  | "ATOMIC_WRITE_FAILED"

  // Device salt
  | "DEVICE_SALT_MISSING"
  | "DEVICE_SALT_WRITE_FAILED"
  | "DEVICE_SALT_READ_FAILED"

  // Export / import
  | "EXPORT_FAILED"
  | "EXPORT_MISSING_RING3"
  | "IMPORT_FAILED"
  | "IMPORT_MISSING_RING3"
  | "IMPORT_MISSING_META"
  | "IMPORT_CHAIN_INVALID"
  | "DECRYPT_FAILED"
  | "ENCRYPT_FAILED"

  // Audit log
  | "AUDIT_WRITE_FAILED"
  | "AUDIT_HMAC_INVALID"
  | "AUDIT_READ_FAILED"

  // Key management
  | "KEY_PIN_MISMATCH"
  | "KEY_PIN_WRITE_FAILED"
  | "KEY_GENERATION_FAILED"

  // Promotion
  | "PROMOTION_FAILED"
  | "PROMOTION_SUMMARIZER_FAILED"
  | "PROMOTION_LOCKED"

  // Tombstone
  | "TOMBSTONE_WRITE_FAILED"
  | "TOMBSTONE_READ_FAILED"

  // Breadcrumb (anti-rollback)
  | "BREADCRUMB_ROLLBACK_DETECTED"
  | "BREADCRUMB_WRITE_FAILED"
  | "BREADCRUMB_READ_FAILED"

  // Timestamp / clock
  | "CLOCK_INVALID"

  // Cryptographic self-test
  | "CRYPTO_SELF_TEST_FAILED";

/**
 * Base error class for all MOCI errors.
 * Every expected failure in the system throws a MociError with a typed code.
 */
export class MociError extends Error {
  /** Machine-readable error code for programmatic handling. */
  readonly code: MociErrorCode;

  /**
   * @param code - Typed error code identifying the failure category.
   * @param message - Human-readable description (must not leak secrets or expected values).
   */
  constructor(code: MociErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "MociError";

    // Maintain proper prototype chain for instanceof checks.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
