// Public API — re-export all user-facing functions, classes, and types.

export { generateMociId } from "./core/generate.js";
export { validateMociId, validateName } from "./core/validate.js";
export { MociIdentityManager } from "./core/identity.js";
export { addMemory, promoteRings } from "./core/memory.js";
export { verifyIdentity, verifyRing3Chain } from "./core/verify.js";
export { computeTrustScore } from "./core/trust.js";
export { suspend, resume, revoke, deletePermanent } from "./core/lifecycle.js";
export { MociError } from "./core/errors.js";

export { createCIT } from "./cit/create.js";
export { verifyCIT } from "./cit/verify.js";
export { generateSkillKey, verifyKeyPin } from "./cit/keypin.js";

export { exportIdentity } from "./export/export.js";
export { importIdentity } from "./export/import.js";

export { AuditLogger } from "./audit/logger.js";
export { verifyAuditChain, queryAuditLog } from "./audit/query.js";

export { listTombstones } from "./storage/tombstone.js";
export { getIdentitiesDir, getIdentityDir } from "./storage/paths.js";

export type {
  MociIdentity,
  MemoryEntry,
  Ring3Entry,
  IdentityStatus,
  OwnerBinding,
  DelegationLink,
  IdentityMeta,
  MemoryRings,
  ExportPackage,
  GenerateOptions,
  ValidationResult,
  NameValidation,
  VerificationResult,
  WriteResult,
  PromotionResult,
  StatusReport,
  CallerToken,
  CITPayload,
  CITResult,
  CITOptions,
  TrustScore,
  AuditEvent,
  BreadcrumbData,
  AuditLogger as AuditLoggerInterface,
  AuditChainResult,
  AuditFilter,
} from "./core/types.js";

export type { MociErrorCode } from "./core/errors.js";
export type { CreateCITOptions } from "./cit/create.js";
