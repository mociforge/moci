/**
 * Core type definitions for the MOCI identity system.
 * All interfaces match the reference implementation exactly.
 */

export interface MemoryEntry {
  seq: number;
  timestamp: number;
  content: string;
  source?: string;
  writer: string;
  hmac: string;
}

export interface Ring3Entry {
  hash: string;
  input_digest: string;
  promoted_at: number;
}

export type IdentityStatus = "active" | "suspended" | "revoked" | "deleted";

export interface OwnerBinding {
  owner_hash: string;
  owner_type: "email" | "github" | "custom";
  bound_at: number;
}

export interface DelegationLink {
  type: "human" | "agent";
  id_hash?: string;
  moci_id?: string;
  at: number;
}

export interface IdentityMeta {
  memory_seq: number;
  promotion_counter: number;
  last_promotion_at: number;
  last_write_timestamp: number;
  write_cooldown_until: number;
  security_tier: 1 | 2 | 3;
  status: IdentityStatus;
  owner?: OwnerBinding;
}

export interface MemoryRings {
  ring0: MemoryEntry[];
  ring1: MemoryEntry[];
  ring2: MemoryEntry[];
  ring3_chain: Ring3Entry[];
}

export interface MociIdentity {
  moci_id: string;
  layer0_hash: string;
  memory: MemoryRings;
  meta: IdentityMeta;
  created_at: number;
  version: string;
}

export interface ExportPackage {
  moci_id: string;
  layer0_hash: string;
  memory: MemoryRings;
  meta: IdentityMeta;
  created_at: number;
  exported_at: number;
  version: string;
}

export interface GenerateOptions {
  name?: string;
  passphrase?: string;
  ring0Budget?: number;
  totalBudget?: number;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  parsed?: {
    prefix: string;
    name: string;
    suffix: string;
    checksum: string;
    isPremium: boolean;
  };
}

export interface NameValidation {
  valid: boolean;
  normalized?: string;
  error?: string;
}

export interface VerificationResult {
  authenticated: boolean;
  keyValid: boolean;
  memoryMatch: boolean;
  forkDetected: boolean;
}

export interface WriteResult {
  success: boolean;
  seq?: number;
  error?: string;
}

export interface PromotionResult {
  success: boolean;
  entriesPromoted: number;
  bytesFreed: number;
  newChainHead?: string;
  errors: string[];
}

export interface StatusReport {
  moci_id: string;
  created_at: number;
  age_days: number;
  security_tier: number;
  ring0_entries: number;
  ring1_entries: number;
  ring2_entries: number;
  ring3_chain_length: number;
  estimated_size_bytes: number;
  last_ring3_hash: string;
  promotion_counter: number;
  status: IdentityStatus;
  last_promotion_at: number;
}

export interface CallerToken {
  callerId: string;
  issuedAt: number;
  nonce: string;
}

export interface CITPayload {
  moci_id: string;
  ring3_head: string;
  trust_score: number;
  issued_at: number;
  expires_at: number;
  nonce: string;
  skill_target: string;
  session_id?: string;
  request_hash?: string;
  delegation_chain?: DelegationLink[];
}

export interface CITResult {
  valid: boolean;
  mociId?: string;
  ring3Head?: string;
  trustScore?: number;
  delegationChain?: DelegationLink[];
  error?: string;
}

export interface CITOptions {
  mySkillId: string;
  verifyKey: string;
  seenNonces?: Set<string>;
  keyPinPath?: string;
  maxDelegationDepth?: number;
}

export interface TrustScore {
  total: number;
  base: number;
  ageBonus: number;
  continuityBonus: number;
  verificationBonus: number;
}

export interface AuditEvent {
  event: string;
  moci_id: string;
  timestamp: number;
  details: Record<string, unknown>;
  seq: number;
  hmac: string;
}

export interface BreadcrumbData {
  promotion_counter: number;
  last_promotion_at: number;
  moci_id: string;
}

export interface AuditLogger {
  log(event: string, mociId: string, details: Record<string, unknown>): void;
}

export interface AuditChainResult {
  valid: boolean;
  brokenAt?: number;
}

export interface AuditFilter {
  event?: string;
  mociId?: string;
  after?: number;
  before?: number;
  limit?: number;
}
