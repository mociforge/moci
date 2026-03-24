import {
  INJECTION_PATTERNS,
  ESCALATION_PATTERNS,
  ALLOWED_WRITERS,
  RING0_MAX_ENTRIES_PER_HOUR,
  RING0_MAX_BYTES_PER_ENTRY,
  RING0_MAX_TOTAL_BYTES,
  COOLDOWN_ON_BREACH_MS,
  CALLER_TOKEN_MAX_AGE_MS,
  RING1_MAX_AGE_MS,
  RING2_MAX_AGE_MS,
  RING1_MAX_ENTRIES,
  RING2_MAX_ENTRIES,
  RING1_MAX_BYTES_PER_ENTRY,
  RING2_MAX_BYTES_PER_ENTRY,
  RING0_OVERFLOW_THRESHOLD,
  PROMOTION_RETRY_DELAYS_MS,
  PROMOTION_MAX_RETRIES,
} from "./constants.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { keccak256 } from "../crypto/keccak.js";
import { timingSafeEqual } from "../crypto/timing.js";
import { getMonotonicTimestamp } from "./timestamp.js";
import { MociError } from "./errors.js";
import { verifyRing3Chain } from "./verify.js";
import type {
  MociIdentity,
  MemoryEntry,
  CallerToken,
  WriteResult,
  PromotionResult,
} from "./types.js";

const ENCODER = new TextEncoder();

function byteLength(s: string): number {
  return ENCODER.encode(s).length;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Sanitization ────────────────────────────────────────────────────

/**
 * Filter prompt-injection patterns from memory content.
 * Replaces injection patterns with [FILTERED], strips zero-width characters,
 * and deduplicates excessive consecutive identical lines (max 4 consecutive).
 *
 * @param content - Raw memory content string.
 * @returns Sanitized content safe for LLM context windows.
 */
export function sanitizeForLLM(content: string): string {
  let s = content;
  for (const p of INJECTION_PATTERNS) {
    s = s.replace(p, "[FILTERED]");
  }
  s = s.replace(/[\u200B-\u200F\u202A-\u202E\uFEFF]/g, "");

  const lines = s.split("\n");
  const out: string[] = [];
  let prev = "";
  let count = 0;
  for (const line of lines) {
    if (line === prev) {
      count++;
      if (count <= 3) out.push(line);
    } else {
      count = 0;
      out.push(line);
    }
    prev = line;
  }
  return out.join("\n");
}

/**
 * Detect privilege-escalation language in text.
 *
 * @param text - Text to scan for escalation patterns.
 * @returns True if any escalation pattern matches.
 */
export function containsEscalation(text: string): boolean {
  return ESCALATION_PATTERNS.some((p) => {
    p.lastIndex = 0;
    return p.test(text);
  });
}

// ── Caller verification ─────────────────────────────────────────────

/**
 * Decode and verify a Base64-encoded caller token.
 *
 * @param token - Base64-encoded JSON caller token.
 * @returns Parsed CallerToken with callerId, issuedAt, and nonce.
 * @throws MociError with code CALLER_TOKEN_INVALID or CALLER_TOKEN_EXPIRED.
 */
export function verifyCallerToken(token: string): CallerToken {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
  } catch {
    throw new MociError("CALLER_TOKEN_INVALID", "Cannot decode caller token");
  }
  if (
    typeof parsed.callerId !== "string" ||
    typeof parsed.issuedAt !== "number"
  ) {
    throw new MociError("CALLER_TOKEN_INVALID", "Bad token structure");
  }
  if (Date.now() - parsed.issuedAt > CALLER_TOKEN_MAX_AGE_MS) {
    throw new MociError("CALLER_TOKEN_EXPIRED", "Caller token expired");
  }
  return parsed as unknown as CallerToken;
}

// ── Default summarizer ──────────────────────────────────────────────

/**
 * Default summarizer: joins entry contents with " | " and truncates to 512 bytes.
 * Used as fallback when the caller-provided summarizer fails after all retries.
 *
 * @param entries - Memory entries to summarize.
 * @returns Concatenated and truncated summary string.
 */
export function defaultSummarizer(entries: MemoryEntry[]): string {
  const joined = entries.map((e) => e.content).join(" | ");
  const bytes = ENCODER.encode(joined);
  if (bytes.length <= 512) return joined;
  return new TextDecoder().decode(bytes.slice(0, 512));
}

// ── Memory write gate ───────────────────────────────────────────────

/**
 * Write a new memory entry to Ring 0 with full gate checks.
 * Pipeline: verify caller → check rate limits → check size → sanitize → HMAC sign → append.
 *
 * When Ring 0 is at ≥90% capacity, heartbeat entries are dropped before rejecting writes.
 *
 * @param identity - The identity to write to (mutated in-place).
 * @param content - Raw memory content.
 * @param source - Source tag (e.g. "heartbeat", "skill:moci").
 * @param callerToken - Base64-encoded caller token for authentication.
 * @param hmacKey - HMAC signing key.
 * @returns WriteResult indicating success or failure with reason.
 */
export function addMemory(
  identity: MociIdentity,
  content: string,
  source: string,
  callerToken: string,
  hmacKey: string,
): WriteResult {
  let caller: CallerToken;
  try {
    caller = verifyCallerToken(callerToken);
  } catch (e) {
    return { success: false, error: `Auth: ${(e as MociError).message}` };
  }

  if (!ALLOWED_WRITERS.includes(caller.callerId)) {
    return { success: false, error: `Writer not allowed: ${caller.callerId}` };
  }

  if (Date.now() < identity.meta.write_cooldown_until) {
    return { success: false, error: "Rate cooldown active" };
  }

  const recent = identity.memory.ring0.filter(
    (e) => e.timestamp > Date.now() - 3_600_000,
  ).length;
  if (recent >= RING0_MAX_ENTRIES_PER_HOUR) {
    identity.meta.write_cooldown_until = Date.now() + COOLDOWN_ON_BREACH_MS;
    return { success: false, error: "Rate limit exceeded" };
  }

  const contentBytes = byteLength(content);
  if (contentBytes > RING0_MAX_BYTES_PER_ENTRY) {
    return { success: false, error: `Too large: ${contentBytes}b` };
  }

  const budgetResult = ensureRing0Budget(identity, contentBytes);
  if (!budgetResult.ok) {
    return { success: false, error: "Ring 0 budget full" };
  }

  const sanitized = sanitizeForLLM(content);
  identity.meta.memory_seq += 1;
  const seq = identity.meta.memory_seq;
  const ts = getMonotonicTimestamp(identity.meta);
  const hmac = hmacSha256(sanitized + source + ts + seq, hmacKey);

  const maxSeq = identity.memory.ring0.reduce(
    (m, e) => Math.max(m, e.seq),
    0,
  );
  if (seq <= maxSeq) {
    return { success: false, error: "Replay detected" };
  }

  identity.memory.ring0.push({
    seq,
    timestamp: ts,
    content: sanitized,
    source,
    writer: caller.callerId,
    hmac,
  });
  return { success: true, seq };
}

/**
 * Check Ring 0 budget, dropping heartbeat entries at ≥90% capacity if needed.
 */
function ensureRing0Budget(
  identity: MociIdentity,
  contentBytes: number,
): { ok: boolean } {
  let r0size = byteLength(JSON.stringify(identity.memory.ring0));
  if (r0size + contentBytes <= RING0_MAX_TOTAL_BYTES) return { ok: true };

  const threshold = Math.floor(
    RING0_MAX_TOTAL_BYTES * RING0_OVERFLOW_THRESHOLD,
  );
  if (r0size >= threshold) {
    identity.memory.ring0 = identity.memory.ring0.filter(
      (e) => e.source !== "heartbeat",
    );
    r0size = byteLength(JSON.stringify(identity.memory.ring0));
  }

  return { ok: r0size + contentBytes <= RING0_MAX_TOTAL_BYTES };
}

// ── Summarizer retry ────────────────────────────────────────────────

async function callSummarizerWithRetry(
  entries: MemoryEntry[],
  summarizer: (entries: MemoryEntry[]) => Promise<string>,
  errors: string[],
): Promise<string> {
  try {
    return await summarizer(entries);
  } catch (e) {
    errors.push(`Summarizer failed: ${(e as Error).message}`);
  }

  for (let retry = 0; retry < PROMOTION_MAX_RETRIES; retry++) {
    await sleep(PROMOTION_RETRY_DELAYS_MS[retry]);
    try {
      return await summarizer(entries);
    } catch (e) {
      errors.push(
        `Summarizer retry ${retry + 1} failed: ${(e as Error).message}`,
      );
    }
  }

  errors.push("promotion_fallback");
  return defaultSummarizer(entries);
}

/**
 * Apply escalation filtering and byte-limit truncation to a summary string.
 */
function postProcessSummary(
  summary: string,
  maxBytes: number,
  errors: string[],
): string {
  let result = summary;
  if (containsEscalation(result)) {
    result = "[REDACTED: injection]";
    errors.push("Escalation in summary");
  }
  if (byteLength(result) > maxBytes) {
    result = result.slice(0, maxBytes - 20) + " [truncated]";
  }
  return result;
}

// ── Ring 0 integrity verification ───────────────────────────────────

function verifyRing0Integrity(
  ring0: MemoryEntry[],
  hmacKey: string,
  errors: string[],
): MemoryEntry[] {
  const valid: MemoryEntry[] = [];
  for (const entry of ring0) {
    const expected = hmacSha256(
      entry.content + (entry.source || "") + entry.timestamp + entry.seq,
      hmacKey,
    );
    if (!timingSafeEqual(entry.hmac, expected)) {
      errors.push(`HMAC fail seq=${entry.seq}`);
    } else {
      valid.push(entry);
    }
  }
  return valid;
}

// ── Ring promotion ──────────────────────────────────────────────────

/**
 * Promote memory entries through the ring hierarchy: Ring 0→1→2→3.
 * Validates HMAC integrity, summarizes via callback with retry/fallback,
 * and extends the Ring 3 hash chain.
 *
 * Retry policy: on summarizer failure, retries 3 times (1s → 5s → 30s backoff),
 * then falls back to defaultSummarizer to preserve chain continuity.
 *
 * @param identity - The identity whose memory rings to promote (mutated in-place).
 * @param summarizer - Async callback that summarizes a batch of entries.
 * @param hmacKey - HMAC key for verifying and signing entries.
 * @returns PromotionResult with stats, new chain head, and any errors/warnings.
 */
export async function promoteRings(
  identity: MociIdentity,
  summarizer: (entries: MemoryEntry[]) => Promise<string>,
  hmacKey: string,
): Promise<PromotionResult> {
  const now = Date.now();
  const errors: string[] = [];
  let entriesPromoted = 0;
  const sizeBefore = byteLength(JSON.stringify(identity.memory));

  const valid = verifyRing0Integrity(identity.memory.ring0, hmacKey, errors);

  for (let i = 1; i < valid.length; i++) {
    if (valid[i].seq <= valid[i - 1].seq) {
      errors.push(`Seq break: ${valid[i].seq}`);
      return { success: false, entriesPromoted: 0, bytesFreed: 0, errors };
    }
  }

  if (valid.length > 5) {
    const counts = new Map<string, number>();
    for (const e of valid) {
      counts.set(e.writer, (counts.get(e.writer) || 0) + 1);
    }
    for (const [w, n] of counts) {
      if (n / valid.length > 0.8) {
        errors.push(`WARN: ${w} wrote ${n}/${valid.length}`);
      }
    }
  }

  if (valid.length > 0) {
    const cleaned = valid.map((e) => ({
      ...e,
      content: sanitizeForLLM(e.content),
    }));
    let summary = await callSummarizerWithRetry(cleaned, summarizer, errors);
    summary = postProcessSummary(summary, RING1_MAX_BYTES_PER_ENTRY, errors);
    const hmac = hmacSha256(summary + now + "ring0_promotion", hmacKey);
    identity.memory.ring1.push({
      seq: identity.meta.memory_seq + 1,
      timestamp: now,
      content: summary,
      source: "ring0_promotion",
      writer: "system:promoter",
      hmac,
    });
    entriesPromoted += valid.length;
    identity.memory.ring0 = [];
  }

  entriesPromoted += await promoteRing1ToRing2(
    identity,
    now,
    summarizer,
    hmacKey,
    errors,
  );

  entriesPromoted += promoteRing2ToRing3(identity, now);

  identity.meta.promotion_counter += 1;
  identity.meta.last_promotion_at = now;

  if (!verifyRing3Chain(identity)) {
    errors.push("CRITICAL: Ring 3 chain broken");
    return { success: false, entriesPromoted, bytesFreed: 0, errors };
  }

  const sizeAfter = byteLength(JSON.stringify(identity.memory));
  return {
    success: errors.filter((e) => e.startsWith("CRITICAL")).length === 0,
    entriesPromoted,
    bytesFreed: Math.max(0, sizeBefore - sizeAfter),
    newChainHead:
      identity.memory.ring3_chain[identity.memory.ring3_chain.length - 1].hash,
    errors,
  };
}

async function promoteRing1ToRing2(
  identity: MociIdentity,
  now: number,
  summarizer: (entries: MemoryEntry[]) => Promise<string>,
  hmacKey: string,
  errors: string[],
): Promise<number> {
  const keep: MemoryEntry[] = [];
  const promote: MemoryEntry[] = [];
  for (const e of identity.memory.ring1) {
    (now - e.timestamp > RING1_MAX_AGE_MS ? promote : keep).push(e);
  }

  let promoted = 0;
  if (promote.length > 0) {
    const cleaned = promote.map((e) => ({
      ...e,
      content: sanitizeForLLM(e.content),
    }));
    let digest = await callSummarizerWithRetry(cleaned, summarizer, errors);
    digest = postProcessSummary(digest, RING2_MAX_BYTES_PER_ENTRY, errors);
    const hmac = hmacSha256(digest + now + "ring1_promotion", hmacKey);
    identity.memory.ring2.push({
      seq: identity.meta.memory_seq + 2,
      timestamp: now,
      content: digest,
      source: "ring1_promotion",
      writer: "system:promoter",
      hmac,
    });
    promoted = promote.length;
  }

  identity.memory.ring1 = keep.slice(-RING1_MAX_ENTRIES);
  return promoted;
}

function promoteRing2ToRing3(
  identity: MociIdentity,
  now: number,
): number {
  const keep: MemoryEntry[] = [];
  const archive: MemoryEntry[] = [];
  for (const e of identity.memory.ring2) {
    (now - e.timestamp > RING2_MAX_AGE_MS ? archive : keep).push(e);
  }

  let promoted = 0;
  if (archive.length > 0) {
    const digest = archive.map((e) => e.content).join("|");
    const prev =
      identity.memory.ring3_chain[identity.memory.ring3_chain.length - 1];
    const newHash = keccak256(prev.hash + digest);
    identity.memory.ring3_chain.push({
      hash: newHash,
      input_digest: digest,
      promoted_at: now,
    });
    promoted = archive.length;
  }

  identity.memory.ring2 = keep.slice(-RING2_MAX_ENTRIES);
  return promoted;
}
