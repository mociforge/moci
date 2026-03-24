import fs from "node:fs";
import { MociError } from "../core/errors.js";
import type { AuditEvent, AuditChainResult, AuditFilter } from "../core/types.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { timingSafeEqual } from "../crypto/timing.js";
import { getAuditLogPath } from "../storage/paths.js";

/**
 * Verify the HMAC chain integrity of the audit log.
 * Re-derives every entry's HMAC from the chain predecessor and checks
 * it against the stored value using constant-time comparison.
 *
 * @param auditKey - The HMAC key used when the entries were written.
 * @param basePath - Override base directory (for testing).
 * @returns Chain validity and the index of the first broken entry (if any).
 * @throws MociError with code AUDIT_READ_FAILED on I/O errors.
 */
export function verifyAuditChain(
  auditKey: string,
  basePath?: string,
): AuditChainResult {
  const lines = readLogLines(basePath);
  if (lines.length === 0) return { valid: true };

  let prevHmac = "";
  for (let i = 0; i < lines.length; i++) {
    let entry: AuditEvent;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return { valid: false, brokenAt: i };
    }

    const { hmac, ...rest } = entry;
    const expected = hmacSha256(prevHmac + JSON.stringify(rest), auditKey);

    if (!timingSafeEqual(hmac, expected)) {
      return { valid: false, brokenAt: i };
    }
    prevHmac = hmac;
  }

  return { valid: true };
}

/**
 * Query the audit log with optional filters.
 *
 * @param filter - Criteria to narrow results (event type, mociId, time range, limit).
 * @param basePath - Override base directory (for testing).
 * @returns Matching audit entries in chronological order.
 * @throws MociError with code AUDIT_READ_FAILED on I/O errors.
 */
export function queryAuditLog(
  filter: AuditFilter,
  basePath?: string,
): AuditEvent[] {
  const lines = readLogLines(basePath);
  const results: AuditEvent[] = [];

  for (const line of lines) {
    let entry: AuditEvent;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }

    if (filter.event && entry.event !== filter.event) continue;
    if (filter.mociId && entry.moci_id !== filter.mociId) continue;
    if (filter.after !== undefined && entry.timestamp <= filter.after) continue;
    if (filter.before !== undefined && entry.timestamp >= filter.before) continue;

    results.push(entry);
    if (filter.limit && results.length >= filter.limit) break;
  }

  return results;
}

/** Read the audit log file into trimmed, non-empty lines. */
function readLogLines(basePath?: string): string[] {
  const logPath = getAuditLogPath(basePath);
  if (!fs.existsSync(logPath)) return [];

  try {
    const content = fs.readFileSync(logPath, "utf8").trim();
    if (!content) return [];
    return content.split("\n").filter(Boolean);
  } catch (e) {
    throw new MociError(
      "AUDIT_READ_FAILED",
      `Cannot read audit log: ${(e as Error).message}`,
    );
  }
}
