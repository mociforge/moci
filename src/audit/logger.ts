import fs from "node:fs";
import path from "node:path";
import { MociError } from "../core/errors.js";
import { AUDIT_LOG_MAX_BYTES } from "../core/constants.js";
import type { AuditLogger as AuditLoggerInterface, AuditEvent } from "../core/types.js";
import { hmacSha256 } from "../crypto/hmac.js";
import { getAuditLogPath } from "../storage/paths.js";

const MAX_ROTATED_FILES = 3;

/**
 * Append-only audit logger with HMAC-chained integrity.
 *
 * Each entry's HMAC covers the previous entry's HMAC + the current record
 * (excluding the hmac field), forming a tamper-evident chain. The log file
 * auto-rotates when it exceeds 1 MB, retaining the most recent 3 archives.
 */
export class AuditLogger implements AuditLoggerInterface {
  private _auditKey: string;
  private _basePath: string | undefined;
  private _seq: number;
  private _prevHmac: string;

  /**
   * @param auditKey - HMAC key for chaining audit entries.
   * @param basePath - Override base directory (for testing).
   */
  constructor(auditKey: string, basePath?: string) {
    this._auditKey = auditKey;
    this._basePath = basePath;
    const state = this._loadState();
    this._seq = state.seq;
    this._prevHmac = state.prevHmac;
  }

  /**
   * Append an audit event to the log with an HMAC chain link.
   *
   * @param event - Event type name (e.g. "identity_suspended").
   * @param mociId - The MOCI ID associated with this event.
   * @param details - Arbitrary key-value details (must not contain secrets).
   */
  log(event: string, mociId: string, details: Record<string, unknown>): void {
    this._seq += 1;
    const timestamp = Date.now();
    const seq = this._seq;

    const core = { event, moci_id: mociId, timestamp, details, seq };
    const hmac = hmacSha256(this._prevHmac + JSON.stringify(core), this._auditKey);
    this._prevHmac = hmac;

    const entry: AuditEvent = { ...core, hmac };
    this._appendLine(JSON.stringify(entry));
  }

  /** Append a single line to the audit log, rotating if needed. */
  private _appendLine(line: string): void {
    const logPath = getAuditLogPath(this._basePath);
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    this._rotateIfNeeded(logPath);

    try {
      fs.appendFileSync(logPath, line + "\n", { mode: 0o600 });
    } catch (e) {
      throw new MociError(
        "AUDIT_WRITE_FAILED",
        `Cannot append to audit log: ${(e as Error).message}`,
      );
    }
  }

  /** Rotate the current log file when it exceeds the size threshold. */
  private _rotateIfNeeded(logPath: string): void {
    if (!fs.existsSync(logPath)) return;
    try {
      if (fs.statSync(logPath).size < AUDIT_LOG_MAX_BYTES) return;
    } catch {
      return;
    }

    const base = logPath.replace(/\.jsonl$/, "");

    const oldest = `${base}.${MAX_ROTATED_FILES}.jsonl`;
    if (fs.existsSync(oldest)) fs.unlinkSync(oldest);

    for (let i = MAX_ROTATED_FILES - 1; i >= 1; i--) {
      const from = `${base}.${i}.jsonl`;
      const to = `${base}.${i + 1}.jsonl`;
      if (fs.existsSync(from)) fs.renameSync(from, to);
    }

    fs.renameSync(logPath, `${base}.1.jsonl`);
  }

  /** Read the last entry from the current log to resume seq and HMAC chain. */
  private _loadState(): { seq: number; prevHmac: string } {
    const logPath = getAuditLogPath(this._basePath);
    if (!fs.existsSync(logPath)) return { seq: 0, prevHmac: "" };

    try {
      const content = fs.readFileSync(logPath, "utf8").trim();
      if (!content) return { seq: 0, prevHmac: "" };

      const lines = content.split("\n").filter(Boolean);
      if (lines.length === 0) return { seq: 0, prevHmac: "" };

      const last = JSON.parse(lines[lines.length - 1]) as AuditEvent;
      return { seq: last.seq, prevHmac: last.hmac };
    } catch {
      return { seq: 0, prevHmac: "" };
    }
  }
}
