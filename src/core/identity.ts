import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { MociError } from "./errors.js";
import { DISK_SPACE_MIN_BYTES } from "./constants.js";
import type { MociIdentity, MemoryEntry } from "./types.js";
import { keccak256, verifyCryptoIntegrity } from "../crypto/keccak.js";
import { timingSafeEqual } from "../crypto/timing.js";
import { encrypt, decrypt } from "../crypto/aes.js";
import {
  getIdentityDir,
  getIdentityFilePath,
  getIdentityBackupPath,
  getBaseDir,
  getIdentitiesDir,
} from "../storage/paths.js";
import { atomicWriteFile, atomicReadFile } from "../storage/atomic.js";
import { readBreadcrumb, writeBreadcrumb } from "../storage/breadcrumb.js";

/**
 * Manages loading, saving, and lifecycle of a MOCI identity on disk.
 *
 * Responsibilities:
 * - Encrypted persistence with AES-256-GCM
 * - Ring 3 chain integrity verification on load
 * - Anti-rollback via breadcrumb counter
 * - Automatic backup on save
 * - Graceful shutdown on SIGTERM/SIGINT
 */
export class MociIdentityManager {
  private _identity: MociIdentity | null = null;
  private _basePath: string | undefined;
  private _readOnly = false;
  private _shutdownRegistered = false;
  private _legacyFingerprintWarning = false;

  /**
   * @param basePath - Override base directory (for testing). Omit for production (~/.openclaw/).
   * @throws MociError with code CRYPTO_SELF_TEST_FAILED if the keccak-256 implementation
   *         does not produce the expected reference digests.
   */
  constructor(basePath?: string) {
    if (!verifyCryptoIntegrity()) {
      throw new MociError(
        "CRYPTO_SELF_TEST_FAILED",
        "Cryptographic library integrity check failed. The keccak256 implementation may have been tampered with. Refusing to start.",
      );
    }
    this._basePath = basePath;
  }

  /**
   * The currently loaded identity, or null if none is loaded.
   */
  get identity(): MociIdentity | null {
    return this._identity;
  }

  /**
   * Whether the manager is in read-only mode (disk-full emergency).
   */
  get readOnly(): boolean {
    return this._readOnly;
  }

  /**
   * The base path used for storage (undefined = default ~/.openclaw/).
   */
  get basePath(): string | undefined {
    return this._basePath;
  }

  /**
   * True when the most recent load() succeeded only via a legacy (pre-hardware-binding)
   * fingerprint. The caller should advise the user to run `moci migrate-fingerprint`.
   */
  get usedLegacyFingerprint(): boolean {
    return this._legacyFingerprintWarning;
  }

  /**
   * Load an identity from disk, decrypt it, verify its integrity.
   *
   * Checks performed:
   * 1. Decrypt with passphrase
   * 2. Parse JSON
   * 3. Verify Ring 3 chain hashes
   * 4. Breadcrumb anti-rollback (1-behind tolerance for crash recovery)
   *
   * Falls back to .bak file if primary is corrupted.
   * When a legacyPassphrase is supplied the loader will attempt decryption
   * with the primary passphrase first and, on failure, retry with the legacy
   * one to support the v0.1.0→v0.2.0 fingerprint migration.
   *
   * @param mociId - The MOCI ID to load.
   * @param passphrase - Decryption passphrase (Tier 2) or device-derived key.
   * @param legacyPassphrase - Optional pre-hardware-binding fingerprint (v0.1.0 compat).
   * @returns The loaded MociIdentity.
   * @throws MociError with code IDENTITY_NOT_FOUND, IDENTITY_CORRUPTED, or BREADCRUMB_ROLLBACK_DETECTED.
   */
  load(mociId: string, passphrase: string, legacyPassphrase?: string): MociIdentity {
    const primaryPath = getIdentityFilePath(mociId, this._basePath);
    const backupPath = getIdentityBackupPath(mociId, this._basePath);

    let identity: MociIdentity | null = null;
    let usedLegacy = false;

    identity = this._tryLoad(primaryPath, passphrase);
    if (!identity) {
      identity = this._tryLoad(backupPath, passphrase);
    }

    if (!identity && legacyPassphrase) {
      identity = this._tryLoad(primaryPath, legacyPassphrase);
      if (!identity) {
        identity = this._tryLoad(backupPath, legacyPassphrase);
      }
      if (identity) usedLegacy = true;
    }

    if (!identity) {
      throw new MociError("IDENTITY_NOT_FOUND", `Identity not found: ${mociId}`);
    }

    if (usedLegacy) {
      this._legacyFingerprintWarning = true;
    }

    this._verifyRing3Chain(identity);
    this._checkBreadcrumb(identity);

    this._identity = identity;
    this._recoverPendingRing0(identity);
    this._registerShutdownHandler();
    return identity;
  }

  /**
   * Save the current identity to disk.
   *
   * Performs: encrypt → atomic write → update backup → update breadcrumb.
   * Checks free disk space before writing; enters read-only mode if below 1 MB.
   *
   * @param passphrase - Encryption passphrase.
   * @throws MociError with code DISK_FULL or FILE_WRITE_FAILED.
   */
  save(passphrase: string): void {
    if (!this._identity) {
      throw new MociError("IDENTITY_NOT_FOUND", "No identity loaded to save");
    }
    if (this._readOnly) {
      throw new MociError("DISK_FULL", "Manager is in read-only mode due to low disk space");
    }

    this._checkDiskSpace();

    const idDir = getIdentityDir(this._identity.moci_id, this._basePath);
    const primaryPath = getIdentityFilePath(this._identity.moci_id, this._basePath);
    const backupPath = getIdentityBackupPath(this._identity.moci_id, this._basePath);

    this._ensureDir(getBaseDir(this._basePath));
    this._ensureDir(getIdentitiesDir(this._basePath));
    this._ensureDir(idDir);

    const plaintext = JSON.stringify(this._identity);
    const payload = encrypt(plaintext, passphrase);
    const serialized = JSON.stringify(payload);

    atomicWriteFile(primaryPath, serialized);
    atomicWriteFile(backupPath, serialized);
    writeBreadcrumb(this._identity.meta.promotion_counter, this._basePath);

    const pendingPath = this._pendingRing0Path();
    if (pendingPath && fs.existsSync(pendingPath)) {
      try { fs.unlinkSync(pendingPath); } catch { /* best-effort */ }
    }
  }

  /**
   * Set the loaded identity directly (used after generateMociId).
   *
   * @param identity - A freshly generated MociIdentity.
   */
  setIdentity(identity: MociIdentity): void {
    this._identity = identity;
    this._registerShutdownHandler();
  }

  /**
   * Check whether the filesystem at basePath supports Unix permissions.
   * Returns false on FAT32, some network drives, etc.
   *
   * @returns True if mode bits are respected.
   */
  checkPermissionSupport(): boolean {
    const baseDir = getBaseDir(this._basePath);
    this._ensureDir(baseDir);

    const testPath = `${baseDir}/.perm-test-${Date.now()}`;
    try {
      fs.writeFileSync(testPath, "", { mode: 0o600 });
      const stat = fs.statSync(testPath);
      const mode = stat.mode & 0o777;
      return mode === 0o600;
    } catch {
      return false;
    } finally {
      try { fs.unlinkSync(testPath); } catch { /* best-effort */ }
    }
  }

  // --- Private helpers ---

  private _tryLoad(filePath: string, passphrase: string): MociIdentity | null {
    if (!fs.existsSync(filePath)) return null;
    try {
      const raw = atomicReadFile(filePath);
      const payload = JSON.parse(raw);
      const plaintext = decrypt(payload, passphrase);
      const identity = JSON.parse(plaintext) as MociIdentity;
      return identity;
    } catch (e) {
      if (e instanceof MociError && e.code === "DECRYPT_FAILED") return null;
      return null;
    }
  }

  private _verifyRing3Chain(identity: MociIdentity): void {
    const chain = identity.memory.ring3_chain;
    if (chain.length === 0) {
      throw new MociError("RING3_CHAIN_EMPTY", "Ring 3 chain is empty");
    }
    if (!chain[0].hash || chain[0].hash.length !== 64) {
      throw new MociError("RING3_HASH_INVALID", "Genesis hash is malformed");
    }

    for (let i = 1; i < chain.length; i++) {
      const entry = chain[i];
      if (!entry.hash || entry.hash.length !== 64 || !entry.input_digest) {
        throw new MociError("RING3_HASH_INVALID", `Ring 3 entry ${i} is malformed`);
      }
      const recomputed = keccak256(chain[i - 1].hash + entry.input_digest);
      if (!timingSafeEqual(recomputed, entry.hash)) {
        throw new MociError("RING3_CHAIN_BROKEN", `Ring 3 chain broken at entry ${i}`);
      }
    }
  }

  private _checkBreadcrumb(identity: MociIdentity): void {
    const stored = readBreadcrumb(this._basePath);
    const current = identity.meta.promotion_counter;

    if (stored === 0) return;

    // 1-behind tolerance: crash during save leaves breadcrumb at counter-1
    if (stored === current - 1) {
      writeBreadcrumb(current, this._basePath);
      return;
    }

    if (stored < current - 1) {
      throw new MociError(
        "BREADCRUMB_ROLLBACK_DETECTED",
        `Breadcrumb counter ${stored} is behind identity counter ${current} — possible rollback attack`,
      );
    }
    // stored >= current is fine (breadcrumb may be ahead after crash recovery)
  }

  private _checkDiskSpace(): void {
    const baseDir = getBaseDir(this._basePath);
    this._ensureDir(baseDir);
    const testPath = path.join(baseDir, `.disk-check-${Date.now()}`);
    try {
      const testData = Buffer.alloc(DISK_SPACE_MIN_BYTES, 0);
      fs.writeFileSync(testPath, testData, { mode: 0o600 });
      fs.unlinkSync(testPath);
    } catch (e) {
      try { fs.unlinkSync(testPath); } catch { /* best-effort cleanup */ }
      if ((e as NodeJS.ErrnoException).code === "ENOSPC") {
        this._readOnly = true;
        throw new MociError("DISK_FULL", "Disk space insufficient — entering read-only mode");
      }
    }
  }

  private _ensureDir(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
    }
  }

  private _pendingRing0Path(): string {
    if (!this._identity) return "";
    return path.join(
      getIdentityDir(this._identity.moci_id, this._basePath),
      ".ring0-pending",
    );
  }

  private _recoverPendingRing0(identity: MociIdentity): void {
    const pendingPath = path.join(
      getIdentityDir(identity.moci_id, this._basePath),
      ".ring0-pending",
    );
    if (!fs.existsSync(pendingPath)) return;
    try {
      const data = JSON.parse(fs.readFileSync(pendingPath, "utf8"));
      if (Array.isArray(data)) {
        const maxSeq = identity.memory.ring0.reduce(
          (m: number, e: MemoryEntry) => Math.max(m, e.seq), 0,
        );
        const recovered = (data as MemoryEntry[]).filter((e) => e.seq > maxSeq);
        identity.memory.ring0.push(...recovered);
      }
      fs.unlinkSync(pendingPath);
    } catch {
      try { fs.unlinkSync(pendingPath); } catch { /* discard corrupt pending */ }
    }
  }

  private _registerShutdownHandler(): void {
    if (this._shutdownRegistered) return;
    this._shutdownRegistered = true;

    const handler = () => {
      if (this._identity && this._identity.memory.ring0.length > 0) {
        try {
          const pendingPath = this._pendingRing0Path();
          if (pendingPath) {
            const dir = path.dirname(pendingPath);
            this._ensureDir(dir);
            fs.writeFileSync(
              pendingPath,
              JSON.stringify(this._identity.memory.ring0),
              { mode: 0o600 },
            );
          }
        } catch { /* best-effort — lose at most Ring 0 data */ }
      }
      process.exit(0);
    };

    process.on("SIGTERM", handler);
    process.on("SIGINT", handler);
  }
}
