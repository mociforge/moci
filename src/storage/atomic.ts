import fs from "node:fs";
import crypto from "node:crypto";
import { MociError } from "../core/errors.js";

const DEFAULT_MODE = 0o600;

/**
 * Write a file atomically: write to temp → fsync → rename.
 * Guarantees the target file is either fully new or fully old, never half-written.
 *
 * @param filepath - Target file path.
 * @param content - String content to write.
 * @param mode - File permission mode (default 0o600).
 * @throws MociError with code ATOMIC_WRITE_FAILED on any I/O error.
 */
export function atomicWriteFile(
  filepath: string,
  content: string,
  mode: number = DEFAULT_MODE,
): void {
  const tmpPath = filepath + ".tmp." + crypto.randomBytes(4).toString("hex");
  try {
    fs.writeFileSync(tmpPath, content, { mode });
    const fd = fs.openSync(tmpPath, "r+");
    try {
      fs.fdatasyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, filepath);
  } catch (e) {
    try { fs.unlinkSync(tmpPath); } catch { /* best-effort cleanup */ }
    if (e instanceof MociError) throw e;
    throw new MociError("ATOMIC_WRITE_FAILED", `Atomic write failed for ${filepath}: ${(e as Error).message}`);
  }
}

/**
 * Read a file, throwing a typed error if it does not exist.
 *
 * @param filepath - Path to the file to read.
 * @returns The file contents as a UTF-8 string.
 * @throws MociError with code FILE_NOT_FOUND if the file is missing.
 * @throws MociError with code FILE_READ_FAILED on other I/O errors.
 */
export function atomicReadFile(filepath: string): string {
  if (!fs.existsSync(filepath)) {
    throw new MociError("FILE_NOT_FOUND", `File not found: ${filepath}`);
  }
  try {
    return fs.readFileSync(filepath, "utf8");
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("FILE_READ_FAILED", `Failed to read ${filepath}: ${(e as Error).message}`);
  }
}
