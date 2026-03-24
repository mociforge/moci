import fs from "node:fs";
import { MociError } from "../core/errors.js";
import { getTombstonePath } from "./paths.js";

/**
 * Append a MOCI ID to the tombstone list.
 * Prevents re-registration of a deleted identity.
 *
 * @param mociId - The MOCI ID to tombstone.
 * @param basePath - Override base directory (for testing).
 * @throws MociError with code TOMBSTONE_WRITE_FAILED on I/O errors.
 */
export function addTombstone(mociId: string, basePath?: string): void {
  const tombPath = getTombstonePath(basePath);
  try {
    fs.appendFileSync(tombPath, mociId + "\n", { mode: 0o600 });
  } catch (e) {
    throw new MociError(
      "TOMBSTONE_WRITE_FAILED",
      `Cannot write tombstone for ${mociId}: ${(e as Error).message}`,
    );
  }
}

/**
 * Check whether a MOCI ID has been tombstoned (deleted and permanently blocked).
 *
 * @param mociId - The MOCI ID to check.
 * @param basePath - Override base directory (for testing).
 * @returns True if the ID is in the tombstone list.
 */
export function isTombstoned(mociId: string, basePath?: string): boolean {
  const tombPath = getTombstonePath(basePath);
  if (!fs.existsSync(tombPath)) return false;
  try {
    const content = fs.readFileSync(tombPath, "utf8");
    return content.split("\n").some((line) => line.trim() === mociId);
  } catch {
    return false;
  }
}

/**
 * List all tombstoned MOCI IDs.
 *
 * @param basePath - Override base directory (for testing).
 * @returns Array of tombstoned MOCI ID strings.
 * @throws MociError with code TOMBSTONE_READ_FAILED on I/O errors.
 */
export function listTombstones(basePath?: string): string[] {
  const tombPath = getTombstonePath(basePath);
  if (!fs.existsSync(tombPath)) return [];
  try {
    const content = fs.readFileSync(tombPath, "utf8");
    return content.split("\n").map((l) => l.trim()).filter(Boolean);
  } catch (e) {
    throw new MociError(
      "TOMBSTONE_READ_FAILED",
      `Cannot read tombstones: ${(e as Error).message}`,
    );
  }
}
