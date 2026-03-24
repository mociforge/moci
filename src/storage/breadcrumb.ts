import fs from "node:fs";
import { MociError } from "../core/errors.js";
import { getCounterPath } from "./paths.js";
import { atomicWriteFile } from "./atomic.js";

/**
 * Read the monotonic promotion counter from the breadcrumb file.
 * Returns 0 if the file does not exist yet (fresh install).
 *
 * @param basePath - Override base directory (for testing).
 * @returns The current counter value.
 * @throws MociError with code BREADCRUMB_READ_FAILED on parse/read errors.
 */
export function readBreadcrumb(basePath?: string): number {
  const counterPath = getCounterPath(basePath);

  if (!fs.existsSync(counterPath)) {
    return 0;
  }

  try {
    const raw = fs.readFileSync(counterPath, "utf8").trim();
    const value = parseInt(raw, 10);
    if (Number.isNaN(value)) {
      throw new MociError("BREADCRUMB_READ_FAILED", "Breadcrumb file contains non-numeric data");
    }
    return value;
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("BREADCRUMB_READ_FAILED", `Cannot read breadcrumb: ${(e as Error).message}`);
  }
}

/**
 * Write the promotion counter atomically to the breadcrumb file.
 *
 * @param count - The counter value to persist.
 * @param basePath - Override base directory (for testing).
 * @throws MociError with code BREADCRUMB_WRITE_FAILED on I/O errors.
 */
export function writeBreadcrumb(count: number, basePath?: string): void {
  const counterPath = getCounterPath(basePath);
  try {
    atomicWriteFile(counterPath, String(count));
  } catch (e) {
    if (e instanceof MociError) throw e;
    throw new MociError("BREADCRUMB_WRITE_FAILED", `Cannot write breadcrumb: ${(e as Error).message}`);
  }
}
