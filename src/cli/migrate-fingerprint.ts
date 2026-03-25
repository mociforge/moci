import fs from "node:fs";
import type { Command } from "commander";
import { MociIdentityManager } from "../core/identity.js";
import { deriveDeviceFingerprint, deriveLegacyDeviceFingerprint } from "../storage/salt.js";
import { getIdentityFilePath } from "../storage/paths.js";
import { findFirstIdentity, deriveKeys, ok, fail, info } from "./helpers.js";
import { AuditLogger } from "../audit/logger.js";

/**
 * Register the `migrate-fingerprint` command.
 * Re-encrypts an identity from the legacy (v0.1.0) fingerprint to the
 * new hardware-bound fingerprint.
 */
export function registerMigrateFingerprint(program: Command): void {
  program
    .command("migrate-fingerprint")
    .description("Migrate identity encryption to hardware-bound fingerprint")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const mociId = opts.id ?? findFirstIdentity();
        const legacySecret = deriveLegacyDeviceFingerprint(mociId);
        const newSecret = deriveDeviceFingerprint(mociId);

        if (legacySecret === newSecret) {
          info("Hardware machine ID is unavailable — fingerprints are identical. No migration needed.");
          return;
        }

        const manager = new MociIdentityManager();

        // Try loading with the legacy fingerprint.
        manager.load(mociId, legacySecret);

        // Save a backup of the original encrypted file before overwriting.
        const primaryPath = getIdentityFilePath(mociId);
        if (fs.existsSync(primaryPath)) {
          const backupV01 = primaryPath + ".v01";
          fs.copyFileSync(primaryPath, backupV01);
        }

        manager.save(newSecret);

        const identity = manager.identity!;
        const keys = deriveKeys(mociId, identity.meta.security_tier);
        const logger = new AuditLogger(keys.auditKey);
        logger.log("fingerprint_migrated", mociId, {
          from: "legacy",
          to: "hardware-bound",
        });

        ok("Fingerprint migrated to hardware-bound. Old backup saved as identity.enc.v01");
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
