import type { Command } from "commander";
import { revoke } from "../core/lifecycle.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";
import { loadIdentity, createAuditLogger, ok, fail } from "./helpers.js";

/**
 * Register the `revoke` command.
 */
export function registerRevoke(program: Command): void {
  program
    .command("revoke")
    .description("Permanently revoke an identity")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .requiredOption("--confirm", "Confirm revocation (required)")
    .action((opts: { id?: string; confirm?: boolean }) => {
      try {
        if (!opts.confirm) {
          fail("Pass --confirm to revoke an identity");
        }

        const { manager, auditKey } = loadIdentity(opts.id);
        const logger = createAuditLogger(auditKey);
        revoke(manager, logger);

        const identity = manager.identity!;
        const secret = process.env.MOCI_PASSPHRASE
          ?? deriveDeviceFingerprint(identity.moci_id);
        manager.save(secret);

        ok(`Revoked ${identity.moci_id}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
