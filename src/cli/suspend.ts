import type { Command } from "commander";
import { suspend } from "../core/lifecycle.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";
import { loadIdentity, createAuditLogger, ok, fail } from "./helpers.js";

/**
 * Register the `suspend` command.
 */
export function registerSuspend(program: Command): void {
  program
    .command("suspend")
    .description("Suspend an active identity")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const { manager, auditKey } = loadIdentity(opts.id);
        const logger = createAuditLogger(auditKey);
        suspend(manager, logger);

        const identity = manager.identity!;
        const secret = process.env.MOCI_PASSPHRASE
          ?? deriveDeviceFingerprint(identity.moci_id);
        manager.save(secret);

        ok(`Suspended ${identity.moci_id}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
