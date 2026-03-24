import type { Command } from "commander";
import { resume } from "../core/lifecycle.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";
import { loadIdentity, createAuditLogger, ok, fail } from "./helpers.js";

/**
 * Register the `resume` command.
 */
export function registerResume(program: Command): void {
  program
    .command("resume")
    .description("Resume a suspended identity")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const { manager, auditKey } = loadIdentity(opts.id);
        const logger = createAuditLogger(auditKey);
        resume(manager, logger);

        const identity = manager.identity!;
        const secret = process.env.MOCI_PASSPHRASE
          ?? deriveDeviceFingerprint(identity.moci_id);
        manager.save(secret);

        ok(`Resumed ${identity.moci_id}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
