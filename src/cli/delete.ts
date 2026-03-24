import type { Command } from "commander";
import { deletePermanent } from "../core/lifecycle.js";
import { loadIdentity, createAuditLogger, ok, fail } from "./helpers.js";

/**
 * Register the `delete` command.
 */
export function registerDelete(program: Command): void {
  program
    .command("delete")
    .description("Permanently delete a revoked identity")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .requiredOption("--confirm", "Confirm deletion (required)")
    .action((opts: { id?: string; confirm?: boolean }) => {
      try {
        if (!opts.confirm) {
          fail("Pass --confirm to permanently delete an identity");
        }

        const { manager, auditKey } = loadIdentity(opts.id);
        const logger = createAuditLogger(auditKey);
        const mociId = manager.identity!.moci_id;
        deletePermanent(manager, logger);

        ok(`Deleted ${mociId}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
