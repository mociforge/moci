import type { Command } from "commander";
import { verifyAuditChain } from "../audit/query.js";
import { loadIdentity, ok, fail } from "./helpers.js";

/**
 * Register the `audit-verify` command.
 */
export function registerAuditVerify(program: Command): void {
  program
    .command("audit-verify")
    .description("Verify audit log HMAC chain integrity")
    .action(() => {
      try {
        const { auditKey } = loadIdentity();
        const result = verifyAuditChain(auditKey);
        if (result.valid) {
          ok("Audit chain is intact");
        } else {
          fail(`Audit chain broken at entry ${result.brokenAt}`);
        }
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
