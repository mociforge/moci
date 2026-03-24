import fs from "node:fs";
import type { Command } from "commander";
import { queryAuditLog } from "../audit/query.js";
import { ok, fail } from "./helpers.js";

/**
 * Register the `audit-export` command.
 */
export function registerAuditExport(program: Command): void {
  program
    .command("audit-export")
    .description("Export audit log to a file")
    .requiredOption("--format <fmt>", "Output format (json)")
    .requiredOption("--output <file>", "Output file path")
    .action((opts: { format: string; output: string }) => {
      try {
        if (opts.format !== "json") {
          fail(`Unsupported format: ${opts.format}`);
        }
        const entries = queryAuditLog({});
        fs.writeFileSync(opts.output, JSON.stringify(entries, null, 2));
        ok(`Exported ${entries.length} entries to ${opts.output}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
