import fs from "node:fs";
import type { Command } from "commander";
import { getAuditLogPath } from "../storage/paths.js";
import { fail } from "./helpers.js";

/**
 * Register the `audit-tail` command.
 */
export function registerAuditTail(program: Command): void {
  program
    .command("audit-tail")
    .description("Show the last N audit log entries")
    .option("--lines <n>", "Number of lines to show", "20")
    .action((opts: { lines: string }) => {
      try {
        const n = parseInt(opts.lines, 10);
        const logPath = getAuditLogPath();
        if (!fs.existsSync(logPath)) {
          console.log("(no audit log)");
          return;
        }
        const content = fs.readFileSync(logPath, "utf8").trim();
        if (!content) {
          console.log("(empty audit log)");
          return;
        }
        const lines = content.split("\n");
        const tail = lines.slice(-n);
        for (const line of tail) {
          try {
            const entry = JSON.parse(line);
            console.log(
              `[${new Date(entry.timestamp).toISOString()}] ${entry.event} — ${entry.moci_id}`,
            );
          } catch {
            console.log(line);
          }
        }
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
