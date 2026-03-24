import type { Command } from "commander";
import { queryAuditLog } from "../audit/query.js";
import { fail } from "./helpers.js";

/**
 * Register the `audit-query` command.
 */
export function registerAuditQuery(program: Command): void {
  program
    .command("audit-query")
    .description("Query audit log by event type and time range")
    .requiredOption("--event <type>", "Event type to filter")
    .option("--last <duration>", "Time window, e.g. '1h', '7d'")
    .action((opts: { event: string; last?: string }) => {
      try {
        let after: number | undefined;
        if (opts.last) {
          after = Date.now() - parseDuration(opts.last);
        }
        const entries = queryAuditLog({ event: opts.event, after });
        if (entries.length === 0) {
          console.log("No matching entries.");
          return;
        }
        for (const e of entries) {
          console.log(
            `[${new Date(e.timestamp).toISOString()}] ${e.event} — ${e.moci_id}`,
          );
        }
        console.log(`\n${entries.length} entries found.`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}

function parseDuration(s: string): number {
  const m = s.match(/^(\d+)([smhd])$/);
  if (!m) return 3600_000;
  const n = parseInt(m[1], 10);
  const unit = m[2];
  switch (unit) {
    case "s": return n * 1000;
    case "m": return n * 60_000;
    case "h": return n * 3600_000;
    case "d": return n * 86400_000;
    default: return 3600_000;
  }
}
