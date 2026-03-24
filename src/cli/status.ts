import type { Command } from "commander";
import { computeTrustScore } from "../core/trust.js";
import { loadIdentity, info, fail } from "./helpers.js";

/**
 * Register the `status` command.
 */
export function registerStatus(program: Command): void {
  program
    .command("status")
    .description("Show identity status and ring statistics")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const { manager } = loadIdentity(opts.id);
        const identity = manager.identity!;
        const trust = computeTrustScore(identity);

        const labels: Record<number, string> = {
          10: "New", 20: "Low", 30: "Low", 40: "Medium",
          50: "Medium", 60: "Good", 70: "Good", 80: "High",
          90: "Very High", 100: "Maximum",
        };
        const bucket = Math.floor(trust / 10) * 10;
        const label = labels[bucket] ?? "Unknown";

        info(`ID:     ${identity.moci_id}`);
        info(`Status: ${identity.meta.status}`);
        info(`Tier:   ${identity.meta.security_tier}`);
        info(`Trust:  ${trust} (${label})`);
        info(`Ring 0: ${identity.memory.ring0.length} entries`);
        info(`Ring 1: ${identity.memory.ring1.length} entries`);
        info(`Ring 2: ${identity.memory.ring2.length} entries`);
        info(`Ring 3: ${identity.memory.ring3_chain.length} hash${identity.memory.ring3_chain.length === 1 ? " (genesis)" : "es"}`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
