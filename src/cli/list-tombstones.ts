import type { Command } from "commander";
import { listTombstones } from "../storage/tombstone.js";
import { info } from "./helpers.js";

/**
 * Register the `list-tombstones` command.
 */
export function registerListTombstones(program: Command): void {
  program
    .command("list-tombstones")
    .description("List all tombstoned (permanently revoked) identities")
    .action(() => {
      const tombstones = listTombstones();
      if (tombstones.length === 0) {
        console.log("No tombstones.");
        return;
      }
      console.log(`Found ${tombstones.length} tombstone(s):`);
      for (const t of tombstones) {
        info(t);
      }
    });
}
