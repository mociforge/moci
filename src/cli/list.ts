import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getIdentitiesDir } from "../storage/paths.js";
import { info } from "./helpers.js";

/**
 * Register the `list` command.
 */
export function registerList(program: Command): void {
  program
    .command("list")
    .description("List all identities on this device")
    .action(() => {
      const dir = getIdentitiesDir();
      if (!fs.existsSync(dir)) {
        console.log("No identities found.");
        return;
      }
      const entries = fs.readdirSync(dir).filter((e) => {
        const full = path.join(dir, e);
        return fs.statSync(full).isDirectory() && e.startsWith("CW-");
      });
      if (entries.length === 0) {
        console.log("No identities found.");
        return;
      }
      console.log(`Found ${entries.length} identity(ies):`);
      for (const e of entries) {
        info(e);
      }
    });
}
