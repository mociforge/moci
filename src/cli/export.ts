import fs from "node:fs";
import type { Command } from "commander";
import { exportIdentity } from "../export/export.js";
import { loadIdentity, ok, fail, info } from "./helpers.js";

/**
 * Register the `export` command.
 */
export function registerExport(program: Command): void {
  program
    .command("export")
    .description("Export identity as an encrypted package")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const exportPass = process.env.MOCI_EXPORT_PASSPHRASE;
        if (!exportPass) {
          fail("Set MOCI_EXPORT_PASSPHRASE env var");
        }

        const { manager, hmacKey } = loadIdentity(opts.id);
        const result = exportIdentity(manager, exportPass, hmacKey);

        fs.writeFileSync(result.filename, result.encryptedData, { mode: 0o600 });

        ok(`Exported to ${result.filename}`);
        info(`Size: ${result.encryptedData.length} bytes`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
