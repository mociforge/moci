import fs from "node:fs";
import type { Command } from "commander";
import { importIdentity } from "../export/import.js";
import { MociIdentityManager } from "../core/identity.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";
import { ok, fail, info } from "./helpers.js";

/**
 * Register the `import` command.
 */
export function registerImport(program: Command): void {
  program
    .command("import <file>")
    .description("Import an identity from an encrypted export file")
    .action((file: string) => {
      try {
        const exportPass = process.env.MOCI_EXPORT_PASSPHRASE;
        if (!exportPass) {
          fail("Set MOCI_EXPORT_PASSPHRASE env var");
        }

        if (!fs.existsSync(file)) {
          fail(`File not found: ${file}`);
        }

        const data = fs.readFileSync(file, "utf8");
        const { identity } = importIdentity(data, exportPass);

        const manager = new MociIdentityManager();
        manager.setIdentity(identity);

        const secret = deriveDeviceFingerprint(identity.moci_id);
        manager.save(secret);

        ok(`Imported ${identity.moci_id}`);
        info(`Ring 3 head: ${identity.memory.ring3_chain[identity.memory.ring3_chain.length - 1].hash.slice(0, 16)}...`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
