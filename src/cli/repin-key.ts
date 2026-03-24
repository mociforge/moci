import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Command } from "commander";
import { ok, fail, info } from "./helpers.js";

/**
 * Register the `repin-key` command.
 */
export function registerRepinKey(program: Command): void {
  program
    .command("repin-key <skill-name>")
    .description("Delete the existing key pin so the next verify re-pins")
    .action((skillName: string) => {
      try {
        const pinPath = path.join(
          os.homedir(), ".openclaw", "skills", `${skillName}.pin`,
        );
        if (!fs.existsSync(pinPath)) {
          fail(`No pin file for skill "${skillName}"`);
        }
        fs.unlinkSync(pinPath);
        ok(`Re-pinned key for skill "${skillName}"`);
        info("Next CIT verification will establish a new pin.");
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
