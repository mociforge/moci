import path from "node:path";
import os from "node:os";
import type { Command } from "commander";
import { generateSkillKey } from "../cit/keypin.js";
import { ok, fail, info } from "./helpers.js";

/**
 * Register the `keygen` command.
 */
export function registerKeygen(program: Command): void {
  program
    .command("keygen <skill-name>")
    .description("Generate an HMAC key for a skill")
    .action((skillName: string) => {
      try {
        const skillDir = path.join(os.homedir(), ".openclaw", "skills");
        const key = generateSkillKey(skillName, skillDir);

        ok(`Generated key for skill "${skillName}"`);
        info(`Key file: ${path.join(skillDir, skillName + ".key")}`);
        info(`Key (hex): ${key.slice(0, 8)}...`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
