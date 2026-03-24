import type { Command } from "commander";
import { validateMociId } from "../core/validate.js";
import { ok, fail, info } from "./helpers.js";

/**
 * Register the `validate` command.
 */
export function registerValidate(program: Command): void {
  program
    .command("validate <id>")
    .description("Validate a MOCI ID format and checksum")
    .action((id: string) => {
      const result = validateMociId(id);
      if (!result.valid) {
        fail(`Invalid: ${result.error}`);
      }
      ok(`Valid MOCI ID: ${id}`);
      if (result.parsed) {
        info(`Name: ${result.parsed.name}`);
        info(`Suffix: ${result.parsed.suffix || "(premium)"}`);
        info(`Checksum: ${result.parsed.checksum}`);
      }
    });
}
