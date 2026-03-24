import type { Command } from "commander";
import { verifyRing3Chain } from "../core/verify.js";
import { loadIdentity, ok, fail, info } from "./helpers.js";

/**
 * Register the `verify` command.
 */
export function registerVerify(program: Command): void {
  program
    .command("verify")
    .description("Verify identity integrity (layer-0 + Ring 3 chain)")
    .option("--id <id>", "MOCI ID (defaults to first found)")
    .action((opts: { id?: string }) => {
      try {
        const { manager } = loadIdentity(opts.id);
        const identity = manager.identity!;

        const chainOk = verifyRing3Chain(identity);
        if (!chainOk) {
          fail("Ring 3 chain integrity check failed");
        }

        ok("Identity verified");
        info(`ID: ${identity.moci_id}`);
        info(`Ring 3 chain: ${identity.memory.ring3_chain.length} entries — intact`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
