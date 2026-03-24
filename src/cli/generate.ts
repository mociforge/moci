import type { Command } from "commander";
import { generateMociId } from "../core/generate.js";
import { MociIdentityManager } from "../core/identity.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";
import { AuditLogger } from "../audit/logger.js";
import { deriveKeys, ok, fail, info } from "./helpers.js";

/**
 * Register the `generate` command.
 */
export function registerGenerate(program: Command): void {
  program
    .command("generate")
    .description("Generate a new MOCI identity")
    .option("--name <n>", "Custom name (2-12 alphanumeric chars)")
    .option("--passphrase", "Use passphrase-based Tier 2 key")
    .option("--owner <email>", "Bind an owner email")
    .action((opts: { name?: string; passphrase?: boolean; owner?: string }) => {
      try {
        const passphrase = opts.passphrase
          ? process.env.MOCI_PASSPHRASE
          : undefined;
        if (opts.passphrase && !passphrase) {
          fail("Set MOCI_PASSPHRASE env var for passphrase-based identity");
        }

        const identity = generateMociId({
          name: opts.name,
          passphrase,
        });

        const manager = new MociIdentityManager();
        manager.setIdentity(identity);

        const secret = passphrase ?? deriveDeviceFingerprint(identity.moci_id);
        manager.save(secret);

        const keys = deriveKeys(
          identity.moci_id,
          identity.meta.security_tier,
          passphrase,
        );
        const logger = new AuditLogger(keys.auditKey);
        logger.log("identity_created", identity.moci_id, {
          tier: identity.meta.security_tier,
        });

        ok(`Created ${identity.moci_id}`);
        info(`Tier: ${identity.meta.security_tier} (${identity.meta.security_tier === 1 ? "device key" : "passphrase"})`);
        info(`Path: ~/.openclaw/identities/${identity.moci_id}/`);
      } catch (e) {
        fail((e as Error).message);
      }
    });
}
