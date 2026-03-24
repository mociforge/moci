import { MociError } from "./errors.js";
import { IDENTITY_VERSION, GENESIS_PREFIX } from "./constants.js";
import type { MociIdentity, GenerateOptions } from "./types.js";
import { validateName, crc8, crcToBase32 } from "./validate.js";
import { keccak256 } from "../crypto/keccak.js";
import { randomBase32 } from "../crypto/random.js";
import { deriveDeviceFingerprint } from "../storage/salt.js";

/**
 * Generate a new MOCI identity.
 *
 * - Tier 1 (default): secret derived from device fingerprint (no passphrase needed).
 * - Tier 2 (passphrase): secret is the user-provided passphrase.
 * - Genesis hash includes layer0Hash + random nonce for forgery resistance.
 * - Suffix is always 6 Crockford Base32 characters (~30 bits entropy).
 *
 * @param options - Optional name and passphrase.
 * @param basePath - Override base directory for device salt (testing).
 * @returns A fully initialized MociIdentity with genesis Ring 3 entry.
 * @throws MociError with code INVALID_NAME if the name fails validation.
 */
export function generateMociId(
  options: GenerateOptions = {},
  basePath?: string,
): MociIdentity {
  let name: string;
  if (options.name) {
    const check = validateName(options.name);
    if (!check.valid) {
      throw new MociError("INVALID_NAME", check.error!);
    }
    name = check.normalized!;
  } else {
    name = randomBase32(4);
  }

  const suffix = randomBase32(6);
  const body = `CW-${name}.${suffix}`;
  const checksum = crcToBase32(crc8(body));
  const mociId = `${body}-${checksum}`;

  const secret = options.passphrase
    ? options.passphrase
    : deriveDeviceFingerprint(mociId, basePath);
  const layer0Hash = keccak256(mociId + "|" + secret);

  const now = Date.now();
  const genesisNonce = randomBase32(8);
  const genesisInput = `${GENESIS_PREFIX}|${mociId}|${now}|${layer0Hash}|${genesisNonce}`;
  const genesisHash = keccak256(genesisInput);

  return {
    moci_id: mociId,
    layer0_hash: layer0Hash,
    memory: {
      ring0: [],
      ring1: [],
      ring2: [],
      ring3_chain: [
        { hash: genesisHash, input_digest: genesisInput, promoted_at: now },
      ],
    },
    meta: {
      memory_seq: 0,
      promotion_counter: 0,
      last_promotion_at: 0,
      last_write_timestamp: now,
      write_cooldown_until: 0,
      security_tier: options.passphrase ? 2 : 1,
      status: "active",
    },
    created_at: now,
    version: IDENTITY_VERSION,
  };
}
