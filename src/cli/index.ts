#!/usr/bin/env node
import process from "node:process";
import { Command } from "commander";
import { verifyCryptoIntegrity } from "../crypto/keccak.js";

import { registerGenerate } from "./generate.js";
import { registerValidate } from "./validate.js";
import { registerVerify } from "./verify.js";
import { registerStatus } from "./status.js";
import { registerExport } from "./export.js";
import { registerImport } from "./import.js";
import { registerSuspend } from "./suspend.js";
import { registerResume } from "./resume.js";
import { registerRevoke } from "./revoke.js";
import { registerDelete } from "./delete.js";
import { registerKeygen } from "./keygen.js";
import { registerRepinKey } from "./repin-key.js";
import { registerAuditTail } from "./audit-tail.js";
import { registerAuditQuery } from "./audit-query.js";
import { registerAuditExport } from "./audit-export.js";
import { registerAuditVerify } from "./audit-verify.js";
import { registerList } from "./list.js";
import { registerListTombstones } from "./list-tombstones.js";
import { registerMigrateFingerprint } from "./migrate-fingerprint.js";

if (!verifyCryptoIntegrity()) {
  process.stderr.write(
    "\x1b[31m[MOCI FATAL] Cryptographic self-test failed. The keccak256 implementation may have been tampered with. Refusing to start.\x1b[0m\n",
  );
  process.exit(1);
}

const program = new Command();

program
  .name("moci")
  .description("MOCI — Memory-bound OpenClaw Identity CLI")
  .version("0.1.0");

registerGenerate(program);
registerValidate(program);
registerVerify(program);
registerStatus(program);
registerExport(program);
registerImport(program);
registerSuspend(program);
registerResume(program);
registerRevoke(program);
registerDelete(program);
registerKeygen(program);
registerRepinKey(program);
registerAuditTail(program);
registerAuditQuery(program);
registerAuditExport(program);
registerAuditVerify(program);
registerList(program);
registerListTombstones(program);
registerMigrateFingerprint(program);

program.parse();
