#!/usr/bin/env node
import { Command } from "commander";

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

program.parse();
