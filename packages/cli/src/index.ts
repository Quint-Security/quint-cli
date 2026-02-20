#!/usr/bin/env node

import { Command } from "commander";
import { proxyCommand } from "./commands/proxy.js";
import { logsCommand } from "./commands/logs.js";
import { keysCommand } from "./commands/keys.js";
import { verifyCommand } from "./commands/verify.js";
import { policyCommand } from "./commands/policy.js";
import { statusCommand } from "./commands/status.js";

const program = new Command()
  .name("quint")
  .version("0.1.0")
  .description("Local security proxy for MCP tool calls");

program.addCommand(proxyCommand);
program.addCommand(logsCommand);
program.addCommand(keysCommand);
program.addCommand(verifyCommand);
program.addCommand(policyCommand);
program.addCommand(statusCommand);

program.parse();
