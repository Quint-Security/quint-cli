#!/usr/bin/env node

import { Command } from "commander";
import { proxyCommand } from "./commands/proxy.js";
import { httpProxyCommand } from "./commands/http-proxy.js";
import { logsCommand } from "./commands/logs.js";
import { keysCommand } from "./commands/keys.js";
import { verifyCommand } from "./commands/verify.js";
import { policyCommand } from "./commands/policy.js";
import { statusCommand } from "./commands/status.js";
import { authCommand } from "./commands/auth.js";
import { initCommand } from "./commands/init.js";
import { connectCommand } from "./commands/connect.js";
import { dashboardCommand } from "./commands/dashboard.js";

const program = new Command()
  .name("quint")
  .version("0.1.0")
  .description("Local security proxy for MCP tool calls");

program.addCommand(initCommand);
program.addCommand(proxyCommand);
program.addCommand(httpProxyCommand);
program.addCommand(logsCommand);
program.addCommand(keysCommand);
program.addCommand(verifyCommand);
program.addCommand(policyCommand);
program.addCommand(statusCommand);
program.addCommand(authCommand);
program.addCommand(connectCommand);
program.addCommand(dashboardCommand);

program.parse();
