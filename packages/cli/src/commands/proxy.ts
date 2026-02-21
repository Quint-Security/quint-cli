import { Command } from "commander";
import { loadPolicy, resolveDataDir } from "@quint-security/core";
import { startProxy } from "@quint-security/proxy";

export const proxyCommand = new Command("proxy")
  .description("Run as MCP stdio proxy wrapping another MCP server")
  .requiredOption("--name <name>", "Name identifier for the proxied server")
  .option("--policy <path>", "Path to policy.json (default: ~/.quint/policy.json)")
  .argument("<command>", "Command to spawn the real MCP server")
  .argument("[args...]", "Arguments for the real MCP server")
  .allowExcessArguments(true)
  .action((command: string, args: string[], opts: { name: string; policy?: string }) => {
    const policy = loadPolicy(opts.policy ? opts.policy : undefined);
    const dataDir = resolveDataDir(policy.data_dir);

    startProxy({
      serverName: opts.name,
      command,
      args,
      policy,
    });
  });
