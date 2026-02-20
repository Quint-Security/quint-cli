import { Command } from "commander";
import { loadPolicy } from "@quint/core";
import { startHttpProxy } from "@quint/proxy";

export const httpProxyCommand = new Command("http-proxy")
  .description("Run as HTTP proxy in front of a remote MCP server")
  .requiredOption("--name <name>", "Name identifier for the proxied server")
  .requiredOption("--port <port>", "Local port to listen on", parseInt)
  .requiredOption("--target <url>", "Remote MCP server URL to proxy to")
  .option("--policy <path>", "Path to policy.json (default: ~/.quint/policy.json)")
  .action(async (opts: { name: string; port: number; target: string; policy?: string }) => {
    if (isNaN(opts.port) || opts.port < 1 || opts.port > 65535) {
      process.stderr.write("quint: --port must be a valid port number (1-65535)\n");
      process.exit(1);
    }

    try {
      new URL(opts.target);
    } catch {
      process.stderr.write(`quint: --target must be a valid URL\n`);
      process.exit(1);
    }

    const policy = loadPolicy(opts.policy ? opts.policy : undefined);

    await startHttpProxy({
      serverName: opts.name,
      port: opts.port,
      targetUrl: opts.target,
      policy,
    });
  });
