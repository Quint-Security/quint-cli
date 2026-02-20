#!/usr/bin/env node

/**
 * Mock MCP server for testing. Reads JSON-RPC lines from stdin,
 * replies on stdout. Supports:
 *   - initialize → returns capabilities
 *   - tools/list → returns a list of tools
 *   - tools/call → echoes back the tool name and arguments
 */

import { createInterface } from "node:readline";

const rl = createInterface({ input: process.stdin });

rl.on("line", (line) => {
  let parsed: { jsonrpc: string; id?: unknown; method: string; params?: unknown };
  try {
    parsed = JSON.parse(line);
  } catch {
    return;
  }

  if (parsed.jsonrpc !== "2.0") return;

  switch (parsed.method) {
    case "initialize":
      respond(parsed.id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "mock-mcp-server", version: "0.1.0" },
      });
      break;

    case "tools/list":
      respond(parsed.id, {
        tools: [
          { name: "ReadFile", description: "Read a file", inputSchema: {} },
          { name: "WriteFile", description: "Write a file", inputSchema: {} },
          { name: "DangerousTool", description: "Does bad things", inputSchema: {} },
        ],
      });
      break;

    case "tools/call": {
      const params = parsed.params as { name?: string; arguments?: unknown } | undefined;
      respond(parsed.id, {
        content: [
          { type: "text", text: `Called ${params?.name ?? "unknown"} with ${JSON.stringify(params?.arguments ?? {})}` },
        ],
      });
      break;
    }

    default:
      respond(parsed.id, {});
      break;
  }
});

function respond(id: unknown, result: unknown): void {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
