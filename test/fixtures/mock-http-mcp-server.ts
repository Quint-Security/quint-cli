/**
 * Mock HTTP MCP server for testing. Listens on a port passed as argv[2],
 * handles JSON-RPC POST requests over HTTP. Supports:
 *   - initialize → returns capabilities
 *   - tools/list → returns a list of tools
 *   - tools/call → echoes back the tool name and arguments
 */

import { createServer } from "node:http";

const port = parseInt(process.argv[2] ?? "0", 10);

const server = createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Method not allowed" }));
    return;
  }

  const chunks: Buffer[] = [];
  req.on("data", (chunk: Buffer) => chunks.push(chunk));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf-8");
    let parsed: { jsonrpc: string; id?: unknown; method: string; params?: unknown };

    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    if (parsed.jsonrpc !== "2.0") {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not JSON-RPC 2.0" }));
      return;
    }

    let result: unknown;
    switch (parsed.method) {
      case "initialize":
        result = {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "mock-http-mcp-server", version: "0.1.0" },
        };
        break;

      case "tools/list":
        result = {
          tools: [
            { name: "ReadFile", description: "Read a file", inputSchema: {} },
            { name: "WriteFile", description: "Write a file", inputSchema: {} },
            { name: "DangerousTool", description: "Does bad things", inputSchema: {} },
          ],
        };
        break;

      case "tools/call": {
        const params = parsed.params as { name?: string; arguments?: unknown } | undefined;
        result = {
          content: [
            { type: "text", text: `Called ${params?.name ?? "unknown"} with ${JSON.stringify(params?.arguments ?? {})}` },
          ],
        };
        break;
      }

      default:
        result = {};
        break;
    }

    const response = JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(response);
  });
});

server.listen(port, () => {
  const addr = server.address();
  const actualPort = typeof addr === "object" && addr ? addr.port : port;
  // Print port to stdout so the test can discover it
  process.stdout.write(String(actualPort) + "\n");
});
