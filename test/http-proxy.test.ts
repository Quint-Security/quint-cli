import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const PROJECT_ROOT = join(__dirname, "..", "..");
const MOCK_HTTP_SERVER = join(__dirname, "fixtures", "mock-http-mcp-server.js");

/**
 * Start the mock HTTP MCP server and return its port.
 */
function startMockServer(): Promise<{ port: number; proc: ChildProcess }> {
  return new Promise((resolve, reject) => {
    // Pass port 0 to let the OS pick an available port
    const proc = spawn("node", [MOCK_HTTP_SERVER, "0"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    proc.on("error", reject);

    let stdout = "";
    proc.stdout!.setEncoding("utf-8");
    proc.stdout!.on("data", (chunk: string) => {
      stdout += chunk;
      // The mock server prints the port number on the first line
      const match = stdout.match(/^(\d+)/);
      if (match) {
        resolve({ port: parseInt(match[1], 10), proc });
      }
    });

    setTimeout(() => reject(new Error("Mock server did not start")), 5000);
  });
}

/**
 * Start the quint http-proxy pointing at a target URL.
 */
function startHttpProxy(opts: {
  dataDir: string;
  policyPath: string;
  serverName: string;
  port: number;
  targetUrl: string;
}): Promise<{ port: number; proc: ChildProcess }> {
  const CLI_PATH = join(PROJECT_ROOT, "packages", "cli", "dist", "index.js");
  return new Promise((resolve, reject) => {
    const proc = spawn("node", [
      CLI_PATH,
      "http-proxy",
      "--name", opts.serverName,
      "--port", String(opts.port),
      "--target", opts.targetUrl,
      "--policy", opts.policyPath,
    ], {
      env: { ...process.env, QUINT_DATA_DIR: opts.dataDir },
      stdio: ["pipe", "pipe", "pipe"],
    });

    proc.on("error", reject);

    let stderr = "";
    proc.stderr!.setEncoding("utf-8");
    proc.stderr!.on("data", (chunk: string) => {
      stderr += chunk;
      // Wait for the "listening" message
      if (stderr.includes("listening on")) {
        resolve({ port: opts.port, proc });
      }
    });

    setTimeout(() => reject(new Error(`HTTP proxy did not start. stderr: ${stderr}`)), 5000);
  });
}

/**
 * Send a JSON-RPC request to the proxy and return the response body.
 */
async function sendRequest(port: number, body: object): Promise<unknown> {
  const res = await fetch(`http://localhost:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

describe("http-proxy integration", () => {
  let mockProc: ChildProcess | null = null;
  let proxyProc: ChildProcess | null = null;
  let tempDir: string | null = null;

  afterEach(() => {
    mockProc?.kill();
    proxyProc?.kill();
    mockProc = null;
    proxyProc = null;
    if (tempDir) {
      rmSync(tempDir, { recursive: true });
      tempDir = null;
    }
  });

  async function setup(policyOverride?: object) {
    tempDir = mkdtempSync(join(tmpdir(), "quint-http-test-"));
    const policyPath = join(tempDir, "policy.json");
    writeFileSync(policyPath, JSON.stringify(policyOverride ?? {
      version: 1,
      data_dir: tempDir,
      log_level: "info",
      servers: [{ server: "test-http", default_action: "allow", tools: [] }],
    }));

    // Start mock HTTP MCP server
    const mock = await startMockServer();
    mockProc = mock.proc;

    // Find an available port for the proxy (use 0 trick via a temporary server)
    const { createServer } = await import("node:http");
    const proxyPort = await new Promise<number>((resolve) => {
      const s = createServer();
      s.listen(0, () => {
        const addr = s.address();
        const port = typeof addr === "object" && addr ? addr.port : 0;
        s.close(() => resolve(port));
      });
    });

    // Start the HTTP proxy
    const proxy = await startHttpProxy({
      dataDir: tempDir,
      policyPath,
      serverName: "test-http",
      port: proxyPort,
      targetUrl: `http://localhost:${mock.port}`,
    });
    proxyProc = proxy.proc;

    return { proxyPort: proxy.port, mockPort: mock.port, dir: tempDir, policyPath };
  }

  it("passes through initialize and allowed tool calls", async () => {
    const { proxyPort } = await setup();

    // Send initialize
    const initRes = await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "1.0" } },
    }) as { id: number; result?: { serverInfo?: { name: string } } };

    assert.equal(initRes.id, 1);
    assert.ok(initRes.result, "Expected result in initialize response");
    assert.equal(initRes.result!.serverInfo?.name, "mock-http-mcp-server");

    // Send allowed tool call
    const toolRes = await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name: "ReadFile", arguments: { path: "/tmp/x" } },
    }) as { id: number; result?: { content?: Array<{ text: string }> } };

    assert.equal(toolRes.id, 2);
    assert.ok(toolRes.result, "Expected result in tool call response");
    assert.ok(toolRes.result!.content![0].text.includes("ReadFile"));
  });

  it("denies blocked tool calls with JSON-RPC error", async () => {
    const { proxyPort } = await setup({
      version: 1,
      data_dir: tempDir!,
      log_level: "info",
      servers: [{
        server: "test-http",
        default_action: "allow",
        tools: [{ tool: "DangerousTool", action: "deny" }],
      }],
    });

    const denyRes = await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "DangerousTool", arguments: {} },
    }) as { id: number; error?: { code: number; message: string } };

    assert.equal(denyRes.id, 1);
    assert.ok(denyRes.error, "Expected error field in deny response");
    assert.equal(denyRes.error!.code, -32600);
    assert.ok(denyRes.error!.message.includes("denied"));
  });

  it("logs entries to the audit database", async () => {
    const { proxyPort, dir } = await setup();

    // Send an allowed tool call
    await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "ReadFile", arguments: { path: "/tmp/x" } },
    });

    // Give logger time to write
    await new Promise((r) => setTimeout(r, 200));

    const { AuditDb } = await import("@quint-security/core");
    const db = new AuditDb(join(dir, "quint.db"));
    const count = db.count();
    // Should have: request + response = 2+
    assert.ok(count >= 2, `Expected >= 2 audit entries, got ${count}`);
    db.close();
  });

  it("forwards non-tools/call methods as passthrough", async () => {
    const { proxyPort } = await setup();

    const listRes = await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 1, method: "tools/list", params: {},
    }) as { id: number; result?: { tools?: Array<{ name: string }> } };

    assert.equal(listRes.id, 1);
    assert.ok(listRes.result, "Expected result in tools/list response");
    assert.ok(listRes.result!.tools!.length >= 3, "Expected at least 3 tools");
  });

  it("creates entries with valid signatures", async () => {
    const { proxyPort, dir } = await setup();

    await sendRequest(proxyPort, {
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "WriteFile", arguments: { path: "/tmp/y", content: "hello" } },
    });

    await new Promise((r) => setTimeout(r, 200));

    const { AuditDb, verifySignature, canonicalize } = await import("@quint-security/core");
    const db = new AuditDb(join(dir, "quint.db"));
    const entries = db.getAll();
    assert.ok(entries.length >= 2, `Expected >= 2 entries, got ${entries.length}`);

    for (const entry of entries) {
      const signable: Record<string, unknown> = {
        timestamp: entry.timestamp,
        server_name: entry.server_name,
        direction: entry.direction,
        method: entry.method,
        message_id: entry.message_id,
        tool_name: entry.tool_name,
        arguments_json: entry.arguments_json,
        response_json: entry.response_json,
        verdict: entry.verdict,
        risk_score: entry.risk_score ?? null,
        risk_level: entry.risk_level ?? null,
        policy_hash: entry.policy_hash,
        prev_hash: entry.prev_hash,
        nonce: entry.nonce,
        public_key: entry.public_key,
      };
      const canonical = canonicalize(signable);
      const valid = verifySignature(canonical, entry.signature, entry.public_key);
      assert.ok(valid, `Signature invalid for entry ${entry.id}`);
    }

    db.close();
  });
});
