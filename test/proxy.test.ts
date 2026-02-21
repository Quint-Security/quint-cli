import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";

// __dirname at runtime = quint/dist/test, so project root = ../..
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "packages", "cli", "dist", "index.js");
const MOCK_SERVER = join(__dirname, "fixtures", "mock-mcp-server.js");

/**
 * Helper: spawn `quint proxy` wrapping the mock MCP server,
 * write all input lines to stdin, then close stdin and collect all stdout.
 */
function runProxy(opts: {
  dataDir: string;
  policyPath: string;
  serverName?: string;
  inputLines: string[];
  timeoutMs?: number;
}): Promise<{ stdout: string[]; stderr: string; exitCode: number | null }> {
  return new Promise((resolve, reject) => {
    const args = [
      CLI_PATH,
      "proxy",
      "--name", opts.serverName ?? "test-server",
      "--policy", opts.policyPath,
      "--", "node", MOCK_SERVER,
    ];

    const child = spawn("node", args, {
      env: { ...process.env, QUINT_DATA_DIR: opts.dataDir },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdoutLines: string[] = [];
    let stderrBuf = "";

    child.stdout!.setEncoding("utf-8");
    child.stdout!.on("data", (chunk: string) => {
      for (const line of chunk.split("\n").filter(Boolean)) {
        stdoutLines.push(line);
      }
    });

    child.stderr!.setEncoding("utf-8");
    child.stderr!.on("data", (chunk: string) => {
      stderrBuf += chunk;
    });

    child.on("exit", (code) => {
      resolve({ stdout: stdoutLines, stderr: stderrBuf, exitCode: code });
    });

    child.on("error", reject);

    // Write all input lines, then close stdin after a brief delay
    // to give the child process time to start up
    setTimeout(() => {
      for (const line of opts.inputLines) {
        child.stdin!.write(line + "\n");
      }
      // Give the proxy time to forward and receive responses
      setTimeout(() => {
        child.stdin!.end();
      }, 500);
    }, 200);

    // Safety timeout
    setTimeout(() => {
      child.kill();
    }, opts.timeoutMs ?? 8000);
  });
}

describe("proxy integration", () => {
  it("passes through initialize and allowed tool calls", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-proxy-test-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify({
      version: 1,
      data_dir: dir,
      log_level: "info",
      servers: [{ server: "test-server", default_action: "allow", tools: [] }],
    }));

    try {
      const initMsg = JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "1.0" } },
      });
      const toolCall = JSON.stringify({
        jsonrpc: "2.0", id: 2, method: "tools/call",
        params: { name: "ReadFile", arguments: { path: "/tmp/x" } },
      });

      const result = await runProxy({
        dataDir: dir,
        policyPath,
        inputLines: [initMsg, toolCall],
      });

      assert.ok(result.stdout.length >= 2, `Expected >= 2 stdout lines, got ${result.stdout.length}: ${JSON.stringify(result.stdout)}. stderr: ${result.stderr}`);

      const initResponse = JSON.parse(result.stdout[0]);
      assert.equal(initResponse.id, 1);
      assert.ok(initResponse.result);

      const toolResponse = JSON.parse(result.stdout[1]);
      assert.equal(toolResponse.id, 2);
      assert.ok(toolResponse.result);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("denies blocked tool calls with JSON-RPC error", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-proxy-test-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify({
      version: 1,
      data_dir: dir,
      log_level: "info",
      servers: [{
        server: "test-server",
        default_action: "allow",
        tools: [{ tool: "DangerousTool", action: "deny" }],
      }],
    }));

    try {
      const toolCall = JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "DangerousTool", arguments: {} },
      });

      const result = await runProxy({
        dataDir: dir,
        policyPath,
        inputLines: [toolCall],
      });

      assert.ok(result.stdout.length >= 1, `Expected >= 1 stdout lines, got ${result.stdout.length}. stderr: ${result.stderr}`);

      const denyResponse = JSON.parse(result.stdout[0]);
      assert.equal(denyResponse.id, 1);
      assert.ok(denyResponse.error, "Expected error field in deny response");
      assert.equal(denyResponse.error.code, -32600);
      assert.ok(denyResponse.error.message.includes("denied"));
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("logs entries to the audit database", async () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-proxy-test-"));
    const policyPath = join(dir, "policy.json");
    writeFileSync(policyPath, JSON.stringify({
      version: 1,
      data_dir: dir,
      log_level: "info",
      servers: [{
        server: "test-server",
        default_action: "allow",
        tools: [{ tool: "DangerousTool", action: "deny" }],
      }],
    }));

    try {
      const allowedCall = JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "ReadFile", arguments: { path: "/tmp/x" } },
      });
      const deniedCall = JSON.stringify({
        jsonrpc: "2.0", id: 2, method: "tools/call",
        params: { name: "DangerousTool", arguments: {} },
      });

      await runProxy({
        dataDir: dir,
        policyPath,
        inputLines: [allowedCall, deniedCall],
      });

      // Verify the audit database was created and has entries
      // We import dynamically to avoid test file requiring native deps at parse time
      const { AuditDb } = await import("@quint-security/core");
      const db = new AuditDb(join(dir, "quint.db"));
      const count = db.count();
      // Should have: allow request + allow response + deny request + deny response = 4+
      assert.ok(count >= 4, `Expected >= 4 audit entries, got ${count}`);

      const denied = db.query({ verdict: "deny" });
      assert.ok(denied.length >= 1, "Should have at least 1 denied entry");

      db.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
