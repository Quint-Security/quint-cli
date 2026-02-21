import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { openAuthDb, generateApiKey } from "@quint/core";

const PROJECT_ROOT = join(__dirname, "..", "..");
const MOCK_HTTP_SERVER = join(__dirname, "fixtures", "mock-http-mcp-server.js");
const CLI_PATH = join(PROJECT_ROOT, "packages", "cli", "dist", "index.js");

function startMockServer(): Promise<{ port: number; proc: ChildProcess }> {
  return new Promise((resolve, reject) => {
    const proc = spawn("node", [MOCK_HTTP_SERVER, "0"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    proc.on("error", reject);
    let stdout = "";
    proc.stdout!.setEncoding("utf-8");
    proc.stdout!.on("data", (chunk: string) => {
      stdout += chunk;
      const match = stdout.match(/^(\d+)/);
      if (match) resolve({ port: parseInt(match[1], 10), proc });
    });
    setTimeout(() => reject(new Error("Mock server did not start")), 5000);
  });
}

async function findFreePort(): Promise<number> {
  const { createServer } = await import("node:http");
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      s.close(() => resolve(port));
    });
  });
}

function startProxy(opts: {
  dataDir: string;
  policyPath: string;
  port: number;
  targetUrl: string;
  requireAuth: boolean;
}): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const args = [
      CLI_PATH, "http-proxy",
      "--name", "auth-test",
      "--port", String(opts.port),
      "--target", opts.targetUrl,
      "--policy", opts.policyPath,
    ];
    if (opts.requireAuth) args.push("--require-auth");

    const proc = spawn("node", args, {
      env: { ...process.env, QUINT_DATA_DIR: opts.dataDir },
      stdio: ["pipe", "pipe", "pipe"],
    });
    proc.on("error", reject);
    let stderr = "";
    proc.stderr!.setEncoding("utf-8");
    proc.stderr!.on("data", (chunk: string) => {
      stderr += chunk;
      if (stderr.includes("listening on")) resolve(proc);
    });
    setTimeout(() => reject(new Error(`Proxy did not start: ${stderr}`)), 5000);
  });
}

describe("authenticated HTTP proxy", () => {
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

  async function setup() {
    tempDir = mkdtempSync(join(tmpdir(), "quint-auth-proxy-test-"));
    const policyPath = join(tempDir, "policy.json");
    writeFileSync(policyPath, JSON.stringify({
      version: 1,
      data_dir: tempDir,
      log_level: "info",
      servers: [{ server: "auth-test", default_action: "allow", tools: [] }],
    }));

    // Create an API key
    const authDb = openAuthDb(tempDir);
    const { rawKey } = generateApiKey(authDb, { label: "test-key" });
    authDb.close();

    const mock = await startMockServer();
    mockProc = mock.proc;

    const proxyPort = await findFreePort();
    proxyProc = await startProxy({
      dataDir: tempDir,
      policyPath,
      port: proxyPort,
      targetUrl: `http://localhost:${mock.port}`,
      requireAuth: true,
    });

    return { proxyPort, rawKey, dir: tempDir };
  }

  it("rejects requests without auth header", async () => {
    const { proxyPort } = await setup();

    const res = await fetch(`http://localhost:${proxyPort}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    assert.equal(res.status, 401);
    const body = await res.json() as { error?: { message: string } };
    assert.ok(body.error?.message.includes("Authorization"), "Should mention Authorization header");
  });

  it("rejects requests with invalid key", async () => {
    const { proxyPort } = await setup();

    const res = await fetch(`http://localhost:${proxyPort}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer qk_boguskey",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    assert.equal(res.status, 401);
    const body = await res.json() as { error?: { message: string } };
    assert.ok(body.error?.message.includes("invalid"), "Should mention invalid key");
  });

  it("allows requests with valid API key", async () => {
    const { proxyPort, rawKey } = await setup();

    const res = await fetch(`http://localhost:${proxyPort}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${rawKey}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });

    assert.equal(res.status, 200);
    const body = await res.json() as { result?: { tools?: unknown[] } };
    assert.ok(body.result?.tools, "Should get tools list back");
  });
});
