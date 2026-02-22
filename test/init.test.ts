import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";

// __dirname at runtime = quint/dist/test, so project root = ../..
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI = join(PROJECT_ROOT, "packages", "cli", "dist", "index.js");

function run(args: string[], env?: Record<string, string>): string {
  return execFileSync("node", [CLI, ...args], {
    encoding: "utf-8",
    env: { ...process.env, ...env },
    timeout: 10000,
  });
}

describe("quint init", () => {
  it("--list-roles shows available presets", () => {
    const output = run(["init", "--list-roles"]);
    assert.ok(output.includes("coding-assistant"));
    assert.ok(output.includes("research-agent"));
    assert.ok(output.includes("strict"));
    assert.ok(output.includes("permissive"));
  });

  it("detects MCP servers from claude.json", () => {
    // Create a fake claude.json in a temp dir
    const dir = mkdtempSync(join(tmpdir(), "quint-init-test-"));
    const fakeHome = dir;
    const quintDir = join(fakeHome, ".quint");
    mkdirSync(quintDir, { recursive: true });

    const claudeConfig = {
      mcpServers: {
        "builder-mcp": {
          type: "stdio",
          command: "builder-mcp",
          args: [],
          env: {},
        },
        "gandalf": {
          type: "stdio",
          command: "/usr/local/bin/gandalf-mcp-server",
          args: [],
          env: {},
        },
      },
    };
    writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify(claudeConfig));

    try {
      const output = run(["init", "--dry-run"], { HOME: fakeHome });
      assert.ok(output.includes("builder-mcp"), "Should detect builder-mcp");
      assert.ok(output.includes("gandalf"), "Should detect gandalf");
      assert.ok(output.includes("Found 2 MCP server"), "Should find 2 servers");
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("--apply wraps stdio servers through quint proxy", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-init-test-"));
    const fakeHome = dir;
    const quintDir = join(fakeHome, ".quint");
    mkdirSync(quintDir, { recursive: true });

    const claudeConfig = {
      mcpServers: {
        "test-mcp": {
          type: "stdio",
          command: "test-mcp-server",
          args: ["--flag"],
          env: { FOO: "bar" },
        },
      },
    };
    writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify(claudeConfig));

    try {
      run(["init", "--apply"], { HOME: fakeHome });

      // Read back the modified config
      const modified = JSON.parse(readFileSync(join(fakeHome, ".claude.json"), "utf-8"));
      const server = modified.mcpServers["test-mcp"];

      assert.equal(server.command, "quint", "Command should be 'quint'");
      assert.ok(server.args.includes("proxy"), "Args should include 'proxy'");
      assert.ok(server.args.includes("--name"), "Args should include '--name'");
      assert.ok(server.args.includes("test-mcp"), "Args should include server name");
      assert.ok(server.args.includes("--"), "Args should include '--'");
      assert.ok(server.args.includes("test-mcp-server"), "Args should include original command");
      assert.ok(server.args.includes("--flag"), "Args should include original args");
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("--revert restores original commands", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-init-test-"));
    const fakeHome = dir;
    const quintDir = join(fakeHome, ".quint");
    mkdirSync(quintDir, { recursive: true });

    // Start with a quint-proxied config
    const claudeConfig = {
      mcpServers: {
        "test-mcp": {
          type: "stdio",
          command: "quint",
          args: ["proxy", "--name", "test-mcp", "--", "test-mcp-server", "--flag"],
          env: { FOO: "bar" },
        },
      },
    };
    writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify(claudeConfig));

    try {
      run(["init", "--revert"], { HOME: fakeHome });

      const modified = JSON.parse(readFileSync(join(fakeHome, ".claude.json"), "utf-8"));
      const server = modified.mcpServers["test-mcp"];

      assert.equal(server.command, "test-mcp-server", "Should restore original command");
      assert.deepEqual(server.args, ["--flag"], "Should restore original args");
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("--role coding-assistant creates policy with deny rules", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-init-test-"));
    const fakeHome = dir;
    const quintDir = join(fakeHome, ".quint");
    mkdirSync(quintDir, { recursive: true });

    const claudeConfig = {
      mcpServers: {
        "builder-mcp": { type: "stdio", command: "builder-mcp", args: [], env: {} },
      },
    };
    writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify(claudeConfig));

    try {
      run(["init", "--role", "coding-assistant", "--dry-run"], { HOME: fakeHome });

      // Policy should have been created
      const policy = JSON.parse(readFileSync(join(quintDir, "policy.json"), "utf-8"));
      assert.ok(policy.servers.length >= 2, "Should have server entries + wildcard");

      const builderPolicy = policy.servers.find((s: { server: string }) => s.server === "builder-mcp");
      assert.ok(builderPolicy, "Should have builder-mcp entry");
      assert.equal(builderPolicy.default_action, "allow");
      assert.ok(builderPolicy.tools.some((t: { tool: string }) => t.tool === "Delete*"), "Should deny Delete*");
      assert.ok(builderPolicy.tools.some((t: { tool: string }) => t.tool === "MechanicRun*"), "Should deny MechanicRun*");
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("skips servers already proxied through quint", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-init-test-"));
    const fakeHome = dir;
    const quintDir = join(fakeHome, ".quint");
    mkdirSync(quintDir, { recursive: true });

    const claudeConfig = {
      mcpServers: {
        "already-proxied": {
          type: "stdio",
          command: "quint",
          args: ["proxy", "--name", "already-proxied", "--", "some-server"],
          env: {},
        },
        "not-proxied": {
          type: "stdio",
          command: "some-server",
          args: [],
          env: {},
        },
      },
    };
    writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify(claudeConfig));

    try {
      const output = run(["init", "--dry-run"], { HOME: fakeHome });
      assert.ok(output.includes("already proxied"), "Should note already-proxied server");
      assert.ok(output.includes("1 server(s)"), "Should only show 1 change needed");
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
