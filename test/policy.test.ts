import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, validatePolicy, globMatch, type PolicyConfig } from "@quint/core";

const testPolicy: PolicyConfig = {
  version: 1,
  data_dir: "/tmp/quint",
  log_level: "info",
  servers: [
    {
      server: "builder-mcp",
      default_action: "allow",
      tools: [
        { tool: "MechanicRunTool", action: "deny" },
        { tool: "TicketingWriteActions", action: "deny" },
      ],
    },
    {
      server: "gandalf",
      default_action: "deny",
      tools: [
        { tool: "read_excel_data", action: "allow" },
      ],
    },
    { server: "*", default_action: "allow", tools: [] },
  ],
};

describe("evaluatePolicy", () => {
  it("allows tools not in deny list", () => {
    const result = evaluatePolicy(testPolicy, "builder-mcp", "ReadFile");
    assert.equal(result, "allow");
  });

  it("denies explicitly denied tools", () => {
    const result = evaluatePolicy(testPolicy, "builder-mcp", "MechanicRunTool");
    assert.equal(result, "deny");
  });

  it("denies all tools on deny-default server except explicit allows", () => {
    assert.equal(evaluatePolicy(testPolicy, "gandalf", "write_excel_data"), "deny");
    assert.equal(evaluatePolicy(testPolicy, "gandalf", "read_excel_data"), "allow");
  });

  it("uses wildcard server for unknown servers", () => {
    const result = evaluatePolicy(testPolicy, "unknown-server", "SomeTool");
    assert.equal(result, "allow"); // * server defaults to allow
  });

  it("returns passthrough when no tool name (non-tools/call)", () => {
    const result = evaluatePolicy(testPolicy, "builder-mcp", null);
    assert.equal(result, "passthrough");
  });

  it("returns deny for no server match when no wildcard", () => {
    const noWildcard: PolicyConfig = {
      version: 1,
      data_dir: "/tmp",
      log_level: "info",
      servers: [
        { server: "only-this", default_action: "allow", tools: [] },
      ],
    };
    const result = evaluatePolicy(noWildcard, "other-server", "SomeTool");
    assert.equal(result, "deny"); // fail-closed
  });
});

describe("globMatch", () => {
  it("matches exact strings", () => {
    assert.ok(globMatch("ReadFile", "ReadFile"));
    assert.ok(!globMatch("ReadFile", "WriteFile"));
  });

  it("matches * wildcard", () => {
    assert.ok(globMatch("write_*", "write_file"));
    assert.ok(globMatch("write_*", "write_data"));
    assert.ok(!globMatch("write_*", "read_file"));
  });

  it("matches Mechanic* pattern", () => {
    assert.ok(globMatch("Mechanic*", "MechanicRunTool"));
    assert.ok(globMatch("Mechanic*", "MechanicDescribeTool"));
    assert.ok(!globMatch("Mechanic*", "ReadFile"));
  });

  it("matches ? single char wildcard", () => {
    assert.ok(globMatch("tool_?", "tool_a"));
    assert.ok(globMatch("tool_?", "tool_1"));
    assert.ok(!globMatch("tool_?", "tool_ab"));
  });

  it("matches * as catch-all", () => {
    assert.ok(globMatch("*", "anything"));
    assert.ok(globMatch("*", ""));
  });
});

describe("evaluatePolicy with globs", () => {
  it("denies tools matching a glob pattern", () => {
    const policy: PolicyConfig = {
      version: 1,
      data_dir: "/tmp",
      log_level: "info",
      servers: [{
        server: "builder-mcp",
        default_action: "allow",
        tools: [{ tool: "Mechanic*", action: "deny" }],
      }],
    };
    assert.equal(evaluatePolicy(policy, "builder-mcp", "MechanicRunTool"), "deny");
    assert.equal(evaluatePolicy(policy, "builder-mcp", "MechanicDescribeTool"), "deny");
    assert.equal(evaluatePolicy(policy, "builder-mcp", "ReadFile"), "allow");
  });

  it("allows tools matching a glob pattern on deny-default server", () => {
    const policy: PolicyConfig = {
      version: 1,
      data_dir: "/tmp",
      log_level: "info",
      servers: [{
        server: "strict-server",
        default_action: "deny",
        tools: [{ tool: "read_*", action: "allow" }],
      }],
    };
    assert.equal(evaluatePolicy(policy, "strict-server", "read_file"), "allow");
    assert.equal(evaluatePolicy(policy, "strict-server", "read_data"), "allow");
    assert.equal(evaluatePolicy(policy, "strict-server", "write_file"), "deny");
  });

  it("matches server names with globs", () => {
    const policy: PolicyConfig = {
      version: 1,
      data_dir: "/tmp",
      log_level: "info",
      servers: [{
        server: "builder-*",
        default_action: "allow",
        tools: [{ tool: "DangerousTool", action: "deny" }],
      }],
    };
    assert.equal(evaluatePolicy(policy, "builder-mcp", "DangerousTool"), "deny");
    assert.equal(evaluatePolicy(policy, "builder-v2", "DangerousTool"), "deny");
    assert.equal(evaluatePolicy(policy, "other-mcp", "DangerousTool"), "deny"); // no match = fail-closed
  });
});

describe("validatePolicy", () => {
  it("passes valid policy", () => {
    const errors = validatePolicy(testPolicy);
    assert.equal(errors.length, 0);
  });

  it("rejects invalid version", () => {
    const bad: PolicyConfig = { ...testPolicy, version: 99 };
    const errors = validatePolicy(bad);
    assert.ok(errors.some((e) => e.includes("version")));
  });

  it("rejects invalid action", () => {
    const bad: PolicyConfig = {
      ...testPolicy,
      servers: [
        { server: "x", default_action: "maybe" as any, tools: [] },
      ],
    };
    const errors = validatePolicy(bad);
    assert.ok(errors.some((e) => e.includes("default_action")));
  });
});
