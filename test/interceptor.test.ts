import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { inspectRequest, inspectResponse, buildDenyResponse } from "@quint-security/proxy";
import type { PolicyConfig } from "@quint-security/core";

const policy: PolicyConfig = {
  version: 1,
  data_dir: "/tmp/quint",
  log_level: "info",
  servers: [
    {
      server: "test-server",
      default_action: "allow",
      tools: [
        { tool: "DangerousTool", action: "deny" },
      ],
    },
  ],
};

describe("inspectRequest", () => {
  it("allows permitted tool calls", () => {
    const msg = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "ReadFile", arguments: { path: "/tmp/x" } },
    });
    const result = inspectRequest(msg, "test-server", policy);
    assert.equal(result.verdict, "allow");
    assert.equal(result.toolName, "ReadFile");
    assert.equal(result.method, "tools/call");
    assert.equal(result.messageId, "1");
  });

  it("denies blocked tool calls", () => {
    const msg = JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "DangerousTool", arguments: {} },
    });
    const result = inspectRequest(msg, "test-server", policy);
    assert.equal(result.verdict, "deny");
    assert.equal(result.toolName, "DangerousTool");
  });

  it("passes through non-tools/call methods", () => {
    const msg = JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "initialize",
      params: {},
    });
    const result = inspectRequest(msg, "test-server", policy);
    assert.equal(result.verdict, "passthrough");
    assert.equal(result.method, "initialize");
  });

  it("passes through unparseable lines", () => {
    const result = inspectRequest("not json", "test-server", policy);
    assert.equal(result.verdict, "passthrough");
    assert.equal(result.method, "unknown");
  });
});

describe("inspectResponse", () => {
  it("extracts message id from response", () => {
    const msg = JSON.stringify({
      jsonrpc: "2.0",
      id: 42,
      result: { tools: [] },
    });
    const result = inspectResponse(msg);
    assert.equal(result.messageId, "42");
    assert.equal(result.method, "response");
    assert.ok(result.responseJson);
  });
});

describe("buildDenyResponse", () => {
  it("produces valid JSON-RPC error", () => {
    const raw = buildDenyResponse(5);
    const parsed = JSON.parse(raw);
    assert.equal(parsed.jsonrpc, "2.0");
    assert.equal(parsed.id, 5);
    assert.equal(parsed.error.code, -32600);
    assert.ok(parsed.error.message.includes("denied"));
  });

  it("handles null request id", () => {
    const raw = buildDenyResponse(null);
    const parsed = JSON.parse(raw);
    assert.equal(parsed.id, null);
  });
});
