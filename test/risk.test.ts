import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RiskEngine,
  BehaviorDb,
  AuditDb,
  generateKeyPair,
  canonicalize,
  verifySignature,
  type PolicyConfig,
} from "@quint-security/core";
import { AuditLogger } from "@quint-security/proxy";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("RiskEngine", () => {
  it("scores read operations as low risk", () => {
    const engine = new RiskEngine();
    const risk = engine.score("ReadFile", null);
    assert.ok(risk.score <= 20, `ReadFile score ${risk.score} should be <= 20`);
    assert.equal(risk.level, "low");
  });

  it("scores delete operations as high risk", () => {
    const engine = new RiskEngine();
    const risk = engine.score("DeleteFile", null);
    assert.ok(risk.score >= 60, `DeleteFile score ${risk.score} should be >= 60`);
    assert.ok(risk.level === "high" || risk.level === "critical");
  });

  it("scores shell/execute tools as high risk", () => {
    const engine = new RiskEngine();
    const risk = engine.score("ExecuteCommand", null);
    assert.ok(risk.score >= 60, `ExecuteCommand score ${risk.score} should be >= 60`);
  });

  it("boosts score for dangerous argument keywords", () => {
    const engine = new RiskEngine();
    const safe = engine.score("WriteFile", JSON.stringify({ path: "/tmp/test.txt", content: "hello" }));
    const dangerous = engine.score("WriteFile", JSON.stringify({ query: "DROP TABLE users" }));
    assert.ok(dangerous.score > safe.score, `Dangerous args (${dangerous.score}) should score higher than safe (${safe.score})`);
    assert.ok(dangerous.argBoost > 0, "Should have argument boost");
  });

  it("escalates on repeated high-risk actions", () => {
    const engine = new RiskEngine({ thresholds: { flag: 60, deny: 85, revokeAfter: 3, windowMs: 60000 } });

    const first = engine.score("DeleteFile", null, "agent-1");
    const second = engine.score("DeleteFile", null, "agent-1");
    const third = engine.score("DeleteFile", null, "agent-1");

    assert.ok(third.score > first.score, `Third attempt (${third.score}) should be higher than first (${first.score})`);
    assert.ok(third.behaviorBoost > 0, "Should have behavior boost");
  });

  it("triggers revocation after threshold", () => {
    const engine = new RiskEngine({ thresholds: { flag: 60, deny: 85, revokeAfter: 3, windowMs: 60000 } });

    // DeleteFile scores 80 (high), which is >= flag threshold of 60
    engine.score("DeleteFile", null, "agent-1");
    engine.score("DeleteFile", null, "agent-1");
    engine.score("DeleteFile", null, "agent-1");

    assert.ok(engine.shouldRevoke("agent-1"), "Should recommend revocation after 3 high-risk actions");
  });

  it("does not trigger revocation for low-risk actions", () => {
    const engine = new RiskEngine({ thresholds: { flag: 60, deny: 85, revokeAfter: 3, windowMs: 60000 } });

    engine.score("ReadFile", null, "agent-2");
    engine.score("ReadFile", null, "agent-2");
    engine.score("ReadFile", null, "agent-2");
    engine.score("ReadFile", null, "agent-2");

    assert.ok(!engine.shouldRevoke("agent-2"), "Should NOT revoke for read operations");
  });

  it("evaluate returns correct action based on score", () => {
    const engine = new RiskEngine({ thresholds: { flag: 60, deny: 85, revokeAfter: 5, windowMs: 60000 } });

    const low = engine.score("ReadFile", null);
    assert.equal(engine.evaluate(low), "allow");

    const high = engine.score("DeleteFile", null);
    assert.equal(engine.evaluate(high), "flag");
  });

  it("auto-denies when score exceeds deny threshold", () => {
    const engine = new RiskEngine({ thresholds: { flag: 40, deny: 70, revokeAfter: 5, windowMs: 60000 } });

    // DeleteFile (80) + dangerous args should exceed 70
    const risk = engine.score("DeleteFile", JSON.stringify({ cmd: "rm -rf /" }));
    assert.equal(engine.evaluate(risk), "deny", `Score ${risk.score} should trigger deny`);
  });

  it("accepts custom risk patterns", () => {
    const engine = new RiskEngine({
      customPatterns: [
        { tool: "MyDangerousTool", baseScore: 95 },
        { tool: "MySafeTool", baseScore: 5 },
      ],
    });

    const dangerous = engine.score("MyDangerousTool", null);
    assert.ok(dangerous.score >= 85, `Custom dangerous tool score ${dangerous.score} should be >= 85`);

    const safe = engine.score("MySafeTool", null);
    assert.ok(safe.score <= 10, `Custom safe tool score ${safe.score} should be <= 10`);
  });

  it("scores unknown tools with default base score", () => {
    const engine = new RiskEngine();
    const risk = engine.score("SomeRandomTool", null);
    assert.equal(risk.baseScore, 20, "Unknown tools should get default base score of 20");
  });
});

describe("risk scores in audit entries", () => {
  const testPolicy: PolicyConfig = {
    version: 1,
    data_dir: "/tmp",
    log_level: "info",
    servers: [{ server: "*", default_action: "allow", tools: [] }],
  };

  function setup() {
    const dir = mkdtempSync(join(tmpdir(), "quint-risk-audit-"));
    const db = new AuditDb(join(dir, "quint.db"));
    const kp = generateKeyPair();
    const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, testPolicy);
    return { dir, db, kp, logger };
  }

  it("stores risk_score and risk_level in audit entries", () => {
    const { dir, db, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "tools/call",
        messageId: "1",
        toolName: "DeleteFile",
        argumentsJson: "{}",
        responseJson: null,
        verdict: "allow",
        riskScore: 80,
        riskLevel: "high",
      });

      const entry = db.getById(1)!;
      assert.equal(entry.risk_score, 80, "risk_score should be 80");
      assert.equal(entry.risk_level, "high", "risk_level should be high");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("stores null risk when not provided", () => {
    const { dir, db, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "initialize",
        messageId: "1",
        toolName: null,
        argumentsJson: null,
        responseJson: null,
        verdict: "passthrough",
      });

      const entry = db.getById(1)!;
      assert.equal(entry.risk_score, null, "risk_score should be null for non-tool calls");
      assert.equal(entry.risk_level, null, "risk_level should be null for non-tool calls");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("risk score is included in signature", () => {
    const { dir, db, kp, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "tools/call",
        messageId: "1",
        toolName: "WriteFile",
        argumentsJson: "{}",
        responseJson: null,
        verdict: "allow",
        riskScore: 50,
        riskLevel: "medium",
      });

      const entry = db.getById(1)!;
      assert.equal(entry.risk_score, 50);
      assert.equal(entry.risk_level, "medium");
      // Verify that the signature covers the risk fields by rebuilding the signable
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
        risk_score: entry.risk_score,
        risk_level: entry.risk_level,
        policy_hash: entry.policy_hash,
        prev_hash: entry.prev_hash,
        nonce: entry.nonce,
        public_key: entry.public_key,
      };
      const canonical = canonicalize(signable);
      const valid = verifySignature(canonical, entry.signature, kp.publicKey);
      assert.ok(valid, "Signature should be valid with risk fields included");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });
});

describe("BehaviorDb persistence", () => {
  it("persists behavior records across db instances", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-behavior-"));
    const dbPath = join(dir, "behavior.db");
    try {
      // First instance: record some high-risk actions
      const db1 = new BehaviorDb(dbPath);
      const now = Date.now();
      db1.record("agent-1", now - 1000);
      db1.record("agent-1", now - 500);
      db1.record("agent-1", now);
      db1.close();

      // Second instance: should see previous records
      const db2 = new BehaviorDb(dbPath);
      const cutoff = now - 5000; // 5 seconds ago
      const count = db2.count("agent-1", cutoff);
      assert.equal(count, 3, "Should see 3 records from previous instance");
      db2.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("prunes old records on count", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-behavior-"));
    const dbPath = join(dir, "behavior.db");
    try {
      const db = new BehaviorDb(dbPath);
      const now = Date.now();
      // Old record (should be pruned)
      db.record("agent-1", now - 600000);
      // Recent records
      db.record("agent-1", now - 1000);
      db.record("agent-1", now);

      const cutoff = now - 300000; // 5 minutes ago
      const count = db.count("agent-1", cutoff);
      assert.equal(count, 2, "Should only see 2 recent records after pruning");
      db.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("RiskEngine with BehaviorDb persists escalation across instances", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-behavior-"));
    const dbPath = join(dir, "behavior.db");
    try {
      // First engine instance: accumulate behavior
      const db1 = new BehaviorDb(dbPath);
      const engine1 = new RiskEngine({
        thresholds: { flag: 60, deny: 85, revokeAfter: 3, windowMs: 60000 },
        behaviorDb: db1,
      });
      engine1.score("DeleteFile", null, "agent-1"); // score 80 >= flag(60), recorded
      engine1.score("DeleteFile", null, "agent-1"); // score 85 (80+5), recorded
      db1.close();

      // Second engine instance: should see prior behavior
      const db2 = new BehaviorDb(dbPath);
      const engine2 = new RiskEngine({
        thresholds: { flag: 60, deny: 85, revokeAfter: 3, windowMs: 60000 },
        behaviorDb: db2,
      });
      const risk = engine2.score("DeleteFile", null, "agent-1");
      assert.ok(risk.behaviorBoost > 0, `Should have behavior boost from prior instance (got ${risk.behaviorBoost})`);
      assert.ok(risk.score > 80, `Score (${risk.score}) should be escalated above base 80`);
      db2.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
