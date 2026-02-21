import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RiskEngine } from "@quint/core";

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
