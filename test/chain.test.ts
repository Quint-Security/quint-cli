import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AuditDb,
  generateKeyPair,
  sha256,
  canonicalize,
  verifySignature,
  type PolicyConfig,
} from "@quint-security/core";
import { AuditLogger } from "@quint-security/proxy";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const testPolicy: PolicyConfig = {
  version: 1,
  data_dir: "/tmp",
  log_level: "info",
  servers: [{ server: "*", default_action: "allow", tools: [] }],
};

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "quint-chain-test-"));
  const db = new AuditDb(join(dir, "quint.db"));
  const kp = generateKeyPair();
  const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, testPolicy);
  return { dir, db, kp, logger };
}

describe("hash chain", () => {
  it("first entry has empty prev_hash", () => {
    const { dir, db, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "tools/call",
        messageId: "1",
        toolName: "ReadFile",
        argumentsJson: "{}",
        responseJson: null,
        verdict: "allow",
      });

      const entry = db.getById(1)!;
      assert.equal(entry.prev_hash, "");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("second entry prev_hash = sha256(first entry signature)", () => {
    const { dir, db, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "tools/call",
        messageId: "1",
        toolName: "ReadFile",
        argumentsJson: "{}",
        responseJson: null,
        verdict: "allow",
      });

      logger.log({
        serverName: "test",
        direction: "response",
        method: "response",
        messageId: "1",
        toolName: null,
        argumentsJson: null,
        responseJson: '{"result":{}}',
        verdict: "passthrough",
      });

      const first = db.getById(1)!;
      const second = db.getById(2)!;
      assert.equal(second.prev_hash, sha256(first.signature));
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("chain of 5 entries is fully linked", () => {
    const { dir, db, logger } = setup();
    try {
      for (let i = 0; i < 5; i++) {
        logger.log({
          serverName: "test",
          direction: "request",
          method: "tools/call",
          messageId: String(i),
          toolName: `Tool${i}`,
          argumentsJson: "{}",
          responseJson: null,
          verdict: "allow",
        });
      }

      const all = db.getAll();
      assert.equal(all.length, 5);

      // First entry: empty prev_hash
      assert.equal(all[0].prev_hash, "");

      // Each subsequent entry chains to the previous
      for (let i = 1; i < all.length; i++) {
        assert.equal(all[i].prev_hash, sha256(all[i - 1].signature),
          `Entry ${all[i].id} prev_hash should equal sha256(entry ${all[i - 1].id} signature)`);
      }
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("all entries have valid signatures", () => {
    const { dir, db, kp, logger } = setup();
    try {
      for (let i = 0; i < 3; i++) {
        logger.log({
          serverName: "test",
          direction: "request",
          method: "tools/call",
          messageId: String(i),
          toolName: `Tool${i}`,
          argumentsJson: "{}",
          responseJson: null,
          verdict: "allow",
        });
      }

      const all = db.getAll();
      for (const entry of all) {
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
          nonce: entry.nonce ?? "",
          public_key: entry.public_key,
        };
        const canonical = canonicalize(signable);
        const valid = verifySignature(canonical, entry.signature, kp.publicKey);
        assert.ok(valid, `Entry #${entry.id} signature should be valid`);
      }
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("all entries have policy_hash set", () => {
    const { dir, db, logger } = setup();
    try {
      logger.log({
        serverName: "test",
        direction: "request",
        method: "tools/call",
        messageId: "1",
        toolName: "ReadFile",
        argumentsJson: "{}",
        responseJson: null,
        verdict: "allow",
      });

      const entry = db.getById(1)!;
      const expectedHash = sha256(canonicalize(testPolicy as unknown as Record<string, unknown>));
      assert.equal(entry.policy_hash, expectedHash);
      assert.ok(entry.policy_hash.length > 0);
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });
});
