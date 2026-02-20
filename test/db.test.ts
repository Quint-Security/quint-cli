import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AuditDb, generateKeyPair, signData, canonicalize } from "@quint/core";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeTmpDb(): { db: AuditDb; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "quint-test-"));
  const db = new AuditDb(join(dir, "quint.db"));
  return { db, dir };
}

function makeEntry(overrides: Partial<Parameters<AuditDb["insert"]>[0]> = {}) {
  const kp = generateKeyPair();
  const base = {
    timestamp: new Date().toISOString(),
    server_name: "test-server",
    direction: "request" as const,
    method: "tools/call",
    message_id: "1",
    tool_name: "ReadFile",
    arguments_json: '{"path":"/tmp/x"}',
    response_json: null,
    verdict: "allow" as const,
    public_key: kp.publicKey,
  };
  const signable = { ...base };
  const canonical = canonicalize(signable as unknown as Record<string, unknown>);
  const signature = signData(canonical, kp.privateKey);
  return { ...base, signature, ...overrides };
}

describe("AuditDb", () => {
  it("creates schema and inserts an entry", () => {
    const { db, dir } = makeTmpDb();
    try {
      const entry = makeEntry();
      const id = db.insert(entry);
      assert.ok(id > 0);
      assert.equal(db.count(), 1);
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("retrieves entry by ID", () => {
    const { db, dir } = makeTmpDb();
    try {
      const entry = makeEntry();
      const id = db.insert(entry);
      const retrieved = db.getById(id);
      assert.ok(retrieved);
      assert.equal(retrieved.server_name, "test-server");
      assert.equal(retrieved.tool_name, "ReadFile");
      assert.equal(retrieved.verdict, "allow");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("queries by server name", () => {
    const { db, dir } = makeTmpDb();
    try {
      db.insert(makeEntry({ server_name: "server-a" }));
      db.insert(makeEntry({ server_name: "server-b" }));
      db.insert(makeEntry({ server_name: "server-a" }));

      const results = db.query({ server: "server-a" });
      assert.equal(results.length, 2);
      for (const r of results) {
        assert.equal(r.server_name, "server-a");
      }
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("queries by verdict", () => {
    const { db, dir } = makeTmpDb();
    try {
      db.insert(makeEntry({ verdict: "allow" }));
      db.insert(makeEntry({ verdict: "deny" }));
      db.insert(makeEntry({ verdict: "allow" }));

      const denied = db.query({ verdict: "deny" });
      assert.equal(denied.length, 1);
      assert.equal(denied[0].verdict, "deny");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("getLast returns entries in reverse order", () => {
    const { db, dir } = makeTmpDb();
    try {
      db.insert(makeEntry({ tool_name: "first" }));
      db.insert(makeEntry({ tool_name: "second" }));
      db.insert(makeEntry({ tool_name: "third" }));

      const last2 = db.getLast(2);
      assert.equal(last2.length, 2);
      assert.equal(last2[0].tool_name, "third");
      assert.equal(last2[1].tool_name, "second");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });
});
