import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { AuditDb, generateKeyPair, signData, canonicalize, sha256 } from "@quint-security/core";
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
    risk_score: null as number | null,
    risk_level: null as string | null,
    policy_hash: "abc123",
    prev_hash: "",
    nonce: crypto.randomUUID(),
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

  it("retrieves entry by ID with new fields", () => {
    const { db, dir } = makeTmpDb();
    try {
      const entry = makeEntry({ policy_hash: "policyabc", prev_hash: "prevdef" });
      const id = db.insert(entry);
      const retrieved = db.getById(id);
      assert.ok(retrieved);
      assert.equal(retrieved.server_name, "test-server");
      assert.equal(retrieved.tool_name, "ReadFile");
      assert.equal(retrieved.verdict, "allow");
      assert.equal(retrieved.policy_hash, "policyabc");
      assert.equal(retrieved.prev_hash, "prevdef");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("getLastSignature returns null for empty db", () => {
    const { db, dir } = makeTmpDb();
    try {
      assert.equal(db.getLastSignature(), null);
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("getLastSignature returns most recent signature", () => {
    const { db, dir } = makeTmpDb();
    try {
      const e1 = makeEntry();
      const e2 = makeEntry();
      db.insert(e1);
      db.insert(e2);
      assert.equal(db.getLastSignature(), e2.signature);
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("getAll returns entries in ascending order", () => {
    const { db, dir } = makeTmpDb();
    try {
      db.insert(makeEntry({ tool_name: "first" }));
      db.insert(makeEntry({ tool_name: "second" }));
      db.insert(makeEntry({ tool_name: "third" }));

      const all = db.getAll();
      assert.equal(all.length, 3);
      assert.equal(all[0].tool_name, "first");
      assert.equal(all[2].tool_name, "third");
    } finally {
      db.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("insertAtomic reads last sig and inserts in one transaction", () => {
    const { db, dir } = makeTmpDb();
    try {
      // Insert first entry normally
      const e1 = makeEntry();
      db.insert(e1);

      // insertAtomic should see e1's signature as prevSignature
      let seenPrevSig: string | null = "NOT_CALLED";
      db.insertAtomic((prevSig) => {
        seenPrevSig = prevSig;
        return makeEntry({ prev_hash: prevSig ? sha256(prevSig) : "" });
      });

      assert.equal(seenPrevSig, e1.signature);
      assert.equal(db.count(), 2);

      // The second entry's prev_hash should chain to the first
      const all = db.getAll();
      assert.equal(all[1].prev_hash, sha256(all[0].signature));
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
