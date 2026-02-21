import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthDb,
  openAuthDb,
  generateApiKey,
  verifyApiKey,
  createSession,
  validateSession,
  authenticateBearer,
} from "@quint-security/core";

describe("AuthDb + API keys", () => {
  let tempDir: string;
  let db: AuthDb;

  afterEach(() => {
    db?.close();
    if (tempDir) rmSync(tempDir, { recursive: true });
  });

  function setup() {
    tempDir = mkdtempSync(join(tmpdir(), "quint-auth-test-"));
    db = openAuthDb(tempDir);
    return db;
  }

  it("generates and verifies an API key", () => {
    const db = setup();
    const { rawKey, apiKey } = generateApiKey(db, { label: "test-key" });

    assert.ok(rawKey.startsWith("qk_"), "Raw key should start with qk_");
    assert.ok(apiKey.id.startsWith("qk_"), "Key ID should start with qk_");
    assert.equal(apiKey.label, "test-key");
    assert.equal(apiKey.revoked, false);

    // Verify the key
    const verified = verifyApiKey(db, rawKey);
    assert.ok(verified, "Key should verify successfully");
    assert.equal(verified!.id, apiKey.id);
  });

  it("rejects invalid raw key", () => {
    const db = setup();
    generateApiKey(db, { label: "test-key" });

    const verified = verifyApiKey(db, "qk_bogus");
    assert.equal(verified, undefined);
  });

  it("rejects revoked key", () => {
    const db = setup();
    const { rawKey, apiKey } = generateApiKey(db, { label: "test-key" });

    db.revokeApiKey(apiKey.id);

    const verified = verifyApiKey(db, rawKey);
    assert.equal(verified, undefined);
  });

  it("rejects expired key", () => {
    const db = setup();
    const { rawKey, apiKey } = generateApiKey(db, { label: "expired", ttlSeconds: 1 });

    // Manually backdate the expiry to the past
    (db as any).db.prepare(
      "UPDATE api_keys SET expires_at = ? WHERE id = ?"
    ).run("2020-01-01T00:00:00.000Z", apiKey.id);

    const verified = verifyApiKey(db, rawKey);
    assert.equal(verified, undefined, "Expired key should not verify");
  });

  it("lists keys", () => {
    const db = setup();
    generateApiKey(db, { label: "key-1" });
    generateApiKey(db, { label: "key-2" });

    const keys = db.listApiKeys();
    assert.equal(keys.length, 2);
  });

  it("stores scopes", () => {
    const db = setup();
    const { apiKey } = generateApiKey(db, {
      label: "scoped",
      scopes: ["proxy:read", "audit:write"],
    });

    assert.equal(apiKey.scopes, "proxy:read,audit:write");
  });
});

describe("Sessions", () => {
  let tempDir: string;
  let db: AuthDb;

  afterEach(() => {
    db?.close();
    if (tempDir) rmSync(tempDir, { recursive: true });
  });

  function setup() {
    tempDir = mkdtempSync(join(tmpdir(), "quint-session-test-"));
    db = openAuthDb(tempDir);
    return db;
  }

  it("creates and validates a session", () => {
    const db = setup();
    const session = createSession(db, {
      subjectId: "user-1",
      authMethod: "api_key",
      scopes: "proxy:read",
    });

    assert.ok(session.id, "Session should have an ID");
    assert.equal(session.subject_id, "user-1");
    assert.equal(session.auth_method, "api_key");

    const validated = validateSession(db, session.id);
    assert.ok(validated, "Session should validate");
    assert.equal(validated!.id, session.id);
  });

  it("rejects revoked session", () => {
    const db = setup();
    const session = createSession(db, {
      subjectId: "user-1",
      authMethod: "api_key",
    });

    db.revokeSession(session.id);

    const validated = validateSession(db, session.id);
    assert.equal(validated, undefined);
  });

  it("rejects expired session", () => {
    const db = setup();
    // Create session that already expired
    const session = createSession(db, {
      subjectId: "user-1",
      authMethod: "api_key",
      ttlMs: -1000, // expired 1 second ago
    });

    const validated = validateSession(db, session.id);
    assert.equal(validated, undefined, "Expired session should not validate");
  });

  it("revokes sessions by subject", () => {
    const db = setup();
    createSession(db, { subjectId: "key-1", authMethod: "api_key" });
    createSession(db, { subjectId: "key-1", authMethod: "api_key" });
    createSession(db, { subjectId: "key-2", authMethod: "api_key" });

    const revoked = db.revokeSessionsBySubject("key-1");
    assert.equal(revoked, 2);
  });
});

describe("authenticateBearer", () => {
  let tempDir: string;
  let db: AuthDb;

  afterEach(() => {
    db?.close();
    if (tempDir) rmSync(tempDir, { recursive: true });
  });

  function setup() {
    tempDir = mkdtempSync(join(tmpdir(), "quint-bearer-test-"));
    db = openAuthDb(tempDir);
    return db;
  }

  it("authenticates with raw API key", () => {
    const db = setup();
    const { rawKey, apiKey } = generateApiKey(db, { label: "bearer-test" });

    const result = authenticateBearer(db, rawKey);
    assert.ok(result, "Should authenticate with raw key");
    assert.equal(result!.type, "api_key");
    assert.equal(result!.subjectId, apiKey.id);
  });

  it("authenticates with session token", () => {
    const db = setup();
    const session = createSession(db, {
      subjectId: "key-1",
      authMethod: "api_key",
      scopes: "proxy:read",
    });

    const result = authenticateBearer(db, session.id);
    assert.ok(result, "Should authenticate with session token");
    assert.equal(result!.type, "session");
    assert.equal(result!.scopes, "proxy:read");
  });

  it("rejects invalid token", () => {
    const db = setup();
    const result = authenticateBearer(db, "totally-bogus-token");
    assert.equal(result, undefined);
  });
});
