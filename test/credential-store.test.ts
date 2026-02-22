import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CredentialStore,
  openCredentialStore,
  deriveCredentialKey,
  generateKeyPair,
} from "@quint-security/core";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeTmpStore(passphrase = "test-passphrase"): { store: CredentialStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "quint-cred-test-"));
  const store = new CredentialStore(join(dir, "credentials.db"), passphrase);
  return { store, dir };
}

describe("CredentialStore", () => {
  it("stores and retrieves a credential", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "ghp_abc123",
        scopes: "repo,read:org",
      });

      const cred = store.get("github");
      assert.ok(cred);
      assert.equal(cred.id, "github");
      assert.equal(cred.provider, "github");
      assert.equal(cred.token_type, "bearer");
      assert.equal(cred.scopes, "repo,read:org");
      // access_token should be encrypted in the DB, not plaintext
      assert.ok(cred.access_token.startsWith("QUINT-CRED-V1:"));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("decrypts access token correctly", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "ghp_secret_token_123",
      });

      const token = store.getAccessToken("github");
      assert.equal(token, "ghp_secret_token_123");
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("returns undefined for missing credential", () => {
    const { store, dir } = makeTmpStore();
    try {
      assert.equal(store.get("nonexistent"), undefined);
      assert.equal(store.getAccessToken("nonexistent"), undefined);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("lists credentials without exposing tokens", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", { provider: "github", accessToken: "ghp_abc" });
      store.store("notion", { provider: "notion", accessToken: "ntn_xyz", scopes: "read" });

      const list = store.list();
      assert.equal(list.length, 2);
      assert.equal(list[0].id, "github");
      assert.equal(list[1].id, "notion");
      assert.equal(list[1].scopes, "read");
      // CredentialSummary should not have access_token or refresh_token
      assert.ok(!("access_token" in list[0]));
      assert.ok(!("refresh_token" in list[0]));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("removes a credential", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", { provider: "github", accessToken: "ghp_abc" });
      assert.ok(store.get("github"));

      const removed = store.remove("github");
      assert.ok(removed);
      assert.equal(store.get("github"), undefined);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("returns false when removing nonexistent credential", () => {
    const { store, dir } = makeTmpStore();
    try {
      assert.equal(store.remove("nonexistent"), false);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("replaces credential on duplicate store", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", { provider: "github", accessToken: "old_token" });
      store.store("github", { provider: "github", accessToken: "new_token" });

      const token = store.getAccessToken("github");
      assert.equal(token, "new_token");
      assert.equal(store.list().length, 1);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("stores and decrypts refresh token", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "access_123",
        refreshToken: "refresh_456",
      });

      const cred = store.get("github");
      assert.ok(cred);
      assert.ok(cred.refresh_token);
      assert.ok(cred.refresh_token.startsWith("QUINT-CRED-V1:"));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("handles null refresh token", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "access_123",
      });

      const cred = store.get("github");
      assert.ok(cred);
      assert.equal(cred.refresh_token, null);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("detects expired credentials", () => {
    const { store, dir } = makeTmpStore();
    try {
      // Store an already-expired credential
      const pastDate = new Date(Date.now() - 60_000).toISOString();
      store.store("expired-service", {
        provider: "custom",
        accessToken: "token",
        expiresAt: pastDate,
      });

      assert.ok(store.isExpired("expired-service"));

      // Store a credential that expires in the future
      const futureDate = new Date(Date.now() + 3600_000).toISOString();
      store.store("valid-service", {
        provider: "custom",
        accessToken: "token",
        expiresAt: futureDate,
      });

      assert.ok(!store.isExpired("valid-service"));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("treats missing credential as expired", () => {
    const { store, dir } = makeTmpStore();
    try {
      assert.ok(store.isExpired("nonexistent"));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("treats null expires_at as never-expiring", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "token",
      });

      assert.ok(!store.isExpired("github"));
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("updates tokens", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "old_access",
        refreshToken: "old_refresh",
      });

      const newExpiry = new Date(Date.now() + 7200_000).toISOString();
      store.updateTokens("github", "new_access", "new_refresh", newExpiry);

      assert.equal(store.getAccessToken("github"), "new_access");
      const cred = store.get("github");
      assert.ok(cred);
      assert.equal(cred.expires_at, newExpiry);
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("updates access token without changing refresh token", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "old_access",
        refreshToken: "keep_this_refresh",
      });

      store.updateTokens("github", "new_access");

      assert.equal(store.getAccessToken("github"), "new_access");
      // refresh_token should be unchanged
      const cred = store.get("github");
      assert.ok(cred);
      assert.ok(cred.refresh_token); // still encrypted, not null
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("stores metadata as JSON", () => {
    const { store, dir } = makeTmpStore();
    try {
      store.store("github", {
        provider: "github",
        accessToken: "token",
        metadata: { client_id: "abc", token_url: "https://example.com/token" },
      });

      const cred = store.get("github");
      assert.ok(cred);
      assert.ok(cred.metadata);
      const meta = JSON.parse(cred.metadata);
      assert.equal(meta.client_id, "abc");
      assert.equal(meta.token_url, "https://example.com/token");
    } finally {
      store.close();
      rmSync(dir, { recursive: true });
    }
  });

  it("cannot decrypt with wrong passphrase", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-cred-test-"));
    try {
      const store1 = new CredentialStore(join(dir, "credentials.db"), "correct-pass");
      store1.store("github", { provider: "github", accessToken: "secret_token" });
      store1.close();

      const store2 = new CredentialStore(join(dir, "credentials.db"), "wrong-pass");
      const token = store2.getAccessToken("github");
      assert.equal(token, undefined); // decryption fails, returns undefined
      store2.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});

describe("deriveCredentialKey", () => {
  it("uses passphrase when provided", () => {
    const key = deriveCredentialKey("my-passphrase", "some-private-key-pem");
    assert.equal(key, "my-passphrase");
  });

  it("derives from private key when no passphrase", () => {
    const kp = generateKeyPair();
    const key = deriveCredentialKey(undefined, kp.privateKey);
    assert.ok(key.length === 64); // SHA-256 hex
    // Same key should be derived deterministically
    const key2 = deriveCredentialKey(undefined, kp.privateKey);
    assert.equal(key, key2);
  });

  it("throws when neither passphrase nor key available", () => {
    assert.throws(() => deriveCredentialKey(undefined, undefined), /No encryption key available/);
  });
});

describe("openCredentialStore", () => {
  it("creates store at the expected path", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-cred-test-"));
    try {
      const store = openCredentialStore(dir, "test-key");
      store.store("test", { provider: "test", accessToken: "tok" });
      assert.equal(store.list().length, 1);
      store.close();
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
