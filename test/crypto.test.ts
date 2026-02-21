import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  signData,
  verifySignature,
  canonicalize,
  saveKeyPair,
  loadKeyPair,
  ensureKeyPair,
} from "@quint-security/core";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("crypto", () => {
  it("generates a valid Ed25519 keypair", () => {
    const kp = generateKeyPair();
    assert.ok(kp.publicKey.includes("BEGIN PUBLIC KEY"));
    assert.ok(kp.privateKey.includes("BEGIN PRIVATE KEY"));
  });

  it("signs and verifies data", () => {
    const kp = generateKeyPair();
    const data = "hello world";
    const sig = signData(data, kp.privateKey);

    assert.ok(typeof sig === "string");
    assert.ok(sig.length > 0);

    const valid = verifySignature(data, sig, kp.publicKey);
    assert.ok(valid, "signature should be valid");
  });

  it("rejects tampered data", () => {
    const kp = generateKeyPair();
    const sig = signData("original data", kp.privateKey);

    const valid = verifySignature("tampered data", sig, kp.publicKey);
    assert.ok(!valid, "tampered data should not verify");
  });

  it("rejects wrong public key", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const sig = signData("data", kp1.privateKey);

    const valid = verifySignature("data", sig, kp2.publicKey);
    assert.ok(!valid, "wrong key should not verify");
  });

  it("canonicalize produces sorted keys", () => {
    const obj = { z: 1, a: 2, m: 3 };
    const result = canonicalize(obj);
    assert.equal(result, '{"a":2,"m":3,"z":1}');
  });

  it("save and load keypair round-trips", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-test-"));
    try {
      const kp = generateKeyPair();
      saveKeyPair(dir, kp);

      const loaded = loadKeyPair(dir);
      assert.ok(loaded);
      assert.equal(loaded.publicKey, kp.publicKey);
      assert.equal(loaded.privateKey, kp.privateKey);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("ensureKeyPair generates if missing, reuses if present", () => {
    const dir = mkdtempSync(join(tmpdir(), "quint-test-"));
    try {
      const kp1 = ensureKeyPair(dir);
      const kp2 = ensureKeyPair(dir);
      assert.equal(kp1.publicKey, kp2.publicKey);
      assert.equal(kp1.privateKey, kp2.privateKey);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
