import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import type { KeyPair } from "./types.js";

const ALGORITHM = "Ed25519";

// ── Key generation ──────────────────────────────────────────────

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// ── Key persistence ─────────────────────────────────────────────

export function saveKeyPair(dataDir: string, kp: KeyPair): void {
  const keysDir = join(dataDir, "keys");
  mkdirSync(keysDir, { recursive: true });

  const privPath = join(keysDir, "quint.key");
  const pubPath = join(keysDir, "quint.pub");

  writeFileSync(privPath, kp.privateKey, { mode: 0o600 });
  // Ensure permission is set even if file existed
  chmodSync(privPath, 0o600);
  writeFileSync(pubPath, kp.publicKey, { mode: 0o644 });
}

export function loadKeyPair(dataDir: string): KeyPair | null {
  const privPath = join(dataDir, "keys", "quint.key");
  const pubPath = join(dataDir, "keys", "quint.pub");

  if (!existsSync(privPath) || !existsSync(pubPath)) return null;

  return {
    privateKey: readFileSync(privPath, "utf-8"),
    publicKey: readFileSync(pubPath, "utf-8"),
  };
}

export function ensureKeyPair(dataDir: string): KeyPair {
  const existing = loadKeyPair(dataDir);
  if (existing) return existing;
  const kp = generateKeyPair();
  saveKeyPair(dataDir, kp);
  return kp;
}

// ── Signing ─────────────────────────────────────────────────────

export function signData(data: string, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  const signature = sign(null, Buffer.from(data, "utf-8"), key);
  return signature.toString("hex");
}

export function verifySignature(data: string, signatureHex: string, publicKeyPem: string): boolean {
  const key = createPublicKey(publicKeyPem);
  const sigBuf = Buffer.from(signatureHex, "hex");
  return verify(null, Buffer.from(data, "utf-8"), key, sigBuf);
}

// ── Canonical JSON for signing ──────────────────────────────────

export function canonicalize(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ── Public key fingerprint (first 16 hex chars of key hash) ─────

export function publicKeyFingerprint(publicKeyPem: string): string {
  // Use a simple approach: take first 16 chars of the base64 key body
  const body = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  return body.substring(0, 16);
}
