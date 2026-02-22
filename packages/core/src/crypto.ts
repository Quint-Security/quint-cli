import {
  generateKeyPairSync, createPrivateKey, createPublicKey,
  sign, verify, createHash,
  scryptSync, randomBytes,
  createCipheriv, createDecipheriv,
} from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { KeyPair } from "./types.js";

const ALGORITHM = "Ed25519";
const ENCRYPTED_MAGIC = "QUINT-ENC-V1";

// ── Key generation ──────────────────────────────────────────────

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// ── Private key encryption (scrypt + AES-256-GCM) ──────────────

/**
 * Encrypt a private key PEM with a passphrase.
 * Format: QUINT-ENC-V1:<salt_hex>:<iv_hex>:<authTag_hex>:<ciphertext_hex>
 */
export function encryptPrivateKey(privateKeyPem: string, passphrase: string): string {
  const salt = randomBytes(32);
  const key = scryptSync(passphrase, salt, 32, { N: 2 ** 14, r: 8, p: 1 });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKeyPem, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [
    ENCRYPTED_MAGIC,
    salt.toString("hex"),
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex"),
  ].join(":");
}

/**
 * Decrypt an encrypted private key. Returns null if passphrase is wrong.
 */
export function decryptPrivateKey(encrypted: string, passphrase: string): string | null {
  const parts = encrypted.split(":");
  if (parts.length !== 5 || parts[0] !== ENCRYPTED_MAGIC) return null;

  const salt = Buffer.from(parts[1], "hex");
  const iv = Buffer.from(parts[2], "hex");
  const authTag = Buffer.from(parts[3], "hex");
  const ciphertext = Buffer.from(parts[4], "hex");

  const key = scryptSync(passphrase, salt, 32, { N: 2 ** 14, r: 8, p: 1 });
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf-8");
  } catch {
    return null; // Wrong passphrase or tampered data
  }
}

/** Check if a file's contents are an encrypted private key. */
export function isEncryptedKey(data: string): boolean {
  return data.startsWith(ENCRYPTED_MAGIC + ":");
}

// ── Key persistence ─────────────────────────────────────────────

/**
 * Save a keypair. If passphrase is provided, the private key is encrypted.
 */
export function saveKeyPair(dataDir: string, kp: KeyPair, passphrase?: string): void {
  const keysDir = join(dataDir, "keys");
  mkdirSync(keysDir, { recursive: true });

  const privPath = join(keysDir, "quint.key");
  const pubPath = join(keysDir, "quint.pub");

  const privData = passphrase ? encryptPrivateKey(kp.privateKey, passphrase) : kp.privateKey;
  writeFileSync(privPath, privData, { mode: 0o600 });
  chmodSync(privPath, 0o600);
  writeFileSync(pubPath, kp.publicKey, { mode: 0o644 });
}

/**
 * Load a keypair. If the private key is encrypted, a passphrase is required.
 * Returns null if keys don't exist.
 * Throws if encrypted and passphrase is missing or wrong.
 */
export function loadKeyPair(dataDir: string, passphrase?: string): KeyPair | null {
  const privPath = join(dataDir, "keys", "quint.key");
  const pubPath = join(dataDir, "keys", "quint.pub");

  if (!existsSync(privPath) || !existsSync(pubPath)) return null;

  const privData = readFileSync(privPath, "utf-8");
  const publicKey = readFileSync(pubPath, "utf-8");

  if (isEncryptedKey(privData)) {
    if (!passphrase) {
      throw new Error("Private key is encrypted. Provide a passphrase with QUINT_PASSPHRASE or --passphrase.");
    }
    const privateKey = decryptPrivateKey(privData, passphrase);
    if (!privateKey) {
      throw new Error("Wrong passphrase — could not decrypt private key.");
    }
    return { publicKey, privateKey };
  }

  return { publicKey, privateKey: privData };
}

/**
 * Check if the stored private key is encrypted.
 */
export function isKeyEncrypted(dataDir: string): boolean {
  const privPath = join(dataDir, "keys", "quint.key");
  if (!existsSync(privPath)) return false;
  const data = readFileSync(privPath, "utf-8");
  return isEncryptedKey(data);
}

/**
 * Ensure a keypair exists. If passphrase is provided, new keys are encrypted.
 * For existing encrypted keys, passphrase is used to decrypt.
 */
export function ensureKeyPair(dataDir: string, passphrase?: string): KeyPair {
  const existing = loadKeyPair(dataDir, passphrase);
  if (existing) return existing;
  const kp = generateKeyPair();
  saveKeyPair(dataDir, kp, passphrase);
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
// NOTE: This is NOT RFC 8785 (JCS) compliant. It uses simple sorted-key
// JSON.stringify which works correctly for ASCII strings, numbers, booleans,
// and null values. It may produce non-deterministic output for:
//   - Unicode strings with special escape sequences
//   - Numbers requiring special IEEE 754 formatting
// This is sufficient for the current use case where all values are ASCII
// strings/numbers. If interoperability with external verifiers is needed,
// replace with a proper RFC 8785 implementation.

export function canonicalize(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ── Hashing ─────────────────────────────────────────────────────

export function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
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
