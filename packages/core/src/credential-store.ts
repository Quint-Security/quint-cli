import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  scryptSync, randomBytes,
  createCipheriv, createDecipheriv,
  createHash,
} from "node:crypto";
import { openDatabase, type DatabaseInstance } from "./sqlite.js";

// ── Types ──────────────────────────────────────────────────────

export interface StoredCredential {
  id: string;
  provider: string;
  access_token: string;
  refresh_token: string | null;
  token_type: string;
  scopes: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  metadata: string | null;
}

export interface CredentialSummary {
  id: string;
  provider: string;
  token_type: string;
  scopes: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface StoreCredentialOpts {
  provider: string;
  accessToken: string;
  refreshToken?: string;
  tokenType?: string;
  scopes?: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}

// ── Schema ─────────────────────────────────────────────────────

const SCHEMA = `
CREATE TABLE IF NOT EXISTS credentials (
  id              TEXT PRIMARY KEY,
  provider        TEXT NOT NULL,
  access_token    TEXT NOT NULL,
  refresh_token   TEXT,
  token_type      TEXT NOT NULL DEFAULT 'bearer',
  scopes          TEXT NOT NULL DEFAULT '',
  expires_at      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  metadata        TEXT
);
`;

// ── Encryption helpers (AES-256-GCM with scrypt) ───────────────

const CRED_MAGIC = "QUINT-CRED-V1";

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: 2 ** 14, r: 8, p: 1 });
}

function encryptToken(plaintext: string, passphrase: string): string {
  const salt = randomBytes(32);
  const key = deriveKey(passphrase, salt);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [
    CRED_MAGIC,
    salt.toString("hex"),
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex"),
  ].join(":");
}

function decryptToken(encrypted: string, passphrase: string): string | null {
  const parts = encrypted.split(":");
  if (parts.length !== 5 || parts[0] !== CRED_MAGIC) return null;

  const salt = Buffer.from(parts[1], "hex");
  const iv = Buffer.from(parts[2], "hex");
  const authTag = Buffer.from(parts[3], "hex");
  const ciphertext = Buffer.from(parts[4], "hex");

  const key = deriveKey(passphrase, salt);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf-8");
  } catch {
    return null;
  }
}

// ── CredentialStore ────────────────────────────────────────────

export class CredentialStore {
  private db: DatabaseInstance;
  private passphrase: string;

  constructor(dbPath: string, encryptionKey: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = openDatabase(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
    this.passphrase = encryptionKey;
  }

  store(id: string, opts: StoreCredentialOpts): void {
    const now = new Date().toISOString();
    const encAccessToken = encryptToken(opts.accessToken, this.passphrase);
    const encRefreshToken = opts.refreshToken
      ? encryptToken(opts.refreshToken, this.passphrase)
      : null;

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO credentials
        (id, provider, access_token, refresh_token, token_type, scopes,
         expires_at, created_at, updated_at, metadata)
      VALUES
        (@id, @provider, @access_token, @refresh_token, @token_type, @scopes,
         @expires_at, @created_at, @updated_at, @metadata)
    `);

    stmt.run({
      id,
      provider: opts.provider,
      access_token: encAccessToken,
      refresh_token: encRefreshToken,
      token_type: opts.tokenType ?? "bearer",
      scopes: opts.scopes ?? "",
      expires_at: opts.expiresAt ?? null,
      created_at: now,
      updated_at: now,
      metadata: opts.metadata ? JSON.stringify(opts.metadata) : null,
    });
  }

  get(id: string): StoredCredential | undefined {
    const row = this.db.prepare(
      "SELECT * FROM credentials WHERE id = @id"
    ).get({ id }) as StoredCredential | undefined;
    return row ?? undefined;
  }

  getAccessToken(id: string): string | undefined {
    const row = this.db.prepare(
      "SELECT access_token FROM credentials WHERE id = @id"
    ).get({ id }) as { access_token: string } | undefined;
    if (!row) return undefined;
    return decryptToken(row.access_token, this.passphrase) ?? undefined;
  }

  list(): CredentialSummary[] {
    return this.db.prepare(
      "SELECT id, provider, token_type, scopes, expires_at, created_at, updated_at FROM credentials ORDER BY id ASC"
    ).all() as CredentialSummary[];
  }

  remove(id: string): boolean {
    const result = this.db.prepare(
      "DELETE FROM credentials WHERE id = @id"
    ).run({ id });
    return result.changes > 0;
  }

  isExpired(id: string): boolean {
    const row = this.db.prepare(
      "SELECT expires_at FROM credentials WHERE id = @id"
    ).get({ id }) as { expires_at: string | null } | undefined;
    if (!row) return true;
    if (!row.expires_at) return false;
    return new Date(row.expires_at) < new Date();
  }

  updateTokens(id: string, accessToken: string, refreshToken?: string, expiresAt?: string): void {
    const now = new Date().toISOString();
    const encAccessToken = encryptToken(accessToken, this.passphrase);
    const encRefreshToken = refreshToken
      ? encryptToken(refreshToken, this.passphrase)
      : undefined;

    if (encRefreshToken !== undefined) {
      this.db.prepare(`
        UPDATE credentials
        SET access_token = @access_token,
            refresh_token = @refresh_token,
            expires_at = @expires_at,
            updated_at = @updated_at
        WHERE id = @id
      `).run({
        id,
        access_token: encAccessToken,
        refresh_token: encRefreshToken,
        expires_at: expiresAt ?? null,
        updated_at: now,
      });
    } else {
      this.db.prepare(`
        UPDATE credentials
        SET access_token = @access_token,
            expires_at = @expires_at,
            updated_at = @updated_at
        WHERE id = @id
      `).run({
        id,
        access_token: encAccessToken,
        expires_at: expiresAt ?? null,
        updated_at: now,
      });
    }
  }

  close(): void {
    this.db.close();
  }
}

// ── Factory ────────────────────────────────────────────────────

/**
 * Derive an encryption key from either QUINT_PASSPHRASE or the private key PEM.
 */
export function deriveCredentialKey(passphrase?: string, privateKeyPem?: string): string {
  if (passphrase) return passphrase;
  if (privateKeyPem) {
    return createHash("sha256").update(privateKeyPem, "utf-8").digest("hex");
  }
  throw new Error("No encryption key available. Set QUINT_PASSPHRASE or ensure signing keys exist.");
}

export function openCredentialStore(dataDir: string, encryptionKey: string): CredentialStore {
  return new CredentialStore(join(dataDir, "credentials.db"), encryptionKey);
}
