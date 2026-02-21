import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ApiKey, Session } from "./types.js";

const AUTH_SCHEMA = `
CREATE TABLE IF NOT EXISTS api_keys (
  id          TEXT PRIMARY KEY,
  key_hash    TEXT NOT NULL UNIQUE,
  owner_id    TEXT NOT NULL,
  label       TEXT NOT NULL,
  scopes      TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT,
  revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  subject_id  TEXT NOT NULL,
  auth_method TEXT NOT NULL,
  scopes      TEXT NOT NULL DEFAULT '',
  issued_at   TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner   ON api_keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);
`;

export class AuthDb {
  private db: Database.Database;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(AUTH_SCHEMA);
  }

  // ── API Keys ──────────────────────────────────────────────────

  insertApiKey(key: ApiKey): void {
    this.db.prepare(`
      INSERT INTO api_keys (id, key_hash, owner_id, label, scopes, created_at, expires_at, revoked)
      VALUES (@id, @key_hash, @owner_id, @label, @scopes, @created_at, @expires_at, @revoked)
    `).run({
      ...key,
      revoked: key.revoked ? 1 : 0,
    });
  }

  getApiKeyByHash(keyHash: string): ApiKey | undefined {
    const row = this.db.prepare(
      "SELECT * FROM api_keys WHERE key_hash = ?"
    ).get(keyHash) as (Omit<ApiKey, "revoked"> & { revoked: number }) | undefined;
    if (!row) return undefined;
    return { ...row, revoked: row.revoked === 1 };
  }

  getApiKeyById(id: string): ApiKey | undefined {
    const row = this.db.prepare(
      "SELECT * FROM api_keys WHERE id = ?"
    ).get(id) as (Omit<ApiKey, "revoked"> & { revoked: number }) | undefined;
    if (!row) return undefined;
    return { ...row, revoked: row.revoked === 1 };
  }

  listApiKeys(ownerId?: string): ApiKey[] {
    const query = ownerId
      ? "SELECT * FROM api_keys WHERE owner_id = ? ORDER BY created_at DESC"
      : "SELECT * FROM api_keys ORDER BY created_at DESC";
    const rows = (ownerId
      ? this.db.prepare(query).all(ownerId)
      : this.db.prepare(query).all()
    ) as Array<Omit<ApiKey, "revoked"> & { revoked: number }>;
    return rows.map((r) => ({ ...r, revoked: r.revoked === 1 }));
  }

  revokeApiKey(id: string): boolean {
    const result = this.db.prepare(
      "UPDATE api_keys SET revoked = 1 WHERE id = ?"
    ).run(id);
    return result.changes > 0;
  }

  // ── Sessions ──────────────────────────────────────────────────

  insertSession(session: Session): void {
    this.db.prepare(`
      INSERT INTO sessions (id, subject_id, auth_method, scopes, issued_at, expires_at, revoked)
      VALUES (@id, @subject_id, @auth_method, @scopes, @issued_at, @expires_at, @revoked)
    `).run({
      ...session,
      revoked: session.revoked ? 1 : 0,
    });
  }

  getSession(id: string): Session | undefined {
    const row = this.db.prepare(
      "SELECT * FROM sessions WHERE id = ?"
    ).get(id) as (Omit<Session, "revoked"> & { revoked: number }) | undefined;
    if (!row) return undefined;
    return { ...row, revoked: row.revoked === 1 };
  }

  revokeSession(id: string): boolean {
    const result = this.db.prepare(
      "UPDATE sessions SET revoked = 1 WHERE id = ?"
    ).run(id);
    return result.changes > 0;
  }

  revokeSessionsBySubject(subjectId: string): number {
    const result = this.db.prepare(
      "UPDATE sessions SET revoked = 1 WHERE subject_id = ? AND revoked = 0"
    ).run(subjectId);
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}

export function openAuthDb(dataDir: string): AuthDb {
  return new AuthDb(join(dataDir, "auth.db"));
}
