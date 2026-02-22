import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { openDatabase, type DatabaseInstance } from "./sqlite.js";
import type { AuditEntry } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp       TEXT NOT NULL,
  server_name     TEXT NOT NULL,
  direction       TEXT NOT NULL,
  method          TEXT NOT NULL,
  message_id      TEXT,
  tool_name       TEXT,
  arguments_json  TEXT,
  response_json   TEXT,
  verdict         TEXT NOT NULL,
  risk_score      INTEGER,
  risk_level      TEXT,
  policy_hash     TEXT NOT NULL DEFAULT '',
  prev_hash       TEXT NOT NULL DEFAULT '',
  nonce           TEXT NOT NULL DEFAULT '',
  signature       TEXT NOT NULL,
  public_key      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_server_name ON audit_log(server_name);
CREATE INDEX IF NOT EXISTS idx_tool_name   ON audit_log(tool_name);
CREATE INDEX IF NOT EXISTS idx_verdict     ON audit_log(verdict);
`;

// Migration: add columns if they don't exist (for DBs created before this version)
const MIGRATIONS = [
  `ALTER TABLE audit_log ADD COLUMN policy_hash TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE audit_log ADD COLUMN nonce TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE audit_log ADD COLUMN risk_score INTEGER`,
  `ALTER TABLE audit_log ADD COLUMN risk_level TEXT`,
];

export class AuditDb {
  private db: DatabaseInstance;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = openDatabase(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
    this.migrate();
  }

  private migrate(): void {
    for (const sql of MIGRATIONS) {
      try {
        this.db.exec(sql);
      } catch {
        // Column already exists — ignore
      }
    }
  }

  /** Get the signature of the last entry (for hash chaining) */
  getLastSignature(): string | null {
    const row = this.db.prepare(
      "SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1"
    ).get() as { signature: string } | undefined;
    return row?.signature ?? null;
  }

  /**
   * Atomically read the last signature and insert a new entry.
   * This prevents chain breaks when multiple proxy instances share a DB.
   */
  insertAtomic(buildEntry: (prevSignature: string | null) => Omit<AuditEntry, "id">): number {
    const insertStmt = this.db.prepare(`
      INSERT INTO audit_log
        (timestamp, server_name, direction, method, message_id, tool_name,
         arguments_json, response_json, verdict, risk_score, risk_level,
         policy_hash, prev_hash, nonce, signature, public_key)
      VALUES
        (@timestamp, @server_name, @direction, @method, @message_id, @tool_name,
         @arguments_json, @response_json, @verdict, @risk_score, @risk_level,
         @policy_hash, @prev_hash, @nonce, @signature, @public_key)
    `);
    const lastSigStmt = this.db.prepare(
      "SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1"
    );

    let rowId = 0;
    this.db.transaction(() => {
      const lastRow = lastSigStmt.get() as { signature: string } | undefined;
      const entry = buildEntry(lastRow?.signature ?? null);
      const result = insertStmt.run(entry);
      rowId = result.lastInsertRowid as number;
    })();
    return rowId;
  }

  insert(entry: Omit<AuditEntry, "id">): number {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log
        (timestamp, server_name, direction, method, message_id, tool_name,
         arguments_json, response_json, verdict, risk_score, risk_level,
         policy_hash, prev_hash, nonce, signature, public_key)
      VALUES
        (@timestamp, @server_name, @direction, @method, @message_id, @tool_name,
         @arguments_json, @response_json, @verdict, @risk_score, @risk_level,
         @policy_hash, @prev_hash, @nonce, @signature, @public_key)
    `);
    const result = stmt.run(entry);
    return result.lastInsertRowid as number;
  }

  getById(id: number): AuditEntry | undefined {
    return this.db.prepare("SELECT * FROM audit_log WHERE id = ?").get(id) as AuditEntry | undefined;
  }

  /** Get entries in ID order (ascending) for chain verification */
  getRange(startId: number, endId: number): AuditEntry[] {
    return this.db.prepare(
      "SELECT * FROM audit_log WHERE id >= ? AND id <= ? ORDER BY id ASC"
    ).all(startId, endId) as AuditEntry[];
  }

  /** Get all entries in ID order (ascending) for chain verification */
  getAll(): AuditEntry[] {
    return this.db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all() as AuditEntry[];
  }

  query(opts: {
    server?: string;
    tool?: string;
    verdict?: string;
    since?: string;
    limit?: number;
  } = {}): AuditEntry[] {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (opts.server) {
      conditions.push("server_name = @server");
      params.server = opts.server;
    }
    if (opts.tool) {
      conditions.push("tool_name = @tool");
      params.tool = opts.tool;
    }
    if (opts.verdict) {
      conditions.push("verdict = @verdict");
      params.verdict = opts.verdict;
    }
    if (opts.since) {
      conditions.push("timestamp >= @since");
      params.since = opts.since;
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = opts.limit ?? 100;

    return this.db.prepare(
      `SELECT * FROM audit_log ${where} ORDER BY id DESC LIMIT ${limit}`
    ).all(params) as AuditEntry[];
  }

  getLast(n: number): AuditEntry[] {
    return this.db.prepare(
      "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?"
    ).all(n) as AuditEntry[];
  }

  count(): number {
    const row = this.db.prepare("SELECT COUNT(*) as cnt FROM audit_log").get() as { cnt: number };
    return row.cnt;
  }

  close(): void {
    this.db.close();
  }
}

export function openAuditDb(dataDir: string): AuditDb {
  return new AuditDb(join(dataDir, "quint.db"));
}
