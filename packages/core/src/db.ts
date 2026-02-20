import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
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
  signature       TEXT NOT NULL,
  public_key      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_server_name ON audit_log(server_name);
CREATE INDEX IF NOT EXISTS idx_tool_name   ON audit_log(tool_name);
CREATE INDEX IF NOT EXISTS idx_verdict     ON audit_log(verdict);
`;

export class AuditDb {
  private db: Database.Database;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  insert(entry: Omit<AuditEntry, "id">): number {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log
        (timestamp, server_name, direction, method, message_id, tool_name,
         arguments_json, response_json, verdict, signature, public_key)
      VALUES
        (@timestamp, @server_name, @direction, @method, @message_id, @tool_name,
         @arguments_json, @response_json, @verdict, @signature, @public_key)
    `);
    const result = stmt.run(entry);
    return result.lastInsertRowid as number;
  }

  getById(id: number): AuditEntry | undefined {
    return this.db.prepare("SELECT * FROM audit_log WHERE id = ?").get(id) as AuditEntry | undefined;
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
