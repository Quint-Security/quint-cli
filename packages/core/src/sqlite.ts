/**
 * SQLite compatibility layer.
 *
 * Under bun (standalone binary), uses bun:sqlite.
 * Under Node.js (development), uses better-sqlite3.
 *
 * The key difference: better-sqlite3 strips @ prefixes from named param keys
 * (SQL uses @name, JS passes { name: value }). bun:sqlite requires exact key
 * matches. This adapter normalizes the difference.
 */

// Detect runtime
const isBun = typeof (globalThis as Record<string, unknown>).Bun !== "undefined";

/** Minimal interface matching the subset of better-sqlite3 we use. */
export interface Statement {
  run(...params: unknown[]): { lastInsertRowid: number | bigint; changes: number };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface DatabaseInstance {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  transaction<T>(fn: () => T): () => T;
  pragma(pragma: string): unknown;
  close(): void;
}

/**
 * Add $ prefix to object keys for bun:sqlite named parameter binding.
 * better-sqlite3 strips @/$/: from keys; bun:sqlite needs them.
 */
function prefixParams(params: unknown): unknown {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    return params;
  }
  const obj = params as Record<string, unknown>;
  const prefixed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (key.startsWith("$") || key.startsWith("@") || key.startsWith(":")) {
      prefixed[key] = value;
    } else {
      prefixed[`$${key}`] = value;
    }
  }
  return prefixed;
}

function wrapBunStatement(stmt: { run: Function; get: Function; all: Function }): Statement {
  return {
    run(...params: unknown[]) {
      const args = params.length === 1 ? [prefixParams(params[0])] : params;
      const result = stmt.run(...args);
      return {
        lastInsertRowid: result?.lastInsertRowid ?? 0,
        changes: result?.changes ?? 0,
      };
    },
    get(...params: unknown[]) {
      const args = params.length === 1 ? [prefixParams(params[0])] : params;
      return stmt.get(...args) ?? undefined;
    },
    all(...params: unknown[]) {
      const args = params.length === 1 ? [prefixParams(params[0])] : params;
      return stmt.all(...args);
    },
  };
}

function wrapBunDatabase(db: { exec: Function; prepare: Function; transaction: Function; close: Function }): DatabaseInstance {
  return {
    exec(sql: string) { db.exec(sql); },
    prepare(sql: string) {
      // bun:sqlite uses $param, convert @param to $param in SQL
      const normalizedSql = sql.replace(/@(\w+)/g, "$$$$1");
      return wrapBunStatement(db.prepare(normalizedSql));
    },
    transaction<T>(fn: () => T): () => T {
      return db.transaction(fn);
    },
    pragma(pragma: string) {
      // bun:sqlite uses db.exec("PRAGMA ...")
      db.exec(`PRAGMA ${pragma}`);
    },
    close() { db.close(); },
  };
}

export function openDatabase(path: string): DatabaseInstance {
  if (isBun) {
    // Dynamic import workaround: bun:sqlite is only available under bun
    // Use eval to avoid Node.js/tsc trying to resolve the import
    const BunDatabase = (globalThis as Record<string, unknown>).__bunSqlite ??
      (() => { const m = require("bun:sqlite"); (globalThis as Record<string, unknown>).__bunSqlite = m.Database; return m.Database; })();
    const instance = new (BunDatabase as new (path: string) => unknown)(path);
    return wrapBunDatabase(instance as { exec: Function; prepare: Function; transaction: Function; close: Function });
  } else {
    // Node.js: use better-sqlite3
    const BetterSqlite3 = require("better-sqlite3");
    return new BetterSqlite3(path) as DatabaseInstance;
  }
}
