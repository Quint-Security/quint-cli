/**
 * Risk scoring engine.
 *
 * Each intercepted action gets a risk score from 0–100.
 * The score is based on:
 *   1. The method being called (tools/call is riskier than tools/list)
 *   2. The tool name (some tools are inherently more dangerous)
 *   3. The arguments (e.g. destructive keywords like "delete", "drop", "rm")
 *   4. Accumulated behavior (repeated high-risk attempts escalate)
 *
 * If the score exceeds a threshold, the action can be:
 *   - Flagged for manual approval
 *   - Auto-denied
 *   - Trigger session/token revocation
 */

// ── Built-in risk patterns ──────────────────────────────────────

interface RiskPattern {
  /** Glob pattern for tool name */
  tool: string;
  /** Base risk score for this tool (0-100) */
  baseScore: number;
}

const DEFAULT_TOOL_RISKS: RiskPattern[] = [
  // Destructive file operations
  { tool: "Delete*",       baseScore: 80 },
  { tool: "Remove*",       baseScore: 80 },
  { tool: "Rm*",           baseScore: 80 },
  // Write operations
  { tool: "Write*",        baseScore: 50 },
  { tool: "Create*",       baseScore: 40 },
  { tool: "Update*",       baseScore: 45 },
  { tool: "Edit*",         baseScore: 45 },
  // Database operations
  { tool: "*Sql*",         baseScore: 60 },
  { tool: "*Query*",       baseScore: 40 },
  { tool: "*Database*",    baseScore: 55 },
  // Execution
  { tool: "*Execute*",     baseScore: 70 },
  { tool: "*Run*",         baseScore: 65 },
  { tool: "*Shell*",       baseScore: 75 },
  { tool: "*Bash*",        baseScore: 75 },
  { tool: "*Command*",     baseScore: 70 },
  // Network
  { tool: "*Fetch*",       baseScore: 35 },
  { tool: "*Http*",        baseScore: 35 },
  { tool: "*Request*",     baseScore: 35 },
  // Read operations (low risk)
  { tool: "Read*",         baseScore: 10 },
  { tool: "Get*",          baseScore: 10 },
  { tool: "List*",         baseScore: 5 },
  { tool: "Search*",       baseScore: 10 },
];

// Argument keywords that bump the risk score
const DANGEROUS_ARG_KEYWORDS = [
  { pattern: /\bdrop\b/i,       boost: 30 },
  { pattern: /\bdelete\b/i,     boost: 25 },
  { pattern: /\btruncate\b/i,   boost: 25 },
  { pattern: /\brm\s+-rf\b/i,   boost: 30 },
  { pattern: /\bformat\b/i,     boost: 20 },
  { pattern: /\b(sudo|chmod|chown)\b/i, boost: 25 },
  { pattern: /\bpassword\b/i,   boost: 15 },
  { pattern: /\bsecret\b/i,     boost: 15 },
  { pattern: /\btoken\b/i,      boost: 10 },
  { pattern: /\b(\.env|credentials)\b/i, boost: 20 },
];

// ── Risk scoring logic ──────────────────────────────────────────

import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { globMatch } from "./config.js";

export interface RiskScore {
  /** Final score 0-100 (capped) */
  score: number;
  /** Base score from tool pattern match */
  baseScore: number;
  /** Boost from argument analysis */
  argBoost: number;
  /** Boost from repeated high-risk behavior */
  behaviorBoost: number;
  /** Human-readable risk level */
  level: "low" | "medium" | "high" | "critical";
  /** Reasons contributing to the score */
  reasons: string[];
}

export interface RiskThresholds {
  /** Score at which action is flagged for review (default 60) */
  flag: number;
  /** Score at which action is auto-denied (default 85) */
  deny: number;
  /** Number of high-risk actions in window before revocation (default 5) */
  revokeAfter: number;
  /** Time window in ms for behavior tracking (default 5 minutes) */
  windowMs: number;
}

const DEFAULT_THRESHOLDS: RiskThresholds = {
  flag: 60,
  deny: 85,
  revokeAfter: 5,
  windowMs: 5 * 60 * 1000,
};

// ── Behavior persistence ────────────────────────────────────────

const BEHAVIOR_SCHEMA = `
CREATE TABLE IF NOT EXISTS behavior_tracker (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id  TEXT NOT NULL,
  timestamp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_behavior_subject ON behavior_tracker(subject_id);
CREATE INDEX IF NOT EXISTS idx_behavior_ts      ON behavior_tracker(timestamp);
`;

export class BehaviorDb {
  private db: Database.Database;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(BEHAVIOR_SCHEMA);
  }

  record(subjectId: string, timestamp: number): void {
    this.db.prepare(
      "INSERT INTO behavior_tracker (subject_id, timestamp) VALUES (?, ?)"
    ).run(subjectId, timestamp);
  }

  /** Count entries for subject within the window, and prune older ones. */
  count(subjectId: string, cutoff: number): number {
    // Prune old entries
    this.db.prepare(
      "DELETE FROM behavior_tracker WHERE subject_id = ? AND timestamp <= ?"
    ).run(subjectId, cutoff);
    // Count remaining
    const row = this.db.prepare(
      "SELECT COUNT(*) as cnt FROM behavior_tracker WHERE subject_id = ?"
    ).get(subjectId) as { cnt: number };
    return row.cnt;
  }

  close(): void {
    this.db.close();
  }
}

export function openBehaviorDb(dataDir: string): BehaviorDb {
  return new BehaviorDb(join(dataDir, "behavior.db"));
}

/**
 * Tracker for repeated high-risk behavior per subject.
 * Uses SQLite for persistence when a BehaviorDb is provided,
 * falls back to in-memory tracking otherwise.
 */
class BehaviorTracker {
  // In-memory fallback: subjectId → timestamps of high-risk actions
  private history: Map<string, number[]> = new Map();
  private windowMs: number;
  private behaviorDb: BehaviorDb | null;

  constructor(windowMs: number, behaviorDb?: BehaviorDb) {
    this.windowMs = windowMs;
    this.behaviorDb = behaviorDb ?? null;
  }

  private pruneInMemory(subjectId: string): number[] {
    const cutoff = Date.now() - this.windowMs;
    const entries = (this.history.get(subjectId) ?? []).filter((t) => t > cutoff);
    if (entries.length === 0) {
      this.history.delete(subjectId);
    } else {
      this.history.set(subjectId, entries);
    }
    return entries;
  }

  record(subjectId: string): void {
    const now = Date.now();
    if (this.behaviorDb) {
      this.behaviorDb.record(subjectId, now);
    } else {
      const entries = this.pruneInMemory(subjectId);
      entries.push(now);
      this.history.set(subjectId, entries);
    }
  }

  /** Count of high-risk actions within the sliding window. */
  count(subjectId: string): number {
    if (this.behaviorDb) {
      const cutoff = Date.now() - this.windowMs;
      return this.behaviorDb.count(subjectId, cutoff);
    }
    return this.pruneInMemory(subjectId).length;
  }
}

export class RiskEngine {
  private thresholds: RiskThresholds;
  private tracker: BehaviorTracker;
  private customPatterns: RiskPattern[];

  constructor(opts?: {
    thresholds?: Partial<RiskThresholds>;
    customPatterns?: RiskPattern[];
    behaviorDb?: BehaviorDb;
  }) {
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...opts?.thresholds };
    this.tracker = new BehaviorTracker(this.thresholds.windowMs, opts?.behaviorDb);
    this.customPatterns = opts?.customPatterns ?? [];
  }

  /**
   * Score a tool call.
   * @param toolName  The MCP tool being called
   * @param argsJson  JSON string of arguments (optional)
   * @param subjectId Who is making the call (API key ID, session subject, or "anonymous")
   */
  score(toolName: string, argsJson: string | null, subjectId: string = "anonymous"): RiskScore {
    const reasons: string[] = [];
    let baseScore = 20; // default for unknown tools

    // Check custom patterns first, then defaults
    const allPatterns = [...this.customPatterns, ...DEFAULT_TOOL_RISKS];
    for (const pattern of allPatterns) {
      if (globMatch(pattern.tool, toolName)) {
        baseScore = pattern.baseScore;
        reasons.push(`tool "${toolName}" matches pattern "${pattern.tool}" (base=${pattern.baseScore})`);
        break;
      }
    }

    if (reasons.length === 0) {
      reasons.push(`tool "${toolName}" — no pattern match, using default base score`);
    }

    // Argument analysis
    let argBoost = 0;
    if (argsJson) {
      for (const kw of DANGEROUS_ARG_KEYWORDS) {
        if (kw.pattern.test(argsJson)) {
          argBoost += kw.boost;
          reasons.push(`argument contains "${kw.pattern.source}" (+${kw.boost})`);
        }
      }
    }

    // Behavior escalation
    let behaviorBoost = 0;
    const recentCount = this.tracker.count(subjectId);
    if (recentCount > 0) {
      // Each prior high-risk action in the window adds 5 points
      behaviorBoost = recentCount * 5;
      reasons.push(`${recentCount} high-risk action(s) in window (+${behaviorBoost})`);
    }

    const raw = baseScore + argBoost + behaviorBoost;
    const score = Math.min(100, Math.max(0, raw));

    const level = score >= this.thresholds.deny ? "critical"
      : score >= this.thresholds.flag ? "high"
      : score >= 30 ? "medium"
      : "low";

    // Record if this was a high-risk action
    if (score >= this.thresholds.flag) {
      this.tracker.record(subjectId);
    }

    return { score, baseScore, argBoost, behaviorBoost, level, reasons };
  }

  /**
   * Check if the subject should be revoked based on repeated high-risk behavior.
   */
  shouldRevoke(subjectId: string): boolean {
    return this.tracker.count(subjectId) >= this.thresholds.revokeAfter;
  }

  /**
   * Determine the action based on risk score.
   */
  evaluate(risk: RiskScore): "allow" | "flag" | "deny" {
    if (risk.score >= this.thresholds.deny) return "deny";
    if (risk.score >= this.thresholds.flag) return "flag";
    return "allow";
  }

  getThresholds(): RiskThresholds {
    return { ...this.thresholds };
  }
}
