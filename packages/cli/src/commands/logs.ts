import { Command } from "commander";
import { loadPolicy, resolveDataDir, openAuditDb, type AuditEntry } from "@quint-security/core";

export const logsCommand = new Command("logs")
  .description("Search and display the audit log")
  .option("--server <name>", "Filter by server name")
  .option("--tool <name>", "Filter by tool name")
  .option("--denied", "Show only denied entries")
  .option("--since <iso-date>", "Show entries since ISO-8601 date")
  .option("-n, --limit <count>", "Max entries to show", "50")
  .option("--json", "Output as JSON")
  .action((opts: {
    server?: string;
    tool?: string;
    denied?: boolean;
    since?: string;
    limit: string;
    json?: boolean;
  }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuditDb(dataDir);

    try {
      const entries = db.query({
        server: opts.server,
        tool: opts.tool,
        verdict: opts.denied ? "deny" : undefined,
        since: opts.since,
        limit: parseInt(opts.limit, 10),
      });

      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      if (entries.length === 0) {
        console.log("No audit log entries found.");
        return;
      }

      console.log(`Showing ${entries.length} entries (newest first):\n`);

      for (const entry of entries) {
        printEntry(entry);
      }
    } finally {
      db.close();
    }
  });

function printEntry(e: AuditEntry): void {
  const icon = e.verdict === "deny" ? "✗" : e.verdict === "allow" ? "✓" : "→";
  const ts = e.timestamp.replace("T", " ").replace(/\.\d+Z$/, "Z");
  const tool = e.tool_name ? ` tool=${e.tool_name}` : "";
  const risk = e.risk_score != null ? ` risk=${e.risk_score}(${e.risk_level})` : "";
  console.log(`  ${icon} [${ts}] ${e.direction} ${e.method}${tool} server=${e.server_name} verdict=${e.verdict}${risk} id=${e.id}`);
}
