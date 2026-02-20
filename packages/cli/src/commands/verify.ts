import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  openAuditDb,
  verifySignature,
  canonicalize,
  type AuditEntry,
} from "@quint/core";

export const verifyCommand = new Command("verify")
  .description("Verify Ed25519 signatures on audit log entries")
  .option("--id <n>", "Verify a specific entry by ID")
  .option("--last <n>", "Verify the last N entries", "20")
  .option("--all", "Verify all entries")
  .action((opts: { id?: string; last?: string; all?: boolean }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuditDb(dataDir);

    try {
      let entries: AuditEntry[];

      if (opts.id) {
        const entry = db.getById(parseInt(opts.id, 10));
        entries = entry ? [entry] : [];
      } else if (opts.all) {
        entries = db.query({ limit: 100000 });
      } else {
        entries = db.getLast(parseInt(opts.last!, 10));
      }

      if (entries.length === 0) {
        console.log("No entries to verify.");
        return;
      }

      let valid = 0;
      let invalid = 0;

      for (const entry of entries) {
        const ok = verifyEntry(entry);
        if (ok) {
          valid++;
        } else {
          invalid++;
          console.log(`  ✗ INVALID signature on entry #${entry.id} (${entry.timestamp})`);
        }
      }

      console.log(`\nVerified ${entries.length} entries: ${valid} valid, ${invalid} invalid`);

      if (invalid > 0) {
        process.exit(1);
      }
    } finally {
      db.close();
    }
  });

function verifyEntry(entry: AuditEntry): boolean {
  // Reconstruct the signable object
  const signable: Record<string, unknown> = {
    timestamp: entry.timestamp,
    server_name: entry.server_name,
    direction: entry.direction,
    method: entry.method,
    message_id: entry.message_id,
    tool_name: entry.tool_name,
    arguments_json: entry.arguments_json,
    response_json: entry.response_json,
    verdict: entry.verdict,
    public_key: entry.public_key,
  };

  const canonical = canonicalize(signable);
  return verifySignature(canonical, entry.signature, entry.public_key);
}
