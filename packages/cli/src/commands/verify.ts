import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  openAuditDb,
  verifySignature,
  canonicalize,
  sha256,
  type AuditEntry,
} from "@quint/core";

export const verifyCommand = new Command("verify")
  .description("Verify Ed25519 signatures and hash chain on audit log entries")
  .option("--id <n>", "Verify a specific entry by ID")
  .option("--last <n>", "Verify the last N entries", "20")
  .option("--all", "Verify all entries")
  .option("--chain", "Also verify hash chain integrity (requires --all or --last)")
  .action((opts: { id?: string; last?: string; all?: boolean; chain?: boolean }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuditDb(dataDir);

    try {
      let entries: AuditEntry[];

      if (opts.id) {
        const entry = db.getById(parseInt(opts.id, 10));
        entries = entry ? [entry] : [];
      } else if (opts.all) {
        entries = db.getAll(); // ascending order for chain verification
      } else {
        entries = db.getLast(parseInt(opts.last!, 10));
        // Reverse to ascending for chain verification
        entries.reverse();
      }

      if (entries.length === 0) {
        console.log("No entries to verify.");
        return;
      }

      // Signature verification
      let sigValid = 0;
      let sigInvalid = 0;

      for (const entry of entries) {
        const ok = verifyEntry(entry);
        if (ok) {
          sigValid++;
        } else {
          sigInvalid++;
          console.log(`  ✗ INVALID signature on entry #${entry.id} (${entry.timestamp})`);
        }
      }

      console.log(`\nSignatures: ${entries.length} checked, ${sigValid} valid, ${sigInvalid} invalid`);

      // Hash chain verification
      if (opts.chain || opts.all) {
        let chainValid = 0;
        let chainBroken = 0;

        for (let i = 1; i < entries.length; i++) {
          const prev = entries[i - 1];
          const curr = entries[i];

          if (curr.prev_hash === "" && prev.prev_hash === "") {
            // Legacy entries without hash chain — skip
            continue;
          }

          const expectedHash = sha256(prev.signature);
          if (curr.prev_hash === expectedHash) {
            chainValid++;
          } else {
            chainBroken++;
            console.log(`  ⛓ BROKEN chain at entry #${curr.id} — prev_hash doesn't match entry #${prev.id}`);
          }
        }

        if (chainValid + chainBroken > 0) {
          console.log(`Chain:      ${chainValid + chainBroken} links checked, ${chainValid} valid, ${chainBroken} broken`);
        } else {
          console.log(`Chain:      no chain data (legacy entries)`);
        }
      }

      if (sigInvalid > 0) {
        process.exit(1);
      }
    } finally {
      db.close();
    }
  });

function verifyEntry(entry: AuditEntry): boolean {
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
    policy_hash: entry.policy_hash ?? "",
    prev_hash: entry.prev_hash ?? "",
    public_key: entry.public_key,
  };

  const canonical = canonicalize(signable);
  return verifySignature(canonical, entry.signature, entry.public_key);
}
