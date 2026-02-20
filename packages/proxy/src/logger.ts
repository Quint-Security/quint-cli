import {
  type AuditEntry,
  type AuditDb,
  type Verdict,
  type PolicyConfig,
  signData,
  canonicalize,
  sha256,
} from "@quint/core";

export class AuditLogger {
  private db: AuditDb;
  private privateKey: string;
  private publicKey: string;
  private policyHash: string;
  private lastSignature: string | null;

  constructor(db: AuditDb, privateKey: string, publicKey: string, policy: PolicyConfig) {
    this.db = db;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.policyHash = sha256(canonicalize(policy as unknown as Record<string, unknown>));
    // Initialize chain from the last entry in the database
    this.lastSignature = db.getLastSignature();
  }

  log(opts: {
    serverName: string;
    direction: "request" | "response";
    method: string;
    messageId: string | null;
    toolName: string | null;
    argumentsJson: string | null;
    responseJson: string | null;
    verdict: Verdict;
  }): number {
    const timestamp = new Date().toISOString();

    // Hash of the previous entry's signature (or empty string for first entry)
    const prevHash = this.lastSignature ? sha256(this.lastSignature) : "";

    // Build the entry object for signing (without id and signature)
    const signable: Record<string, unknown> = {
      timestamp,
      server_name: opts.serverName,
      direction: opts.direction,
      method: opts.method,
      message_id: opts.messageId,
      tool_name: opts.toolName,
      arguments_json: opts.argumentsJson,
      response_json: opts.responseJson,
      verdict: opts.verdict,
      policy_hash: this.policyHash,
      prev_hash: prevHash,
      public_key: this.publicKey,
    };

    const canonical = canonicalize(signable);
    const signature = signData(canonical, this.privateKey);

    const entry: Omit<AuditEntry, "id"> = {
      timestamp,
      server_name: opts.serverName,
      direction: opts.direction,
      method: opts.method,
      message_id: opts.messageId,
      tool_name: opts.toolName,
      arguments_json: opts.argumentsJson,
      response_json: opts.responseJson,
      verdict: opts.verdict,
      policy_hash: this.policyHash,
      prev_hash: prevHash,
      signature,
      public_key: this.publicKey,
    };

    const id = this.db.insert(entry);

    // Update chain pointer
    this.lastSignature = signature;

    return id;
  }
}
