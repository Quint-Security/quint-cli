import {
  type AuditEntry,
  type Verdict,
  type AuditDb,
  signData,
  canonicalize,
} from "@quint/core";

export class AuditLogger {
  private db: AuditDb;
  private privateKey: string;
  private publicKey: string;

  constructor(db: AuditDb, privateKey: string, publicKey: string) {
    this.db = db;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
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
      signature,
      public_key: this.publicKey,
    };

    return this.db.insert(entry);
  }
}
