import {
  type AuditEntry,
  type AuditDb,
  type Verdict,
  type PolicyConfig,
  signData,
  canonicalize,
  sha256,
} from "@quint-security/core";
import { randomUUID } from "node:crypto";

export class AuditLogger {
  private db: AuditDb;
  private privateKey: string;
  private publicKey: string;
  private policyHash: string;

  constructor(db: AuditDb, privateKey: string, publicKey: string, policy: PolicyConfig) {
    this.db = db;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.policyHash = sha256(canonicalize(policy as unknown as Record<string, unknown>));
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
    riskScore?: number | null;
    riskLevel?: string | null;
  }): number {
    // Use insertAtomic to read last signature and insert in one transaction,
    // preventing chain breaks when multiple proxy instances share the same DB.
    return this.db.insertAtomic((prevSignature: string | null) => {
      const timestamp = new Date().toISOString();
      const nonce = randomUUID();
      const prevHash = prevSignature ? sha256(prevSignature) : "";

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
        risk_score: opts.riskScore ?? null,
        risk_level: opts.riskLevel ?? null,
        policy_hash: this.policyHash,
        prev_hash: prevHash,
        nonce,
        public_key: this.publicKey,
      };

      const canonical = canonicalize(signable);
      const signature = signData(canonical, this.privateKey);

      return {
        timestamp,
        server_name: opts.serverName,
        direction: opts.direction,
        method: opts.method,
        message_id: opts.messageId,
        tool_name: opts.toolName,
        arguments_json: opts.argumentsJson,
        response_json: opts.responseJson,
        verdict: opts.verdict,
        risk_score: opts.riskScore ?? null,
        risk_level: opts.riskLevel ?? null,
        policy_hash: this.policyHash,
        prev_hash: prevHash,
        nonce,
        signature,
        public_key: this.publicKey,
      };
    });
  }
}
