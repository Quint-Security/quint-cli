import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  generateKeyPair,
  saveKeyPair,
  loadKeyPair,
  publicKeyFingerprint,
} from "@quint-security/core";
import { existsSync } from "node:fs";
import { join } from "node:path";

export const keysCommand = new Command("keys")
  .description("Manage Ed25519 signing keys");

keysCommand
  .command("generate")
  .description("Generate a new Ed25519 keypair")
  .option("--force", "Overwrite existing keys")
  .action((opts: { force?: boolean }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const privPath = join(dataDir, "keys", "quint.key");

    if (existsSync(privPath) && !opts.force) {
      console.log("Keys already exist. Use --force to overwrite.");
      return;
    }

    const kp = generateKeyPair();
    saveKeyPair(dataDir, kp);
    const fp = publicKeyFingerprint(kp.publicKey);
    console.log(`Ed25519 keypair generated.`);
    console.log(`  Private key: ${join(dataDir, "keys", "quint.key")} (mode 0600)`);
    console.log(`  Public key:  ${join(dataDir, "keys", "quint.pub")}`);
    console.log(`  Fingerprint: ${fp}`);
  });

keysCommand
  .command("show")
  .description("Show current public key")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const kp = loadKeyPair(dataDir);

    if (!kp) {
      console.log("No keys found. Run `quint keys generate` first.");
      return;
    }

    const fp = publicKeyFingerprint(kp.publicKey);
    console.log(`Public key fingerprint: ${fp}`);
    console.log(`\n${kp.publicKey.trim()}`);
  });

keysCommand
  .command("export")
  .description("Export public key to stdout")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const kp = loadKeyPair(dataDir);

    if (!kp) {
      console.error("No keys found. Run `quint keys generate` first.");
      process.exit(1);
    }

    process.stdout.write(kp.publicKey);
  });
