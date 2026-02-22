import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  generateKeyPair,
  saveKeyPair,
  loadKeyPair,
  publicKeyFingerprint,
  isKeyEncrypted,
} from "@quint-security/core";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

function getPassphrase(opts: { passphrase?: string }): string | undefined {
  return opts.passphrase || process.env.QUINT_PASSPHRASE || undefined;
}

export const keysCommand = new Command("keys")
  .description("Manage Ed25519 signing keys");

keysCommand
  .command("generate")
  .description("Generate a new Ed25519 keypair")
  .option("--force", "Overwrite existing keys")
  .option("--passphrase <passphrase>", "Encrypt the private key with a passphrase")
  .action((opts: { force?: boolean; passphrase?: string }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const privPath = join(dataDir, "keys", "quint.key");

    if (existsSync(privPath) && !opts.force) {
      console.log("Keys already exist. Use --force to overwrite.");
      return;
    }

    const passphrase = getPassphrase(opts);
    const kp = generateKeyPair();
    saveKeyPair(dataDir, kp, passphrase);
    const fp = publicKeyFingerprint(kp.publicKey);
    console.log(`Ed25519 keypair generated.`);
    console.log(`  Private key: ${privPath} (mode 0600${passphrase ? ", encrypted" : ""})`);
    console.log(`  Public key:  ${join(dataDir, "keys", "quint.pub")}`);
    console.log(`  Fingerprint: ${fp}`);
  });

keysCommand
  .command("encrypt")
  .description("Encrypt an existing plaintext private key with a passphrase")
  .requiredOption("--passphrase <passphrase>", "Passphrase to encrypt the key with")
  .action((opts: { passphrase: string }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);

    if (isKeyEncrypted(dataDir)) {
      console.log("Private key is already encrypted.");
      return;
    }

    const kp = loadKeyPair(dataDir);
    if (!kp) {
      console.error("No keys found. Run `quint keys generate` first.");
      process.exit(1);
    }

    saveKeyPair(dataDir, kp, opts.passphrase);
    console.log("Private key encrypted successfully.");
  });

keysCommand
  .command("show")
  .description("Show current public key")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);

    // show doesn't need the private key — just read the pub key directly
    const pubPath = join(dataDir, "keys", "quint.pub");
    if (!existsSync(pubPath)) {
      console.log("No keys found. Run `quint keys generate` first.");
      return;
    }

    const publicKey = readFileSync(pubPath, "utf-8");
    const fp = publicKeyFingerprint(publicKey);
    const encrypted = isKeyEncrypted(dataDir);
    console.log(`Public key fingerprint: ${fp}`);
    console.log(`Private key: ${encrypted ? "encrypted" : "plaintext"}`);
    console.log(`\n${publicKey.trim()}`);
  });

keysCommand
  .command("export")
  .description("Export public key to stdout")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);

    const pubPath = join(dataDir, "keys", "quint.pub");
    if (!existsSync(pubPath)) {
      console.error("No keys found. Run `quint keys generate` first.");
      process.exit(1);
    }

    process.stdout.write(readFileSync(pubPath, "utf-8"));
  });
