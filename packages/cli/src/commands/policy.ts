import { Command } from "commander";
import { loadPolicy, resolveDataDir, initPolicy, validatePolicy } from "@quint/core";

export const policyCommand = new Command("policy")
  .description("Manage access control policy");

policyCommand
  .command("init")
  .description("Create a default policy.json if none exists")
  .action(() => {
    const path = initPolicy();
    console.log(`Policy file: ${path}`);
  });

policyCommand
  .command("validate")
  .description("Validate the current policy.json")
  .action(() => {
    const policy = loadPolicy();
    const errors = validatePolicy(policy);

    if (errors.length === 0) {
      console.log("Policy is valid.");
    } else {
      console.log("Policy validation errors:");
      for (const err of errors) {
        console.log(`  - ${err}`);
      }
      process.exit(1);
    }
  });

policyCommand
  .command("show")
  .description("Display the current policy")
  .action(() => {
    const policy = loadPolicy();
    console.log(JSON.stringify(policy, null, 2));
  });
