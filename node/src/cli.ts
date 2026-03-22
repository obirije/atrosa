import { Command } from "commander";
import { registerHuntCommand } from "./commands/hunt.js";
import { registerSentinelCommand } from "./commands/sentinel.js";
import { registerTelemetryCommand } from "./commands/telemetry.js";
import { registerInitCommand } from "./commands/init.js";

export function main(): void {
  const program = new Command();

  program
    .name("atrosa")
    .description("ATROSA — Autonomous Threat Research & Offensive Security Agent")
    .version("0.1.0");

  registerHuntCommand(program);
  registerSentinelCommand(program);
  registerTelemetryCommand(program);
  registerInitCommand(program);

  program.parse();
}
