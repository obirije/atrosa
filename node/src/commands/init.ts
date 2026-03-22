/**
 * ATROSA Init Command — Generate mock telemetry data
 */

import type { Command } from "commander";
import { generateAll } from "../mock/generator.js";

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description("Generate synthetic telemetry data for testing")
    .action(() => {
      generateAll();
    });
}
