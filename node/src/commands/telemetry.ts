/**
 * ATROSA Telemetry Command — Telemetry engineer subcommands
 */

import fs from "node:fs";
import type { Command } from "commander";
import { TelemetryGapAnalyzer } from "../telemetry/gap-analyzer.js";
import {
  ObservabilityRequestManager,
} from "../telemetry/requests.js";
import { DeliveryChannel } from "../telemetry/delivery.js";
import { readJsonl } from "../utils/jsonl.js";
import { DATA_DIR, REQUESTS_PATH } from "../utils/paths.js";
import path from "node:path";

function cmdAudit(channels: string[]): void {
  console.log("=".repeat(60));
  console.log("  ATROSA — Telemetry Engineer: Schema Audit");
  console.log("=".repeat(60));

  console.log("\n[*] Loading telemetry data...");
  const data: Record<string, Record<string, unknown>[]> = {};
  const sources: Record<string, string> = {
    api: path.join(DATA_DIR, "api_gateway.jsonl"),
    db: path.join(DATA_DIR, "ledger_db_commits.jsonl"),
    mobile: path.join(DATA_DIR, "mobile_client_errors.jsonl"),
    webhooks: path.join(DATA_DIR, "payment_webhooks.jsonl"),
  };

  for (const [name, filepath] of Object.entries(sources)) {
    if (!fs.existsSync(filepath)) {
      console.log(`[!] Missing data file: ${filepath}. Run 'atrosa init' first.`);
      process.exit(1);
    }
    data[name] = readJsonl(filepath);
    console.log(`    Loaded ${name}: ${data[name].length} rows`);
  }

  console.log("\n[*] Auditing against ideal schema...");
  const analyzer = new TelemetryGapAnalyzer();
  const gaps = analyzer.auditSchema(data);

  if (gaps.length === 0) {
    console.log("\n[+] No gaps found. Telemetry is complete.");
    return;
  }

  const bySeverity: Record<string, typeof gaps> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const gap of gaps) {
    bySeverity[gap.severity]?.push(gap);
  }

  console.log(`\n[*] Found ${gaps.length} telemetry gaps:`);
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (bySeverity[sev].length > 0) {
      console.log(`    ${sev.toUpperCase()}: ${bySeverity[sev].length}`);
    }
  }

  const requestMgr = new ObservabilityRequestManager();
  console.log("\n[*] Generating observability requests...");

  for (const gap of gaps) {
    const req = requestMgr.createRequest(gap, "Schema audit");
    DeliveryChannel.deliver(req, channels);
  }

  const openCount = requestMgr.getOpenRequests().length;
  console.log(
    `\n[+] ${openCount} open observability requests. Saved to ${REQUESTS_PATH}`,
  );
}

function cmdAnalyze(
  error: string,
  huntLog?: string,
  errorLog?: string,
  channels: string[] = ["console", "file"],
): void {
  console.log("=".repeat(60));
  console.log("  ATROSA — Telemetry Engineer: Error Analysis");
  console.log("=".repeat(60));

  let detectCode = "";
  if (huntLog) {
    detectCode = fs.readFileSync(huntLog, "utf-8");
  }

  let errorText = error || "";
  if (errorLog) {
    errorText += "\n" + fs.readFileSync(errorLog, "utf-8");
  }

  if (!errorText.trim()) {
    console.log("[!] No error text provided. Use --error or --error-log.");
    return;
  }

  console.log("\n[*] Analyzing error...");
  const analyzer = new TelemetryGapAnalyzer();
  const gaps = analyzer.analyzeHunterError(errorText, detectCode);

  if (gaps.length === 0) {
    console.log("\n[*] No telemetry gaps detected from this error.");
    return;
  }

  const requestMgr = new ObservabilityRequestManager();
  let created = 0;

  for (const gap of gaps) {
    const req = requestMgr.createRequest(gap, "Manual analysis");
    if (req.status === "open") {
      DeliveryChannel.deliver(req, channels);
      created++;
    }
  }

  if (created > 0) {
    console.log(`\n[+] Created ${created} observability requests.`);
  } else {
    console.log("\n[*] No new telemetry gaps detected from this error.");
  }
}

function cmdStatus(): void {
  console.log("=".repeat(60));
  console.log("  ATROSA — Telemetry Engineer: Request Status");
  console.log("=".repeat(60));

  const requestMgr = new ObservabilityRequestManager();
  const allReqs = requestMgr.getAllRequests();

  if (allReqs.length === 0) {
    console.log("\n  No observability requests found.");
    return;
  }

  const openReqs = allReqs.filter((r) => r.status === "open");
  const resolvedReqs = allReqs.filter((r) => r.status === "resolved");

  console.log(
    `\n  Total: ${allReqs.length} | Open: ${openReqs.length} | Resolved: ${resolvedReqs.length}`,
  );

  if (openReqs.length > 0) {
    console.log(`\n  ${"─".repeat(50)}`);
    console.log("  OPEN REQUESTS");
    console.log(`  ${"─".repeat(50)}`);
    const severityIcons: Record<string, string> = {
      critical: "[!!!]",
      high: "[!!]",
      medium: "[!]",
      low: "[i]",
    };
    for (const req of openReqs) {
      const icon = severityIcons[req.severity] ?? "[?]";
      console.log(`\n  ${icon} ${req.request_id} — ${req.severity.toUpperCase()}`);
      console.log(`      Source: ${req.source} / Field: ${req.field}`);
      console.log(`      Action: ${req.action_required.slice(0, 100)}`);
      console.log(`      Created: ${req.created_at}`);
    }
  }

  if (resolvedReqs.length > 0) {
    console.log(`\n  ${"─".repeat(50)}`);
    console.log("  RESOLVED");
    console.log(`  ${"─".repeat(50)}`);
    for (const req of resolvedReqs) {
      console.log(
        `  [OK] ${req.request_id} — ${req.source}/${req.field} (resolved ${req.resolved_at})`,
      );
    }
  }
}

function cmdResolve(reqId: string): void {
  const requestMgr = new ObservabilityRequestManager();
  const result = requestMgr.resolveRequest(reqId);
  if (result) {
    console.log(`[+] ${reqId} marked as resolved.`);
  } else {
    console.log(`[!] Request ${reqId} not found.`);
  }
}

export function registerTelemetryCommand(program: Command): void {
  const telCmd = program
    .command("telemetry")
    .description("Telemetry Engineer — Active observability agent");

  telCmd
    .command("audit")
    .description("Audit current telemetry for completeness gaps")
    .option("--channel <channel...>", "Delivery channels", ["console", "file"])
    .action((opts) => {
      cmdAudit(opts.channel);
    });

  telCmd
    .command("analyze")
    .description("Analyze a specific Hunter error for data gaps")
    .option("-e, --error <text>", "Error text", "")
    .option("--hunt-log <path>", "Path to hunt iteration code")
    .option("--error-log <path>", "Path to error log file")
    .option("--channel <channel...>", "Delivery channels", ["console", "file"])
    .action((opts) => {
      cmdAnalyze(opts.error, opts.huntLog, opts.errorLog, opts.channel);
    });

  telCmd
    .command("status")
    .description("Show all observability requests and their status")
    .action(() => {
      cmdStatus();
    });

  telCmd
    .command("resolve <request-id>")
    .description("Mark a request as resolved")
    .action((reqId: string) => {
      cmdResolve(reqId);
    });
}
