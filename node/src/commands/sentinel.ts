/**
 * ATROSA Sentinel Command — Live Enforcement
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { Command } from "commander";
import { RuleEngine } from "../engine/rule-engine.js";
import { MitigationRegistry, type Alert } from "../engine/mitigation.js";
import { readJsonl } from "../utils/jsonl.js";
import { DATA_DIR, RULES_PATH } from "../utils/paths.js";

const DEFAULT_INTERVAL = 10;
const DEFAULT_BATCH_SIZE = 500;

interface EventRecord {
  source?: string;
  timestamp?: string;
  [key: string]: unknown;
}

function splitBatchBySource(batch: EventRecord[]): {
  api: EventRecord[];
  db: EventRecord[];
  mobile: EventRecord[];
  webhooks: EventRecord[];
} {
  return {
    api: batch.filter((e) => e.source === "api_gateway"),
    db: batch.filter((e) => e.source === "ledger_db_commits"),
    mobile: batch.filter((e) => e.source === "mobile_client_errors"),
    webhooks: batch.filter((e) => e.source === "payment_webhooks"),
  };
}

class SimulatedStream {
  private allEvents: EventRecord[];
  private offset = 0;
  private batchSize: number;

  constructor(batchSize: number) {
    this.batchSize = batchSize;

    const files = [
      "api_gateway.jsonl",
      "ledger_db_commits.jsonl",
      "mobile_client_errors.jsonl",
      "payment_webhooks.jsonl",
    ];

    this.allEvents = [];
    for (const file of files) {
      const filepath = path.join(DATA_DIR, file);
      if (fs.existsSync(filepath)) {
        const records = readJsonl<EventRecord>(filepath);
        this.allEvents.push(...records);
      }
    }

    this.allEvents.sort((a, b) =>
      String(a.timestamp ?? "").localeCompare(String(b.timestamp ?? "")),
    );
  }

  nextBatch(): EventRecord[] | null {
    if (this.offset >= this.allEvents.length) return null;
    const end = Math.min(this.offset + this.batchSize, this.allEvents.length);
    const batch = this.allEvents.slice(this.offset, end);
    this.offset = end;
    return batch;
  }
}

class WatchStream {
  private watchDir: string;
  private seenFiles = new Set<string>();

  constructor(watchDir: string) {
    this.watchDir = watchDir;
    if (fs.existsSync(watchDir)) {
      for (const file of fs.readdirSync(watchDir)) {
        if (file.endsWith(".jsonl")) {
          this.seenFiles.add(path.join(watchDir, file));
        }
      }
    }
  }

  nextBatch(): EventRecord[] | null {
    if (!fs.existsSync(this.watchDir)) return null;
    const newEvents: EventRecord[] = [];
    const files = fs.readdirSync(this.watchDir).filter((f) => f.endsWith(".jsonl")).sort();

    for (const file of files) {
      const filepath = path.join(this.watchDir, file);
      if (!this.seenFiles.has(filepath)) {
        this.seenFiles.add(filepath);
        try {
          const records = readJsonl<EventRecord>(filepath);
          newEvents.push(...records);
          console.log(`  [WATCH] New file: ${file} (${records.length} events)`);
        } catch (err) {
          console.log(`  [WATCH] Error reading ${file}: ${err}`);
        }
      }
    }

    return newEvents.length > 0 ? newEvents : null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function runSentinel(
  mode: string,
  interval: number,
  batchSize: number,
  watchDir?: string,
  dryRun = false,
): Promise<boolean> {
  console.log("=".repeat(60));
  console.log("  ATROSA — Sentinel Swarm");
  console.log("=".repeat(60));
  console.log(`  Mode: ${mode}`);
  console.log(`  Interval: ${interval}s`);
  console.log(`  Dry run: ${dryRun}`);

  // Load rules
  console.log("\n[*] Loading graduated detection rules...");
  const engine = new RuleEngine();
  engine.loadRules();

  if (engine.loadedRuleIds.size === 0) {
    console.log("[!] No rules loaded. Run the Hunter first to graduate rules.");
    return false;
  }

  const mitigation = new MitigationRegistry(dryRun);

  // Initialize stream source
  let stream: SimulatedStream | WatchStream;
  if (mode === "simulate") {
    console.log(`\n[*] Starting simulated stream (batch_size=${batchSize})...`);
    stream = new SimulatedStream(batchSize);
  } else if (mode === "watch") {
    if (!watchDir) {
      console.log("[!] --watch-dir is required in watch mode");
      return false;
    }
    console.log(`\n[*] Watching directory: ${watchDir}`);
    stream = new WatchStream(watchDir);
  } else {
    console.log(`[!] Unknown mode: ${mode}`);
    return false;
  }

  let totalBatches = 0;
  let totalEvents = 0;
  let totalAlerts = 0;
  const startTime = Date.now();

  console.log(`\n[*] Sentinel active. Processing events...\n`);

  const handleInterrupt = (): void => {
    console.log("\n\n[*] Sentinel stopped by user.");
    printSummary();
    process.exit(0);
  };
  process.on("SIGINT", handleInterrupt);

  function printSummary(): void {
    const elapsedTotal = (Date.now() - startTime) / 1000;
    console.log(`\n${"=".repeat(60)}`);
    console.log("  SENTINEL SESSION SUMMARY");
    console.log("=".repeat(60));
    console.log(`  Runtime: ${elapsedTotal.toFixed(1)}s`);
    console.log(`  Batches processed: ${totalBatches}`);
    console.log(`  Events scanned: ${totalEvents}`);
    console.log(`  Alerts triggered: ${totalAlerts}`);
    console.log(`  Rules active: ${engine.loadedRuleIds.size}`);
    console.log("=".repeat(60));
  }

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const batch = stream.nextBatch();

    if (batch === null) {
      if (mode === "simulate") {
        console.log(`\n${"─".repeat(40)}`);
        console.log("[*] Stream exhausted.");
        break;
      }
      await sleep(interval * 1000);
      continue;
    }

    totalBatches++;
    const batchEvents = batch.length;
    totalEvents += batchEvents;

    const split = splitBatchBySource(batch);
    console.log(
      `[Batch ${totalBatches}] ${batchEvents} events ` +
        `(api=${split.api.length}, db=${split.db.length}, mobile=${split.mobile.length}, webhooks=${split.webhooks.length})`,
    );

    // Execute all rules (shells out to Python)
    const t0 = Date.now();
    const ruleResults = engine.executeRules();
    const elapsed = Date.now() - t0;

    if (ruleResults.length > 0) {
      for (const result of ruleResults) {
        totalAlerts++;
        const alert: Alert = {
          alert_id: `ALERT-${crypto.randomBytes(4).toString("hex")}`,
          rule_id: "UNKNOWN",
          threat_hypothesis: "",
          flagged_tx_ids: result.flagged_tx_ids,
          flagged_user_ids: result.flagged_user_ids,
          mitigation_action: "log_alert",
          timestamp: new Date().toISOString(),
          execution_time_ms: elapsed,
          batch_number: totalBatches,
          batch_size: batchEvents,
        };

        console.log(`\n  ${"!".repeat(50)}`);
        console.log(`  THREAT DETECTED`);
        console.log(`  Transactions: ${JSON.stringify(alert.flagged_tx_ids)}`);
        console.log(`  Users: ${JSON.stringify(alert.flagged_user_ids)}`);
        console.log(`  Execution: ${elapsed}ms`);

        mitigation.execute(alert.mitigation_action, alert);
        console.log(`  ${"!".repeat(50)}\n`);
      }
    } else {
      console.log(`  Clean — ${elapsed}ms`);
    }

    if (mode === "simulate") {
      await sleep(interval * 1000);
    }
  }

  process.removeListener("SIGINT", handleInterrupt);
  printSummary();
  return true;
}

export function registerSentinelCommand(program: Command): void {
  program
    .command("sentinel")
    .description("Run the Sentinel swarm — live enforcement")
    .option("--mode <mode>", "Stream mode: simulate or watch", "simulate")
    .option(
      "-i, --interval <seconds>",
      "Seconds between batches",
      String(DEFAULT_INTERVAL),
    )
    .option(
      "-b, --batch-size <size>",
      "Events per batch in simulate mode",
      String(DEFAULT_BATCH_SIZE),
    )
    .option("--watch-dir <dir>", "Directory to watch for new JSONL files")
    .option(
      "--dry-run",
      "Detect threats but don't execute mitigation actions",
      false,
    )
    .action(async (opts) => {
      const success = await runSentinel(
        opts.mode,
        parseInt(opts.interval, 10),
        parseInt(opts.batchSize, 10),
        opts.watchDir,
        opts.dryRun,
      );
      process.exit(success ? 0 : 1);
    });
}
