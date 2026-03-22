/**
 * ATROSA Hunt Command — Hunter Loop Orchestrator
 */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import type { Command } from "commander";
import {
  createProvider,
  DEFAULT_MODELS,
} from "../providers/index.js";
import { extractCodeBlock } from "../utils/code-extract.js";
import { setup } from "../engine/ingest.js";
import { scoreDetections } from "../engine/scoring.js";
import {
  DETECT_PATH,
  HUNT_PROMPT_PATH,
  LOG_DIR,
  RULES_PATH,
} from "../utils/paths.js";

const MAX_ITERATIONS = 10;
const DETECT_TIMEOUT = 30_000;

interface DetectionOutput {
  flagged_tx_ids: string[];
  flagged_user_ids: string[];
  error?: string;
  stderr?: string;
  raw_output?: string;
}

function runDetect(): DetectionOutput {
  try {
    const result = execFileSync("python3", ["detect.py"], {
      timeout: DETECT_TIMEOUT,
      encoding: "utf-8",
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    });

    const lines = result.trim().split("\n");
    const jsonLine = lines[lines.length - 1] || "";
    return JSON.parse(jsonLine) as DetectionOutput;
  } catch (err: unknown) {
    if (err && typeof err === "object" && "killed" in err && (err as { killed: boolean }).killed) {
      return {
        error: `detect.py timed out after ${DETECT_TIMEOUT / 1000}s`,
        flagged_tx_ids: [],
        flagged_user_ids: [],
      };
    }

    const execErr = err as { status?: number; stderr?: string; stdout?: string };
    const stderr = typeof execErr.stderr === "string" ? execErr.stderr.trim() : "";
    const stdout = typeof execErr.stdout === "string" ? execErr.stdout.trim() : "";

    if (stderr) {
      console.error(`  [detect.py stderr] ${stderr.slice(0, 500)}`);
    }

    // Try to parse stdout anyway
    if (stdout) {
      try {
        const lines = stdout.split("\n");
        const jsonLine = lines[lines.length - 1];
        return JSON.parse(jsonLine) as DetectionOutput;
      } catch {
        // fall through
      }
    }

    return {
      error: `detect.py exited with code ${execErr.status ?? "unknown"}`,
      stderr: stderr.slice(0, 1000),
      flagged_tx_ids: [],
      flagged_user_ids: [],
    };
  }
}

function graduateRule(
  detectCode: string,
  scoreResult: ReturnType<typeof scoreDetections>,
  iteration: number,
): string {
  const ruleId = `FIN-RACE-${crypto.createHash("sha256").update(detectCode).digest("hex").slice(0, 6).toUpperCase()}`;
  const ruleFilename = `rules/${ruleId.toLowerCase().replace(/-/g, "_")}.py`;

  fs.mkdirSync("rules", { recursive: true });
  fs.writeFileSync(ruleFilename, detectCode, "utf-8");

  let rulesData: { rules: Record<string, unknown>[] } = { rules: [] };
  if (fs.existsSync(RULES_PATH)) {
    rulesData = JSON.parse(fs.readFileSync(RULES_PATH, "utf-8"));
  }

  const ruleEntry = {
    rule_id: ruleId,
    threat_hypothesis:
      "Double-spend via webhook desync: CREDIT without matching DEBIT after forced network disconnect",
    required_telemetry: [
      "api_gateway",
      "mobile_client_errors",
      "ledger_db_commits",
      "payment_webhooks",
    ],
    detection_logic_file: ruleFilename,
    mitigation_action: "suspend_user_id_and_flag_ledger",
    confidence_score: scoreResult.tx_precision ?? 0.99,
    graduated_at: new Date().toISOString(),
    iterations_to_prove: iteration,
  };

  rulesData.rules.push(ruleEntry);
  fs.writeFileSync(RULES_PATH, JSON.stringify(rulesData, null, 2), "utf-8");

  console.log(`\n[+] RULE GRADUATED: ${ruleId}`);
  console.log(`    Detection script: ${ruleFilename}`);
  console.log(`    Iterations: ${iteration}`);
  console.log(`    Confidence: ${ruleEntry.confidence_score}`);

  return ruleId;
}

async function runHunt(
  providerName: string,
  model?: string,
  baseUrl?: string,
  maxIterations = MAX_ITERATIONS,
  huntPrompt?: string,
): Promise<boolean> {
  console.log("=".repeat(60));
  console.log("  ATROSA — Hunter Swarm Orchestrator");
  console.log("=".repeat(60));

  // Ensure data exists
  const dataDir = path.resolve("data");
  if (!fs.existsSync(path.join(dataDir, "api_gateway.jsonl"))) {
    console.log("[!] No telemetry data found. Generating...");
    const { generateAll } = await import("../mock/generator.js");
    generateAll();
  }

  // Load ground truth and total events
  const harness = setup();

  // Initialize LLM
  const promptPath = huntPrompt ?? HUNT_PROMPT_PATH;
  const systemPrompt = fs.readFileSync(promptPath, "utf-8");
  const displayModel =
    model || DEFAULT_MODELS[providerName] || "default";

  console.log(`\n[*] Initializing Hunter LLM agent...`);
  console.log(`    Provider: ${providerName}`);
  console.log(`    Model: ${displayModel}`);
  if (baseUrl) console.log(`    Base URL: ${baseUrl}`);

  const provider = createProvider(providerName, systemPrompt, model, baseUrl);

  // Build schema info
  const schemaInfo: string[] = [];
  const datasets: [string, Record<string, unknown>[]][] = [
    ["df_api", harness.df_api as unknown as Record<string, unknown>[]],
    ["df_db", harness.df_db as unknown as Record<string, unknown>[]],
    ["df_mobile", harness.df_mobile as unknown as Record<string, unknown>[]],
    ["df_webhooks", harness.df_webhooks as unknown as Record<string, unknown>[]],
  ];

  for (const [name, data] of datasets) {
    const cols = data.length > 0 ? Object.keys(data[0]) : [];
    schemaInfo.push(`**${name}**: ${data.length} rows, columns: ${JSON.stringify(cols)}`);
    if (data.length > 0) {
      schemaInfo.push(`  Sample row: ${JSON.stringify(data[0])}`);
    }
  }

  const detectTemplate = `"""detect.py — ATROSA Hunter Detection Script"""
import json
import sys
import ingest

def detect():
    harness = ingest.setup()
    df_api = harness["df_api"]
    df_db = harness["df_db"]
    df_mobile = harness["df_mobile"]
    df_webhooks = harness["df_webhooks"]

    flagged_tx_ids = []
    flagged_user_ids = []

    # YOUR DETECTION LOGIC HERE

    return flagged_tx_ids, flagged_user_ids

if __name__ == "__main__":
    try:
        tx_ids, user_ids = detect()
        result = {
            "flagged_tx_ids": list(set(tx_ids)),
            "flagged_user_ids": list(set(user_ids)),
        }
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "flagged_tx_ids": [], "flagged_user_ids": []}))
        sys.exit(1)
`;

  const initialContext =
    "Begin your hunt. Here is the current dataset schema:\n\n" +
    schemaInfo.join("\n") +
    `\n\nTotal events across all sources: ${harness.total_events}` +
    "\n\nIMPORTANT: You MUST use exactly this template structure for detect.py. " +
    "Data is loaded via `ingest.setup()` — do NOT import data any other way.\n\n" +
    `\`\`\`python\n${detectTemplate}\`\`\`\n\n` +
    "Fill in the detection logic. Return the COMPLETE detect.py file in a Python code block.";

  fs.mkdirSync(LOG_DIR, { recursive: true });
  let feedbackContext = initialContext;

  // --- Iteration Loop ---
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    console.log(`\n${"─".repeat(40)}`);
    console.log(`  ITERATION ${iteration}/${maxIterations}`);
    console.log(`${"─".repeat(40)}`);

    // Step 1: Get new detect.py from LLM
    console.log("[*] Requesting detection code from Hunter agent...");
    let newCode: string;
    try {
      const context = iteration === 1 ? initialContext : feedbackContext;
      const response = await provider.chat(context);
      const code = extractCodeBlock(response);
      if (!code) {
        throw new Error("LLM response did not contain a Python code block.");
      }
      newCode = code;
    } catch (err) {
      console.log(`[!] LLM error: ${err}`);
      continue;
    }

    // Step 2: Write the new detect.py
    fs.writeFileSync(DETECT_PATH, newCode, "utf-8");
    console.log(`[*] detect.py updated (${newCode.length} chars)`);

    // Log this iteration
    const logPath = path.join(LOG_DIR, `iteration_${String(iteration).padStart(2, "0")}.py`);
    fs.writeFileSync(logPath, newCode, "utf-8");

    // Step 3: Execute detect.py
    console.log("[*] Executing detect.py...");
    const t0 = Date.now();
    const detectionOutput = runDetect();
    const elapsed = (Date.now() - t0) / 1000;
    console.log(`[*] Execution completed in ${elapsed.toFixed(2)}s`);

    // Step 4: Check for errors
    if (detectionOutput.error) {
      console.log(`[!] Error: ${detectionOutput.error}`);

      feedbackContext =
        `ITERATION ${iteration} RESULT:\n` +
        `Your detect.py CRASHED with error:\n${detectionOutput.error}\n`;
      if (detectionOutput.stderr) {
        feedbackContext += `Stderr output:\n${detectionOutput.stderr.slice(0, 1000)}\n`;
      }
      feedbackContext +=
        "\nFix the error and try again. REMEMBER: You MUST use `harness = ingest.setup()` to load data. " +
        "Do NOT import data any other way. Return the COMPLETE corrected detect.py in a Python code block.";
      continue;
    }

    // Step 5: Score the detection
    const flaggedTx = detectionOutput.flagged_tx_ids || [];
    const flaggedUsers = detectionOutput.flagged_user_ids || [];

    console.log(
      `[*] Flagged: ${flaggedTx.length} transactions, ${flaggedUsers.length} users`,
    );

    const scoreResult = scoreDetections(
      flaggedTx,
      flaggedUsers,
      harness.total_events,
      harness.ground_truth,
    );

    console.log(`[*] SNR Score: ${scoreResult.score}/100`);
    console.log(`    ${scoreResult.feedback}`);

    // Log score
    const scoreLog = {
      iteration,
      score: scoreResult.score,
      flagged_tx: flaggedTx.length,
      flagged_users: flaggedUsers.length,
      elapsed_s: elapsed,
      feedback: scoreResult.feedback,
    };
    fs.writeFileSync(
      path.join(LOG_DIR, `score_${String(iteration).padStart(2, "0")}.json`),
      JSON.stringify(scoreLog, null, 2),
      "utf-8",
    );

    // Step 6: Check for graduation
    if (scoreResult.score === 100) {
      console.log("\n[!!!] PERFECT SCORE — GRADUATING RULE");
      const ruleId = graduateRule(newCode, scoreResult, iteration);
      console.log(`\n[+] Hunt complete. Rule ${ruleId} is now active.`);
      return true;
    }

    // Step 7: Build feedback for next iteration
    feedbackContext =
      `ITERATION ${iteration} RESULT:\n` +
      `SNR Score: ${scoreResult.score}/100\n` +
      `Flagged ${flaggedTx.length} transactions, ${flaggedUsers.length} users.\n` +
      `Feedback: ${scoreResult.feedback}\n`;
    if (scoreResult.true_positive_txs?.length) {
      feedbackContext += `Correctly identified TXs: ${scoreResult.true_positive_txs.join(", ")}\n`;
    }
    if (scoreResult.true_positive_users?.length) {
      feedbackContext += `Correctly identified users: ${scoreResult.true_positive_users.join(", ")}\n`;
    }
    feedbackContext +=
      "\nImprove your detection logic based on this feedback. " +
      "Return the COMPLETE updated detect.py in a Python code block.";
  }

  console.log(
    `\n[X] Max iterations (${maxIterations}) reached without perfect score.`,
  );
  return false;
}

export function registerHuntCommand(program: Command): void {
  program
    .command("hunt")
    .description("Run the Hunter swarm orchestrator loop")
    .option(
      "-p, --provider <name>",
      "LLM provider (anthropic, openai, gemini, openrouter, local)",
      "anthropic",
    )
    .option("-m, --model <model>", "Model name/ID")
    .option("--base-url <url>", "Custom API base URL (for local models)")
    .option(
      "-n, --max-iterations <n>",
      "Max hunt iterations",
      String(MAX_ITERATIONS),
    )
    .option(
      "--hunt-prompt <path>",
      "Path to hunt prompt file",
      HUNT_PROMPT_PATH,
    )
    .action(async (opts) => {
      const success = await runHunt(
        opts.provider,
        opts.model,
        opts.baseUrl,
        parseInt(opts.maxIterations, 10),
        opts.huntPrompt,
      );
      process.exit(success ? 0 : 1);
    });
}
