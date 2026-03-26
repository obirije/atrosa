/**
 * ATROSA Rule Engine — Load + execute graduated detection rules
 *
 * Rules are Python detect.py scripts. We shell out to Python to run them.
 *
 * Security:
 *  - Path validation: rule scripts must be within allowed directories
 *  - Hash integrity: file hash verified against graduation record
 */

import fs from "node:fs";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { RULES_PATH } from "../utils/paths.js";

export interface Rule {
  rule_id: string;
  threat_hypothesis: string;
  required_telemetry: string[];
  detection_logic_file: string;
  mitigation_action: string;
  confidence_score: number;
  graduated_at: string;
  iterations_to_prove: number;
  code_hash?: string;
}

export interface RulesData {
  rules: Rule[];
}

export interface RuleExecResult {
  flagged_tx_ids: string[];
  flagged_user_ids: string[];
  error?: string;
}

// Allowed directories for rule scripts (prevent path traversal)
const ALLOWED_RULE_DIRS = new Set(["rules", "tenants"]);

function validateRulePath(scriptPath: string): boolean {
  const resolved = path.resolve(scriptPath);
  const cwd = process.cwd();

  // Must be under the current working directory
  if (!resolved.startsWith(cwd + path.sep)) {
    return false;
  }

  // Get relative path and check first directory
  const relative = path.relative(cwd, resolved);
  const parts = relative.split(path.sep);

  if (parts.length === 0 || !ALLOWED_RULE_DIRS.has(parts[0])) {
    return false;
  }

  // Must not contain path traversal
  if (parts.includes("..")) {
    return false;
  }

  // Must be a .py file
  if (!resolved.endsWith(".py")) {
    return false;
  }

  return true;
}

function verifyRuleHash(scriptPath: string, expectedHash?: string): boolean {
  if (!expectedHash) return true; // No hash recorded — legacy rule

  const content = fs.readFileSync(scriptPath);
  const actualHash = crypto.createHash("sha256").update(content).digest("hex").slice(0, 12);
  return actualHash === expectedHash;
}

export class RuleEngine {
  rules: Rule[] = [];
  loadedRuleIds: Set<string> = new Set();

  loadRules(): void {
    if (!fs.existsSync(RULES_PATH)) {
      console.log("[!] No active_rules.json found. Run the Hunter first.");
      return;
    }

    const data: RulesData = JSON.parse(
      fs.readFileSync(RULES_PATH, "utf-8"),
    );
    this.rules = data.rules || [];

    for (const rule of this.rules) {
      // Security: validate path is within allowed directories
      if (!validateRulePath(rule.detection_logic_file)) {
        console.log(
          `[!] Rule ${rule.rule_id}: BLOCKED — path '${rule.detection_logic_file}' is outside allowed directories`,
        );
        continue;
      }

      const scriptPath = path.resolve(rule.detection_logic_file);
      if (!fs.existsSync(scriptPath)) {
        console.log(`[!] Rule ${rule.rule_id}: missing script ${scriptPath}`);
        continue;
      }

      // Security: verify file hash matches graduation record
      if (rule.code_hash && !verifyRuleHash(scriptPath, rule.code_hash)) {
        console.log(
          `[!] Rule ${rule.rule_id}: BLOCKED — file hash does not match graduation record`,
        );
        console.log(
          `    The rule file may have been modified after graduation.`,
        );
        continue;
      }

      this.loadedRuleIds.add(rule.rule_id);
      console.log(`    Loaded rule: ${rule.rule_id} (${scriptPath})`);
    }

    console.log(
      `[*] ${this.loadedRuleIds.size}/${this.rules.length} rules loaded`,
    );
  }

  executeRules(): RuleExecResult[] {
    const alerts: RuleExecResult[] = [];

    for (const rule of this.rules) {
      if (!this.loadedRuleIds.has(rule.rule_id)) continue;

      const scriptPath = path.resolve(rule.detection_logic_file);
      try {
        const output = execFileSync("python3", [scriptPath], {
          timeout: 30_000,
          encoding: "utf-8",
          cwd: process.cwd(),
        });

        const lines = output.trim().split("\n");
        const jsonLine = lines[lines.length - 1];
        const result: RuleExecResult = JSON.parse(jsonLine);
        if (
          result.flagged_tx_ids?.length > 0 ||
          result.flagged_user_ids?.length > 0
        ) {
          alerts.push(result);
        }
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        console.log(`  [!] Rule ${rule.rule_id} execution error: ${errMsg}`);
      }
    }

    return alerts;
  }
}
