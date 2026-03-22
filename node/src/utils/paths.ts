/**
 * Path constants — relative to CWD (same as Python version)
 */

import path from "node:path";

export const DATA_DIR = path.resolve("data");
export const RULES_PATH = path.resolve("active_rules.json");
export const DETECT_PATH = path.resolve("detect.py");
export const LOG_DIR = path.resolve("logs");
export const HUNT_PROMPT_PATH = path.resolve("hunt.md");
export const ALERTS_PATH = path.resolve("sentinel_alerts.jsonl");
export const REQUESTS_PATH = path.resolve("telemetry_requests.json");
export const REQUESTS_LOG_PATH = path.resolve("telemetry_requests_log.jsonl");
export const GROUND_TRUTH_PATH = path.join(DATA_DIR, ".ground_truth.json");
