/**
 * ATROSA Ingestion — JSONL loading into typed arrays
 */

import fs from "node:fs";
import path from "node:path";
import { readJsonl } from "../utils/jsonl.js";
import { DATA_DIR, GROUND_TRUTH_PATH } from "../utils/paths.js";

export interface ApiEvent {
  source: string;
  timestamp: string;
  request_id: string;
  user_id: string;
  session_id: string;
  method: string;
  endpoint: string;
  status_code: number;
  response_time_ms: number;
  ip_address: string;
  user_agent: string;
  transaction_id: string | null;
  amount: number | null;
  currency: string | null;
}

export interface DbEvent {
  source: string;
  timestamp: string;
  commit_id: string;
  user_id: string;
  operation: string;
  amount: number;
  currency: string;
  balance_before: number;
  balance_after: number | null;
  transaction_id: string;
  provider: string;
  idempotency_key: string;
}

export interface MobileEvent {
  source: string;
  timestamp: string;
  event_id: string;
  user_id: string;
  session_id: string;
  event_type: string;
  device_os: string;
  app_version: string;
  network_type: string;
  error_code: string | null;
  screen: string;
  ip_address?: string;
}

export interface WebhookEvent {
  source: string;
  timestamp: string;
  webhook_id: string;
  provider: string;
  event_type: string;
  transaction_id: string;
  user_id: string;
  amount: number;
  currency: string;
  status: string;
  delivery_attempt: number;
  latency_ms: number;
}

export interface GroundTruth {
  anomaly_count: number;
  attacker_user_ids: string[];
  attacker_transaction_ids: string[];
  description: string;
}

export interface TelemetryData {
  api: ApiEvent[];
  db: DbEvent[];
  mobile: MobileEvent[];
  webhooks: WebhookEvent[];
}

export interface Harness {
  df_api: ApiEvent[];
  df_db: DbEvent[];
  df_mobile: MobileEvent[];
  df_webhooks: WebhookEvent[];
  ground_truth: GroundTruth;
  total_events: number;
}

export function loadJsonlFile<T>(filepath: string): T[] {
  if (!fs.existsSync(filepath)) {
    console.error(`[!] Missing data file: ${filepath}. Run 'atrosa init' first.`);
    process.exit(1);
  }
  return readJsonl<T>(filepath);
}

export function loadAllData(): TelemetryData {
  const sources: Record<string, string> = {
    api: path.join(DATA_DIR, "api_gateway.jsonl"),
    db: path.join(DATA_DIR, "ledger_db_commits.jsonl"),
    mobile: path.join(DATA_DIR, "mobile_client_errors.jsonl"),
    webhooks: path.join(DATA_DIR, "payment_webhooks.jsonl"),
  };

  const data: TelemetryData = {
    api: [],
    db: [],
    mobile: [],
    webhooks: [],
  };

  for (const [name, filepath] of Object.entries(sources)) {
    const records = loadJsonlFile<Record<string, unknown>>(filepath);
    (data as unknown as Record<string, unknown[]>)[name] = records;
    console.log(
      `    Loaded ${name}: ${records.length} rows, columns: ${records.length > 0 ? JSON.stringify(Object.keys(records[0])) : "[]"}`,
    );
  }

  return data;
}

export function loadGroundTruth(): GroundTruth {
  const content = fs.readFileSync(GROUND_TRUTH_PATH, "utf-8");
  return JSON.parse(content) as GroundTruth;
}

export function setup(): Harness {
  console.log("[*] ATROSA Ingestion Harness");
  console.log("[*] Loading telemetry data...");
  const data = loadAllData();
  const groundTruth = loadGroundTruth();

  const totalEvents =
    data.api.length + data.db.length + data.mobile.length + data.webhooks.length;
  console.log(`[*] Total events loaded: ${totalEvents}`);

  return {
    df_api: data.api,
    df_db: data.db,
    df_mobile: data.mobile,
    df_webhooks: data.webhooks,
    ground_truth: groundTruth,
    total_events: totalEvents,
  };
}
