/**
 * ATROSA Mock Telemetry Generator — Synthetic data with seeded RNG
 *
 * Produces the same schema as the Python version:
 * - api_gateway.jsonl (~10,000 events)
 * - ledger_db_commits.jsonl (~8,000 events)
 * - mobile_client_errors.jsonl (~5,000 events)
 * - payment_webhooks.jsonl (~3,000 events)
 * - 3 hidden double-spend anomalies
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import seedrandom from "seedrandom";
import { DATA_DIR } from "../utils/paths.js";

// Seeded RNG
const rng = seedrandom("42");

function randomFloat(min: number, max: number): number {
  return rng() * (max - min) + min;
}

function randomInt(min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function choice<T>(arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

function sample<T>(arr: T[], n: number): T[] {
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, n);
}

function uuid4hex(len: number): string {
  const bytes = new Uint8Array(Math.ceil(len / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(rng() * 256);
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, len);
}

function sha256hex(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

// --- Config ---
const BASE_TIME = new Date("2026-03-20T00:00:00.000Z");
const NUM_USERS = 500;
const NUM_API_EVENTS = 10_000;
const NUM_DB_COMMITS = 8_000;
const NUM_MOBILE_EVENTS = 5_000;
const NUM_WEBHOOK_EVENTS = 3_000;

const USER_IDS: string[] = [];
for (let i = 0; i < NUM_USERS; i++) {
  USER_IDS.push(`USR-${uuid4hex(8).toUpperCase()}`);
}

const ENDPOINTS = [
  "/api/v2/transfer/initiate",
  "/api/v2/transfer/confirm",
  "/api/v2/balance/check",
  "/api/v2/kyc/verify",
  "/api/v2/cards/list",
  "/api/v2/accounts/summary",
  "/api/v2/webhook/payment-callback",
  "/api/v2/transfer/status",
  "/api/v2/auth/token",
  "/api/v2/auth/refresh",
];

const HTTP_METHODS = ["POST", "GET", "PUT"];
const STATUS_CODES = [200, 200, 200, 200, 200, 201, 400, 401, 403, 500];
const CURRENCIES = ["NGN", "USD", "GBP", "KES", "GHS"];
const PROVIDERS = ["paystack", "flutterwave", "stripe", "monnify"];
const MOBILE_EVENTS = [
  "app_open", "screen_view", "transfer_initiated", "transfer_confirmed",
  "network_error", "timeout", "biometric_auth", "pin_entry", "logout",
];

const ATTACKER_IDS = sample(USER_IDS, 3);
const ATTACKER_TX_IDS = [
  `TXN-${uuid4hex(12).toUpperCase()}`,
  `TXN-${uuid4hex(12).toUpperCase()}`,
  `TXN-${uuid4hex(12).toUpperCase()}`,
];

function randTime(biasHour?: number): string {
  let ms: number;
  if (biasHour !== undefined) {
    const base = BASE_TIME.getTime() + biasHour * 3600_000;
    ms = base + randomFloat(0, 3599) * 1000;
  } else {
    ms = BASE_TIME.getTime() + randomFloat(0, 86399) * 1000;
  }
  return new Date(ms).toISOString();
}

function genTxId(): string {
  return `TXN-${uuid4hex(12).toUpperCase()}`;
}

function genSessionId(): string {
  return `SES-${uuid4hex(10).toUpperCase()}`;
}

function genIp(): string {
  return `${randomInt(1, 223)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;
}

// ===========================
// 1. API Gateway Logs
// ===========================
function generateApiEvents(): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  for (let i = 0; i < NUM_API_EVENTS; i++) {
    const endpoint = choice(ENDPOINTS);
    const isTransfer = endpoint.includes("transfer");
    const method =
      endpoint.includes("initiate") || endpoint.includes("confirm")
        ? "POST"
        : choice(HTTP_METHODS);
    events.push({
      source: "api_gateway",
      timestamp: randTime(),
      request_id: uuid4hex(16),
      user_id: choice(USER_IDS),
      session_id: genSessionId(),
      method,
      endpoint,
      status_code: choice(STATUS_CODES),
      response_time_ms: randomInt(12, 2500),
      ip_address: genIp(),
      user_agent: choice([
        "AtrosaApp/3.2.1 (Android 14)",
        "AtrosaApp/3.2.1 (iOS 17.4)",
        "Mozilla/5.0",
        "PostmanRuntime/7.36.0",
      ]),
      transaction_id: isTransfer ? genTxId() : null,
      amount: isTransfer ? Math.round(randomFloat(100, 500000) * 100) / 100 : null,
      currency: isTransfer ? choice(CURRENCIES) : null,
    });
  }
  return events;
}

// ===========================
// 2. Ledger DB Commits
// ===========================
function generateDbCommits(): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  for (let i = 0; i < NUM_DB_COMMITS; i++) {
    const op = choice(["CREDIT", "DEBIT", "HOLD", "RELEASE", "REVERSAL"]);
    const amount = Math.round(randomFloat(50, 300000) * 100) / 100;
    const balanceBefore = Math.round(randomFloat(1000, 2000000) * 100) / 100;
    let balanceAfter: number;
    if (op === "CREDIT") {
      balanceAfter = Math.round((balanceBefore + amount) * 100) / 100;
    } else if (op === "DEBIT") {
      balanceAfter = Math.round((balanceBefore - amount) * 100) / 100;
    } else {
      balanceAfter = balanceBefore;
    }

    events.push({
      source: "ledger_db_commits",
      timestamp: randTime(),
      commit_id: uuid4hex(16),
      user_id: choice(USER_IDS),
      operation: op,
      amount,
      currency: choice(CURRENCIES),
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      transaction_id: genTxId(),
      provider: choice(PROVIDERS),
      idempotency_key: sha256hex(uuid4hex(16)).slice(0, 24),
    });
  }
  return events;
}

// ===========================
// 3. Mobile Client Logs
// ===========================
function generateMobileEvents(): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  for (let i = 0; i < NUM_MOBILE_EVENTS; i++) {
    events.push({
      source: "mobile_client_errors",
      timestamp: randTime(),
      event_id: uuid4hex(16),
      user_id: choice(USER_IDS),
      session_id: genSessionId(),
      event_type: choice(MOBILE_EVENTS),
      device_os: choice(["Android 14", "iOS 17.4", "Android 13"]),
      app_version: "3.2.1",
      network_type: choice(["4G", "WiFi", "3G"]),
      error_code: choice([
        null, null, null,
        "E_TIMEOUT", "E_NETWORK_LOST", "E_SSL_HANDSHAKE",
      ]),
      screen: choice(["home", "transfer", "history", "settings", "kyc"]),
      ip_address: genIp(),
    });
  }
  return events;
}

// ===========================
// 4. Webhook Events
// ===========================
function generateWebhookEvents(): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  for (let i = 0; i < NUM_WEBHOOK_EVENTS; i++) {
    const status = choice(["success", "success", "success", "failed", "pending"]);
    events.push({
      source: "payment_webhooks",
      timestamp: randTime(),
      webhook_id: uuid4hex(16),
      provider: choice(PROVIDERS),
      event_type: status === "success" ? "payment.completed" : `payment.${status}`,
      transaction_id: genTxId(),
      user_id: choice(USER_IDS),
      amount: Math.round(randomFloat(100, 500000) * 100) / 100,
      currency: choice(CURRENCIES),
      status,
      delivery_attempt: randomInt(1, 3),
      latency_ms: randomInt(50, 5000),
    });
  }
  return events;
}

// ===========================
// 5. INJECT ANOMALIES
// ===========================
function injectAnomalies(
  apiEvents: Record<string, unknown>[],
  dbEvents: Record<string, unknown>[],
  mobileEvents: Record<string, unknown>[],
  webhookEvents: Record<string, unknown>[],
): void {
  const anomalyHours = [3, 11, 19];

  for (let i = 0; i < 3; i++) {
    const attacker = ATTACKER_IDS[i];
    const txId = ATTACKER_TX_IDS[i];
    const hour = anomalyHours[i];
    const amount = Math.round(randomFloat(45000, 250000) * 100) / 100;
    const currency = "NGN";
    const provider = choice(PROVIDERS);
    const ip = genIp();
    const session = genSessionId();
    const tInitiate =
      BASE_TIME.getTime() + hour * 3600_000 + randomInt(5, 50) * 60_000;

    // (a) API: transfer initiate - success
    apiEvents.push({
      source: "api_gateway",
      timestamp: new Date(tInitiate).toISOString(),
      request_id: uuid4hex(16),
      user_id: attacker,
      session_id: session,
      method: "POST",
      endpoint: "/api/v2/transfer/initiate",
      status_code: 200,
      response_time_ms: randomInt(80, 300),
      ip_address: ip,
      user_agent: "AtrosaApp/3.2.1 (Android 14)",
      transaction_id: txId,
      amount,
      currency,
    });

    // (b) Mobile: network disconnect 2-5s after initiation
    const tDisconnect = tInitiate + randomInt(2, 5) * 1000;
    mobileEvents.push({
      source: "mobile_client_errors",
      timestamp: new Date(tDisconnect).toISOString(),
      event_id: uuid4hex(16),
      user_id: attacker,
      session_id: session,
      event_type: "network_error",
      device_os: "Android 14",
      app_version: "3.2.1",
      network_type: "4G",
      error_code: "E_NETWORK_LOST",
      screen: "transfer",
      ip_address: ip,
    });

    // (c) Webhook: arrives LATE (90-300s) with success
    const tWebhook = tInitiate + randomInt(90, 300) * 1000;
    webhookEvents.push({
      source: "payment_webhooks",
      timestamp: new Date(tWebhook).toISOString(),
      webhook_id: uuid4hex(16),
      provider,
      event_type: "payment.completed",
      transaction_id: txId,
      user_id: attacker,
      amount,
      currency,
      status: "success",
      delivery_attempt: randomInt(2, 4),
      latency_ms: randomInt(90000, 300000),
    });

    // (d) DB: CREDIT appears but NO DEBIT
    const balanceBefore = Math.round(randomFloat(50000, 500000) * 100) / 100;
    const tCredit = tWebhook + randomInt(1, 3) * 1000;
    dbEvents.push({
      source: "ledger_db_commits",
      timestamp: new Date(tCredit).toISOString(),
      commit_id: uuid4hex(16),
      user_id: attacker,
      operation: "CREDIT",
      amount,
      currency,
      balance_before: balanceBefore,
      balance_after: Math.round((balanceBefore + amount) * 100) / 100,
      transaction_id: txId,
      provider,
      idempotency_key: sha256hex(txId).slice(0, 24),
    });
    // NOTE: Deliberately NO matching DEBIT for this transaction_id.
  }
}

// ===========================
// MAIN
// ===========================
export function generateAll(): {
  anomaly_count: number;
  attacker_user_ids: string[];
  attacker_transaction_ids: string[];
  description: string;
} {
  console.log("[*] Generating synthetic telemetry...");
  const api = generateApiEvents();
  const db = generateDbCommits();
  const mobile = generateMobileEvents();
  const webhooks = generateWebhookEvents();

  console.log(
    `[*] Injecting 3 double-spend anomalies (attackers: ${JSON.stringify(ATTACKER_IDS)})`,
  );
  injectAnomalies(api, db, mobile, webhooks);

  // Sort all by timestamp
  for (const dataset of [api, db, mobile, webhooks]) {
    dataset.sort((a, b) =>
      String(a.timestamp).localeCompare(String(b.timestamp)),
    );
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });

  const datasets: Record<string, Record<string, unknown>[]> = {
    "api_gateway.jsonl": api,
    "ledger_db_commits.jsonl": db,
    "mobile_client_errors.jsonl": mobile,
    "payment_webhooks.jsonl": webhooks,
  };

  for (const [filename, data] of Object.entries(datasets)) {
    const filepath = path.join(DATA_DIR, filename);
    const content = data.map((e) => JSON.stringify(e)).join("\n") + "\n";
    fs.writeFileSync(filepath, content, "utf-8");
    console.log(`    -> ${filepath} (${data.length} events)`);
  }

  // Write ground truth
  const groundTruth = {
    anomaly_count: 3,
    attacker_user_ids: ATTACKER_IDS,
    attacker_transaction_ids: ATTACKER_TX_IDS,
    description:
      "Double-spend via webhook desync: CREDIT without matching DEBIT",
  };

  const gtPath = path.join(DATA_DIR, ".ground_truth.json");
  fs.writeFileSync(gtPath, JSON.stringify(groundTruth, null, 2), "utf-8");
  console.log(`    -> ${gtPath} (ground truth — hidden from agents)`);

  const totalEvents = Object.values(datasets).reduce(
    (sum, d) => sum + d.length,
    0,
  );
  console.log(
    `\n[+] Telemetry generation complete. Total events: ${totalEvents}`,
  );

  return groundTruth;
}
