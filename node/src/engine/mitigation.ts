/**
 * ATROSA Mitigation Actions — alert actions: log, webhook, slack
 */

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { ALERTS_PATH } from "../utils/paths.js";

export interface Alert {
  alert_id: string;
  rule_id: string;
  threat_hypothesis: string;
  flagged_tx_ids: string[];
  flagged_user_ids: string[];
  mitigation_action: string;
  timestamp: string;
  execution_time_ms: number;
  batch_number?: number;
  batch_size?: number;
}

type ActionFn = (alert: Alert) => void;

export class MitigationRegistry {
  private dryRun: boolean;
  private actions: Map<string, ActionFn> = new Map();

  constructor(dryRun = false) {
    this.dryRun = dryRun;
    this.registerBuiltins();
  }

  private registerBuiltins(): void {
    this.register("log_alert", (a) => this.actionLogAlert(a));
    this.register("suspend_user_id_and_flag_ledger", (a) =>
      this.actionSuspendAndFlag(a),
    );
    this.register("webhook", (a) => this.actionWebhook(a));
    this.register("slack", (a) => this.actionSlack(a));
  }

  register(name: string, fn: ActionFn): void {
    this.actions.set(name, fn);
  }

  execute(actionName: string, alert: Alert): void {
    const fn = this.actions.get(actionName) ?? ((a: Alert) => this.actionLogAlert(a));
    if (this.dryRun) {
      console.log(`  [DRY RUN] Would execute: ${actionName}`);
      this.actionLogAlert(alert);
      return;
    }
    fn(alert);
  }

  private actionLogAlert(alert: Alert): void {
    fs.appendFileSync(ALERTS_PATH, JSON.stringify(alert) + "\n", "utf-8");
    console.log(`  [ALERT LOGGED] ${ALERTS_PATH}`);
  }

  private actionSuspendAndFlag(alert: Alert): void {
    this.actionLogAlert(alert);
    for (const userId of alert.flagged_user_ids) {
      console.log(`  [SUSPEND] User ${userId} — ledger flagged for review`);
    }
    for (const txId of alert.flagged_tx_ids) {
      console.log(
        `  [HALT] Transaction ${txId} — frozen pending investigation`,
      );
    }
  }

  private actionWebhook(alert: Alert): void {
    const url = process.env.SENTINEL_WEBHOOK_URL;
    if (!url) {
      console.log(
        "  [WEBHOOK] SENTINEL_WEBHOOK_URL not set, falling back to log",
      );
      this.actionLogAlert(alert);
      return;
    }
    postJson(url, alert)
      .then((status) => console.log(`  [WEBHOOK] POST ${url} -> ${status}`))
      .catch((err) => {
        console.log(`  [WEBHOOK] Failed: ${err}`);
        this.actionLogAlert(alert);
      });
  }

  private actionSlack(alert: Alert): void {
    const url = process.env.SENTINEL_SLACK_WEBHOOK;
    if (!url) {
      console.log(
        "  [SLACK] SENTINEL_SLACK_WEBHOOK not set, falling back to log",
      );
      this.actionLogAlert(alert);
      return;
    }
    const txIds = alert.flagged_tx_ids.slice(0, 5).join(", ");
    const userIds = alert.flagged_user_ids.slice(0, 5).join(", ");
    const text =
      `:rotating_light: *ATROSA Sentinel Alert*\n` +
      `*Rule:* \`${alert.rule_id}\`\n` +
      `*Threat:* ${alert.threat_hypothesis}\n` +
      `*Transactions:* \`${txIds}\`\n` +
      `*Users:* \`${userIds}\`\n` +
      `*Action:* ${alert.mitigation_action}`;

    postJson(url, { text })
      .then((status) => console.log(`  [SLACK] Alert sent -> ${status}`))
      .catch((err) => {
        console.log(`  [SLACK] Failed: ${err}`);
        this.actionLogAlert(alert);
      });
  }
}

function postJson(
  url: string,
  data: unknown,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = JSON.stringify(data);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(
      parsed,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: 10_000,
      },
      (res) => resolve(res.statusCode ?? 0),
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}
