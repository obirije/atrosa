/**
 * ATROSA Telemetry Gap Analyzer — IDEAL_SCHEMA + gap detection
 */

export interface TelemetryGap {
  source: string;
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  field?: string;
  detail: string;
  fields?: string[];
  null_pct?: number;
  trigger?: string;
}

interface IdealSource {
  required: string[];
  recommended: string[];
}

export const IDEAL_SCHEMA: Record<string, IdealSource> = {
  api_gateway: {
    required: [
      "timestamp", "request_id", "user_id", "session_id", "method",
      "endpoint", "status_code", "response_time_ms", "ip_address",
      "user_agent", "transaction_id", "amount", "currency",
    ],
    recommended: [
      "jwt_claims", "jwt_expiry", "correlation_id", "idempotency_key",
      "request_body_hash", "geo_country", "geo_city", "device_fingerprint",
      "tls_version", "rate_limit_remaining", "upstream_latency_ms",
    ],
  },
  ledger_db_commits: {
    required: [
      "timestamp", "commit_id", "user_id", "operation", "amount",
      "currency", "balance_before", "balance_after", "transaction_id",
      "provider", "idempotency_key",
    ],
    recommended: [
      "ledger_version", "double_entry_pair_id", "approval_chain",
      "source_account_id", "destination_account_id", "fee_amount",
      "exchange_rate", "settlement_status", "reconciliation_id",
    ],
  },
  mobile_client_errors: {
    required: [
      "timestamp", "event_id", "user_id", "session_id", "event_type",
      "device_os", "app_version", "network_type", "error_code", "screen",
    ],
    recommended: [
      "stack_trace", "device_model", "carrier", "battery_level",
      "memory_usage_mb", "connection_quality_ms", "gps_lat", "gps_lon",
      "last_successful_request_id", "certificate_pin_status",
    ],
  },
  payment_webhooks: {
    required: [
      "timestamp", "webhook_id", "provider", "event_type",
      "transaction_id", "user_id", "amount", "currency", "status",
      "delivery_attempt", "latency_ms",
    ],
    recommended: [
      "signature_valid", "raw_payload_hash", "source_ip",
      "idempotency_key", "parent_transaction_id", "settlement_date",
      "fee_amount", "provider_reference", "retry_after_ms",
    ],
  },
};

const ERROR_TO_GAP_HINTS: Record<string, [string, string, string]> = {
  jwt: ["api_gateway", "jwt_claims", "JWT token claims not logged — cannot verify token reuse or expiry manipulation"],
  token: ["api_gateway", "jwt_claims", "Auth token fields missing — cannot detect token replay attacks"],
  idempotency: ["api_gateway", "idempotency_key", "Idempotency keys not logged at API layer — cannot detect replay attacks"],
  correlation: ["api_gateway", "correlation_id", "No correlation ID linking requests across services — cannot trace distributed transactions"],
  device_fingerprint: ["api_gateway", "device_fingerprint", "Device fingerprinting not logged — cannot detect account sharing or device spoofing"],
  geo: ["api_gateway", "geo_country", "Geolocation not logged — cannot detect impossible travel or geo-anomalies"],
  double_entry: ["ledger_db_commits", "double_entry_pair_id", "Double-entry pair IDs missing — cannot verify balanced ledger operations"],
  source_account: ["ledger_db_commits", "source_account_id", "Source/destination account IDs missing — cannot trace fund flow"],
  destination_account: ["ledger_db_commits", "destination_account_id", "Source/destination account IDs missing — cannot trace fund flow"],
  settlement: ["ledger_db_commits", "settlement_status", "Settlement status not logged — cannot detect settlement timing attacks"],
  stack_trace: ["mobile_client_errors", "stack_trace", "Stack traces missing from mobile errors — cannot distinguish genuine crashes from forced disconnects"],
  carrier: ["mobile_client_errors", "carrier", "Mobile carrier info missing — cannot correlate network-based attack patterns"],
  signature: ["payment_webhooks", "signature_valid", "Webhook signature validation status not logged — cannot detect forged webhooks"],
  raw_payload: ["payment_webhooks", "raw_payload_hash", "Raw webhook payload hash missing — cannot detect tampered webhook bodies"],
  source_ip: ["payment_webhooks", "source_ip", "Webhook source IP not logged — cannot verify webhook origin"],
};

export class TelemetryGapAnalyzer {
  gaps: TelemetryGap[] = [];

  /**
   * Compare actual data schema against ideal schema.
   * `data` maps short names (api, db, mobile, webhooks) to arrays of records.
   */
  auditSchema(data: Record<string, Record<string, unknown>[]>): TelemetryGap[] {
    this.gaps = [];

    const sourceMap: Record<string, string> = {
      api_gateway: "api",
      ledger_db_commits: "db",
      mobile_client_errors: "mobile",
      payment_webhooks: "webhooks",
    };

    for (const [sourceName, ideal] of Object.entries(IDEAL_SCHEMA)) {
      const dataKey = sourceMap[sourceName];
      const records = data[dataKey];

      if (!records || records.length === 0) {
        this.gaps.push({
          source: sourceName,
          severity: "critical",
          type: "missing_source",
          detail: `Entire telemetry source '${sourceName}' is missing or empty`,
          fields: ideal.required,
        });
        continue;
      }

      const actualCols = new Set(Object.keys(records[0]));

      // Check required fields
      for (const field of ideal.required) {
        if (!actualCols.has(field)) {
          this.gaps.push({
            source: sourceName,
            severity: "high",
            type: "missing_required_field",
            field,
            detail: `Required field '${field}' missing from ${sourceName}`,
          });
        } else {
          const nullCount = records.filter(
            (r) => r[field] === null || r[field] === undefined,
          ).length;
          if (nullCount / records.length > 0.5) {
            this.gaps.push({
              source: sourceName,
              severity: "medium",
              type: "sparse_field",
              field,
              detail: `Required field '${field}' is >50% null in ${sourceName}`,
              null_pct: Math.round((nullCount / records.length) * 1000) / 10,
            });
          }
        }
      }

      // Check recommended fields
      for (const field of ideal.recommended) {
        if (!actualCols.has(field)) {
          this.gaps.push({
            source: sourceName,
            severity: "low",
            type: "missing_recommended_field",
            field,
            detail: `Recommended field '${field}' not present in ${sourceName}`,
          });
        }
      }
    }

    return this.gaps;
  }

  /**
   * Analyze a Hunter error to identify what telemetry is missing.
   */
  analyzeHunterError(errorText: string, detectCode = ""): TelemetryGap[] {
    const errorGaps: TelemetryGap[] = [];
    const combined = (errorText + " " + detectCode).toLowerCase();

    for (const [keyword, [source, field, description]] of Object.entries(ERROR_TO_GAP_HINTS)) {
      if (combined.includes(keyword)) {
        errorGaps.push({
          source,
          severity: "high",
          type: "hunter_data_gap",
          field,
          detail: description,
          trigger: `Hunter referenced '${keyword}' but field is unavailable`,
        });
      }
    }

    // Check for KeyError patterns
    const keyErrorRegex = /KeyError:\s*['"](\w+)['"]/g;
    let match: RegExpExecArray | null;
    while ((match = keyErrorRegex.exec(errorText)) !== null) {
      const key = match[1];
      let found = false;
      for (const [sourceName, ideal] of Object.entries(IDEAL_SCHEMA)) {
        const allFields = [...ideal.required, ...ideal.recommended];
        if (allFields.includes(key)) {
          errorGaps.push({
            source: sourceName,
            severity: "critical",
            type: "missing_field_access",
            field: key,
            detail: `Hunter tried to access '${key}' in ${sourceName} but it doesn't exist`,
          });
          found = true;
          break;
        }
      }
      if (!found) {
        errorGaps.push({
          source: "unknown",
          severity: "high",
          type: "missing_field_access",
          field: key,
          detail: `Hunter tried to access column '${key}' which doesn't exist in any source`,
        });
      }
    }

    return errorGaps;
  }
}
