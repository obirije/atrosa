/**
 * ATROSA Observability Request lifecycle management
 */

import fs from "node:fs";
import crypto from "node:crypto";
import { REQUESTS_PATH } from "../utils/paths.js";
import type { TelemetryGap } from "./gap-analyzer.js";

export interface ObservabilityReq {
  request_id: string;
  status: "open" | "resolved";
  created_at: string;
  resolved_at: string | null;
  severity: string;
  source: string;
  field: string;
  type: string;
  detail: string;
  hunt_context: string;
  action_required: string;
}

interface RequestsFile {
  requests: ObservabilityReq[];
}

export class ObservabilityRequestManager {
  requests: ObservabilityReq[] = [];

  constructor() {
    this.loadExisting();
  }

  private loadExisting(): void {
    if (fs.existsSync(REQUESTS_PATH)) {
      const data: RequestsFile = JSON.parse(
        fs.readFileSync(REQUESTS_PATH, "utf-8"),
      );
      this.requests = data.requests || [];
    }
  }

  private save(): void {
    fs.writeFileSync(
      REQUESTS_PATH,
      JSON.stringify({ requests: this.requests }, null, 2),
      "utf-8",
    );
  }

  createRequest(gap: TelemetryGap, huntContext = ""): ObservabilityReq {
    const hash = crypto
      .createHash("sha256")
      .update(JSON.stringify(gap, Object.keys(gap).sort()))
      .digest("hex")
      .slice(0, 6)
      .toUpperCase();
    const reqId = `TEL-REQ-${hash}`;

    // Check for duplicate
    const existing = this.requests.find((r) => r.request_id === reqId);
    if (existing) return existing;

    const request: ObservabilityReq = {
      request_id: reqId,
      status: "open",
      created_at: new Date().toISOString(),
      resolved_at: null,
      severity: gap.severity,
      source: gap.source,
      field: gap.field ?? "N/A",
      type: gap.type,
      detail: gap.detail,
      hunt_context: huntContext,
      action_required: this.generateAction(gap),
    };

    this.requests.push(request);
    this.save();
    return request;
  }

  private generateAction(gap: TelemetryGap): string {
    const { source, field, type } = gap;

    if (type === "missing_source") {
      return (
        `Enable logging for '${source}' and forward to the ATROSA ingestion pipeline. ` +
        `Required fields: ${(gap.fields ?? []).join(", ")}`
      );
    }
    if (type === "missing_required_field") {
      return `Add field '${field}' to the ${source} log output. This is a required field for threat detection.`;
    }
    if (type === "sparse_field") {
      const nullPct = gap.null_pct ?? "unknown";
      return (
        `Field '${field}' in ${source} is ${nullPct}% null. ` +
        `Ensure this field is populated on all log entries.`
      );
    }
    if (type === "missing_recommended_field") {
      return (
        `Consider adding '${field}' to ${source} logging. ` +
        `This field enables detection of additional threat classes. ` +
        `Detail: ${gap.detail}`
      );
    }
    if (type === "hunter_data_gap" || type === "missing_field_access") {
      return (
        `URGENT: A threat hunt is blocked because '${field}' is not available in ${source}. ` +
        `Temporarily enable debug-level logging on the relevant endpoint/service to capture this field. ` +
        `Detail: ${gap.detail}`
      );
    }
    return `Review telemetry gap: ${gap.detail}`;
  }

  resolveRequest(reqId: string): ObservabilityReq | null {
    const req = this.requests.find((r) => r.request_id === reqId);
    if (!req) return null;
    req.status = "resolved";
    req.resolved_at = new Date().toISOString();
    this.save();
    return req;
  }

  getOpenRequests(): ObservabilityReq[] {
    return this.requests.filter((r) => r.status === "open");
  }

  getAllRequests(): ObservabilityReq[] {
    return this.requests;
  }
}
