"""
ATROSA Telemetry Engineer — Active Observability Agent
========================================================
The feedback loop. When a Hunter agent cannot prove a hypothesis because
the telemetry is incomplete (missing columns, missing log sources, insufficient
granularity), the Telemetry Engineer:

1. Analyzes the Hunter's error output and detection code to identify data gaps
2. Generates specific, actionable observability requests
3. Delivers them via Slack, Jira, GitHub Issues, or local file
4. Tracks outstanding requests and their resolution status

The Telemetry Engineer can run standalone (audit mode) or be integrated
into the orchestrator's iteration loop.

Usage:
    python telemetry_engineer.py audit                       # Audit current telemetry for gaps
    python telemetry_engineer.py analyze --error "KeyError: 'jwt_claims'"
    python telemetry_engineer.py analyze --hunt-log logs/iteration_03.py --error-log logs/error_03.txt
    python telemetry_engineer.py status                      # Show outstanding requests
    python telemetry_engineer.py resolve TEL-REQ-001         # Mark a request as resolved
"""

import argparse
import json
import os
import sys
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from providers import create_provider, DEFAULT_MODELS

# --- Config ---
REQUESTS_PATH = Path("telemetry_requests.json")
DATA_DIR = Path("data")
HUNT_PROMPT_PATH = Path("hunt.md")


# ===========================
# TELEMETRY GAP ANALYSIS
# ===========================

# Known telemetry fields that a well-instrumented fintech platform should have
IDEAL_SCHEMA = {
    "api_gateway": {
        "required": [
            "timestamp", "request_id", "user_id", "session_id", "method",
            "endpoint", "status_code", "response_time_ms", "ip_address",
            "user_agent", "transaction_id", "amount", "currency",
        ],
        "recommended": [
            "jwt_claims", "jwt_expiry", "correlation_id", "idempotency_key",
            "request_body_hash", "geo_country", "geo_city", "device_fingerprint",
            "tls_version", "rate_limit_remaining", "upstream_latency_ms",
        ],
    },
    "ledger_db_commits": {
        "required": [
            "timestamp", "commit_id", "user_id", "operation", "amount",
            "currency", "balance_before", "balance_after", "transaction_id",
            "provider", "idempotency_key",
        ],
        "recommended": [
            "ledger_version", "double_entry_pair_id", "approval_chain",
            "source_account_id", "destination_account_id", "fee_amount",
            "exchange_rate", "settlement_status", "reconciliation_id",
        ],
    },
    "mobile_client_errors": {
        "required": [
            "timestamp", "event_id", "user_id", "session_id", "event_type",
            "device_os", "app_version", "network_type", "error_code", "screen",
        ],
        "recommended": [
            "stack_trace", "device_model", "carrier", "battery_level",
            "memory_usage_mb", "connection_quality_ms", "gps_lat", "gps_lon",
            "last_successful_request_id", "certificate_pin_status",
        ],
    },
    "payment_webhooks": {
        "required": [
            "timestamp", "webhook_id", "provider", "event_type",
            "transaction_id", "user_id", "amount", "currency", "status",
            "delivery_attempt", "latency_ms",
        ],
        "recommended": [
            "signature_valid", "raw_payload_hash", "source_ip",
            "idempotency_key", "parent_transaction_id", "settlement_date",
            "fee_amount", "provider_reference", "retry_after_ms",
        ],
    },
}

# Maps error patterns to likely missing telemetry
ERROR_TO_GAP_HINTS = {
    "jwt": ("api_gateway", "jwt_claims", "JWT token claims not logged — cannot verify token reuse or expiry manipulation"),
    "token": ("api_gateway", "jwt_claims", "Auth token fields missing — cannot detect token replay attacks"),
    "idempotency": ("api_gateway", "idempotency_key", "Idempotency keys not logged at API layer — cannot detect replay attacks"),
    "correlation": ("api_gateway", "correlation_id", "No correlation ID linking requests across services — cannot trace distributed transactions"),
    "device_fingerprint": ("api_gateway", "device_fingerprint", "Device fingerprinting not logged — cannot detect account sharing or device spoofing"),
    "geo": ("api_gateway", "geo_country", "Geolocation not logged — cannot detect impossible travel or geo-anomalies"),
    "double_entry": ("ledger_db_commits", "double_entry_pair_id", "Double-entry pair IDs missing — cannot verify balanced ledger operations"),
    "source_account": ("ledger_db_commits", "source_account_id", "Source/destination account IDs missing — cannot trace fund flow"),
    "destination_account": ("ledger_db_commits", "destination_account_id", "Source/destination account IDs missing — cannot trace fund flow"),
    "settlement": ("ledger_db_commits", "settlement_status", "Settlement status not logged — cannot detect settlement timing attacks"),
    "stack_trace": ("mobile_client_errors", "stack_trace", "Stack traces missing from mobile errors — cannot distinguish genuine crashes from forced disconnects"),
    "carrier": ("mobile_client_errors", "carrier", "Mobile carrier info missing — cannot correlate network-based attack patterns"),
    "signature": ("payment_webhooks", "signature_valid", "Webhook signature validation status not logged — cannot detect forged webhooks"),
    "raw_payload": ("payment_webhooks", "raw_payload_hash", "Raw webhook payload hash missing — cannot detect tampered webhook bodies"),
    "source_ip": ("payment_webhooks", "source_ip", "Webhook source IP not logged — cannot verify webhook origin"),
}


class TelemetryGapAnalyzer:
    """Analyzes telemetry data for completeness gaps."""

    def __init__(self):
        self.gaps: list[dict] = []

    def audit_schema(self, data: dict[str, pd.DataFrame]) -> list[dict]:
        """Compare actual schema against ideal schema. Returns list of gaps."""
        self.gaps = []

        source_map = {
            "api_gateway": data.get("api"),
            "ledger_db_commits": data.get("db"),
            "mobile_client_errors": data.get("mobile"),
            "payment_webhooks": data.get("webhooks"),
        }

        for source_name, ideal in IDEAL_SCHEMA.items():
            df = source_map.get(source_name)
            if df is None or df.empty:
                self.gaps.append({
                    "source": source_name,
                    "severity": "critical",
                    "type": "missing_source",
                    "detail": f"Entire telemetry source '{source_name}' is missing or empty",
                    "fields": ideal["required"],
                })
                continue

            actual_cols = set(df.columns)

            # Check required fields
            for field in ideal["required"]:
                if field not in actual_cols:
                    self.gaps.append({
                        "source": source_name,
                        "severity": "high",
                        "type": "missing_required_field",
                        "field": field,
                        "detail": f"Required field '{field}' missing from {source_name}",
                    })
                elif df[field].isna().sum() / len(df) > 0.5:
                    self.gaps.append({
                        "source": source_name,
                        "severity": "medium",
                        "type": "sparse_field",
                        "field": field,
                        "detail": f"Required field '{field}' is >50% null in {source_name}",
                        "null_pct": round(df[field].isna().sum() / len(df) * 100, 1),
                    })

            # Check recommended fields
            for field in ideal["recommended"]:
                if field not in actual_cols:
                    self.gaps.append({
                        "source": source_name,
                        "severity": "low",
                        "type": "missing_recommended_field",
                        "field": field,
                        "detail": f"Recommended field '{field}' not present in {source_name}",
                    })

        return self.gaps

    def analyze_hunter_error(self, error_text: str, detect_code: str = "") -> list[dict]:
        """Analyze a Hunter error to identify what telemetry is missing."""
        error_gaps = []
        combined = (error_text + " " + detect_code).lower()

        for keyword, (source, field, description) in ERROR_TO_GAP_HINTS.items():
            if keyword in combined:
                error_gaps.append({
                    "source": source,
                    "severity": "high",
                    "type": "hunter_data_gap",
                    "field": field,
                    "detail": description,
                    "trigger": f"Hunter referenced '{keyword}' but field is unavailable",
                })

        # Check for KeyError patterns (direct missing column access)
        import re
        key_errors = re.findall(r"KeyError:\s*['\"](\w+)['\"]", error_text)
        for key in key_errors:
            # Try to figure out which source it belongs to
            for source_name, ideal in IDEAL_SCHEMA.items():
                all_fields = ideal["required"] + ideal["recommended"]
                if key in all_fields:
                    error_gaps.append({
                        "source": source_name,
                        "severity": "critical",
                        "type": "missing_field_access",
                        "field": key,
                        "detail": f"Hunter tried to access '{key}' in {source_name} but it doesn't exist",
                    })
                    break
            else:
                error_gaps.append({
                    "source": "unknown",
                    "severity": "high",
                    "type": "missing_field_access",
                    "field": key,
                    "detail": f"Hunter tried to access column '{key}' which doesn't exist in any source",
                })

        return error_gaps


# ===========================
# REQUEST GENERATION
# ===========================
class ObservabilityRequest:
    """Generates and manages observability requests for DevOps."""

    def __init__(self):
        self.requests: list[dict] = []
        self._load_existing()

    def _load_existing(self):
        if REQUESTS_PATH.exists():
            with open(REQUESTS_PATH) as f:
                data = json.load(f)
                self.requests = data.get("requests", [])

    def _save(self):
        with open(REQUESTS_PATH, "w") as f:
            json.dump({"requests": self.requests}, f, indent=2)

    def create_request(self, gap: dict, hunt_context: str = "") -> dict:
        """Create an observability request from a telemetry gap."""
        req_id = f"TEL-REQ-{hashlib.sha256(json.dumps(gap, sort_keys=True).encode()).hexdigest()[:6].upper()}"

        # Check for duplicate
        for existing in self.requests:
            if existing["request_id"] == req_id:
                return existing

        request = {
            "request_id": req_id,
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "resolved_at": None,
            "severity": gap["severity"],
            "source": gap["source"],
            "field": gap.get("field", "N/A"),
            "type": gap["type"],
            "detail": gap["detail"],
            "hunt_context": hunt_context,
            "action_required": self._generate_action(gap),
        }

        self.requests.append(request)
        self._save()
        return request

    def _generate_action(self, gap: dict) -> str:
        """Generate a specific, actionable instruction for DevOps."""
        source = gap["source"]
        field = gap.get("field", "")
        gap_type = gap["type"]

        if gap_type == "missing_source":
            return (
                f"Enable logging for '{source}' and forward to the ATROSA ingestion pipeline. "
                f"Required fields: {', '.join(gap.get('fields', []))}"
            )

        if gap_type == "missing_required_field":
            return f"Add field '{field}' to the {source} log output. This is a required field for threat detection."

        if gap_type == "sparse_field":
            null_pct = gap.get("null_pct", "unknown")
            return (
                f"Field '{field}' in {source} is {null_pct}% null. "
                f"Ensure this field is populated on all log entries."
            )

        if gap_type == "missing_recommended_field":
            return (
                f"Consider adding '{field}' to {source} logging. "
                f"This field enables detection of additional threat classes. "
                f"Detail: {gap['detail']}"
            )

        if gap_type in ("hunter_data_gap", "missing_field_access"):
            return (
                f"URGENT: A threat hunt is blocked because '{field}' is not available in {source}. "
                f"Temporarily enable debug-level logging on the relevant endpoint/service to capture this field. "
                f"Detail: {gap['detail']}"
            )

        return f"Review telemetry gap: {gap['detail']}"

    def resolve_request(self, req_id: str) -> Optional[dict]:
        """Mark a request as resolved."""
        for req in self.requests:
            if req["request_id"] == req_id:
                req["status"] = "resolved"
                req["resolved_at"] = datetime.now().isoformat()
                self._save()
                return req
        return None

    def get_open_requests(self) -> list[dict]:
        return [r for r in self.requests if r["status"] == "open"]

    def get_all_requests(self) -> list[dict]:
        return self.requests


# ===========================
# DELIVERY CHANNELS
# ===========================
class DeliveryChannel:
    """Delivers observability requests to external systems."""

    @staticmethod
    def _validate_url(url: str, name: str) -> bool:
        """Validate that a URL uses HTTPS (or localhost for dev)."""
        if url.startswith("https://"):
            return True
        if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
            return True
        print(f"  [{name}] BLOCKED — URL must use HTTPS (got: {url[:50]}...)")
        return False

    @staticmethod
    def deliver(request: dict, channels: list[str]):
        for channel in channels:
            if channel == "console":
                DeliveryChannel._to_console(request)
            elif channel == "slack":
                DeliveryChannel._to_slack(request)
            elif channel == "github":
                DeliveryChannel._to_github_issue(request)
            elif channel == "jira":
                DeliveryChannel._to_jira(request)
            elif channel == "file":
                DeliveryChannel._to_file(request)

    @staticmethod
    def _to_console(req: dict):
        severity_icons = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[i]"}
        icon = severity_icons.get(req["severity"], "[?]")
        print(f"\n  {icon} {req['request_id']} ({req['severity'].upper()})")
        print(f"      Source: {req['source']}")
        print(f"      Field: {req['field']}")
        print(f"      Detail: {req['detail']}")
        print(f"      Action: {req['action_required']}")

    @staticmethod
    def _to_slack(req: dict):
        url = os.environ.get("TELEMETRY_SLACK_WEBHOOK")
        if not url:
            print(f"  [SLACK] TELEMETRY_SLACK_WEBHOOK not set — skipping Slack delivery")
            return
        if not DeliveryChannel._validate_url(url, "SLACK"):
            return

        severity_emoji = {
            "critical": ":red_circle:",
            "high": ":large_orange_circle:",
            "medium": ":large_yellow_circle:",
            "low": ":white_circle:",
        }
        emoji = severity_emoji.get(req["severity"], ":question:")

        text = (
            f"{emoji} *ATROSA Telemetry Request — {req['request_id']}*\n"
            f"*Severity:* {req['severity'].upper()}\n"
            f"*Source:* `{req['source']}`\n"
            f"*Field:* `{req['field']}`\n"
            f"*Detail:* {req['detail']}\n"
            f"*Action Required:* {req['action_required']}\n"
            f"_Resolve with:_ `python telemetry_engineer.py resolve {req['request_id']}`"
        )

        try:
            import urllib.request
            payload = json.dumps({"text": text}).encode()
            http_req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(http_req, timeout=10) as resp:
                print(f"  [SLACK] Sent {req['request_id']} -> {resp.status}")
        except Exception as e:
            print(f"  [SLACK] Failed: {e}")

    @staticmethod
    def _to_github_issue(req: dict):
        repo = os.environ.get("TELEMETRY_GITHUB_REPO")
        if not repo:
            print(f"  [GITHUB] TELEMETRY_GITHUB_REPO not set — skipping")
            return

        title = f"[ATROSA] {req['request_id']}: Add '{req['field']}' to {req['source']}"
        body = (
            f"## Telemetry Gap Report\n\n"
            f"**Request ID:** `{req['request_id']}`\n"
            f"**Severity:** {req['severity'].upper()}\n"
            f"**Source:** `{req['source']}`\n"
            f"**Field:** `{req['field']}`\n\n"
            f"### Detail\n{req['detail']}\n\n"
            f"### Action Required\n{req['action_required']}\n\n"
            f"### Context\n{req.get('hunt_context', 'N/A')}\n\n"
            f"---\n_Generated by ATROSA Telemetry Engineer_"
        )

        try:
            import subprocess
            result = subprocess.run(
                ["gh", "issue", "create", "--repo", repo,
                 "--title", title, "--body", body,
                 "--label", f"telemetry,{req['severity']}"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                print(f"  [GITHUB] Created issue: {result.stdout.strip()}")
            else:
                print(f"  [GITHUB] Failed: {result.stderr[:200]}")
        except Exception as e:
            print(f"  [GITHUB] Failed: {e}")

    @staticmethod
    def _to_jira(req: dict):
        jira_url = os.environ.get("TELEMETRY_JIRA_URL")
        jira_token = os.environ.get("TELEMETRY_JIRA_TOKEN")
        jira_project = os.environ.get("TELEMETRY_JIRA_PROJECT")

        if not all([jira_url, jira_token, jira_project]):
            print(f"  [JIRA] TELEMETRY_JIRA_URL/TOKEN/PROJECT not set — skipping")
            return
        if not DeliveryChannel._validate_url(jira_url, "JIRA"):
            return

        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}

        payload = {
            "fields": {
                "project": {"key": jira_project},
                "summary": f"[ATROSA] {req['request_id']}: Add '{req['field']}' to {req['source']}",
                "description": (
                    f"h2. Telemetry Gap Report\n\n"
                    f"*Request ID:* {req['request_id']}\n"
                    f"*Severity:* {req['severity'].upper()}\n"
                    f"*Source:* {req['source']}\n"
                    f"*Field:* {req['field']}\n\n"
                    f"h3. Detail\n{req['detail']}\n\n"
                    f"h3. Action Required\n{req['action_required']}"
                ),
                "issuetype": {"name": "Task"},
                "priority": {"name": priority_map.get(req["severity"], "Medium")},
            }
        }

        try:
            import urllib.request
            import base64
            http_req = urllib.request.Request(
                f"{jira_url}/rest/api/2/issue",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {base64.b64encode(jira_token.encode()).decode()}",
                },
                method="POST",
            )
            with urllib.request.urlopen(http_req, timeout=15) as resp:
                result = json.loads(resp.read())
                print(f"  [JIRA] Created: {result.get('key', 'unknown')}")
        except Exception as e:
            print(f"  [JIRA] Failed: {e}")

    @staticmethod
    def _to_file(req: dict):
        path = Path("telemetry_requests_log.jsonl")
        with open(path, "a") as f:
            f.write(json.dumps(req) + "\n")
        print(f"  [FILE] Appended to {path}")


# ===========================
# LLM-POWERED GAP ANALYSIS
# ===========================
class SmartGapAnalyzer:
    """Uses an LLM to analyze complex data gaps that pattern matching misses."""

    def __init__(self, provider_name: str = "anthropic", model: str = None, base_url: str = None):
        system_prompt = (
            "You are a Telemetry Engineer for a fintech security platform. "
            "You analyze failed threat detection attempts and identify exactly what "
            "telemetry data is missing. Be specific: name the exact fields, log sources, "
            "and endpoints that need instrumentation. Output JSON only.\n\n"
            "Output format:\n"
            '{"gaps": [{"source": "...", "field": "...", "severity": "critical|high|medium|low", '
            '"detail": "...", "action": "..."}]}'
        )
        self.provider = create_provider(
            provider_name=provider_name,
            system_prompt=system_prompt,
            model=model,
            base_url=base_url,
        )

    def analyze(self, error_text: str, detect_code: str, schema_info: str) -> list[dict]:
        """Use LLM to identify data gaps from a failed hunt iteration."""
        prompt = (
            f"A threat detection script failed. Analyze the error and detection code "
            f"to identify what telemetry data is missing.\n\n"
            f"## Current Schema\n{schema_info}\n\n"
            f"## Detection Code\n```python\n{detect_code}\n```\n\n"
            f"## Error Output\n```\n{error_text}\n```\n\n"
            f"Identify the specific telemetry gaps. Return JSON only."
        )

        try:
            response = self.provider.chat(prompt)
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return data.get("gaps", [])
        except Exception as e:
            print(f"  [SMART] LLM analysis failed: {e}")

        return []


# ===========================
# ORCHESTRATOR INTEGRATION
# ===========================
def check_hunt_iteration(error_text: str, detect_code: str = "",
                         channels: list[str] = None, hunt_context: str = "") -> list[dict]:
    """
    Called by the orchestrator when a Hunter iteration fails.
    Analyzes the failure, creates requests, and delivers them.
    Returns list of created requests.
    """
    if channels is None:
        channels = ["console", "file"]

    analyzer = TelemetryGapAnalyzer()
    gaps = analyzer.analyze_hunter_error(error_text, detect_code)

    if not gaps:
        return []

    request_mgr = ObservabilityRequest()
    created = []

    for gap in gaps:
        req = request_mgr.create_request(gap, hunt_context=hunt_context)
        if req["status"] == "open":
            DeliveryChannel.deliver(req, channels)
            created.append(req)

    return created


# ===========================
# CLI COMMANDS
# ===========================
def cmd_audit(channels: list[str]):
    """Audit current telemetry for completeness gaps."""
    print("=" * 60)
    print("  ATROSA — Telemetry Engineer: Schema Audit")
    print("=" * 60)

    from ingest import load_all_data
    print("\n[*] Loading telemetry data...")
    data = load_all_data()

    print("\n[*] Auditing against ideal schema...")
    analyzer = TelemetryGapAnalyzer()
    gaps = analyzer.audit_schema(data)

    if not gaps:
        print("\n[+] No gaps found. Telemetry is complete.")
        return

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for gap in gaps:
        by_severity[gap["severity"]].append(gap)

    print(f"\n[*] Found {len(gaps)} telemetry gaps:")
    for sev in ["critical", "high", "medium", "low"]:
        if by_severity[sev]:
            print(f"    {sev.upper()}: {len(by_severity[sev])}")

    # Create and deliver requests
    request_mgr = ObservabilityRequest()
    print(f"\n[*] Generating observability requests...")

    for gap in gaps:
        req = request_mgr.create_request(gap, hunt_context="Schema audit")
        DeliveryChannel.deliver(req, channels)

    open_count = len(request_mgr.get_open_requests())
    print(f"\n[+] {open_count} open observability requests. Saved to {REQUESTS_PATH}")


def cmd_analyze(error: str, hunt_log: str = None, error_log: str = None, channels: list[str] = None):
    """Analyze a specific Hunter failure."""
    if channels is None:
        channels = ["console", "file"]

    print("=" * 60)
    print("  ATROSA — Telemetry Engineer: Error Analysis")
    print("=" * 60)

    detect_code = ""
    if hunt_log:
        detect_code = Path(hunt_log).read_text()

    error_text = error or ""
    if error_log:
        error_text += "\n" + Path(error_log).read_text()

    if not error_text.strip():
        print("[!] No error text provided. Use --error or --error-log.")
        return

    print(f"\n[*] Analyzing error...")
    created = check_hunt_iteration(
        error_text=error_text,
        detect_code=detect_code,
        channels=channels,
        hunt_context=f"Manual analysis",
    )

    if created:
        print(f"\n[+] Created {len(created)} observability requests.")
    else:
        print(f"\n[*] No telemetry gaps detected from this error.")


def cmd_status():
    """Show all observability requests and their status."""
    print("=" * 60)
    print("  ATROSA — Telemetry Engineer: Request Status")
    print("=" * 60)

    request_mgr = ObservabilityRequest()
    all_reqs = request_mgr.get_all_requests()

    if not all_reqs:
        print("\n  No observability requests found.")
        return

    open_reqs = [r for r in all_reqs if r["status"] == "open"]
    resolved_reqs = [r for r in all_reqs if r["status"] == "resolved"]

    print(f"\n  Total: {len(all_reqs)} | Open: {len(open_reqs)} | Resolved: {len(resolved_reqs)}")

    if open_reqs:
        print(f"\n  {'─' * 50}")
        print(f"  OPEN REQUESTS")
        print(f"  {'─' * 50}")
        for req in open_reqs:
            severity_icons = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[i]"}
            icon = severity_icons.get(req["severity"], "[?]")
            print(f"\n  {icon} {req['request_id']} — {req['severity'].upper()}")
            print(f"      Source: {req['source']} / Field: {req['field']}")
            print(f"      Action: {req['action_required'][:100]}")
            print(f"      Created: {req['created_at']}")

    if resolved_reqs:
        print(f"\n  {'─' * 50}")
        print(f"  RESOLVED")
        print(f"  {'─' * 50}")
        for req in resolved_reqs:
            print(f"  [OK] {req['request_id']} — {req['source']}/{req['field']} (resolved {req['resolved_at']})")


def cmd_resolve(req_id: str):
    """Mark a request as resolved."""
    request_mgr = ObservabilityRequest()
    result = request_mgr.resolve_request(req_id)
    if result:
        print(f"[+] {req_id} marked as resolved.")
    else:
        print(f"[!] Request {req_id} not found.")


# ===========================
# CLI
# ===========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="ATROSA Telemetry Engineer — Active Observability Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  audit                  Audit current telemetry against ideal schema
  analyze                Analyze a specific Hunter error for data gaps
  status                 Show all observability requests
  resolve <REQ-ID>       Mark a request as resolved

Delivery channels (--channel):
  console                Print to terminal (default)
  file                   Append to telemetry_requests_log.jsonl
  slack                  Send to Slack (TELEMETRY_SLACK_WEBHOOK)
  github                 Create GitHub issue (TELEMETRY_GITHUB_REPO)
  jira                   Create Jira ticket (TELEMETRY_JIRA_URL/TOKEN/PROJECT)

Examples:
  python telemetry_engineer.py audit
  python telemetry_engineer.py audit --channel slack --channel github
  python telemetry_engineer.py analyze --error "KeyError: 'jwt_claims'"
  python telemetry_engineer.py analyze --hunt-log logs/iteration_03.py --error-log logs/error_03.txt
  python telemetry_engineer.py status
  python telemetry_engineer.py resolve TEL-REQ-A1B2C3
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Audit telemetry completeness")
    audit_parser.add_argument("--channel", action="append", default=None,
                              help="Delivery channel (repeatable)")

    # analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a Hunter error")
    analyze_parser.add_argument("--error", "-e", default="", help="Error text")
    analyze_parser.add_argument("--hunt-log", default=None, help="Path to hunt iteration code")
    analyze_parser.add_argument("--error-log", default=None, help="Path to error log file")
    analyze_parser.add_argument("--channel", action="append", default=None,
                                help="Delivery channel (repeatable)")

    # status
    subparsers.add_parser("status", help="Show request status")

    # resolve
    resolve_parser = subparsers.add_parser("resolve", help="Resolve a request")
    resolve_parser.add_argument("request_id", help="Request ID to resolve (e.g. TEL-REQ-A1B2C3)")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.command == "audit":
        channels = args.channel or ["console", "file"]
        cmd_audit(channels)
    elif args.command == "analyze":
        channels = args.channel or ["console", "file"]
        cmd_analyze(
            error=args.error,
            hunt_log=args.hunt_log,
            error_log=args.error_log,
            channels=channels,
        )
    elif args.command == "status":
        cmd_status()
    elif args.command == "resolve":
        cmd_resolve(args.request_id)
    else:
        print("Usage: python telemetry_engineer.py {audit,analyze,status,resolve}")
        print("Run with --help for details.")
