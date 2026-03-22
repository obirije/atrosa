"""
ATROSA Sentinel Swarm — Live Execution & Response
===================================================
The Blue Team / WAF orchestrator.

Reads proven detection rules from active_rules.json, executes them against
live data streams, and triggers automated mitigation when threats are detected.

Modes:
  simulate  — Replays mock telemetry in batches to simulate a live stream (default)
  watch     — Tails a directory for new JSONL events (file-based ingestion)

Usage:
  python sentinel.py                                    # Simulated stream
  python sentinel.py --interval 5                       # 5-second batches
  python sentinel.py --mode watch --watch-dir ./data    # Watch for new files
  python sentinel.py --dry-run                          # Detect only, no mitigation
"""

import argparse
import importlib.util
import json
import os
import sys
import time
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import pandas as pd

# --- Config ---
RULES_PATH = Path("active_rules.json")
ALERTS_PATH = Path("sentinel_alerts.jsonl")
DEFAULT_INTERVAL = 10  # seconds between batches
DEFAULT_BATCH_SIZE = 500


# ===========================
# MITIGATION ACTIONS
# ===========================
class MitigationRegistry:
    """Registry of available mitigation actions."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._actions: dict[str, Callable] = {}
        self._register_builtins()

    def _register_builtins(self):
        self.register("log_alert", self._action_log_alert)
        self.register("suspend_user_id_and_flag_ledger", self._action_suspend_and_flag)
        self.register("webhook", self._action_webhook)
        self.register("slack", self._action_slack)

    def register(self, name: str, fn: Callable):
        self._actions[name] = fn

    def execute(self, action_name: str, alert: dict):
        fn = self._actions.get(action_name, self._action_log_alert)
        if self.dry_run:
            print(f"  [DRY RUN] Would execute: {action_name}")
            self._action_log_alert(alert)
            return
        fn(alert)

    def _action_log_alert(self, alert: dict):
        """Append alert to sentinel_alerts.jsonl."""
        with open(ALERTS_PATH, "a") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"  [ALERT LOGGED] {ALERTS_PATH}")

    def _action_suspend_and_flag(self, alert: dict):
        """Log alert + print suspension notice for each flagged user."""
        self._action_log_alert(alert)
        for user_id in alert.get("flagged_user_ids", []):
            print(f"  [SUSPEND] User {user_id} — ledger flagged for review")
        for tx_id in alert.get("flagged_tx_ids", []):
            print(f"  [HALT] Transaction {tx_id} — frozen pending investigation")

    def _action_webhook(self, alert: dict):
        """POST alert payload to a configured webhook URL."""
        url = os.environ.get("SENTINEL_WEBHOOK_URL")
        if not url:
            print("  [WEBHOOK] SENTINEL_WEBHOOK_URL not set, falling back to log")
            self._action_log_alert(alert)
            return
        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                data=json.dumps(alert).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"  [WEBHOOK] POST {url} -> {resp.status}")
        except Exception as e:
            print(f"  [WEBHOOK] Failed: {e}")
            self._action_log_alert(alert)

    def _action_slack(self, alert: dict):
        """Send alert to a Slack incoming webhook."""
        url = os.environ.get("SENTINEL_SLACK_WEBHOOK")
        if not url:
            print("  [SLACK] SENTINEL_SLACK_WEBHOOK not set, falling back to log")
            self._action_log_alert(alert)
            return
        rule_id = alert.get("rule_id", "UNKNOWN")
        tx_ids = ", ".join(alert.get("flagged_tx_ids", [])[:5])
        user_ids = ", ".join(alert.get("flagged_user_ids", [])[:5])
        text = (
            f":rotating_light: *ATROSA Sentinel Alert*\n"
            f"*Rule:* `{rule_id}`\n"
            f"*Threat:* {alert.get('threat_hypothesis', 'N/A')}\n"
            f"*Transactions:* `{tx_ids}`\n"
            f"*Users:* `{user_ids}`\n"
            f"*Action:* {alert.get('mitigation_action', 'N/A')}"
        )
        try:
            import urllib.request
            payload = json.dumps({"text": text}).encode()
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"  [SLACK] Alert sent -> {resp.status}")
        except Exception as e:
            print(f"  [SLACK] Failed: {e}")
            self._action_log_alert(alert)


# ===========================
# RULE ENGINE
# ===========================
class RuleEngine:
    """Loads and executes graduated detection rules."""

    def __init__(self):
        self.rules: list[dict] = []
        self.rule_modules: dict[str, object] = {}

    def load_rules(self):
        """Load rules from active_rules.json and import their detection scripts."""
        if not RULES_PATH.exists():
            print("[!] No active_rules.json found. Run the Hunter first.")
            return

        with open(RULES_PATH) as f:
            data = json.load(f)

        self.rules = data.get("rules", [])

        for rule in self.rules:
            rule_id = rule["rule_id"]
            script_path = Path(rule["detection_logic_file"])

            if not script_path.exists():
                print(f"[!] Rule {rule_id}: missing script {script_path}")
                continue

            try:
                spec = importlib.util.spec_from_file_location(rule_id, script_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.rule_modules[rule_id] = module
                print(f"    Loaded rule: {rule_id} ({script_path})")
            except Exception as e:
                print(f"[!] Rule {rule_id}: failed to load — {e}")

        print(f"[*] {len(self.rule_modules)}/{len(self.rules)} rules loaded")

    def execute_rules(self, df_api: pd.DataFrame, df_db: pd.DataFrame,
                      df_mobile: pd.DataFrame, df_webhooks: pd.DataFrame) -> list[dict]:
        """Run all loaded rules against the provided data. Returns list of alerts."""
        alerts = []

        for rule in self.rules:
            rule_id = rule["rule_id"]
            module = self.rule_modules.get(rule_id)
            if module is None:
                continue

            t0 = time.time()
            try:
                # The graduated detect.py scripts use ingest.setup() internally.
                # For the Sentinel, we inject data directly by calling detect()
                # after patching the module's ingest reference.
                tx_ids, user_ids = self._run_rule_module(module, df_api, df_db, df_mobile, df_webhooks)
                elapsed_ms = (time.time() - t0) * 1000

                if tx_ids or user_ids:
                    alert = {
                        "alert_id": f"ALERT-{uuid.uuid4().hex[:8]}",
                        "rule_id": rule_id,
                        "threat_hypothesis": rule.get("threat_hypothesis", ""),
                        "flagged_tx_ids": list(set(tx_ids)),
                        "flagged_user_ids": list(set(user_ids)),
                        "mitigation_action": rule.get("mitigation_action", "log_alert"),
                        "timestamp": datetime.now().isoformat(),
                        "execution_time_ms": round(elapsed_ms, 2),
                    }
                    alerts.append(alert)

            except Exception as e:
                print(f"  [!] Rule {rule_id} execution error: {e}")

        return alerts

    def _run_rule_module(self, module, df_api, df_db, df_mobile, df_webhooks):
        """Execute a rule module's detect() function with injected data."""
        import types

        # Create a mock ingest module that returns our data directly
        mock_ingest = types.ModuleType("ingest")
        mock_ingest.setup = lambda: {
            "df_api": df_api,
            "df_db": df_db,
            "df_mobile": df_mobile,
            "df_webhooks": df_webhooks,
            "ground_truth": {},
            "total_events": len(df_api) + len(df_db) + len(df_mobile) + len(df_webhooks),
            "score_fn": lambda *a, **k: {},
        }

        # Patch the module's ingest reference
        if hasattr(module, "ingest"):
            module.ingest = mock_ingest
        # Also patch in sys.modules temporarily
        old_ingest = sys.modules.get("ingest")
        sys.modules["ingest"] = mock_ingest

        try:
            result = module.detect()
            if isinstance(result, tuple) and len(result) == 2:
                return result
            return [], []
        finally:
            if old_ingest is not None:
                sys.modules["ingest"] = old_ingest
            elif "ingest" in sys.modules:
                del sys.modules["ingest"]


# ===========================
# STREAM SOURCES
# ===========================
class SimulatedStream:
    """Replays mock telemetry in batches to simulate a live stream."""

    def __init__(self, batch_size: int = DEFAULT_BATCH_SIZE):
        self.batch_size = batch_size
        self._load_data()
        self._offset = 0

    def _load_data(self):
        from .ingest import load_jsonl
        data_dir = Path("data")
        self.all_events = pd.concat([
            load_jsonl(data_dir / "api_gateway.jsonl"),
            load_jsonl(data_dir / "ledger_db_commits.jsonl"),
            load_jsonl(data_dir / "mobile_client_errors.jsonl"),
            load_jsonl(data_dir / "payment_webhooks.jsonl"),
        ], ignore_index=True)
        # Sort by timestamp to simulate chronological arrival
        self.all_events = self.all_events.sort_values("timestamp").reset_index(drop=True)
        self.total = len(self.all_events)

    def next_batch(self) -> Optional[pd.DataFrame]:
        """Get next batch of events. Returns None when stream is exhausted."""
        if self._offset >= self.total:
            return None
        end = min(self._offset + self.batch_size, self.total)
        batch = self.all_events.iloc[self._offset:end].copy()
        self._offset = end
        return batch

    def reset(self):
        self._offset = 0


class WatchStream:
    """Watches a directory for new JSONL files and ingests them."""

    def __init__(self, watch_dir: str):
        self.watch_dir = Path(watch_dir)
        self._seen_files: set[str] = set()
        # Track existing files on startup
        for f in self.watch_dir.glob("*.jsonl"):
            self._seen_files.add(str(f))

    def next_batch(self) -> Optional[pd.DataFrame]:
        """Check for new JSONL files and return their contents."""
        new_events = []
        for f in sorted(self.watch_dir.glob("*.jsonl")):
            fpath = str(f)
            if fpath not in self._seen_files:
                self._seen_files.add(fpath)
                try:
                    from .ingest import load_jsonl
                    df = load_jsonl(f)
                    new_events.append(df)
                    print(f"  [WATCH] New file: {f.name} ({len(df)} events)")
                except Exception as e:
                    print(f"  [WATCH] Error reading {f.name}: {e}")

        if new_events:
            return pd.concat(new_events, ignore_index=True)
        return None


def split_batch_by_source(batch: pd.DataFrame):
    """Split a mixed batch into per-source DataFrames."""
    df_api = batch[batch["source"] == "api_gateway"].copy() if "source" in batch.columns else pd.DataFrame()
    df_db = batch[batch["source"] == "ledger_db_commits"].copy() if "source" in batch.columns else pd.DataFrame()
    df_mobile = batch[batch["source"] == "mobile_client_errors"].copy() if "source" in batch.columns else pd.DataFrame()
    df_webhooks = batch[batch["source"] == "payment_webhooks"].copy() if "source" in batch.columns else pd.DataFrame()
    return df_api, df_db, df_mobile, df_webhooks


# ===========================
# MAIN SENTINEL LOOP
# ===========================
def run_sentinel(mode: str = "simulate", interval: int = DEFAULT_INTERVAL,
                 batch_size: int = DEFAULT_BATCH_SIZE, watch_dir: str = None,
                 dry_run: bool = False):
    """Main Sentinel execution loop."""
    print("=" * 60)
    print("  ATROSA — Sentinel Swarm")
    print("=" * 60)
    print(f"  Mode: {mode}")
    print(f"  Interval: {interval}s")
    print(f"  Dry run: {dry_run}")

    # Load rules
    print("\n[*] Loading graduated detection rules...")
    engine = RuleEngine()
    engine.load_rules()

    if not engine.rule_modules:
        print("[!] No rules loaded. Run the Hunter first to graduate rules.")
        return False

    # Initialize mitigation
    mitigation = MitigationRegistry(dry_run=dry_run)

    # Initialize stream source
    if mode == "simulate":
        print(f"\n[*] Starting simulated stream (batch_size={batch_size})...")
        stream = SimulatedStream(batch_size=batch_size)
    elif mode == "watch":
        if not watch_dir:
            print("[!] --watch-dir is required in watch mode")
            return False
        print(f"\n[*] Watching directory: {watch_dir}")
        stream = WatchStream(watch_dir=watch_dir)
    else:
        print(f"[!] Unknown mode: {mode}")
        return False

    # Stats
    total_batches = 0
    total_events = 0
    total_alerts = 0
    start_time = time.time()

    # --- Main Loop ---
    print(f"\n[*] Sentinel active. Processing events...\n")

    try:
        while True:
            batch = stream.next_batch()

            if batch is None:
                if mode == "simulate":
                    print(f"\n{'─' * 40}")
                    print(f"[*] Stream exhausted.")
                    break
                # In watch mode, wait for new files
                time.sleep(interval)
                continue

            total_batches += 1
            batch_events = len(batch)
            total_events += batch_events

            df_api, df_db, df_mobile, df_webhooks = split_batch_by_source(batch)

            print(f"[Batch {total_batches}] {batch_events} events "
                  f"(api={len(df_api)}, db={len(df_db)}, mobile={len(df_mobile)}, webhooks={len(df_webhooks)})")

            # Execute all rules
            t0 = time.time()
            alerts = engine.execute_rules(df_api, df_db, df_mobile, df_webhooks)
            elapsed = (time.time() - t0) * 1000

            if alerts:
                for alert in alerts:
                    alert["batch_number"] = total_batches
                    alert["batch_size"] = batch_events
                    total_alerts += 1

                    print(f"\n  {'!' * 50}")
                    print(f"  THREAT DETECTED — Rule {alert['rule_id']}")
                    print(f"  {alert['threat_hypothesis'][:80]}")
                    print(f"  Transactions: {alert['flagged_tx_ids']}")
                    print(f"  Users: {alert['flagged_user_ids']}")
                    print(f"  Execution: {alert['execution_time_ms']:.1f}ms")

                    # Execute mitigation
                    mitigation.execute(alert["mitigation_action"], alert)
                    print(f"  {'!' * 50}\n")
            else:
                print(f"  Clean — {elapsed:.1f}ms")

            if mode == "simulate":
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[*] Sentinel stopped by user.")

    # Summary
    elapsed_total = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"  SENTINEL SESSION SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Runtime: {elapsed_total:.1f}s")
    print(f"  Batches processed: {total_batches}")
    print(f"  Events scanned: {total_events}")
    print(f"  Alerts triggered: {total_alerts}")
    print(f"  Rules active: {len(engine.rule_modules)}")
    if total_alerts > 0:
        print(f"  Alert log: {ALERTS_PATH}")
    print(f"{'=' * 60}")

    return True


# ===========================
# CLI
# ===========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="ATROSA Sentinel Swarm — Live Threat Enforcement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  simulate    Replay mock telemetry as a simulated live stream (default)
  watch       Tail a directory for new JSONL event files

Mitigation environment variables:
  SENTINEL_WEBHOOK_URL      URL for webhook mitigation action
  SENTINEL_SLACK_WEBHOOK    Slack incoming webhook URL for alerts

Examples:
  python sentinel.py
  python sentinel.py --interval 2 --batch-size 200
  python sentinel.py --mode watch --watch-dir /var/log/fintech/
  python sentinel.py --dry-run
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["simulate", "watch"],
        default="simulate",
        help="Stream mode (default: simulate)",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Seconds between batches (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Events per batch in simulate mode (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--watch-dir",
        default=None,
        help="Directory to watch for new JSONL files (watch mode only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Detect threats but don't execute mitigation actions",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    success = run_sentinel(
        mode=args.mode,
        interval=args.interval,
        batch_size=args.batch_size,
        watch_dir=args.watch_dir,
        dry_run=args.dry_run,
    )
    sys.exit(0 if success else 1)
