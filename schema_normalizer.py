"""
ATROSA Schema Normalizer — Customer Data Mapping
===================================================
Every customer has different column names, formats, and enrichment fields.
This module maps arbitrary customer schemas to ATROSA's canonical schema
so that graduated rules and hunt prompts work across customers.

Approach:
  1. Canonical schema defines the expected column names and types
  2. Customer provides a mapping (or ATROSA auto-discovers via heuristics)
  3. DataFrames are normalized at ingest time — all downstream code sees canonical names
  4. Enrichment columns (from Tier 1-3 sources) are passed through as-is

Usage:
    normalizer = SchemaNormalizer.from_config("tenants/acme/schema_map.json")
    df_api = normalizer.normalize(raw_df, source="api")
"""

import json
import re
from pathlib import Path
from typing import Optional

import pandas as pd


# ===========================
# CANONICAL SCHEMA DEFINITION
# ===========================
CANONICAL_SCHEMA = {
    "api": {
        "required": {
            "timestamp": {"type": "datetime", "aliases": ["ts", "time", "created_at", "event_time", "request_time"]},
            "user_id": {"type": "str", "aliases": ["customer_id", "account_id", "uid", "user", "customer_ref", "client_id"]},
            "endpoint": {"type": "str", "aliases": ["path", "url", "route", "uri", "api_path", "request_path"]},
            "status_code": {"type": "int", "aliases": ["http_status", "status", "response_code", "http_code"]},
            "ip_address": {"type": "str", "aliases": ["ip", "client_ip", "remote_addr", "source_ip", "remote_ip"]},
            "session_id": {"type": "str", "aliases": ["session", "sid", "session_token"]},
        },
        "optional": {
            "transaction_id": {"type": "str", "aliases": ["txn_id", "tx_id", "reference", "ref", "payment_id", "order_id"]},
            "amount": {"type": "float", "aliases": ["value", "txn_amount", "payment_amount", "total"]},
            "currency": {"type": "str", "aliases": ["ccy", "currency_code"]},
            "method": {"type": "str", "aliases": ["http_method", "request_method", "verb"]},
            "user_agent": {"type": "str", "aliases": ["ua", "agent", "browser"]},
            "response_time_ms": {"type": "float", "aliases": ["latency", "duration", "latency_ms", "response_time", "elapsed_ms"]},
            "request_id": {"type": "str", "aliases": ["req_id", "correlation_id", "trace_id"]},
        },
    },
    "db": {
        "required": {
            "timestamp": {"type": "datetime", "aliases": ["ts", "time", "created_at", "committed_at"]},
            "user_id": {"type": "str", "aliases": ["customer_id", "account_id", "uid", "user", "customer_ref"]},
            "operation": {"type": "str", "aliases": ["op", "type", "txn_type", "operation_type", "entry_type"]},
            "amount": {"type": "float", "aliases": ["value", "txn_amount"]},
            "transaction_id": {"type": "str", "aliases": ["txn_id", "tx_id", "reference", "ref"]},
        },
        "optional": {
            "balance_before": {"type": "float", "aliases": ["prev_balance", "opening_balance", "balance_pre"]},
            "balance_after": {"type": "float", "aliases": ["new_balance", "closing_balance", "balance_post"]},
            "provider": {"type": "str", "aliases": ["payment_provider", "processor", "gateway"]},
            "currency": {"type": "str", "aliases": ["ccy", "currency_code"]},
            "idempotency_key": {"type": "str", "aliases": ["idem_key", "dedup_key", "idempotent_key"]},
            "commit_id": {"type": "str", "aliases": ["entry_id", "record_id", "ledger_id"]},
        },
    },
    "mobile": {
        "required": {
            "timestamp": {"type": "datetime", "aliases": ["ts", "time", "event_time"]},
            "user_id": {"type": "str", "aliases": ["customer_id", "account_id", "uid"]},
            "event_type": {"type": "str", "aliases": ["event", "type", "action", "event_name"]},
        },
        "optional": {
            "error_code": {"type": "str", "aliases": ["err_code", "error", "error_type"]},
            "screen": {"type": "str", "aliases": ["page", "view", "screen_name", "activity"]},
            "session_id": {"type": "str", "aliases": ["session", "sid"]},
            "device_os": {"type": "str", "aliases": ["os", "platform", "os_version"]},
            "network_type": {"type": "str", "aliases": ["network", "connection_type", "connectivity"]},
            "ip_address": {"type": "str", "aliases": ["ip", "client_ip"]},
            "app_version": {"type": "str", "aliases": ["version", "build"]},
        },
    },
    "webhooks": {
        "required": {
            "timestamp": {"type": "datetime", "aliases": ["ts", "time", "received_at", "event_time"]},
            "transaction_id": {"type": "str", "aliases": ["txn_id", "tx_id", "reference", "ref", "payment_id"]},
            "status": {"type": "str", "aliases": ["event_status", "payment_status", "result", "state"]},
            "provider": {"type": "str", "aliases": ["payment_provider", "processor", "gateway", "source"]},
        },
        "optional": {
            "user_id": {"type": "str", "aliases": ["customer_id", "account_id"]},
            "amount": {"type": "float", "aliases": ["value", "txn_amount", "payment_amount"]},
            "currency": {"type": "str", "aliases": ["ccy"]},
            "event_type": {"type": "str", "aliases": ["type", "webhook_type", "event_name"]},
            "delivery_attempt": {"type": "int", "aliases": ["attempt", "retry_count", "attempt_number"]},
            "latency_ms": {"type": "float", "aliases": ["latency", "delivery_time_ms", "elapsed_ms"]},
            "webhook_id": {"type": "str", "aliases": ["event_id", "notification_id"]},
        },
    },
}

# Operation value normalization — customers use different terms
OPERATION_ALIASES = {
    "CREDIT": ["credit", "cr", "deposit", "inflow", "receive", "incoming", "add", "top_up", "topup"],
    "DEBIT": ["debit", "dr", "withdrawal", "outflow", "send", "outgoing", "subtract", "payout"],
    "REVERSAL": ["reversal", "reverse", "refund", "chargeback", "dispute", "rollback", "void"],
    "HOLD": ["hold", "freeze", "block", "reserve", "pending"],
    "RELEASE": ["release", "unhold", "unfreeze", "unblock", "unreserve"],
}

# Webhook status normalization
STATUS_ALIASES = {
    "success": ["success", "successful", "completed", "confirmed", "approved", "paid", "settled"],
    "failed": ["failed", "failure", "declined", "rejected", "error", "denied"],
    "pending": ["pending", "processing", "in_progress", "initiated", "awaiting"],
}


class SchemaNormalizer:
    """Maps customer column names and values to ATROSA's canonical schema."""

    def __init__(self, mappings: Optional[dict] = None, value_maps: Optional[dict] = None):
        """
        mappings: {source: {canonical_name: customer_column_name}}
            Example: {"api": {"user_id": "customer_ref", "status_code": "http_status"}}

        value_maps: {source: {column: {canonical_value: [customer_values]}}}
            Example: {"db": {"operation": {"CREDIT": ["deposit", "inflow"]}}}
        """
        self.mappings = mappings or {}
        self.value_maps = value_maps or {}

    @classmethod
    def from_config(cls, config_path: str) -> "SchemaNormalizer":
        """Load normalizer from a JSON config file."""
        path = Path(config_path)
        if not path.exists():
            return cls()  # Empty normalizer — pass-through mode
        with open(path) as f:
            config = json.load(f)
        return cls(
            mappings=config.get("column_mappings", {}),
            value_maps=config.get("value_mappings", {}),
        )

    @classmethod
    def auto_discover(cls, dataframes: dict[str, pd.DataFrame]) -> "SchemaNormalizer":
        """
        Automatically discover mappings by matching customer column names
        against canonical aliases. This is the zero-config path.
        """
        mappings = {}
        value_maps = {}

        for source, df in dataframes.items():
            schema = CANONICAL_SCHEMA.get(source, {})
            source_mapping = {}

            for field_group in ["required", "optional"]:
                for canonical_name, field_def in schema.get(field_group, {}).items():
                    # Direct match first
                    if canonical_name in df.columns:
                        continue  # Already matches canonical name

                    # Check aliases
                    matched = False
                    for alias in field_def.get("aliases", []):
                        if alias in df.columns:
                            source_mapping[canonical_name] = alias
                            matched = True
                            break

                    # Fuzzy match: check if any column contains the canonical name
                    if not matched:
                        for col in df.columns:
                            if canonical_name in col.lower() or col.lower() in canonical_name:
                                source_mapping[canonical_name] = col
                                break

            if source_mapping:
                mappings[source] = source_mapping

            # Auto-discover value mappings for operation and status columns
            if source == "db" and "operation" in df.columns:
                val_map = cls._discover_value_mapping(
                    df["operation"].dropna().unique().tolist(), OPERATION_ALIASES
                )
                if val_map:
                    value_maps.setdefault("db", {})["operation"] = val_map

            if source == "webhooks" and "status" in df.columns:
                val_map = cls._discover_value_mapping(
                    df["status"].dropna().unique().tolist(), STATUS_ALIASES
                )
                if val_map:
                    value_maps.setdefault("webhooks", {})["status"] = val_map

        return cls(mappings=mappings, value_maps=value_maps)

    @staticmethod
    def _discover_value_mapping(actual_values: list, alias_map: dict) -> dict:
        """Match actual column values to canonical values via aliases."""
        mapping = {}
        for actual in actual_values:
            actual_lower = actual.lower().strip()
            for canonical, aliases in alias_map.items():
                if actual_lower == canonical.lower() or actual_lower in aliases:
                    if actual != canonical:
                        mapping[actual] = canonical
                    break
        return mapping if mapping else {}

    def normalize(self, df: pd.DataFrame, source: str) -> pd.DataFrame:
        """
        Normalize a DataFrame to canonical schema.
        - Renames columns per mapping
        - Coerces types
        - Normalizes values (operations, statuses)
        - Passes through enrichment columns untouched
        """
        if df.empty:
            return df

        result = df.copy()

        # Step 1: Rename columns
        column_map = self.mappings.get(source, {})
        if column_map:
            # Invert: {customer_col: canonical_name}
            rename_map = {v: k for k, v in column_map.items() if v in result.columns}
            result = result.rename(columns=rename_map)

        # Step 2: Coerce types
        schema = CANONICAL_SCHEMA.get(source, {})
        for field_group in ["required", "optional"]:
            for canonical_name, field_def in schema.get(field_group, {}).items():
                if canonical_name in result.columns:
                    result = self._coerce_type(result, canonical_name, field_def["type"])

        # Step 3: Normalize values
        source_value_maps = self.value_maps.get(source, {})
        for column, val_map in source_value_maps.items():
            if column in result.columns and val_map:
                result[column] = result[column].replace(val_map)

        return result

    def normalize_all(self, dataframes: dict[str, pd.DataFrame]) -> dict[str, pd.DataFrame]:
        """Normalize all DataFrames."""
        return {source: self.normalize(df, source) for source, df in dataframes.items()}

    @staticmethod
    def _coerce_type(df: pd.DataFrame, column: str, target_type: str) -> pd.DataFrame:
        """Coerce a column to the expected type."""
        try:
            if target_type == "datetime":
                if not pd.api.types.is_datetime64_any_dtype(df[column]):
                    df[column] = pd.to_datetime(df[column], format="mixed", utc=True)
            elif target_type == "float":
                if not pd.api.types.is_float_dtype(df[column]):
                    # Handle string amounts like "$1,234.56" or "1 234,56"
                    if df[column].dtype == object:
                        df[column] = (
                            df[column].astype(str)
                            .str.replace(r"[^\d.\-]", "", regex=True)
                            .astype(float)
                        )
                    else:
                        df[column] = df[column].astype(float)
            elif target_type == "int":
                if not pd.api.types.is_integer_dtype(df[column]):
                    df[column] = pd.to_numeric(df[column], errors="coerce").astype("Int64")
            elif target_type == "str":
                df[column] = df[column].astype(str)
        except Exception:
            pass  # Leave column as-is if coercion fails
        return df

    def get_coverage_report(self, dataframes: dict[str, pd.DataFrame]) -> dict:
        """Report which canonical fields are available vs missing per source."""
        report = {}
        for source, df in dataframes.items():
            schema = CANONICAL_SCHEMA.get(source, {})
            normalized_df = self.normalize(df, source)
            source_report = {"required": {}, "optional": {}, "enrichment": []}

            for field_group in ["required", "optional"]:
                for canonical_name in schema.get(field_group, {}):
                    if canonical_name in normalized_df.columns:
                        null_pct = normalized_df[canonical_name].isna().sum() / len(normalized_df) * 100
                        source_report[field_group][canonical_name] = {
                            "present": True, "null_pct": round(null_pct, 1),
                        }
                    else:
                        source_report[field_group][canonical_name] = {"present": False}

            # Identify enrichment columns (not in canonical schema)
            all_canonical = set()
            for fg in ["required", "optional"]:
                all_canonical.update(schema.get(fg, {}).keys())
            enrichment_cols = [c for c in normalized_df.columns if c not in all_canonical and c != "source"]
            source_report["enrichment"] = enrichment_cols

            report[source] = source_report

        return report

    def save_config(self, path: str):
        """Save the current mapping configuration to a JSON file."""
        config = {
            "column_mappings": self.mappings,
            "value_mappings": self.value_maps,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(config, f, indent=2)

    def generate_template(self, dataframes: dict[str, pd.DataFrame]) -> dict:
        """
        Generate a mapping template for a customer to fill in.
        Pre-populated with auto-discovered matches.
        """
        auto = SchemaNormalizer.auto_discover(dataframes)
        template = {"column_mappings": {}, "value_mappings": auto.value_maps}

        for source, df in dataframes.items():
            schema = CANONICAL_SCHEMA.get(source, {})
            source_template = {}

            for field_group in ["required", "optional"]:
                for canonical_name, field_def in schema.get(field_group, {}).items():
                    if canonical_name in df.columns:
                        source_template[canonical_name] = canonical_name  # Direct match
                    elif canonical_name in auto.mappings.get(source, {}):
                        source_template[canonical_name] = auto.mappings[source][canonical_name]
                    else:
                        source_template[canonical_name] = f"__UNMAPPED__ (available: {list(df.columns)[:5]}...)"

            template["column_mappings"][source] = source_template

        return template
