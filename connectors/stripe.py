"""
Stripe Direct Connector — Pull transaction data from Stripe API.

Fetches charges, payment_intents, refunds, and disputes directly from
Stripe's REST API. No Airweave dependency.

Usage:
    connector = StripeConnector(api_key="sk_live_...")
    result = connector.run()
    result.save("data/")

    # With date range
    connector = StripeConnector(
        api_key="sk_live_...",
        created_after="2026-01-01",
        created_before="2026-03-01",
        limit=10000,
    )
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from .base import BaseConnector, ConnectorResult


class StripeConnector(BaseConnector):
    """Pull transaction data directly from Stripe API."""

    name = "stripe"
    description = "Direct Stripe API connector"
    API_BASE = "https://api.stripe.com/v1"

    def __init__(self, api_key: str, created_after: Optional[str] = None,
                 created_before: Optional[str] = None, limit: int = 10000):
        self.api_key = api_key
        self.created_after = created_after
        self.created_before = created_before
        self.limit = limit

    def pull(self) -> pd.DataFrame:
        """Fetch charges, payment_intents, refunds, and disputes from Stripe."""
        import urllib.request
        import urllib.parse
        import base64

        auth_header = base64.b64encode(f"{self.api_key}:".encode()).decode()
        headers = {"Authorization": f"Basic {auth_header}"}

        all_records = []

        endpoints = {
            "charges": "/v1/charges",
            "payment_intents": "/v1/payment_intents",
            "refunds": "/v1/refunds",
            "disputes": "/v1/disputes",
        }

        for resource_name, endpoint in endpoints.items():
            print(f"    Fetching {resource_name}...")
            records = self._paginate(endpoint, headers, resource_name)
            all_records.extend(records)
            print(f"      {len(records)} {resource_name}")

        if not all_records:
            print("    [!] No data returned from Stripe")
            return pd.DataFrame()

        return pd.DataFrame(all_records)

    def _paginate(self, endpoint: str, headers: dict, resource_name: str) -> list[dict]:
        """Paginate through Stripe API results."""
        import urllib.request
        import urllib.parse

        records = []
        params = {"limit": "100"}

        if self.created_after:
            params["created[gte]"] = str(int(datetime.fromisoformat(self.created_after).timestamp()))
        if self.created_before:
            params["created[lte]"] = str(int(datetime.fromisoformat(self.created_before).timestamp()))

        starting_after = None
        fetched = 0

        while fetched < self.limit:
            if starting_after:
                params["starting_after"] = starting_after

            url = f"{self.API_BASE}{endpoint}?{urllib.parse.urlencode(params)}"

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(2)
                    continue
                print(f"      [!] Stripe API error: {e.code} {e.reason}")
                break
            except Exception as e:
                print(f"      [!] Error: {e}")
                break

            items = data.get("data", [])
            if not items:
                break

            for item in items:
                record = self._flatten_stripe_object(item, resource_name)
                records.append(record)

            fetched += len(items)

            if not data.get("has_more", False):
                break

            starting_after = items[-1]["id"]

        return records[:self.limit]

    @staticmethod
    def _flatten_stripe_object(obj: dict, resource_type: str) -> dict:
        """Flatten a Stripe API object into a flat dict for DataFrame conversion."""
        flat = {"_resource_type": resource_type}

        # Common fields
        flat["stripe_id"] = obj.get("id", "")
        flat["created"] = obj.get("created", 0)
        flat["amount"] = obj.get("amount", 0) / 100.0  # Stripe amounts are in cents
        flat["currency"] = obj.get("currency", "usd")
        flat["status"] = obj.get("status", "")

        # Resource-specific fields
        if resource_type == "charges":
            flat["customer"] = obj.get("customer", "")
            flat["payment_method"] = obj.get("payment_method", "")
            flat["failure_code"] = obj.get("failure_code")
            flat["failure_message"] = obj.get("failure_message")
            flat["disputed"] = obj.get("disputed", False)
            flat["refunded"] = obj.get("refunded", False)
            flat["paid"] = obj.get("paid", False)
            outcome = obj.get("outcome", {}) or {}
            flat["risk_level"] = outcome.get("risk_level", "")
            flat["risk_score"] = outcome.get("risk_score", 0)
            flat["seller_message"] = outcome.get("seller_message", "")
            card = (obj.get("payment_method_details", {}) or {}).get("card", {}) or {}
            flat["card_brand"] = card.get("brand", "")
            flat["card_country"] = card.get("country", "")
            flat["card_last4"] = card.get("last4", "")
            flat["card_funding"] = card.get("funding", "")  # credit/debit/prepaid
            billing = obj.get("billing_details", {}) or {}
            flat["billing_email"] = billing.get("email", "")
            flat["billing_country"] = (billing.get("address", {}) or {}).get("country", "")

        elif resource_type == "payment_intents":
            flat["customer"] = obj.get("customer", "")
            flat["payment_method"] = obj.get("payment_method", "")
            flat["cancellation_reason"] = obj.get("cancellation_reason")
            charges_data = (obj.get("latest_charge") or "")
            flat["latest_charge"] = charges_data if isinstance(charges_data, str) else charges_data.get("id", "")

        elif resource_type == "refunds":
            flat["charge"] = obj.get("charge", "")
            flat["reason"] = obj.get("reason", "")
            flat["payment_intent"] = obj.get("payment_intent", "")

        elif resource_type == "disputes":
            flat["charge"] = obj.get("charge", "")
            flat["reason"] = obj.get("reason", "")
            flat["is_charge_refundable"] = obj.get("is_charge_refundable", False)
            evidence = obj.get("evidence_details", {}) or {}
            flat["has_evidence"] = evidence.get("has_evidence", False)

        # Metadata (customer-defined)
        metadata = obj.get("metadata", {}) or {}
        for k, v in metadata.items():
            flat[f"meta_{k}"] = v

        return flat

    def transform(self, raw: pd.DataFrame) -> ConnectorResult:
        """Transform Stripe data into ATROSA's 4 DataFrames."""
        if raw.empty:
            return ConnectorResult(
                api=pd.DataFrame(), db=pd.DataFrame(),
                mobile=pd.DataFrame(), webhooks=pd.DataFrame(),
            )

        # Generate canonical fields
        raw["timestamp"] = pd.to_datetime(raw["created"], unit="s").dt.strftime("%Y-%m-%dT%H:%M:%S")
        raw["transaction_id"] = raw["stripe_id"]
        raw["user_id"] = raw["customer"].fillna("unknown").apply(
            lambda c: f"USR-STRIPE-{c[:8]}" if c and c != "unknown" else "USR-STRIPE-anon"
        )

        # --- df_api: Request-level view (all transactions) ---
        resource_to_endpoint = {
            "charges": "/api/v2/payment/charge",
            "payment_intents": "/api/v2/payment/intent",
            "refunds": "/api/v2/payment/refund",
            "disputes": "/api/v2/payment/dispute",
        }

        df_api = pd.DataFrame({
            "source": "api_gateway",
            "timestamp": raw["timestamp"],
            "request_id": raw["stripe_id"],
            "user_id": raw["user_id"],
            "session_id": raw["payment_method"].fillna("unknown"),
            "method": "POST",
            "endpoint": raw["_resource_type"].map(resource_to_endpoint),
            "status_code": raw["status"].map({"succeeded": 200, "failed": 400, "pending": 202}).fillna(200).astype(int),
            "response_time_ms": 100,
            "ip_address": raw.get("billing_country", "unknown"),
            "user_agent": "StripeAPI/v1",
            "transaction_id": raw["transaction_id"],
            "amount": raw["amount"],
            "currency": raw["currency"],
        })

        # Pass through Stripe-specific enrichment columns
        for col in ["risk_level", "risk_score", "card_brand", "card_country",
                     "card_funding", "billing_email"]:
            if col in raw.columns:
                df_api[col] = raw[col]

        # --- df_db: Ledger view (financial state changes) ---
        operation_map = {
            "charges": "DEBIT",
            "payment_intents": "DEBIT",
            "refunds": "REVERSAL",
            "disputes": "REVERSAL",
        }

        df_db = pd.DataFrame({
            "source": "ledger_db_commits",
            "timestamp": raw["timestamp"],
            "commit_id": raw["stripe_id"].apply(lambda s: f"CMT-{s}"),
            "user_id": raw["user_id"],
            "operation": raw["_resource_type"].map(operation_map),
            "amount": raw["amount"],
            "currency": raw["currency"],
            "balance_before": 0.0,  # Stripe doesn't expose account balances
            "balance_after": 0.0,
            "transaction_id": raw["transaction_id"],
            "provider": raw["card_brand"].fillna("stripe") if "card_brand" in raw.columns else "stripe",
            "idempotency_key": raw["stripe_id"],
        })

        # Pass through Stripe-specific columns
        for col in ["disputed", "refunded", "paid", "failure_code"]:
            if col in raw.columns:
                df_db[col] = raw[col]

        # --- df_mobile: Empty for Stripe (no mobile SDK data) ---
        # Stripe doesn't provide mobile app events. This DataFrame is empty
        # but could be enriched with Stripe.js fingerprint data if available.
        df_mobile = pd.DataFrame(columns=[
            "source", "timestamp", "event_id", "user_id", "session_id",
            "event_type", "device_os", "app_version", "network_type",
            "error_code", "screen", "ip_address",
        ])

        # --- df_webhooks: Payment outcome events ---
        status_to_event = {
            "succeeded": "payment.completed",
            "failed": "payment.failed",
            "pending": "payment.pending",
            "requires_action": "payment.pending",
            "canceled": "payment.canceled",
            "requires_payment_method": "payment.failed",
        }

        df_webhooks = pd.DataFrame({
            "source": "payment_webhooks",
            "timestamp": raw["timestamp"],
            "webhook_id": raw["stripe_id"].apply(lambda s: f"WH-{s}"),
            "provider": "stripe",
            "event_type": raw["status"].map(status_to_event).fillna("payment.unknown"),
            "transaction_id": raw["transaction_id"],
            "user_id": raw["user_id"],
            "amount": raw["amount"],
            "currency": raw["currency"],
            "status": raw["status"].map({"succeeded": "success", "failed": "failed"}).fillna("pending"),
            "delivery_attempt": 1,
            "latency_ms": 100,
        })

        # Pass through risk data to webhooks
        for col in ["risk_level", "risk_score", "seller_message"]:
            if col in raw.columns:
                df_webhooks[col] = raw[col]

        return ConnectorResult(
            api=df_api, db=df_db, mobile=df_mobile, webhooks=df_webhooks,
            metadata={
                "connector": self.name,
                "total_records": len(raw),
                "resource_types": raw["_resource_type"].value_counts().to_dict(),
                "date_range": {
                    "earliest": raw["timestamp"].min(),
                    "latest": raw["timestamp"].max(),
                },
            },
        )
