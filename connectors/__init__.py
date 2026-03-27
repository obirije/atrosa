"""
ATROSA Connectors — Data Source Integration Layer
====================================================
Pulls data from external systems and transforms it into ATROSA's
4-DataFrame format (api, db, mobile, webhooks).

Connector hierarchy (cascading fallback):
  1. Pre-built connectors (Stripe, Paystack) — zero config
  2. Auto-discovery — heuristic column matching
  3. Airweave adapter — optional, for continuous sync
  4. CSV/JSONL import — manual export fallback
"""

from .base import BaseConnector, ConnectorResult
