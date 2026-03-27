"""
Base Connector — Interface for all ATROSA data source connectors.

Every connector implements:
  pull()      → fetch raw data from the source
  transform() → convert raw data into ATROSA's 4 DataFrames
  validate()  → check the transformed data is usable

Usage:
    connector = StripeConnector(api_key="sk_live_...")
    result = connector.run()
    result.save("data/")  # Writes 4 JSONL files + ground truth
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd


@dataclass
class ConnectorResult:
    """Output of a connector run — the 4 DataFrames ready for ATROSA."""
    api: pd.DataFrame
    db: pd.DataFrame
    mobile: pd.DataFrame
    webhooks: pd.DataFrame
    metadata: dict = field(default_factory=dict)

    @property
    def total_events(self) -> int:
        return len(self.api) + len(self.db) + len(self.mobile) + len(self.webhooks)

    def save(self, output_dir: str):
        """Write all 4 DataFrames as JSONL files."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        file_map = {
            "api": "api_gateway.jsonl",
            "db": "ledger_db_commits.jsonl",
            "mobile": "mobile_client_errors.jsonl",
            "webhooks": "payment_webhooks.jsonl",
        }

        for attr, filename in file_map.items():
            df = getattr(self, attr)
            path = out / filename
            with open(path, "w") as f:
                for _, row in df.iterrows():
                    record = {k: v for k, v in row.items() if pd.notna(v)}
                    f.write(json.dumps(record, default=str) + "\n")
            print(f"  {filename}: {len(df):,} rows")

        # Save metadata
        meta_path = out / "connector_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(self.metadata, f, indent=2)

    def validate(self) -> list[str]:
        """Check the result is usable. Returns list of issues (empty = valid)."""
        issues = []

        # Must have data in at least 2 sources
        non_empty = sum(1 for df in [self.api, self.db, self.mobile, self.webhooks] if len(df) > 0)
        if non_empty < 2:
            issues.append(f"Only {non_empty}/4 DataFrames have data — need at least 2 for cross-correlation")

        # Check required columns
        required = {
            "api": ["timestamp", "user_id", "transaction_id"],
            "db": ["timestamp", "user_id", "transaction_id"],
            "mobile": ["timestamp", "user_id"],
            "webhooks": ["timestamp", "transaction_id"],
        }
        for source, cols in required.items():
            df = getattr(self, source)
            if len(df) > 0:
                for col in cols:
                    if col not in df.columns:
                        issues.append(f"{source} missing required column: {col}")

        # Check transaction_id overlap between sources
        sources_with_txn = {}
        for source in ["api", "db", "webhooks"]:
            df = getattr(self, source)
            if len(df) > 0 and "transaction_id" in df.columns:
                sources_with_txn[source] = set(df["transaction_id"].dropna().unique())

        if len(sources_with_txn) >= 2:
            pairs = list(sources_with_txn.keys())
            for i in range(len(pairs)):
                for j in range(i + 1, len(pairs)):
                    overlap = sources_with_txn[pairs[i]] & sources_with_txn[pairs[j]]
                    if len(overlap) == 0:
                        issues.append(
                            f"No transaction_id overlap between {pairs[i]} and {pairs[j]} — "
                            f"cross-correlation will fail"
                        )

        return issues


class BaseConnector(ABC):
    """Interface for all ATROSA data source connectors."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def pull(self) -> pd.DataFrame:
        """Fetch raw data from the source. Returns a single DataFrame with all available data."""
        ...

    @abstractmethod
    def transform(self, raw: pd.DataFrame) -> ConnectorResult:
        """Transform raw data into ATROSA's 4 DataFrames."""
        ...

    def run(self) -> ConnectorResult:
        """Full pipeline: pull → transform → validate."""
        print(f"[*] {self.name}: Pulling data...")
        raw = self.pull()
        print(f"    {len(raw):,} rows, {len(raw.columns)} columns")

        print(f"[*] {self.name}: Transforming...")
        result = self.transform(raw)
        print(f"    api={len(result.api):,}, db={len(result.db):,}, "
              f"mobile={len(result.mobile):,}, webhooks={len(result.webhooks):,}")

        issues = result.validate()
        if issues:
            print(f"[!] {self.name}: {len(issues)} validation issue(s):")
            for issue in issues:
                print(f"    - {issue}")
        else:
            print(f"[+] {self.name}: Validation passed")

        return result
