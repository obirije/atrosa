"""
CSV/JSONL Import Connector — File-based data import with auto-discovery.

The fallback connector: customer exports data to CSV/JSONL files,
ATROSA auto-discovers the schema and transforms it.

Usage:
    connector = CSVConnector(data_dir="./exported_data/")
    result = connector.run()

    # Or with explicit file mapping
    connector = CSVConnector(
        files={
            "api": "api_logs.csv",
            "db": "transactions.csv",
            "webhooks": "webhook_events.csv",
        },
        data_dir="./exported_data/"
    )
"""

import json
import sys
from pathlib import Path
from typing import Optional

import pandas as pd
import numpy as np

# Add project root for schema_normalizer
sys.path.insert(0, str(Path(__file__).parent.parent))

from .base import BaseConnector, ConnectorResult
from schema_normalizer import SchemaNormalizer


class CSVConnector(BaseConnector):
    """Import from CSV or JSONL files with auto-discovery."""

    name = "csv_import"
    description = "Import from local CSV/JSONL files"

    def __init__(self, data_dir: str, files: Optional[dict[str, str]] = None,
                 schema_config: Optional[str] = None):
        """
        Args:
            data_dir: Directory containing data files
            files: Optional explicit file mapping {source: filename}
                   e.g. {"api": "api_logs.csv", "db": "ledger.csv"}
            schema_config: Optional path to schema mapping JSON
        """
        self.data_dir = Path(data_dir)
        self.files = files or {}
        self.schema_config = schema_config

    def pull(self) -> pd.DataFrame:
        """Load all CSV/JSONL files from the data directory."""
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")

        # If files are explicitly mapped, load those
        if self.files:
            frames = {}
            for source, filename in self.files.items():
                path = self.data_dir / filename
                if path.exists():
                    frames[source] = self._load_file(path)
                    frames[source]["_source_hint"] = source
            if frames:
                return pd.concat(frames.values(), ignore_index=True)

        # Otherwise, load all CSV/JSONL files
        all_files = sorted(self.data_dir.glob("*.csv")) + sorted(self.data_dir.glob("*.jsonl"))
        if not all_files:
            raise FileNotFoundError(f"No CSV or JSONL files found in {self.data_dir}")

        frames = []
        for path in all_files:
            df = self._load_file(path)
            df["_source_file"] = path.name
            frames.append(df)
            print(f"    Loaded {path.name}: {len(df):,} rows")

        return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

    def transform(self, raw: pd.DataFrame) -> ConnectorResult:
        """Transform raw CSV data into ATROSA's 4 DataFrames."""
        if raw.empty:
            return ConnectorResult(
                api=pd.DataFrame(), db=pd.DataFrame(),
                mobile=pd.DataFrame(), webhooks=pd.DataFrame(),
            )

        # If files were explicitly mapped to sources, use that mapping
        if "_source_hint" in raw.columns:
            return self._transform_mapped(raw)

        # If ATROSA-format files already exist, load directly
        if self._is_atrosa_format():
            return self._load_atrosa_format()

        # Otherwise, auto-discover and transform
        return self._transform_auto(raw)

    def _transform_mapped(self, raw: pd.DataFrame) -> ConnectorResult:
        """Transform when files are explicitly mapped to sources."""
        normalizer = self._get_normalizer(raw)

        sources = {}
        for source in ["api", "db", "mobile", "webhooks"]:
            mask = raw["_source_hint"] == source
            if mask.any():
                df = raw[mask].drop(columns=["_source_hint", "_source_file"], errors="ignore")
                sources[source] = normalizer.normalize(df, source)
            else:
                sources[source] = pd.DataFrame()

        return ConnectorResult(
            api=sources.get("api", pd.DataFrame()),
            db=sources.get("db", pd.DataFrame()),
            mobile=sources.get("mobile", pd.DataFrame()),
            webhooks=sources.get("webhooks", pd.DataFrame()),
            metadata={"connector": self.name, "data_dir": str(self.data_dir), "mode": "mapped"},
        )

    def _transform_auto(self, raw: pd.DataFrame) -> ConnectorResult:
        """Auto-discover schema and assign data to sources."""
        normalizer = self._get_normalizer(raw)

        # Classify each file into the best-matching source
        source_assignment = self._classify_files(raw)

        sources = {}
        for source in ["api", "db", "mobile", "webhooks"]:
            assigned_files = [f for f, s in source_assignment.items() if s == source]
            if assigned_files:
                mask = raw["_source_file"].isin(assigned_files)
                df = raw[mask].drop(columns=["_source_file"], errors="ignore")
                sources[source] = normalizer.normalize(df, source)
            else:
                sources[source] = pd.DataFrame()

        # If only one file and no classification, put it in all 4 sources
        if len(source_assignment) <= 1 and all(len(df) == 0 for df in sources.values()):
            df = raw.drop(columns=["_source_file"], errors="ignore")
            normalized = normalizer.normalize(df, "api")
            sources = {"api": normalized, "db": normalized.copy(), "mobile": pd.DataFrame(), "webhooks": normalized.copy()}

        return ConnectorResult(
            api=sources.get("api", pd.DataFrame()),
            db=sources.get("db", pd.DataFrame()),
            mobile=sources.get("mobile", pd.DataFrame()),
            webhooks=sources.get("webhooks", pd.DataFrame()),
            metadata={
                "connector": self.name, "data_dir": str(self.data_dir),
                "mode": "auto", "file_assignments": source_assignment,
            },
        )

    def _is_atrosa_format(self) -> bool:
        """Check if data directory already has ATROSA-format files."""
        expected = ["api_gateway.jsonl", "ledger_db_commits.jsonl",
                    "mobile_client_errors.jsonl", "payment_webhooks.jsonl"]
        return all((self.data_dir / f).exists() for f in expected)

    def _load_atrosa_format(self) -> ConnectorResult:
        """Load pre-existing ATROSA-format JSONL files directly."""
        print("    Found ATROSA-format files — loading directly")
        file_map = {
            "api": "api_gateway.jsonl",
            "db": "ledger_db_commits.jsonl",
            "mobile": "mobile_client_errors.jsonl",
            "webhooks": "payment_webhooks.jsonl",
        }
        sources = {}
        for source, filename in file_map.items():
            path = self.data_dir / filename
            sources[source] = self._load_file(path)

        return ConnectorResult(
            api=sources["api"], db=sources["db"],
            mobile=sources["mobile"], webhooks=sources["webhooks"],
            metadata={"connector": self.name, "mode": "atrosa_format"},
        )

    def _get_normalizer(self, raw: pd.DataFrame) -> SchemaNormalizer:
        """Get schema normalizer — from config file or auto-discovery."""
        if self.schema_config and Path(self.schema_config).exists():
            return SchemaNormalizer.from_config(self.schema_config)
        return SchemaNormalizer.auto_discover({"api": raw})

    def _classify_files(self, raw: pd.DataFrame) -> dict[str, str]:
        """Classify each file to the best-matching ATROSA source."""
        if "_source_file" not in raw.columns:
            return {}

        assignments = {}
        for filename in raw["_source_file"].unique():
            name_lower = filename.lower()

            # Filename heuristics
            if any(k in name_lower for k in ["api", "gateway", "request", "access"]):
                assignments[filename] = "api"
            elif any(k in name_lower for k in ["ledger", "transaction", "payment", "transfer", "db", "commit"]):
                assignments[filename] = "db"
            elif any(k in name_lower for k in ["mobile", "app", "client", "device", "event"]):
                assignments[filename] = "mobile"
            elif any(k in name_lower for k in ["webhook", "callback", "notification", "hook"]):
                assignments[filename] = "webhooks"
            else:
                # Default: put in db (most likely to contain transaction data)
                assignments[filename] = "db"

        return assignments

    @staticmethod
    def _load_file(path: Path) -> pd.DataFrame:
        """Load a CSV or JSONL file."""
        if path.suffix == ".jsonl":
            records = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
            return pd.DataFrame(records)
        elif path.suffix == ".csv":
            return pd.read_csv(path)
        else:
            raise ValueError(f"Unsupported file type: {path.suffix}")
