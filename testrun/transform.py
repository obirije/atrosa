"""
ATROSA Test Run — Universal Dataset Transformer
==================================================
Transforms any supported raw dataset into ATROSA's 4-DataFrame JSONL format
using the schema normalizer. Each dataset has a config defining:
  - Which columns map to which ATROSA sources
  - How to derive the 4 DataFrames from the raw data
  - Where the fraud label lives

Usage:
    python transform.py paysim                  # Transform PaySim
    python transform.py saml_d --sample 50000   # Transform SAML-D, 50K rows per source
    python transform.py --list                  # List available datasets
"""

import json
import sys
from pathlib import Path

import pandas as pd
import numpy as np

# Add project root to path for schema_normalizer
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from schema_normalizer import SchemaNormalizer, OPERATION_ALIASES, STATUS_ALIASES

DATASETS_DIR = Path(__file__).parent / "datasets"
OUTPUT_BASE = Path(__file__).parent / "transformed"


# ===========================
# DATASET CONFIGS
# ===========================
# Each config tells the transformer how to interpret the raw CSV:
#   file_glob:    pattern to find the CSV in datasets/<name>/
#   fraud_column: column name containing the fraud label
#   fraud_values: values that mean "fraud" in that column
#   sources:      which ATROSA DataFrames to generate, with column mappings
#   derive:       columns that need to be computed from raw data

DATASET_CONFIGS = {
    "paysim": {
        "description": "PaySim mobile money — ATO, money mule, balance manipulation",
        "file_glob": "*.csv",
        "fraud_column": "isFraud",
        "fraud_values": [1, "1", True],
        "user_id_column": "nameOrig",
        "user_id_prefix": "USR-PS-",
        "user_id_strip": "C",
        "timestamp_column": "step",
        "timestamp_mode": "step_hours",  # 1 step = 1 hour from base_time
        "amount_column": "amount",
        "type_column": "type",
        "type_to_endpoint": {
            "CASH_IN": "/api/v2/wallet/deposit",
            "CASH_OUT": "/api/v2/wallet/withdraw",
            "DEBIT": "/api/v2/transfer/debit",
            "PAYMENT": "/api/v2/payment/merchant",
            "TRANSFER": "/api/v2/transfer/initiate",
        },
        "type_to_operation": {
            "CASH_IN": "CREDIT",
            "CASH_OUT": "DEBIT",
            "DEBIT": "DEBIT",
            "PAYMENT": "DEBIT",
            "TRANSFER": "DEBIT",
        },
        "balance_before_column": "oldbalanceOrg",
        "balance_after_column": "newbalanceOrig",
    },
    "saml_d": {
        "description": "SAML-D AML monitoring — money laundering, mule patterns",
        "file_glob": "*.csv",
        "fraud_column": "Is Laundering",
        "fraud_values": [1, "1", True],
        "user_id_column": "From Bank",
        "user_id_prefix": "USR-AML-",
        "user_id_strip": "",
        "timestamp_column": "Timestamp",
        "timestamp_mode": "datetime",
        "amount_column": "Amount Paid",
        "type_column": None,
        "type_to_endpoint": {},
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
    },
    "sparkov": {
        "description": "Sparkov credit card — card fraud, BIN enumeration patterns, geo anomalies",
        "file_glob": "fraud*.csv",
        "fraud_column": "is_fraud",
        "fraud_values": [1, "1", True],
        "user_id_column": "cc_num",
        "user_id_prefix": "USR-SK-",
        "user_id_strip": "",
        "timestamp_column": "trans_date_trans_time",
        "timestamp_mode": "datetime",
        "amount_column": "amt",
        "type_column": "category",
        "type_to_endpoint": {
            "grocery_pos": "/api/v2/payment/grocery",
            "gas_transport": "/api/v2/payment/gas",
            "home": "/api/v2/payment/home",
            "shopping_pos": "/api/v2/payment/shopping",
            "kids_pets": "/api/v2/payment/kids",
            "personal_care": "/api/v2/payment/personal",
            "health_fitness": "/api/v2/payment/health",
            "food_dining": "/api/v2/payment/dining",
            "misc_net": "/api/v2/payment/misc_online",
            "misc_pos": "/api/v2/payment/misc_pos",
            "shopping_net": "/api/v2/payment/shopping_online",
            "entertainment": "/api/v2/payment/entertainment",
            "travel": "/api/v2/payment/travel",
        },
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
        # Extra raw columns to pass through to specific DataFrames
        "extra_api_columns": {
            "ip_address": "lat,long",       # Customer lat/long as geo proxy
        },
        "extra_db_columns": {
            "provider": "merchant",          # Merchant name as provider
        },
        "extra_mobile_columns": {
            "device_os": "gender",           # Demographics as device context
            "screen": "category",            # Merchant category as screen/context
            "ip_address": "city,state",      # Customer location
        },
        "extra_webhook_columns": {
            "provider": "merchant",          # Merchant name
            "ip_address": "merch_lat,merch_long",  # Merchant geo
        },
    },
    "ccfraud": {
        "description": "ULB credit card fraud — PCA-anonymized benchmark",
        "file_glob": "*.csv",
        "fraud_column": "Class",
        "fraud_values": [1, "1"],
        "user_id_column": None,
        "user_id_prefix": "USR-CC-",
        "user_id_strip": "",
        "timestamp_column": "Time",
        "timestamp_mode": "seconds_offset",
        "amount_column": "Amount",
        "type_column": None,
        "type_to_endpoint": {},
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
    },
    "banksim": {
        "description": "BankSim bank payments — card fraud, mule patterns",
        "file_glob": "*.csv",
        "fraud_column": "fraud",
        "fraud_values": [1, "1", True],
        "user_id_column": "customer",
        "user_id_prefix": "USR-BS-",
        "user_id_strip": "",
        "timestamp_column": "step",
        "timestamp_mode": "step_hours",
        "amount_column": "amount",
        "type_column": "category",
        "type_to_endpoint": {},
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
    },
    "ieee_cis": {
        "description": "IEEE-CIS e-commerce fraud — card fraud, device fingerprint, identity features",
        "file_glob": "train_transaction.csv",
        "identity_file": "train_identity.csv",  # Joined on TransactionID
        "fraud_column": "isFraud",
        "fraud_values": [1, "1"],
        "user_id_column": "card1",
        "user_id_prefix": "USR-IEEE-",
        "user_id_strip": "",
        "timestamp_column": "TransactionDT",
        "timestamp_mode": "seconds_offset",
        "amount_column": "TransactionAmt",
        "type_column": "ProductCD",
        "type_to_endpoint": {
            "W": "/api/v2/payment/web",
            "H": "/api/v2/payment/hosted",
            "C": "/api/v2/payment/card",
            "S": "/api/v2/payment/subscription",
            "R": "/api/v2/payment/recurring",
        },
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
        # Real multi-source data from the dataset
        "extra_api_columns": {
            "ip_address": "addr1,addr2",        # Address codes as location proxy
        },
        "extra_db_columns": {
            "provider": "card4",                 # Card network (visa, mastercard, etc.)
        },
        "extra_mobile_columns": {
            "device_os": "DeviceType",           # mobile/desktop from identity file
            "screen": "DeviceInfo",              # Device model/OS from identity file
            "ip_address": "id_30",               # OS version from identity file
        },
        "extra_webhook_columns": {
            "provider": "P_emaildomain",         # Purchaser email domain
        },
        # Columns to pass through as-is for richer signal
        "passthrough_api": ["dist1", "P_emaildomain", "R_emaildomain", "card6"],
        "passthrough_db": ["card2", "card3", "card5", "D1", "D2", "D3"],
        "passthrough_mobile": ["id_31", "id_33"],
        "passthrough_webhooks": ["C1", "C2", "C3", "C4", "C5", "C6"],
    },
    "elliptic": {
        "description": "Elliptic Bitcoin — crypto laundering, mixer detection",
        "file_glob": "elliptic_txs_features.csv",
        "fraud_column": None,  # Uses separate classes file
        "fraud_values": ["1"],  # class 1 = illicit in elliptic_txs_classes.csv
        "classes_file": "elliptic_txs_classes.csv",
        "user_id_column": None,
        "user_id_prefix": "USR-EL-",
        "user_id_strip": "",
        "timestamp_column": None,
        "timestamp_mode": "step_hours",
        "amount_column": None,
        "type_column": None,
        "type_to_endpoint": {},
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
    },
}


# ===========================
# UNIVERSAL TRANSFORMER
# ===========================
class DatasetTransformer:
    """Transforms any configured dataset into ATROSA's 4 DataFrames."""

    def __init__(self, dataset_name: str, sample_size: int = None):
        if dataset_name not in DATASET_CONFIGS:
            raise ValueError(f"Unknown dataset: {dataset_name}. Available: {list(DATASET_CONFIGS.keys())}")
        self.name = dataset_name
        self.config = DATASET_CONFIGS[dataset_name]
        self.sample_size = sample_size
        self.rng = np.random.default_rng(42)
        self.base_time = pd.Timestamp("2026-03-01")

    def load(self) -> pd.DataFrame:
        """Load the raw CSV. Handles multi-file datasets (e.g., IEEE-CIS transaction + identity)."""
        data_dir = DATASETS_DIR / self.name
        candidates = sorted(data_dir.glob(self.config["file_glob"]), key=lambda p: p.stat().st_size, reverse=True)
        if not candidates:
            print(f"[!] No files matching '{self.config['file_glob']}' in {data_dir}")
            print(f"    Run: ./download.sh {self.name}")
            sys.exit(1)

        path = candidates[0]
        print(f"[*] Loading {path.name} ({path.stat().st_size / 1024 / 1024:.1f} MB)...")
        df = pd.read_csv(path)
        print(f"    {len(df):,} rows, {len(df.columns)} columns")

        # Join with identity file if specified (IEEE-CIS has transaction + identity)
        identity_file = self.config.get("identity_file")
        if identity_file:
            id_path = data_dir / identity_file
            if id_path.exists():
                print(f"[*] Loading identity file {identity_file}...")
                df_id = pd.read_csv(id_path)
                print(f"    {len(df_id):,} rows, {len(df_id.columns)} columns")
                # Join on TransactionID
                join_col = "TransactionID"
                if join_col in df.columns and join_col in df_id.columns:
                    df = df.merge(df_id, on=join_col, how="left")
                    print(f"    Joined: {len(df):,} rows, {len(df.columns)} columns")

        return df

    def transform(self, df: pd.DataFrame) -> dict:
        """Transform raw data into ATROSA's 4 DataFrames + ground truth."""
        # Resolve core columns
        df = self._resolve_timestamps(df)
        df = self._resolve_user_ids(df)
        df = self._resolve_transaction_ids(df)
        fraud_mask = self._resolve_fraud_labels(df)

        amount_col = self.config["amount_column"]
        if amount_col and amount_col in df.columns:
            df["_amount"] = pd.to_numeric(df[amount_col], errors="coerce").fillna(0).round(2)
        else:
            df["_amount"] = self.rng.uniform(100, 50000, len(df)).round(2)

        # Sample at the transaction level BEFORE building DataFrames.
        # This preserves cross-source correlation: the same transaction_id
        # appears in all 4 sources. Ground truth only references sampled txns.
        if self.sample_size and len(df) > self.sample_size:
            n_fraud = fraud_mask.sum()
            n_sample = self.sample_size

            # Always include ALL fraud transactions, fill remainder with normal
            fraud_idx = df.index[fraud_mask]
            normal_idx = df.index[~fraud_mask]
            n_normal_needed = max(0, n_sample - len(fraud_idx))
            if n_normal_needed > 0 and len(normal_idx) > 0:
                normal_sample = self.rng.choice(normal_idx, min(n_normal_needed, len(normal_idx)), replace=False)
                keep_idx = np.concatenate([fraud_idx.values, normal_sample])
            else:
                keep_idx = fraud_idx.values

            df = df.loc[keep_idx].reset_index(drop=True)
            fraud_mask = self._resolve_fraud_labels(df)
            print(f"    Sampled to {len(df):,} rows (all {n_fraud:,} fraud + {len(df) - fraud_mask.sum():,} normal)")

        # Build 4 DataFrames from the SAME rows — cross-source correlation intact
        df_api = self._build_api(df, fraud_mask)
        df_db = self._build_db(df, fraud_mask)
        df_mobile = self._build_mobile(df, fraud_mask)
        df_webhooks = self._build_webhooks(df, fraud_mask)

        # Ground truth reflects only what's in the sample
        fraud_tx_ids = df.loc[fraud_mask, "_txn_id"].tolist()
        fraud_user_ids = df.loc[fraud_mask, "_user_id"].unique().tolist()

        return {
            "api": df_api,
            "db": df_db,
            "mobile": df_mobile,
            "webhooks": df_webhooks,
            "ground_truth": {
                "dataset": self.name,
                "anomaly_count": min(len(fraud_tx_ids), 1000),
                "attacker_transaction_ids": fraud_tx_ids[:1000],
                "attacker_user_ids": fraud_user_ids[:500],
                "total_fraud_transactions": len(fraud_tx_ids),
                "total_fraud_users": len(fraud_user_ids),
                "description": self.config["description"],
            },
        }

    def save(self, result: dict):
        """Write transformed DataFrames as JSONL + ground truth."""
        out_dir = OUTPUT_BASE / self.name
        out_dir.mkdir(parents=True, exist_ok=True)

        file_map = {
            "api": "api_gateway.jsonl",
            "db": "ledger_db_commits.jsonl",
            "mobile": "mobile_client_errors.jsonl",
            "webhooks": "payment_webhooks.jsonl",
        }

        for key, filename in file_map.items():
            df = result[key]
            # Sampling already happened in transform() at the transaction level
            # to preserve cross-source correlation. No re-sampling here.
            path = out_dir / filename
            with open(path, "w") as f:
                for _, row in df.iterrows():
                    record = {k: v for k, v in row.items() if pd.notna(v)}
                    f.write(json.dumps(record, default=str) + "\n")
            print(f"    {filename}: {len(df):,} rows")

        gt_path = out_dir / ".ground_truth.json"
        with open(gt_path, "w") as f:
            json.dump(result["ground_truth"], f, indent=2)
        gt = result["ground_truth"]
        print(f"    .ground_truth.json: {gt['total_fraud_transactions']:,} fraud / {gt['total_fraud_users']:,} users")

    # ===========================
    # COLUMN RESOLVERS
    # ===========================
    def _resolve_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        ts_col = self.config["timestamp_column"]
        mode = self.config["timestamp_mode"]

        if ts_col and ts_col in df.columns:
            if mode == "step_hours":
                df["_timestamp"] = df[ts_col].apply(lambda s: self.base_time + pd.Timedelta(hours=int(s)))
            elif mode == "seconds_offset":
                df["_timestamp"] = df[ts_col].apply(lambda s: self.base_time + pd.Timedelta(seconds=float(s)))
            elif mode == "datetime":
                df["_timestamp"] = pd.to_datetime(df[ts_col], errors="coerce")
                if df["_timestamp"].isna().sum() > len(df) * 0.5:
                    df["_timestamp"] = pd.date_range(self.base_time, periods=len(df), freq="s")
            else:
                df["_timestamp"] = pd.date_range(self.base_time, periods=len(df), freq="s")
        else:
            df["_timestamp"] = pd.date_range(self.base_time, periods=len(df), freq="s")

        return df

    def _resolve_user_ids(self, df: pd.DataFrame) -> pd.DataFrame:
        uid_col = self.config["user_id_column"]
        prefix = self.config["user_id_prefix"]
        strip = self.config["user_id_strip"]

        if uid_col and uid_col in df.columns:
            raw = df[uid_col].astype(str)
            if strip:
                raw = raw.str.replace(strip, "", regex=False)
            df["_user_id"] = prefix + raw.str[:8]
        else:
            df["_user_id"] = [f"{prefix}{i % 5000:04d}" for i in range(len(df))]

        return df

    def _resolve_transaction_ids(self, df: pd.DataFrame) -> pd.DataFrame:
        df["_txn_id"] = [f"TXN-{self.name.upper()[:3]}-{i:08d}" for i in range(len(df))]
        return df

    def _resolve_fraud_labels(self, df: pd.DataFrame) -> pd.Series:
        fraud_col = self.config["fraud_column"]
        fraud_vals = self.config["fraud_values"]

        if fraud_col and fraud_col in df.columns:
            return df[fraud_col].isin(fraud_vals)

        # Elliptic: separate classes file
        if "classes_file" in self.config:
            classes_path = DATASETS_DIR / self.name / self.config["classes_file"]
            if classes_path.exists():
                classes = pd.read_csv(classes_path)
                class_col = classes.columns[1] if len(classes.columns) > 1 else classes.columns[0]
                id_col = classes.columns[0]
                illicit_ids = set(classes.loc[classes[class_col].astype(str).isin(fraud_vals), id_col].astype(str))
                # Match by index position since we don't have a shared key
                first_col = df.columns[0]
                return df[first_col].astype(str).isin(illicit_ids)

        return pd.Series([False] * len(df), index=df.index)

    # ===========================
    # DATAFRAME BUILDERS
    # ===========================
    # Principle: only use data that exists in the raw dataset.
    # Where the dataset doesn't have a column, use a constant — never randomize.
    # The fraud signal must come from the real data, not from synthetic injection.

    def _build_api(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        """API gateway log — derived directly from raw transaction data."""
        n = len(df)
        type_col = self.config["type_column"]
        endpoint_map = self.config["type_to_endpoint"]

        if type_col and type_col in df.columns and endpoint_map:
            endpoints = df[type_col].map(endpoint_map).fillna("/api/v2/transfer/initiate")
        else:
            endpoints = pd.Series(["/api/v2/transfer/initiate"] * n)

        # Resolve extra columns from raw data
        extras = self.config.get("extra_api_columns", {})
        ip_address = self._resolve_extra(df, extras.get("ip_address"), "0.0.0.0")

        result = pd.DataFrame({
            "source": "api_gateway",
            "timestamp": df["_timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "request_id": [f"REQ-{i:08x}" for i in range(n)],
            "user_id": df["_user_id"],
            "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df["_user_id"]],
            "method": "POST",
            "endpoint": endpoints,
            "status_code": 200,
            "response_time_ms": 100,
            "ip_address": ip_address,
            "user_agent": "App/1.0",
            "transaction_id": df["_txn_id"],
            "amount": df["_amount"],
            "currency": "USD",
        })
        return self._add_passthrough(result, df, "passthrough_api")

    def _build_db(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        """Ledger DB — uses real balance data when available."""
        n = len(df)
        type_col = self.config["type_column"]
        op_map = self.config["type_to_operation"]
        bal_before_col = self.config["balance_before_column"]
        bal_after_col = self.config["balance_after_column"]

        if type_col and type_col in df.columns and op_map:
            operations = df[type_col].map(op_map).fillna("DEBIT")
        else:
            operations = pd.Series(["DEBIT"] * n)

        if bal_before_col and bal_before_col in df.columns:
            balance_before = pd.to_numeric(df[bal_before_col], errors="coerce").fillna(0).round(2)
        else:
            balance_before = pd.Series([0.0] * n)

        if bal_after_col and bal_after_col in df.columns:
            balance_after = pd.to_numeric(df[bal_after_col], errors="coerce").fillna(0).round(2)
        else:
            balance_after = pd.Series([0.0] * n)

        # Resolve extra columns
        extras = self.config.get("extra_db_columns", {})
        provider = self._resolve_extra(df, extras.get("provider"), "unknown")

        result = pd.DataFrame({
            "source": "ledger_db_commits",
            "timestamp": (df["_timestamp"] + pd.Timedelta(seconds=1)).dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "commit_id": [f"CMT-{i:08x}" for i in range(n)],
            "user_id": df["_user_id"],
            "operation": operations,
            "amount": df["_amount"],
            "currency": "USD",
            "balance_before": balance_before,
            "balance_after": balance_after,
            "transaction_id": df["_txn_id"],
            "provider": provider,
            "idempotency_key": [f"IDEM-{i:08x}" for i in range(n)],
        })
        return self._add_passthrough(result, df, "passthrough_db")

    def _build_mobile(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        """Mobile events — one event per transaction. Uses real data where available."""
        n = len(df)
        type_col = self.config["type_column"]

        type_to_event = {
            "CASH_IN": "deposit_initiated",
            "CASH_OUT": "withdrawal_initiated",
            "DEBIT": "debit_initiated",
            "PAYMENT": "payment_initiated",
            "TRANSFER": "transfer_initiated",
        }

        if type_col and type_col in df.columns:
            event_types = df[type_col].map(type_to_event).fillna("transaction_initiated")
        else:
            event_types = pd.Series(["transaction_initiated"] * n)

        # Resolve extra columns from raw data
        extras = self.config.get("extra_mobile_columns", {})
        device_os = self._resolve_extra(df, extras.get("device_os"), "unknown")
        screen = self._resolve_extra(df, extras.get("screen"), "transaction")
        ip_address = self._resolve_extra(df, extras.get("ip_address"), "0.0.0.0")

        result = pd.DataFrame({
            "source": "mobile_client_errors",
            "timestamp": df["_timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_id": [f"EVT-{i:08x}" for i in range(n)],
            "user_id": df["_user_id"],
            "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df["_user_id"]],
            "event_type": event_types,
            "device_os": device_os,
            "app_version": "1.0.0",
            "network_type": "unknown",
            "error_code": None,
            "screen": screen,
            "ip_address": ip_address,
        })
        return self._add_passthrough(result, df, "passthrough_mobile")

    def _build_webhooks(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        """Webhook events — one per transaction. Uses real data where available."""
        n = len(df)

        # Resolve extra columns from raw data
        extras = self.config.get("extra_webhook_columns", {})
        provider = self._resolve_extra(df, extras.get("provider"), "unknown")
        ip_address = self._resolve_extra(df, extras.get("ip_address"), "0.0.0.0")

        result = pd.DataFrame({
            "source": "payment_webhooks",
            "timestamp": (df["_timestamp"] + pd.Timedelta(seconds=5)).dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "webhook_id": [f"WH-{i:08x}" for i in range(n)],
            "provider": provider,
            "event_type": "payment.completed",
            "transaction_id": df["_txn_id"],
            "user_id": df["_user_id"],
            "amount": df["_amount"],
            "currency": "USD",
            "status": "success",
            "delivery_attempt": 1,
            "latency_ms": 100,
        })
        return self._add_passthrough(result, df, "passthrough_webhooks")

    def _add_passthrough(self, result: pd.DataFrame, df: pd.DataFrame, config_key: str) -> pd.DataFrame:
        """Add passthrough columns from raw data to a built DataFrame."""
        cols = self.config.get(config_key, [])
        for col in cols:
            if col in df.columns:
                result[col] = df[col].values
        return result

    def _resolve_extra(self, df: pd.DataFrame, spec: str, default: str) -> pd.Series:
        """Resolve an extra column spec. Spec can be a single column name
        or 'col1,col2' to concatenate multiple columns."""
        if not spec:
            return pd.Series([default] * len(df), index=df.index)

        cols = [c.strip() for c in spec.split(",")]
        available = [c for c in cols if c in df.columns]

        if not available:
            return pd.Series([default] * len(df), index=df.index)

        if len(available) == 1:
            return df[available[0]].astype(str).fillna(default)

        # Concatenate multiple columns
        return df[available].fillna("").astype(str).apply(lambda row: ",".join(row), axis=1)


# ===========================
# CLI
# ===========================
def main():
    if "--list" in sys.argv or "-l" in sys.argv:
        print("Available datasets:")
        for name, cfg in DATASET_CONFIGS.items():
            print(f"  {name:15s} {cfg['description']}")
        return

    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        print("Usage: python transform.py <dataset> [--sample N]")
        print("       python transform.py --list")
        sys.exit(1)

    dataset_name = sys.argv[1]
    sample = None
    if "--sample" in sys.argv:
        idx = sys.argv.index("--sample")
        sample = int(sys.argv[idx + 1])

    transformer = DatasetTransformer(dataset_name, sample_size=sample)
    raw = transformer.load()
    print(f"[*] Transforming {dataset_name}...")
    result = transformer.transform(raw)

    print(f"[*] Saving to {OUTPUT_BASE / dataset_name}/...")
    transformer.save(result)
    print(f"[+] Done. {result['ground_truth']['total_fraud_transactions']:,} fraud transactions identified.")


if __name__ == "__main__":
    main()
