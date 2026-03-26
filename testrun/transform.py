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
        "description": "Sparkov credit card — card fraud, BIN enumeration patterns",
        "file_glob": "*.csv",
        "fraud_column": "is_fraud",
        "fraud_values": [1, "1", True],
        "user_id_column": "cc_num",
        "user_id_prefix": "USR-SK-",
        "user_id_strip": "",
        "timestamp_column": "trans_date_trans_time",
        "timestamp_mode": "datetime",
        "amount_column": "amt",
        "type_column": "category",
        "type_to_endpoint": {},
        "type_to_operation": {},
        "balance_before_column": None,
        "balance_after_column": None,
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
        """Load the raw CSV."""
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

        # Build 4 DataFrames
        df_api = self._build_api(df, fraud_mask)
        df_db = self._build_db(df, fraud_mask)
        df_mobile = self._build_mobile(df, fraud_mask)
        df_webhooks = self._build_webhooks(df, fraud_mask)

        # Ground truth
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
            if self.sample_size and len(df) > self.sample_size:
                df = df.sample(n=self.sample_size, random_state=42)
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
    def _build_api(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        n = len(df)
        type_col = self.config["type_column"]
        endpoint_map = self.config["type_to_endpoint"]

        if type_col and type_col in df.columns and endpoint_map:
            endpoints = df[type_col].map(endpoint_map).fillna("/api/v2/transfer/initiate")
        else:
            endpoints = pd.Series(["/api/v2/transfer/initiate"] * n)

        return pd.DataFrame({
            "source": "api_gateway",
            "timestamp": df["_timestamp"].dt.isoformat(),
            "request_id": [f"REQ-{i:08x}" for i in range(n)],
            "user_id": df["_user_id"],
            "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df["_user_id"]],
            "method": "POST",
            "endpoint": endpoints,
            "status_code": np.where(fraud_mask, self.rng.choice([200, 200, 500], n), 200),
            "response_time_ms": self.rng.integers(15, 800, n),
            "ip_address": [f"{self.rng.integers(1,224)}.{self.rng.integers(0,256)}.{self.rng.integers(0,256)}.{self.rng.integers(1,255)}" for _ in range(n)],
            "user_agent": self.rng.choice(["App/2.1 (Android 14)", "App/2.1 (iOS 17)", "Mozilla/5.0"], n),
            "transaction_id": df["_txn_id"],
            "amount": df["_amount"],
            "currency": "USD",
        })

    def _build_db(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        n = len(df)
        type_col = self.config["type_column"]
        op_map = self.config["type_to_operation"]
        bal_before_col = self.config["balance_before_column"]
        bal_after_col = self.config["balance_after_column"]

        if type_col and type_col in df.columns and op_map:
            operations = df[type_col].map(op_map).fillna("DEBIT")
        else:
            operations = pd.Series(np.where(fraud_mask, "CREDIT", self.rng.choice(["CREDIT", "DEBIT"], n)))

        if bal_before_col and bal_before_col in df.columns:
            balance_before = pd.to_numeric(df[bal_before_col], errors="coerce").fillna(0).round(2)
        else:
            balance_before = self.rng.uniform(1000, 500000, n).round(2)

        if bal_after_col and bal_after_col in df.columns:
            balance_after = pd.to_numeric(df[bal_after_col], errors="coerce").fillna(0).round(2)
        else:
            balance_after = balance_before + np.where(operations == "CREDIT", df["_amount"], -df["_amount"])

        return pd.DataFrame({
            "source": "ledger_db_commits",
            "timestamp": (df["_timestamp"] + pd.Timedelta(seconds=1)).dt.isoformat(),
            "commit_id": [f"CMT-{i:08x}" for i in range(n)],
            "user_id": df["_user_id"],
            "operation": operations,
            "amount": df["_amount"],
            "currency": "USD",
            "balance_before": balance_before,
            "balance_after": balance_after,
            "transaction_id": df["_txn_id"],
            "provider": self.rng.choice(["paystack", "flutterwave", "stripe"], n),
            "idempotency_key": [f"IDEM-{i:08x}" for i in range(n)],
        })

    def _build_mobile(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        # Fraud-associated events
        fraud_idx = df.index[fraud_mask]
        n_fraud = len(fraud_idx)

        # Normal events (sample proportionally, capped)
        normal_idx = df.index[~fraud_mask]
        n_normal = min(len(normal_idx), max(n_fraud * 20, 10000))
        if n_normal > 0:
            normal_idx = self.rng.choice(normal_idx, n_normal, replace=False)

        fraud_events = pd.DataFrame({
            "source": "mobile_client_errors",
            "timestamp": (df.loc[fraud_idx, "_timestamp"] + pd.Timedelta(seconds=2)).dt.isoformat(),
            "event_id": [f"EVT-F-{i:08x}" for i in range(n_fraud)],
            "user_id": df.loc[fraud_idx, "_user_id"].values,
            "session_id": [f"SES-{hash(u) % 10**8:08x}" for u in df.loc[fraud_idx, "_user_id"]],
            "event_type": "network_error",
            "device_os": self.rng.choice(["Android 14", "Android 13"], n_fraud),
            "app_version": "2.1.0",
            "network_type": self.rng.choice(["4G", "3G"], n_fraud),
            "error_code": "E_NETWORK_LOST",
            "screen": "transfer",
            "ip_address": [f"{self.rng.integers(1,224)}.{self.rng.integers(0,256)}.{self.rng.integers(0,256)}.{self.rng.integers(1,255)}" for _ in range(n_fraud)],
        }) if n_fraud > 0 else pd.DataFrame()

        normal_events = pd.DataFrame({
            "source": "mobile_client_errors",
            "timestamp": df.loc[normal_idx, "_timestamp"].dt.isoformat(),
            "event_id": [f"EVT-N-{i:08x}" for i in range(n_normal)],
            "user_id": df.loc[normal_idx, "_user_id"].values,
            "session_id": [f"SES-{hash(u) % 10**8:08x}" for u in df.loc[normal_idx, "_user_id"]],
            "event_type": self.rng.choice(["app_open", "screen_view", "transfer_initiated", "biometric_auth"], n_normal),
            "device_os": self.rng.choice(["Android 14", "iOS 17.4", "Android 13"], n_normal),
            "app_version": "2.1.0",
            "network_type": self.rng.choice(["4G", "WiFi", "3G"], n_normal),
            "error_code": np.where(self.rng.random(n_normal) > 0.9, "E_TIMEOUT", None),
            "screen": self.rng.choice(["home", "transfer", "history", "settings"], n_normal),
            "ip_address": [f"{self.rng.integers(1,224)}.{self.rng.integers(0,256)}.{self.rng.integers(0,256)}.{self.rng.integers(1,255)}" for _ in range(n_normal)],
        }) if n_normal > 0 else pd.DataFrame()

        return pd.concat([fraud_events, normal_events], ignore_index=True)

    def _build_webhooks(self, df: pd.DataFrame, fraud_mask: pd.Series) -> pd.DataFrame:
        n = len(df)
        return pd.DataFrame({
            "source": "payment_webhooks",
            "timestamp": (df["_timestamp"] + pd.Timedelta(seconds=int(self.rng.integers(5, 60)))).dt.isoformat(),
            "webhook_id": [f"WH-{i:08x}" for i in range(n)],
            "provider": self.rng.choice(["paystack", "flutterwave", "stripe"], n),
            "event_type": np.where(fraud_mask, "payment.completed",
                                   self.rng.choice(["payment.completed", "payment.completed", "payment.failed"], n)),
            "transaction_id": df["_txn_id"],
            "user_id": df["_user_id"],
            "amount": df["_amount"],
            "currency": "USD",
            "status": np.where(fraud_mask, "success",
                              self.rng.choice(["success", "success", "success", "failed"], n)),
            "delivery_attempt": np.where(fraud_mask, self.rng.integers(2, 5, n), 1),
            "latency_ms": np.where(fraud_mask, self.rng.integers(60000, 300000, n),
                                   self.rng.integers(50, 5000, n)),
        })


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
