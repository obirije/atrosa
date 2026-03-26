"""
Transform SAML-D → ATROSA 4-DataFrame format.

SAML-D has 9.5M+ AML transactions with 17 suspicious typologies covering
diverse geographies, high-risk countries, and payment types.

Maps to:
  df_api     → API gateway log (transaction requests)
  df_db      → Ledger commits (money movements)
  df_mobile  → Derived mobile events (geo-based)
  df_webhooks → Payment callbacks (cross-border settlements)
"""

import json
import sys
from pathlib import Path

import pandas as pd
import numpy as np

DATASET_DIR = Path(__file__).parent.parent / "datasets" / "saml_d"
OUTPUT_DIR = Path(__file__).parent.parent / "transformed" / "saml_d"


def load_saml_d() -> pd.DataFrame:
    """Load SAML-D CSV."""
    candidates = list(DATASET_DIR.glob("*.csv"))
    if not candidates:
        print(f"[!] No CSV found in {DATASET_DIR}. Run download.sh saml_d first.")
        sys.exit(1)
    path = max(candidates, key=lambda p: p.stat().st_size)
    print(f"[*] Loading {path.name}...")
    df = pd.read_csv(path)
    print(f"    {len(df)} rows, columns: {list(df.columns)}")
    return df


def transform(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Transform SAML-D into ATROSA's 4 DataFrames."""
    np.random.seed(42)

    # Normalize column names (SAML-D variants have different naming)
    col_map = {}
    for c in df.columns:
        cl = c.lower().strip()
        if "time" in cl or "date" in cl:
            col_map[c] = "timestamp"
        elif "sender" in cl and "account" in cl:
            col_map[c] = "sender_account"
        elif "receiver" in cl and "account" in cl:
            col_map[c] = "receiver_account"
        elif "amount" in cl:
            col_map[c] = "amount"
        elif "type" in cl and "payment" in cl:
            col_map[c] = "payment_type"
        elif "sender" in cl and "loc" in cl:
            col_map[c] = "sender_location"
        elif "receiver" in cl and "loc" in cl:
            col_map[c] = "receiver_location"
        elif "currency" in cl or "ccy" in cl:
            col_map[c] = "currency"
        elif "suspicious" in cl or "label" in cl or "is_" in cl:
            col_map[c] = "is_suspicious"
        elif "typology" in cl:
            col_map[c] = "typology"

    df = df.rename(columns=col_map)

    # Parse timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        if df["timestamp"].isna().all():
            df["timestamp"] = pd.date_range("2026-03-01", periods=len(df), freq="s")
    else:
        df["timestamp"] = pd.date_range("2026-03-01", periods=len(df), freq="s")

    df["transaction_id"] = [f"TXN-AML-{i:08d}" for i in range(len(df))]
    if "sender_account" in df.columns:
        df["user_id"] = df["sender_account"].astype(str).apply(lambda x: f"USR-AML-{x[:8]}")
    else:
        df["user_id"] = [f"USR-AML-{i % 5000:04d}" for i in range(len(df))]

    # Determine fraud flag
    if "is_suspicious" in df.columns:
        fraud_mask = df["is_suspicious"].astype(str).str.lower().isin(["1", "true", "yes", "suspicious"])
    else:
        fraud_mask = pd.Series([False] * len(df))

    # Payment type to endpoint
    payment_type_map = {
        "credit card": "/api/v2/payment/card",
        "debit": "/api/v2/transfer/debit",
        "cash": "/api/v2/wallet/deposit",
        "ach": "/api/v2/transfer/ach",
        "cross-border": "/api/v2/transfer/international",
        "cheque": "/api/v2/payment/cheque",
    }
    default_endpoint = "/api/v2/transfer/initiate"

    if "payment_type" in df.columns:
        df["endpoint"] = df["payment_type"].astype(str).str.lower().map(payment_type_map).fillna(default_endpoint)
    else:
        df["endpoint"] = default_endpoint

    # --- df_api ---
    df_api = pd.DataFrame({
        "source": "api_gateway",
        "timestamp": df["timestamp"].dt.isoformat(),
        "request_id": [f"REQ-AML-{i:08x}" for i in range(len(df))],
        "user_id": df["user_id"],
        "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df["user_id"]],
        "method": "POST",
        "endpoint": df["endpoint"],
        "status_code": 200,
        "response_time_ms": np.random.randint(20, 500, len(df)),
        "ip_address": [f"{np.random.randint(1,224)}.{np.random.randint(0,256)}.{np.random.randint(0,256)}.{np.random.randint(1,255)}" for _ in range(len(df))],
        "user_agent": "AMLTestApp/1.0",
        "transaction_id": df["transaction_id"],
        "amount": df["amount"].round(2) if "amount" in df.columns else 0,
        "currency": df.get("currency", "USD"),
    })

    # --- df_db ---
    df_db = pd.DataFrame({
        "source": "ledger_db_commits",
        "timestamp": (df["timestamp"] + pd.Timedelta(seconds=1)).dt.isoformat(),
        "commit_id": [f"CMT-AML-{i:08x}" for i in range(len(df))],
        "user_id": df["user_id"],
        "operation": np.where(fraud_mask, "CREDIT", np.random.choice(["CREDIT", "DEBIT"], len(df))),
        "amount": df["amount"].round(2) if "amount" in df.columns else 0,
        "currency": df.get("currency", "USD"),
        "balance_before": np.random.uniform(1000, 500000, len(df)).round(2),
        "balance_after": np.random.uniform(1000, 500000, len(df)).round(2),
        "transaction_id": df["transaction_id"],
        "provider": np.random.choice(["swift", "ach_network", "card_network"], len(df)),
        "idempotency_key": [f"IDEM-AML-{i:08x}" for i in range(len(df))],
    })

    # --- df_webhooks ---
    df_webhooks = pd.DataFrame({
        "source": "payment_webhooks",
        "timestamp": (df["timestamp"] + pd.Timedelta(seconds=np.random.randint(5, 60))).dt.isoformat(),
        "webhook_id": [f"WH-AML-{i:08x}" for i in range(len(df))],
        "provider": np.random.choice(["swift", "ach_network", "card_network"], len(df)),
        "event_type": "payment.completed",
        "transaction_id": df["transaction_id"],
        "user_id": df["user_id"],
        "amount": df["amount"].round(2) if "amount" in df.columns else 0,
        "currency": df.get("currency", "USD"),
        "status": "success",
        "delivery_attempt": 1,
        "latency_ms": np.random.randint(50, 3000, len(df)),
    })

    # --- df_mobile (minimal — derived from geo) ---
    mobile_sample = min(len(df), 50000)
    sample_idx = np.random.choice(len(df), mobile_sample, replace=False)
    df_mobile = pd.DataFrame({
        "source": "mobile_client_errors",
        "timestamp": df.iloc[sample_idx]["timestamp"].dt.isoformat().values,
        "event_id": [f"EVT-AML-{i:08x}" for i in range(mobile_sample)],
        "user_id": df.iloc[sample_idx]["user_id"].values,
        "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df.iloc[sample_idx]["user_id"]],
        "event_type": np.random.choice(["app_open", "transfer_initiated", "screen_view"], mobile_sample),
        "device_os": np.random.choice(["Android 14", "iOS 17.4"], mobile_sample),
        "app_version": "1.0.0",
        "network_type": np.random.choice(["4G", "WiFi"], mobile_sample),
        "error_code": None,
        "screen": np.random.choice(["home", "transfer", "history"], mobile_sample),
        "ip_address": [f"{np.random.randint(1,224)}.{np.random.randint(0,256)}.{np.random.randint(0,256)}.{np.random.randint(1,255)}" for _ in range(mobile_sample)],
    })

    fraud_tx_ids = df.loc[fraud_mask, "transaction_id"].tolist()
    fraud_user_ids = df.loc[fraud_mask, "user_id"].unique().tolist()

    return {
        "api": df_api,
        "db": df_db,
        "mobile": df_mobile,
        "webhooks": df_webhooks,
        "ground_truth": {
            "dataset": "saml_d",
            "anomaly_count": len(fraud_tx_ids),
            "attacker_transaction_ids": fraud_tx_ids[:1000],
            "attacker_user_ids": fraud_user_ids[:500],
            "total_fraud_transactions": len(fraud_tx_ids),
            "total_fraud_users": len(fraud_user_ids),
            "description": "SAML-D AML transactions with 17 suspicious typologies",
        },
    }


def save(result: dict, sample_size: int = None):
    """Save transformed DataFrames as JSONL."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    file_map = {
        "api": "api_gateway.jsonl",
        "db": "ledger_db_commits.jsonl",
        "mobile": "mobile_client_errors.jsonl",
        "webhooks": "payment_webhooks.jsonl",
    }

    for name, filename in file_map.items():
        df = result[name]
        if sample_size and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42)
        path = OUTPUT_DIR / filename
        with open(path, "w") as f:
            for _, row in df.iterrows():
                f.write(json.dumps({k: v for k, v in row.items() if pd.notna(v)}) + "\n")
        print(f"    {filename}: {len(df)} rows")

    gt_path = OUTPUT_DIR / ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(result["ground_truth"], f, indent=2)
    print(f"    .ground_truth.json: {result['ground_truth']['total_fraud_transactions']} suspicious txns")


if __name__ == "__main__":
    sample = None
    if "--sample" in sys.argv:
        idx = sys.argv.index("--sample")
        sample = int(sys.argv[idx + 1])
        print(f"[*] Sampling {sample} rows per source")

    raw = load_saml_d()
    result = transform(raw)
    print(f"\n[*] Saving to {OUTPUT_DIR}...")
    save(result, sample_size=sample)
    print(f"\n[+] SAML-D transform complete")
