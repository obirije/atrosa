"""
Transform PaySim → ATROSA 4-DataFrame format.

PaySim simulates mobile money: CASH-IN, CASH-OUT, DEBIT, PAYMENT, TRANSFER.
Fraud pattern: attacker drains account via TRANSFER then CASH_OUT.

Maps to:
  df_api     → API-style request log (one row per transaction)
  df_db      → Ledger commits (balance mutations)
  df_mobile  → Simulated mobile events (derived from transaction patterns)
  df_webhooks → Payment callback events (derived from transaction completions)
"""

import json
import sys
from pathlib import Path

import pandas as pd
import numpy as np

DATASET_DIR = Path(__file__).parent.parent / "datasets" / "paysim"
OUTPUT_DIR = Path(__file__).parent.parent / "transformed" / "paysim"


def load_paysim() -> pd.DataFrame:
    """Load the raw PaySim CSV."""
    candidates = list(DATASET_DIR.glob("*.csv"))
    if not candidates:
        print(f"[!] No CSV found in {DATASET_DIR}. Run download.sh paysim first.")
        sys.exit(1)
    path = candidates[0]
    print(f"[*] Loading {path.name}...")
    df = pd.read_csv(path)
    print(f"    {len(df)} rows, columns: {list(df.columns)}")
    return df


def transform(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Transform PaySim into ATROSA's 4 DataFrames."""
    np.random.seed(42)

    # Generate realistic timestamps from step (1 step = 1 hour)
    base_time = pd.Timestamp("2026-03-01")
    df["timestamp"] = df["step"].apply(lambda s: base_time + pd.Timedelta(hours=int(s)))
    df["transaction_id"] = [f"TXN-PS-{i:08d}" for i in range(len(df))]
    df["user_id"] = df["nameOrig"].str.replace("C", "USR-PS-")

    # Endpoint mapping
    type_to_endpoint = {
        "CASH_IN": "/api/v2/wallet/deposit",
        "CASH_OUT": "/api/v2/wallet/withdraw",
        "DEBIT": "/api/v2/transfer/debit",
        "PAYMENT": "/api/v2/payment/merchant",
        "TRANSFER": "/api/v2/transfer/initiate",
    }

    # Operation mapping
    type_to_operation = {
        "CASH_IN": "CREDIT",
        "CASH_OUT": "DEBIT",
        "DEBIT": "DEBIT",
        "PAYMENT": "DEBIT",
        "TRANSFER": "DEBIT",
    }

    # --- df_api: API gateway log ---
    df_api = pd.DataFrame({
        "source": "api_gateway",
        "timestamp": df["timestamp"].dt.isoformat(),
        "request_id": [f"REQ-{i:08x}" for i in range(len(df))],
        "user_id": df["user_id"],
        "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df["user_id"]],
        "method": "POST",
        "endpoint": df["type"].map(type_to_endpoint),
        "status_code": np.where(df["isFraud"] == 1, np.random.choice([200, 200, 200, 500], len(df)), 200),
        "response_time_ms": np.random.randint(15, 800, len(df)),
        "ip_address": [f"{np.random.randint(1,224)}.{np.random.randint(0,256)}.{np.random.randint(0,256)}.{np.random.randint(1,255)}" for _ in range(len(df))],
        "user_agent": np.random.choice([
            "PaySimApp/2.1 (Android 14)", "PaySimApp/2.1 (iOS 17)",
            "Mozilla/5.0", "PostmanRuntime/7.36",
        ], len(df)),
        "transaction_id": df["transaction_id"],
        "amount": df["amount"].round(2),
        "currency": "USD",
    })

    # --- df_db: Ledger commits ---
    df_db = pd.DataFrame({
        "source": "ledger_db_commits",
        "timestamp": (df["timestamp"] + pd.Timedelta(seconds=1)).dt.isoformat(),
        "commit_id": [f"CMT-{i:08x}" for i in range(len(df))],
        "user_id": df["user_id"],
        "operation": df["type"].map(type_to_operation),
        "amount": df["amount"].round(2),
        "currency": "USD",
        "balance_before": df["oldbalanceOrg"].round(2),
        "balance_after": df["newbalanceOrig"].round(2),
        "transaction_id": df["transaction_id"],
        "provider": np.random.choice(["paystack", "flutterwave", "stripe"], len(df)),
        "idempotency_key": [f"IDEM-{i:08x}" for i in range(len(df))],
    })

    # --- df_mobile: Mobile client events ---
    # Generate mobile events for fraudulent transactions (network errors, etc.)
    fraud_mask = df["isFraud"] == 1
    n_fraud = fraud_mask.sum()
    n_normal = min(len(df) - n_fraud, n_fraud * 50)  # Sample normal events

    # Fraud-associated mobile events
    fraud_events = pd.DataFrame({
        "source": "mobile_client_errors",
        "timestamp": (df.loc[fraud_mask, "timestamp"] + pd.Timedelta(seconds=2)).dt.isoformat(),
        "event_id": [f"EVT-F-{i:08x}" for i in range(n_fraud)],
        "user_id": df.loc[fraud_mask, "user_id"].values,
        "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df.loc[fraud_mask, "user_id"]],
        "event_type": "network_error",
        "device_os": np.random.choice(["Android 14", "Android 13"], n_fraud),
        "app_version": "2.1.0",
        "network_type": np.random.choice(["4G", "3G"], n_fraud),
        "error_code": "E_NETWORK_LOST",
        "screen": "transfer",
        "ip_address": [f"{np.random.randint(1,224)}.{np.random.randint(0,256)}.{np.random.randint(0,256)}.{np.random.randint(1,255)}" for _ in range(n_fraud)],
    })

    # Normal mobile events (sampled)
    normal_idx = df[~fraud_mask].sample(n=n_normal, random_state=42).index
    normal_events = pd.DataFrame({
        "source": "mobile_client_errors",
        "timestamp": df.loc[normal_idx, "timestamp"].dt.isoformat(),
        "event_id": [f"EVT-N-{i:08x}" for i in range(n_normal)],
        "user_id": df.loc[normal_idx, "user_id"].values,
        "session_id": [f"SES-{hash(uid) % 10**8:08x}" for uid in df.loc[normal_idx, "user_id"]],
        "event_type": np.random.choice(["app_open", "screen_view", "transfer_initiated", "biometric_auth"], n_normal),
        "device_os": np.random.choice(["Android 14", "iOS 17.4", "Android 13"], n_normal),
        "app_version": "2.1.0",
        "network_type": np.random.choice(["4G", "WiFi", "3G"], n_normal),
        "error_code": np.where(np.random.random(n_normal) > 0.9, "E_TIMEOUT", None),
        "screen": np.random.choice(["home", "transfer", "history", "settings"], n_normal),
        "ip_address": [f"{np.random.randint(1,224)}.{np.random.randint(0,256)}.{np.random.randint(0,256)}.{np.random.randint(1,255)}" for _ in range(n_normal)],
    })

    df_mobile = pd.concat([fraud_events, normal_events], ignore_index=True)

    # --- df_webhooks: Payment webhooks ---
    df_webhooks = pd.DataFrame({
        "source": "payment_webhooks",
        "timestamp": (df["timestamp"] + pd.Timedelta(seconds=np.random.randint(5, 120))).dt.isoformat(),
        "webhook_id": [f"WH-{i:08x}" for i in range(len(df))],
        "provider": np.random.choice(["paystack", "flutterwave", "stripe"], len(df)),
        "event_type": np.where(df["isFraud"] == 1, "payment.completed",
                               np.random.choice(["payment.completed", "payment.completed", "payment.failed"], len(df))),
        "transaction_id": df["transaction_id"],
        "user_id": df["user_id"],
        "amount": df["amount"].round(2),
        "currency": "USD",
        "status": np.where(df["isFraud"] == 1, "success",
                          np.random.choice(["success", "success", "success", "failed"], len(df))),
        "delivery_attempt": np.where(df["isFraud"] == 1, np.random.randint(2, 5, len(df)), 1),
        "latency_ms": np.where(df["isFraud"] == 1, np.random.randint(60000, 300000, len(df)),
                               np.random.randint(50, 5000, len(df))),
    })

    # Add ground truth metadata
    fraud_tx_ids = df.loc[fraud_mask, "transaction_id"].tolist()
    fraud_user_ids = df.loc[fraud_mask, "user_id"].unique().tolist()

    return {
        "api": df_api,
        "db": df_db,
        "mobile": df_mobile,
        "webhooks": df_webhooks,
        "ground_truth": {
            "dataset": "paysim",
            "anomaly_count": len(fraud_tx_ids),
            "attacker_transaction_ids": fraud_tx_ids[:1000],  # Cap for JSON size
            "attacker_user_ids": fraud_user_ids[:500],
            "total_fraud_transactions": len(fraud_tx_ids),
            "total_fraud_users": len(fraud_user_ids),
            "description": "PaySim mobile money fraud: account takeover via TRANSFER then CASH_OUT",
        },
    }


def save(result: dict, sample_size: int = None):
    """Save transformed DataFrames as JSONL files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for name in ["api", "db", "mobile", "webhooks"]:
        df = result[name]
        if sample_size and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42)
        path = OUTPUT_DIR / f"{name}_gateway.jsonl" if name == "api" else \
               OUTPUT_DIR / f"ledger_db_commits.jsonl" if name == "db" else \
               OUTPUT_DIR / f"mobile_client_errors.jsonl" if name == "mobile" else \
               OUTPUT_DIR / f"payment_webhooks.jsonl"

        with open(path, "w") as f:
            for _, row in df.iterrows():
                f.write(json.dumps({k: v for k, v in row.items() if pd.notna(v)}) + "\n")
        print(f"    {path.name}: {len(df)} rows")

    # Save ground truth
    gt_path = OUTPUT_DIR / ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(result["ground_truth"], f, indent=2)
    print(f"    .ground_truth.json: {result['ground_truth']['total_fraud_transactions']} fraud txns")


if __name__ == "__main__":
    # Use --sample N to limit output size for quick testing
    sample = None
    if "--sample" in sys.argv:
        idx = sys.argv.index("--sample")
        sample = int(sys.argv[idx + 1])
        print(f"[*] Sampling {sample} rows per source")

    raw = load_paysim()
    result = transform(raw)
    print(f"\n[*] Saving to {OUTPUT_DIR}...")
    save(result, sample_size=sample)
    print(f"\n[+] PaySim transform complete")
    print(f"    Fraud: {result['ground_truth']['total_fraud_transactions']} transactions, "
          f"{result['ground_truth']['total_fraud_users']} users")
