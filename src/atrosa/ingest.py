"""
ATROSA Ingestion & Scoring Harness
====================================
Loads the synthetic telemetry into DataFrames and provides:
- df_api, df_db, df_mobile, df_webhooks: queryable datasets
- score_detections(flagged_events): SNR scoring function

This file is NOT modified by the Hunter agent during iteration.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import pandas as pd

DATA_DIR = Path("data")
GROUND_TRUTH_PATH = DATA_DIR / ".ground_truth.json"


# ===========================
# DATA LOADING
# ===========================
def load_jsonl(filepath: Path) -> pd.DataFrame:
    """Load a JSONL file into a DataFrame."""
    records = []
    with open(filepath) as f:
        for line in f:
            records.append(json.loads(line.strip()))
    df = pd.DataFrame(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    return df


def load_all_data() -> dict[str, pd.DataFrame]:
    """Load all telemetry sources into a dict of DataFrames."""
    sources = {
        "api": DATA_DIR / "api_gateway.jsonl",
        "db": DATA_DIR / "ledger_db_commits.jsonl",
        "mobile": DATA_DIR / "mobile_client_errors.jsonl",
        "webhooks": DATA_DIR / "payment_webhooks.jsonl",
    }
    data = {}
    for name, path in sources.items():
        if not path.exists():
            print(f"[!] Missing data file: {path}. Run mock_telemetry.py first.")
            sys.exit(1)
        data[name] = load_jsonl(path)
        print(f"    Loaded {name}: {len(data[name])} rows, columns: {list(data[name].columns)}")
    return data


def load_ground_truth() -> dict:
    """Load ground truth for scoring."""
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


# ===========================
# SNR SCORING
# ===========================
def score_detections(
    flagged_tx_ids: list[str],
    flagged_user_ids: list[str],
    total_events: int,
    ground_truth: Optional[dict] = None,
) -> dict:
    """
    Score detection results using Signal-to-Noise Ratio.

    Rules:
    - Score = 0 if: no flags, script crashed, or flagged >1% of total traffic
    - Score = 100 if: correctly identified the anomalous transactions/users
      with minimal false positives
    - Partial credit for partial matches

    Returns dict with score (0-100), details, and feedback for the agent.
    """
    if ground_truth is None:
        ground_truth = load_ground_truth()

    gt_tx = set(ground_truth["attacker_transaction_ids"])
    gt_users = set(ground_truth["attacker_user_ids"])
    anomaly_count = ground_truth["anomaly_count"]

    result = {
        "score": 0,
        "flagged_tx_count": len(flagged_tx_ids),
        "flagged_user_count": len(flagged_user_ids),
        "total_events": total_events,
        "feedback": "",
    }

    # --- Failure conditions ---
    if len(flagged_tx_ids) == 0 and len(flagged_user_ids) == 0:
        result["feedback"] = (
            "SCORE=0. No events flagged. Your detection logic did not identify any anomalies. "
            "Revisit your hypothesis. Look for cross-source correlations: "
            "transactions that appear in one log source but are missing expected counterparts in another."
        )
        return result

    noise_threshold = total_events * 0.01
    if len(flagged_tx_ids) > noise_threshold:
        result["feedback"] = (
            f"SCORE=0. Too noisy: flagged {len(flagged_tx_ids)} transactions "
            f"(>{noise_threshold:.0f} = 1% of {total_events} total events). "
            "Your detection is too broad. Tighten your filters to isolate truly anomalous patterns."
        )
        return result

    # --- Scoring ---
    # Transaction-level accuracy
    true_pos_tx = set(flagged_tx_ids) & gt_tx
    false_pos_tx = set(flagged_tx_ids) - gt_tx

    # User-level accuracy
    true_pos_users = set(flagged_user_ids) & gt_users
    false_pos_users = set(flagged_user_ids) - gt_users

    # Recall: how many of the 3 anomalies did we catch?
    tx_recall = len(true_pos_tx) / anomaly_count if anomaly_count > 0 else 0
    user_recall = len(true_pos_users) / anomaly_count if anomaly_count > 0 else 0

    # Precision: of what we flagged, how much was real?
    tx_precision = len(true_pos_tx) / len(flagged_tx_ids) if flagged_tx_ids else 0
    user_precision = len(true_pos_users) / len(flagged_user_ids) if flagged_user_ids else 0

    # Combined score: weight recall heavily (we must catch all 3), penalize noise
    recall_score = (tx_recall * 0.6 + user_recall * 0.4) * 70  # max 70 from recall
    precision_score = (tx_precision * 0.6 + user_precision * 0.4) * 30  # max 30 from precision

    raw_score = recall_score + precision_score
    score = min(100, max(0, int(raw_score)))

    # Build feedback
    feedback_parts = []
    feedback_parts.append(f"SCORE={score}.")

    if tx_recall == 1.0 and user_recall == 1.0:
        feedback_parts.append(f"All {anomaly_count} anomalies detected!")
    else:
        feedback_parts.append(
            f"Detected {len(true_pos_tx)}/{anomaly_count} anomalous transactions, "
            f"{len(true_pos_users)}/{anomaly_count} anomalous users."
        )

    if false_pos_tx:
        feedback_parts.append(f"False positive transactions: {len(false_pos_tx)}.")
    if false_pos_users:
        feedback_parts.append(f"False positive users: {len(false_pos_users)}.")

    if score < 100:
        if tx_recall < 1.0:
            feedback_parts.append(
                "Hint: Look for transaction IDs that have a webhook CREDIT but no corresponding DEBIT. "
                "Correlate across ledger_db_commits and payment_webhooks."
            )
        if len(false_pos_tx) > 0:
            feedback_parts.append(
                "Hint: Reduce false positives by requiring MULTIPLE correlated signals — "
                "e.g., network_error on mobile + late webhook + missing debit."
            )

    if score == 100:
        feedback_parts.append(
            "PERFECT DETECTION. Rule is ready for graduation to active_rules.json."
        )

    result["score"] = score
    result["tx_recall"] = tx_recall
    result["user_recall"] = user_recall
    result["tx_precision"] = tx_precision
    result["user_precision"] = user_precision
    result["true_positive_txs"] = list(true_pos_tx)
    result["true_positive_users"] = list(true_pos_users)
    result["feedback"] = " ".join(feedback_parts)

    return result


# ===========================
# HARNESS ENTRY POINT
# ===========================
def setup():
    """Called by orchestrator and detect.py to get data + scorer."""
    print("[*] ATROSA Ingestion Harness")
    print("[*] Loading telemetry data...")
    data = load_all_data()
    ground_truth = load_ground_truth()

    total_events = sum(len(df) for df in data.values())
    print(f"[*] Total events loaded: {total_events}")

    return {
        "df_api": data["api"],
        "df_db": data["db"],
        "df_mobile": data["mobile"],
        "df_webhooks": data["webhooks"],
        "ground_truth": ground_truth,
        "total_events": total_events,
        "score_fn": score_detections,
    }


if __name__ == "__main__":
    harness = setup()
    print("\n[*] Harness ready. DataFrames available:")
    for key, val in harness.items():
        if isinstance(val, pd.DataFrame):
            print(f"    {key}: {val.shape}")
    print("\n[*] Run orchestrator.py to begin the Hunter loop.")
