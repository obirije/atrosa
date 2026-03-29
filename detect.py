import sys
import json
import pandas as pd

# Import the ingest module provided by the environment
import ingest

def detect(df_api, df_db, df_mobile, df_webhooks):
    """
    Core detection logic: Identifies fraud by cross-referencing ledger anomalies 
    and webhook latency patterns.
    """
    flagged_tx_ids = set()
    flagged_user_ids = set()

    # --- Analysis 1: Impossible Ledger State Transitions ---
    # Fraud or system errors often cause impossible balance changes.
    # CREDIT operations should not decrease the balance.
    # DEBIT operations should not increase the balance.
    if df_db is not None and not df_db.empty:
        try:
            # Filter rows where operation logic is violated
            impossible_ledger = df_db[
                ((df_db['operation'] == 'CREDIT') & (df_db['balance_after'] < df_db['balance_before'])) |
                ((df_db['operation'] == 'DEBIT') & (df_db['balance_after'] > df_db['balance_before']))
            ]
            
            if not impossible_ledger.empty:
                flagged_tx_ids.update(impossible_ledger['transaction_id'].dropna().astype(str))
                flagged_user_ids.update(impossible_ledger['user_id'].dropna().astype(str))
        except Exception:
            # Fail gracefully on data parsing issues
            pass

    # --- Analysis 2: Stuck Payments ---
    # High latency in webhook delivery (e.g., > 2000ms) indicates a payment 
    # stuck in a processing queue, often a sign of fraud or provider failure.
    if df_webhooks is not None and not df_webhooks.empty:
        try:
            stuck_webhooks = df_webhooks[df_webhooks['latency_ms'] > 2000]
            if not stuck_webhooks.empty:
                flagged_tx_ids.update(stuck_webhooks['transaction_id'].dropna().astype(str))
                flagged_user_ids.update(stuck_webhooks['user_id'].dropna().astype(str))
        except Exception:
            # Fail gracefully
            pass

    # Prepare final output
    result = {
        "flagged_tx_ids": sorted(flagged_tx_ids),
        "flagged_user_ids": sorted(flagged_user_ids)
    }
    return result

if __name__ == "__main__":
    try:
        # Load data using the specific constraint from the error message
        df_api, df_db, df_mobile, df_webhooks = ingest.setup()
        
        # Execute detection
        detection_result = detect(df_api, df_db, df_mobile, df_webhooks)
        
        # Output JSON strictly to stdout
        print(json.dumps(detection_result, separators=(',', ':')))
    except Exception:
        # Fallback: print empty JSON if execution fails
        print(json.dumps({"flagged_tx_ids": [], "flagged_user_ids": []}))