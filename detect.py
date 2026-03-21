"""detect.py — ATROSA Hunter Detection Script"""
import json
import sys
import ingest
import pandas as pd
from datetime import timedelta

def detect():
    harness = ingest.setup()
    df_api = harness["df_api"]
    df_db = harness["df_db"]
    df_mobile = harness["df_mobile"]
    df_webhooks = harness["df_webhooks"]

    flagged_tx_ids = []
    flagged_user_ids = []

    # Step 1: Find successful webhooks (potential credits that went through)
    successful_webhooks = df_webhooks[
        (df_webhooks['status'] == 'success') & 
        (df_webhooks['event_type'].isin(['payment.completed', 'transfer.completed']))
    ].copy()
    
    print(f"Found {len(successful_webhooks)} successful webhooks", file=sys.stderr)
    
    # Step 2: For each successful webhook, check if there's a corresponding CREDIT but no DEBIT
    for _, webhook in successful_webhooks.iterrows():
        tx_id = webhook['transaction_id']
        user_id = webhook['user_id']
        webhook_time = webhook['timestamp']
        
        # Look for ledger operations for this transaction
        tx_operations = df_db[df_db['transaction_id'] == tx_id].copy()
        
        if len(tx_operations) == 0:
            continue  # No ledger operations found
            
        # Check if we have CREDIT but no DEBIT for this transaction
        has_credit = (tx_operations['operation'] == 'CREDIT').any()
        has_debit = (tx_operations['operation'] == 'DEBIT').any()
        
        if has_credit and not has_debit:
            # Potential anomaly - but need to verify with mobile client signal
            
            # Step 3: Look for network error in mobile logs around the same time
            # Check for E_NETWORK_LOST errors for this user on transfer screen
            time_window_start = webhook_time - timedelta(minutes=10)  # Look 10 minutes before webhook
            time_window_end = webhook_time + timedelta(minutes=2)   # And 2 minutes after
            
            mobile_errors = df_mobile[
                (df_mobile['user_id'] == user_id) &
                (df_mobile['timestamp'] >= time_window_start) &
                (df_mobile['timestamp'] <= time_window_end) &
                (df_mobile['error_code'] == 'E_NETWORK_LOST') &
                (df_mobile['screen'] == 'transfer')
            ]
            
            # Step 4: Also check API logs for transfer initiation
            api_transfers = df_api[
                (df_api['user_id'] == user_id) &
                (df_api['transaction_id'] == tx_id) &
                (df_api['endpoint'].str.contains('/transfer', case=False, na=False)) &
                (df_api['timestamp'] >= time_window_start) &
                (df_api['timestamp'] <= webhook_time)
            ]
            
            if len(mobile_errors) > 0 and len(api_transfers) > 0:
                # Found the attack pattern:
                # 1. Successful webhook with CREDIT but no DEBIT
                # 2. Network error on transfer screen 
                # 3. API transfer initiation
                print(f"ANOMALY DETECTED: TX {tx_id}, User {user_id}", file=sys.stderr)
                print(f"  - Webhook success at {webhook_time}", file=sys.stderr)
                print(f"  - CREDIT without DEBIT in ledger", file=sys.stderr)
                print(f"  - {len(mobile_errors)} network errors on transfer screen", file=sys.stderr)
                print(f"  - {len(api_transfers)} API transfer calls", file=sys.stderr)
                
                flagged_tx_ids.append(tx_id)
                flagged_user_ids.append(user_id)

    print(f"Total flagged transactions: {len(flagged_tx_ids)}", file=sys.stderr)
    print(f"Total flagged users: {len(set(flagged_user_ids))}", file=sys.stderr)
    
    return flagged_tx_ids, flagged_user_ids

if __name__ == "__main__":
    try:
        tx_ids, user_ids = detect()
        result = {
            "flagged_tx_ids": list(set(tx_ids)),
            "flagged_user_ids": list(set(user_ids)),
        }
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "flagged_tx_ids": [], "flagged_user_ids": []}))
        sys.exit(1)