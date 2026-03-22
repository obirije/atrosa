"""
ATROSA Mock Telemetry Generator
================================
Generates a synthetic 24-hour fintech log dataset with:
- Standard API gateway traffic (~10,000 events)
- Standard DB ledger commits (~8,000 events)
- Mobile client logs (~5,000 events)
- Webhook callback events (~3,000 events)
- 3 HIDDEN double-spend anomalies via delayed webhook desync

The anomalies simulate: user initiates transfer -> forces network disconnect ->
delayed webhook credits destination without debiting source wallet.
"""

import json
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

# --- Config ---
BASE_TIME = datetime(2026, 3, 20, 0, 0, 0)  # 24h window start
NUM_USERS = 500
NUM_API_EVENTS = 10_000
NUM_DB_COMMITS = 8_000
NUM_MOBILE_EVENTS = 5_000
NUM_WEBHOOK_EVENTS = 3_000
OUTPUT_DIR = Path("data")

# --- Helpers ---
USER_IDS = [f"USR-{uuid.uuid4().hex[:8].upper()}" for _ in range(NUM_USERS)]
ENDPOINTS = [
    "/api/v2/transfer/initiate", "/api/v2/transfer/confirm",
    "/api/v2/balance/check", "/api/v2/kyc/verify", "/api/v2/cards/list",
    "/api/v2/accounts/summary", "/api/v2/webhook/payment-callback",
    "/api/v2/transfer/status", "/api/v2/auth/token", "/api/v2/auth/refresh",
]
HTTP_METHODS = ["POST", "GET", "PUT"]
STATUS_CODES = [200, 200, 200, 200, 200, 201, 400, 401, 403, 500]
CURRENCIES = ["NGN", "USD", "GBP", "KES", "GHS"]
PROVIDERS = ["paystack", "flutterwave", "stripe", "monnify"]
MOBILE_EVENTS = [
    "app_open", "screen_view", "transfer_initiated", "transfer_confirmed",
    "network_error", "timeout", "biometric_auth", "pin_entry", "logout",
]

# Pick 3 random users to be the attackers
ATTACKER_IDS = random.sample(USER_IDS, 3)
ATTACKER_TX_IDS = [f"TXN-{uuid.uuid4().hex[:12].upper()}" for _ in range(3)]


def rand_time(bias_hour=None):
    """Random timestamp within the 24h window, optionally biased to an hour."""
    if bias_hour is not None:
        base = BASE_TIME + timedelta(hours=bias_hour)
        offset = random.uniform(0, 3599)
    else:
        offset = random.uniform(0, 86399)
        base = BASE_TIME
    return base + timedelta(seconds=offset)


def gen_tx_id():
    return f"TXN-{uuid.uuid4().hex[:12].upper()}"


def gen_session_id():
    return f"SES-{uuid.uuid4().hex[:10].upper()}"


def gen_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ===========================
# 1. API Gateway Logs
# ===========================
def generate_api_events():
    events = []
    for _ in range(NUM_API_EVENTS):
        user = random.choice(USER_IDS)
        endpoint = random.choice(ENDPOINTS)
        method = "POST" if "initiate" in endpoint or "confirm" in endpoint else random.choice(HTTP_METHODS)
        events.append({
            "source": "api_gateway",
            "timestamp": rand_time().isoformat(),
            "request_id": uuid.uuid4().hex[:16],
            "user_id": user,
            "session_id": gen_session_id(),
            "method": method,
            "endpoint": endpoint,
            "status_code": random.choice(STATUS_CODES),
            "response_time_ms": random.randint(12, 2500),
            "ip_address": gen_ip(),
            "user_agent": random.choice([
                "AtrosaApp/3.2.1 (Android 14)", "AtrosaApp/3.2.1 (iOS 17.4)",
                "Mozilla/5.0", "PostmanRuntime/7.36.0",
            ]),
            "transaction_id": gen_tx_id() if "transfer" in endpoint else None,
            "amount": round(random.uniform(100, 500000), 2) if "transfer" in endpoint else None,
            "currency": random.choice(CURRENCIES) if "transfer" in endpoint else None,
        })
    return events


# ===========================
# 2. Ledger DB Commits
# ===========================
def generate_db_commits():
    events = []
    for _ in range(NUM_DB_COMMITS):
        user = random.choice(USER_IDS)
        op = random.choice(["CREDIT", "DEBIT", "HOLD", "RELEASE", "REVERSAL"])
        events.append({
            "source": "ledger_db_commits",
            "timestamp": rand_time().isoformat(),
            "commit_id": uuid.uuid4().hex[:16],
            "user_id": user,
            "operation": op,
            "amount": round(random.uniform(50, 300000), 2),
            "currency": random.choice(CURRENCIES),
            "balance_before": round(random.uniform(1000, 2000000), 2),
            "balance_after": None,  # computed below
            "transaction_id": gen_tx_id(),
            "provider": random.choice(PROVIDERS),
            "idempotency_key": hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:24],
        })
        e = events[-1]
        if op == "CREDIT":
            e["balance_after"] = round(e["balance_before"] + e["amount"], 2)
        elif op == "DEBIT":
            e["balance_after"] = round(e["balance_before"] - e["amount"], 2)
        else:
            e["balance_after"] = e["balance_before"]
    return events


# ===========================
# 3. Mobile Client Logs
# ===========================
def generate_mobile_events():
    events = []
    for _ in range(NUM_MOBILE_EVENTS):
        user = random.choice(USER_IDS)
        event_type = random.choice(MOBILE_EVENTS)
        events.append({
            "source": "mobile_client_errors",
            "timestamp": rand_time().isoformat(),
            "event_id": uuid.uuid4().hex[:16],
            "user_id": user,
            "session_id": gen_session_id(),
            "event_type": event_type,
            "device_os": random.choice(["Android 14", "iOS 17.4", "Android 13"]),
            "app_version": "3.2.1",
            "network_type": random.choice(["4G", "WiFi", "3G"]),
            "error_code": random.choice([None, None, None, "E_TIMEOUT", "E_NETWORK_LOST", "E_SSL_HANDSHAKE"]),
            "screen": random.choice(["home", "transfer", "history", "settings", "kyc"]),
            "ip_address": gen_ip(),
        })
    return events


# ===========================
# 4. Webhook Events
# ===========================
def generate_webhook_events():
    events = []
    for _ in range(NUM_WEBHOOK_EVENTS):
        user = random.choice(USER_IDS)
        status = random.choice(["success", "success", "success", "failed", "pending"])
        events.append({
            "source": "payment_webhooks",
            "timestamp": rand_time().isoformat(),
            "webhook_id": uuid.uuid4().hex[:16],
            "provider": random.choice(PROVIDERS),
            "event_type": "payment.completed" if status == "success" else f"payment.{status}",
            "transaction_id": gen_tx_id(),
            "user_id": user,
            "amount": round(random.uniform(100, 500000), 2),
            "currency": random.choice(CURRENCIES),
            "status": status,
            "delivery_attempt": random.randint(1, 3),
            "latency_ms": random.randint(50, 5000),
        })
    return events


# ===========================
# 5. INJECT ANOMALIES
# ===========================
def inject_anomalies(api_events, db_events, mobile_events, webhook_events):
    """
    Inject 3 double-spend anomalies. Pattern:
    1. User calls /transfer/initiate (API) -> 200 OK
    2. User's mobile shows network_error / E_NETWORK_LOST immediately after (~2-5s)
    3. Webhook arrives LATE (90-300s delay) with status=success
    4. DB shows CREDIT to destination but NO corresponding DEBIT from source
       (the debit was "lost" due to the race condition)
    5. User's balance_after > balance_before despite a transfer out
    """
    anomaly_hours = [3, 11, 19]  # spread across the 24h window

    for i, (attacker, tx_id, hour) in enumerate(zip(ATTACKER_IDS, ATTACKER_TX_IDS, anomaly_hours)):
        amount = round(random.uniform(45000, 250000), 2)
        currency = "NGN"
        provider = random.choice(PROVIDERS)
        ip = gen_ip()
        session = gen_session_id()
        t_initiate = BASE_TIME + timedelta(hours=hour, minutes=random.randint(5, 50))

        # (a) API: transfer initiate - success
        api_events.append({
            "source": "api_gateway",
            "timestamp": t_initiate.isoformat(),
            "request_id": uuid.uuid4().hex[:16],
            "user_id": attacker,
            "session_id": session,
            "method": "POST",
            "endpoint": "/api/v2/transfer/initiate",
            "status_code": 200,
            "response_time_ms": random.randint(80, 300),
            "ip_address": ip,
            "user_agent": "AtrosaApp/3.2.1 (Android 14)",
            "transaction_id": tx_id,
            "amount": amount,
            "currency": currency,
        })

        # (b) Mobile: network disconnect 2-5s after initiation
        t_disconnect = t_initiate + timedelta(seconds=random.randint(2, 5))
        mobile_events.append({
            "source": "mobile_client_errors",
            "timestamp": t_disconnect.isoformat(),
            "event_id": uuid.uuid4().hex[:16],
            "user_id": attacker,
            "session_id": session,
            "event_type": "network_error",
            "device_os": "Android 14",
            "app_version": "3.2.1",
            "network_type": "4G",
            "error_code": "E_NETWORK_LOST",
            "screen": "transfer",
            "ip_address": ip,
        })

        # (c) Webhook: arrives LATE (90-300s) with success — the desync
        t_webhook = t_initiate + timedelta(seconds=random.randint(90, 300))
        webhook_events.append({
            "source": "payment_webhooks",
            "timestamp": t_webhook.isoformat(),
            "webhook_id": uuid.uuid4().hex[:16],
            "provider": provider,
            "event_type": "payment.completed",
            "transaction_id": tx_id,
            "user_id": attacker,
            "amount": amount,
            "currency": currency,
            "status": "success",
            "delivery_attempt": random.randint(2, 4),  # retried = suspicious
            "latency_ms": random.randint(90000, 300000),  # abnormally high
        })

        # (d) DB: CREDIT appears (destination funded) but NO DEBIT (source not debited)
        balance_before = round(random.uniform(50000, 500000), 2)
        t_credit = t_webhook + timedelta(seconds=random.randint(1, 3))
        db_events.append({
            "source": "ledger_db_commits",
            "timestamp": t_credit.isoformat(),
            "commit_id": uuid.uuid4().hex[:16],
            "user_id": attacker,
            "operation": "CREDIT",
            "amount": amount,
            "currency": currency,
            "balance_before": balance_before,
            "balance_after": round(balance_before + amount, 2),
            "transaction_id": tx_id,
            "provider": provider,
            "idempotency_key": hashlib.sha256(tx_id.encode()).hexdigest()[:24],
        })
        # NOTE: Deliberately NO matching DEBIT for this transaction_id.
        # This is the exploit: credit without debit = money from nowhere.

    return api_events, db_events, mobile_events, webhook_events


# ===========================
# MAIN
# ===========================
def generate_all():
    print("[*] Generating synthetic telemetry...")
    api = generate_api_events()
    db = generate_db_commits()
    mobile = generate_mobile_events()
    webhooks = generate_webhook_events()

    print(f"[*] Injecting 3 double-spend anomalies (attackers: {ATTACKER_IDS})")
    api, db, mobile, webhooks = inject_anomalies(api, db, mobile, webhooks)

    # Sort all by timestamp
    for dataset in [api, db, mobile, webhooks]:
        dataset.sort(key=lambda x: x["timestamp"])

    OUTPUT_DIR.mkdir(exist_ok=True)

    datasets = {
        "api_gateway.jsonl": api,
        "ledger_db_commits.jsonl": db,
        "mobile_client_errors.jsonl": mobile,
        "payment_webhooks.jsonl": webhooks,
    }

    for filename, data in datasets.items():
        path = OUTPUT_DIR / filename
        with open(path, "w") as f:
            for event in data:
                f.write(json.dumps(event) + "\n")
        print(f"    -> {path} ({len(data)} events)")

    # Write ground truth (for scoring validation only — never shown to Hunter)
    ground_truth = {
        "anomaly_count": 3,
        "attacker_user_ids": ATTACKER_IDS,
        "attacker_transaction_ids": ATTACKER_TX_IDS,
        "description": "Double-spend via webhook desync: CREDIT without matching DEBIT",
    }
    gt_path = OUTPUT_DIR / ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"    -> {gt_path} (ground truth — hidden from agents)")

    print(f"\n[+] Telemetry generation complete. Total events: {sum(len(d) for d in datasets.values())}")
    return ground_truth


if __name__ == "__main__":
    generate_all()
