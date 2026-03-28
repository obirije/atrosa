# ATROSA — Full Documentation

**Autonomous Threat Response & Overwatch Swarm Agents**

Comprehensive documentation covering architecture, usage, internals, security, testing, and the research behind ATROSA.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Quickstart](#3-quickstart)
4. [Architecture](#4-architecture)
5. [Connectors (Data Ingestion)](#5-connectors)
6. [The Hunter (Autoresearch Loop)](#6-the-hunter)
7. [The Sentinel (Live Enforcement)](#7-the-sentinel)
8. [Telemetry Engineer (Feedback Loop)](#8-telemetry-engineer)
9. [Schema Normalization](#9-schema-normalization)
10. [Data Source Tiers](#10-data-source-tiers)
11. [Hunt Catalog (25 Threat Categories)](#11-hunt-catalog)
12. [Scoring System](#12-scoring-system)
13. [Production Mode](#13-production-mode)
14. [Multi-Tenancy](#14-multi-tenancy)
15. [Security Hardening](#15-security-hardening)
16. [Audit Trail & Regulatory Compliance](#16-audit-trail)
17. [LLM Providers](#17-llm-providers)
18. [Test Run Results](#18-test-run-results)
19. [Fraud Landscape Research](#19-fraud-landscape-research)
20. [Project Structure](#20-project-structure)
21. [Contributing](#21-contributing)

---

## 1. Overview

ATROSA is an autonomous cybersecurity platform that detects financial business logic exploitation — the kind of attacks that structural scanners, SIEMs, and WAFs miss. Instead of static rules or black-box ML models, ATROSA uses an AI-driven iterative loop (autoresearch) to:

1. **Hypothesize** what fraud looks like in the data
2. **Write** a deterministic Python detection script
3. **Execute** it against historical telemetry
4. **Score** the results (signal-to-noise ratio)
5. **Iterate** until the detection is mathematically proven
6. **Graduate** the rule for live production enforcement

The output is readable, auditable Python — not a probability score. Every graduated rule can be explained to a regulator line by line.

### Why This Exists

Traditional security tools fail against business logic exploits:

- **SIEMs** alert on known signatures — they can't reason about multi-step transaction flows
- **eBPF/structural scanners** see syscalls and network packets — they can't see that a CREDIT landed without a matching DEBIT
- **API scanners** find injection and auth flaws — they can't detect that a webhook desync created money from nothing
- **Manual threat hunting** doesn't scale when you process millions of transactions daily

Real fintech attacks exploit asynchronous race conditions, webhook desyncs, TOCTOU gaps, KYC state machine bypasses, and balance manipulation. These are **logic flaws**, not CVEs. No scanner has a signature for them.

### Design Principles

- **Explainable AI**: Every detection is readable Python, not a risk score
- **Deterministic execution**: No LLM at runtime — graduated rules are pure Python against DataFrames
- **Iterative proof**: Rules must pass SNR scoring before graduation — not deployed on vibes
- **Separation of concerns**: Heavy LLM compute (Hunter) is decoupled from sub-second execution (Sentinel)
- **Closed feedback loop**: The Telemetry Engineer ensures hunts are never permanently blocked by missing data
- **Read-only tap**: ATROSA connects to the customer's existing stack and reads pre-enriched data — never modifies systems
- **Regulatory audit trail**: Full provenance for every rule — which LLM, prompt, data version, every iteration. SAR-ready explanations

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) iterative loop pattern.

---

## 2. Installation

### Python (primary)

```bash
git clone https://github.com/obirije/atrosa.git
cd atrosa

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This gives you the `atrosa` CLI command.

### Node.js (alternative CLI)

```bash
cd atrosa/node
npm install
npm run build
```

Use `npx atrosa` or `node dist/bin/atrosa.js`. The Node.js CLI requires Python 3.12+ installed for executing detection scripts. In production mode (`--production`), the Node CLI delegates to the Python orchestrator.

### API Keys

```bash
# Pick ONE — whichever LLM provider you want:
export ANTHROPIC_API_KEY="sk-ant-..."       # Anthropic (Claude) — default
export OPENAI_API_KEY="sk-..."              # OpenAI
export GEMINI_API_KEY="..."                 # Google Gemini
export OPENROUTER_API_KEY="sk-or-..."       # OpenRouter (100+ models)
# Local models (Ollama, LM Studio, vLLM) need no key
```

### Requirements

- Python 3.12+
- pandas >= 2.0
- At least one LLM provider (API key or local model server)

---

## 3. Quickstart

```bash
# 1. Generate synthetic telemetry (3 hidden double-spend anomalies)
atrosa init

# 2. Run the Hunter — discovers fraud patterns autonomously
atrosa hunt

# 3. Enforce graduated rules against live streams
atrosa sentinel --dry-run

# 4. Audit telemetry coverage
atrosa telemetry audit
```

### With real data

```bash
# From Stripe
atrosa hunt --source stripe --api-key sk_live_...

# From exported files
atrosa hunt --source csv --data-dir ./exports/

# Via Airweave (optional continuous sync)
atrosa hunt --source airweave --collection stripe-prod

# Using a local model (free)
atrosa hunt --provider local --model qwen2.5-coder:14b
```

---

## 4. Architecture

### System Overview

```
Data Sources                              ATROSA
┌──────────────────┐
│ Stripe / Paystack│──┐
│ Core Banking     │──┤    ┌────────────┐    ┌─────────┐    ┌──────────┐
│ Mobile SDK       │──┼──→ │ Connectors │──→ │ Hunter  │──→ │ Sentinel │
│ Payment Webhooks │──┤    │ (ingest)   │    │ (detect)│    │ (enforce)│
│ Airweave (opt.)  │──┘    └────────────┘    └────┬────┘    └──────────┘
└──────────────────┘                              │
                                           ┌──────▼──────┐
                                           │  Telemetry  │
                                           │  Engineer   │
                                           │ (feedback)  │
                                           └─────────────┘
```

### The 4-DataFrame Model

All data in ATROSA flows through 4 canonical DataFrames:

| DataFrame | Source | Key Columns |
|-----------|--------|-------------|
| `df_api` | API Gateway | timestamp, user_id, endpoint, status_code, transaction_id, amount, ip_address, session_id |
| `df_db` | Ledger DB | timestamp, user_id, operation (CREDIT/DEBIT/HOLD/RELEASE/REVERSAL), amount, balance_before, balance_after, transaction_id |
| `df_mobile` | Mobile Client | timestamp, user_id, event_type, error_code, screen, session_id, device_os |
| `df_webhooks` | Payment Webhooks | timestamp, provider, event_type, transaction_id, user_id, amount, status, delivery_attempt, latency_ms |

Every detection rule cross-correlates across at least 2 of these sources. Single-source detections are too noisy.

### Swarm Components

| Swarm | Role | File |
|-------|------|------|
| **Connectors** | Pull data from external systems, transform to 4 DataFrames | `connectors/` |
| **Cartographer** | Load DataFrames, validate schema, score detections | `ingest.py` |
| **Hunter** | LLM-driven autoresearch loop — writes and proves detection scripts | `orchestrator.py` |
| **Sentinel** | Execute graduated rules against live/simulated streams | `sentinel.py` |
| **Telemetry Engineer** | Detect data gaps, generate observability requests | `telemetry_engineer.py` |

---

## 5. Connectors

Connectors pull data from external systems and transform it into ATROSA's 4-DataFrame format.

### Available Connectors

| Connector | Source | Auth | Notes |
|-----------|--------|------|-------|
| `csv_import` | Local CSV/JSONL files | None | Auto-discovers ATROSA-format files, classifies by filename |
| `stripe` | Stripe REST API | API key | Fetches charges, payment_intents, refunds, disputes |
| `airweave_adapter` | Airweave sync layer | API key (optional) | Pulls from Airweave collections if running |

### Usage

```bash
# CSV/JSONL import (auto-discovers schema)
atrosa hunt --source csv --data-dir ./exported_data/

# Stripe direct (paginated API fetch)
atrosa hunt --source stripe --api-key sk_live_...

# Airweave (continuous sync layer — optional)
atrosa hunt --source airweave --collection stripe-prod --airweave-url http://localhost:8080
```

### Connector Architecture

Every connector implements the `BaseConnector` interface:

```python
class BaseConnector(ABC):
    def pull(self) -> pd.DataFrame:        # Fetch raw data
    def transform(self, raw) -> ConnectorResult:  # Convert to 4 DataFrames
    def run(self) -> ConnectorResult:      # Pull → Transform → Validate
```

`ConnectorResult` validates cross-source integrity:
- At least 2 of 4 DataFrames must have data
- Required columns present (timestamp, user_id, transaction_id)
- Transaction IDs overlap between sources (cross-correlation possible)

### CSV Connector Details

The CSV connector has three modes:

1. **ATROSA-format detection**: If the directory contains `api_gateway.jsonl`, `ledger_db_commits.jsonl`, etc., loads them directly
2. **Explicit file mapping**: `CSVConnector(files={"api": "api_logs.csv", "db": "ledger.csv"})`
3. **Auto-classification**: Classifies files by filename heuristics ("transaction" → db, "webhook" → webhooks)

### Stripe Connector Details

Fetches from 4 Stripe API endpoints with pagination:

| Endpoint | Maps To | Key Fields Extracted |
|----------|---------|---------------------|
| `/v1/charges` | df_api + df_db | amount, status, risk_level, risk_score, card_brand, billing_email |
| `/v1/payment_intents` | df_api | amount, status, customer |
| `/v1/refunds` | df_db (REVERSAL) | amount, reason, charge |
| `/v1/disputes` | df_webhooks | amount, reason, evidence |

Stripe-specific enrichment columns (risk_score, card_brand, card_country, billing_email) are passed through to the DataFrames for the Hunter to use.

### Airweave Adapter

[Airweave](https://github.com/airweave-ai/airweave) is an open-source data sync layer with 50+ connectors. ATROSA's adapter is optional — it talks to Airweave's REST API if running, falls back gracefully if not.

The value of Airweave: **continuous sync**. Without it, data is a point-in-time export. With it, the Hunter can re-run on fresh data each iteration.

```python
adapter = AirweaveAdapter(url="http://localhost:8080")
if adapter.is_available():
    result = adapter.run(collection="stripe-prod")
else:
    # Fall back to direct connector
    result = StripeConnector(api_key="sk_live_...").run()
```

### Schema Auto-Discovery

For unknown data formats, the auto-discovery module maps raw columns to ATROSA's canonical schema:

```bash
# Non-interactive (heuristic matching)
python -m connectors.auto_discover discover --file transactions.csv

# Interactive wizard (confirms each mapping)
python -m connectors.auto_discover wizard --file transactions.csv --save mapping.json
```

The wizard shows sample data for each column and asks the user to confirm or correct the mapping.

### Writing a New Connector

```python
from connectors.base import BaseConnector, ConnectorResult

class PaystackConnector(BaseConnector):
    name = "paystack"

    def pull(self) -> pd.DataFrame:
        # Fetch from Paystack API
        ...

    def transform(self, raw: pd.DataFrame) -> ConnectorResult:
        # Map Paystack fields to ATROSA's 4 DataFrames
        return ConnectorResult(api=df_api, db=df_db, mobile=df_mobile, webhooks=df_webhooks)
```

---

## 6. The Hunter

The Hunter is the core autoresearch loop, based on [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) pattern. It uses an LLM to generate detection scripts, tests them, and iterates based on scoring feedback.

### How It Works

```
Baseline run (establish reference score = 0)
    ↓
LLM generates detect.py  ←──── rich feedback + cumulative experiment history
    ↓                              ↑
AST validation (security)          │
    ↓                              │
Execute in subprocess (5 min)      │
    ↓                              │
Score (SNR 0-100) ─── < 100 ──────┘
    │                   │
    │                   └── Track best-so-far, reset context every 5 iterations
    │
    └── = 100 → GRADUATE RULE → rules/*.py → Sentinel
```

### The Iteration Loop

1. **Baseline**: Run the empty template to establish reference score (always 0)
2. The orchestrator sends the hunt prompt + data schema + experiment history to the LLM
3. The LLM returns a complete `detect.py` in a fenced code block
4. `code_validator.py` parses the code via AST — rejects dangerous constructs
5. The code is executed in an isolated subprocess with a 5-minute timeout
6. Results are scored against ground truth (dev) or multi-strategy scoring (production)
7. Score + rich feedback (precision, recall, comparison to best) are sent back
8. The experiment is logged to `results.tsv` — the LLM sees ALL prior attempts
9. If score regressed from best, the LLM is told to build on what worked
10. Every 5 iterations, conversation history is reset to prevent context saturation
11. On score = 100 (dev) or >= 70 (production), the rule graduates
12. If max iterations reached, best detection code is saved to `logs/best_detect.py`

### Karpathy Autoresearch Alignment

| Karpathy Pattern | ATROSA Implementation |
|---|---|
| `LOOP FOREVER, NEVER STOP` | 50 iterations default, `--max-iterations 0` for unlimited |
| `TIME_BUDGET = 300` (5 min) | `DETECT_TIMEOUT = 300` seconds |
| `results.tsv` cumulative history | Experiment history table sent with every feedback message |
| Baseline first | Empty template run before first LLM iteration |
| `git reset` on regression | Best-so-far tracking — LLM told when it regressed |
| `stdout > run.log` (lean context) | Conversation reset every 5 iterations |
| "Think harder" when stuck | Explicit encouragement after 5+ low-scoring iterations |
| Single file scope (`train.py`) | Single file scope (`detect.py`) |
| Single scalar metric (`val_bpb`) | Single scalar metric (SNR score 0-100) |

### Hunt Prompts

The hunt prompt tells the Hunter what to look for. Two styles:

**Specific** (hunt.md — the default):
```markdown
# Hunt: Webhook Desync / Double-Spend
You are hunting for CREDIT without matching DEBIT...
```

**Generic** (testrun/hunt_generic.md):
```markdown
# Generic Fraud Detection
Find the fraudulent transactions. You do NOT know what the fraud
pattern looks like. Discover it by exploring the data.
```

The generic prompt tests whether the Hunter can discover patterns autonomously. The specific prompt tests whether it can prove a known hypothesis.

### Running a Hunt

```bash
# Default (uses hunt.md, Anthropic Claude)
atrosa hunt

# Specific provider and model
atrosa hunt --provider openai --model gpt-4.1

# Custom hunt prompt
atrosa hunt --hunt-prompt hunt_kyc_bypass.md

# From the hunt catalog (25 pre-defined categories)
atrosa hunt --hunt-id webhook_desync

# With external data
atrosa hunt --source stripe --api-key sk_live_...

# Point at a specific data directory
atrosa hunt --data-dir testrun/transformed/ieee_cis
```

### Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--provider` | LLM provider (anthropic, openai, gemini, openrouter, local) | anthropic |
| `--model` | Model override | Provider default |
| `--base-url` | Custom API endpoint (local models) | Provider default |
| `--max-iterations` | Max autoresearch iterations (0 = unlimited) | 50 |
| `--hunt-prompt` | Path to hunt prompt file | hunt.md |
| `--hunt-id` | Hunt category from catalog | None |
| `--data-dir` | Data directory override | data/ |
| `--source` | Data connector (csv, stripe, airweave) | None |
| `--tenant` | Tenant ID for multi-customer | default |
| `--production` | Production mode (no ground truth) | false |

---

## 7. The Sentinel

The Sentinel executes graduated rules against live or simulated data streams and triggers automated mitigation.

### Running the Sentinel

```bash
# Simulated mode — replays data in batches
atrosa sentinel

# Custom batch interval (seconds between batches)
atrosa sentinel --interval 5

# Watch mode — tail a directory for new JSONL events
atrosa sentinel --mode watch --watch-dir /var/log/fintech/

# Dry run — detect but skip mitigation
atrosa sentinel --dry-run
```

### Security at Load Time

Before executing a graduated rule, the Sentinel:
1. **Validates the path** — must be within `rules/` or `tenants/` directories
2. **Verifies the hash** — SHA-256 must match the graduation record
3. **Rejects modifications** — if the file was changed after graduation, it's blocked

### Mitigation Actions

| Action | What It Does |
|--------|-------------|
| `log_alert` | Append to `sentinel_alerts.jsonl` (default) |
| `suspend_user_id_and_flag_ledger` | Log + print suspension notice |
| `webhook` | POST alert payload to a configured HTTPS URL |
| `slack` | Send formatted alert to Slack webhook |

Custom actions can be registered in the `MitigationRegistry`.

### Alert Format

```json
{
  "alert_id": "ALERT-a1b2c3d4",
  "rule_id": "FIN-RACE-1934C9",
  "threat_hypothesis": "Double-spend via webhook desync...",
  "flagged_tx_ids": ["TXN-CF1C238CF53D"],
  "flagged_user_ids": ["USR-D775472F"],
  "mitigation_action": "suspend_user_id_and_flag_ledger",
  "timestamp": "2026-03-21T22:15:00",
  "execution_time_ms": 45
}
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `SENTINEL_WEBHOOK_URL` | URL for webhook mitigation (must be HTTPS) |
| `SENTINEL_SLACK_WEBHOOK` | Slack incoming webhook URL (must be HTTPS) |

---

## 8. Telemetry Engineer

The feedback loop. When the Hunter can't prove a hypothesis because data is incomplete, the Telemetry Engineer identifies what's missing and generates actionable requests.

### Usage

```bash
# Audit telemetry against ideal fintech schema
atrosa telemetry audit

# Analyze a specific Hunter error
atrosa telemetry analyze --error "KeyError: 'jwt_claims'"

# Full context analysis
atrosa telemetry analyze --hunt-log logs/iteration_03.py --error-log logs/error_03.txt

# Check open observability requests
atrosa telemetry status

# Mark a request as resolved
atrosa telemetry resolve TEL-REQ-A1B2C3

# Deliver to Slack and GitHub
atrosa telemetry audit --channel slack --channel github
```

### Schema Audit

Compares actual telemetry against an ideal fintech schema covering 50+ fields:

- **Critical**: Entire log source missing
- **High**: Required fields missing
- **Medium**: Required fields >50% null
- **Low**: Recommended fields missing (limits future threat classes)

### Delivery Channels

| Channel | Env Variable | Output |
|---------|-------------|--------|
| `console` | — | Terminal output (default) |
| `file` | — | `telemetry_requests_log.jsonl` |
| `slack` | `TELEMETRY_SLACK_WEBHOOK` | Formatted Slack message |
| `github` | `TELEMETRY_GITHUB_REPO` | GitHub Issue with labels |
| `jira` | `TELEMETRY_JIRA_URL/TOKEN/PROJECT` | Jira ticket with priority |

### Orchestrator Integration

The Telemetry Engineer fires automatically when a Hunter iteration crashes. No manual step needed — it parses the error, identifies the data gap, and creates a request.

---

## 9. Schema Normalization

Every customer has different column names. ATROSA's schema normalizer maps them to a canonical schema.

### Auto-Discovery

```python
from schema_normalizer import SchemaNormalizer

# Auto-discover: customer_ref → user_id, http_status → status_code
normalizer = SchemaNormalizer.auto_discover({"api": customer_df})
normalized = normalizer.normalize(customer_df, "api")
```

### Supported Aliases (50+)

| Canonical | Aliases |
|-----------|---------|
| `user_id` | customer_id, account_id, uid, user, customer_ref, client_id |
| `transaction_id` | txn_id, tx_id, reference, ref, payment_id, order_id |
| `timestamp` | ts, time, created_at, event_time, request_time |
| `amount` | value, txn_amount, payment_amount, total |
| `status_code` | http_status, status, response_code, http_code |
| `endpoint` | path, url, route, uri, api_path |

### Value Normalization

| Canonical | Recognized Values |
|-----------|-------------------|
| `CREDIT` | credit, cr, deposit, inflow, receive, incoming, add, top_up |
| `DEBIT` | debit, dr, withdrawal, outflow, send, outgoing, subtract |
| `REVERSAL` | reversal, reverse, refund, chargeback, dispute, rollback, void |
| `success` | success, successful, completed, confirmed, approved, paid, settled |
| `failed` | failed, failure, declined, rejected, error, denied |

### Config-Based Mapping

```python
normalizer = SchemaNormalizer.from_config("tenants/acme/schema_map.json")
```

Config file format:
```json
{
  "column_mappings": {
    "api": {"user_id": "customer_ref", "status_code": "http_status"}
  },
  "value_mappings": {
    "db": {"operation": {"deposit": "CREDIT", "withdrawal": "DEBIT"}}
  }
}
```

---

## 10. Data Source Tiers

ATROSA connects to the customer's existing infrastructure and reads pre-enriched data. More connected sources unlock more detection categories.

### Tier Model

| Tier | What's Connected | Categories | Example Providers |
|------|-----------------|------------|-------------------|
| **0** | API gateway, ledger, mobile, webhooks | 5 | Every fintech has these |
| **1** | + IP risk, device intel, email risk, SIM intel | +6 | MaxMind, Fingerprint, Emailage, Telesign |
| **2** | + KYC/IDV, credit bureau, sanctions, behavioral biometrics | +6 | Jumio, Equifax, World-Check, BioCatch |
| **3** | + blockchain, insurance, card networks, ACH, consortium | +8 | Chainalysis, Verisk, Visa, CIFAS, Plaid |

**5 rules at Tier 0 → 11 at Tier 1 → 17 at Tier 2 → 25 at Tier 3**

### How Tiers Work

ATROSA doesn't integrate with these providers directly. The **customer** already uses them. ATROSA reads the pre-enriched data — IP addresses that already have risk scores, devices that already have fingerprint IDs, KYC checks that already have pass/fail results.

The enrichment shows up as additional columns on the DataFrames. The Hunter sees a richer schema and can write rules that reference those columns.

### Cross-Correlation Advantage

Every tool the customer already pays for has a blind spot:

| Tool | Sees | Blind Spot | ATROSA Fills |
|------|------|-----------|-------------|
| MaxMind | IP risk, geo | What happens after login | Correlates with ledger cashout |
| BioCatch | Behavioral stress | Where money goes | Correlates with beneficiary history |
| Fingerprint | Device identity | Account activity | Correlates with multi-account bonus claims |
| Chainalysis | Wallet risk | Off-chain fiat movements | Correlates with fiat withdrawal in ledger |

No single tool sees the full attack chain. ATROSA sees all of them simultaneously.

---

## 11. Hunt Catalog

25 pre-defined threat categories across all 4 tiers, each with a structured hunt prompt.

### Tier 0: Universal

| ID | Name | Severity |
|----|------|----------|
| `webhook_desync` | Webhook Desync / Double-Spend | Critical |
| `toctou_race_condition` | TOCTOU / Race Condition | Critical |
| `business_logic_flaw` | Business Logic Flaw | High |
| `reversal_abuse` | Refund / Reversal Abuse | High |
| `velocity_anomaly` | Velocity Anomaly (Brute-Force / Enumeration) | High |

### Tier 1: Common Enrichment

| ID | Name | Severity |
|----|------|----------|
| `sim_swap_ato` | SIM Swap Account Takeover | Critical |
| `device_farm_multi_accounting` | Device Farm / Multi-Accounting | High |
| `impossible_travel_cashout` | Impossible Travel + Cashout | Critical |
| `synthetic_identity_onboarding` | Synthetic Identity Onboarding | High |
| `proxy_credential_stuffing` | Proxy-Masked Credential Stuffing | Critical |
| `emulator_promo_abuse` | Emulator-Driven Promo Abuse | Medium |

### Tier 2: Identity & Verification

| ID | Name | Severity |
|----|------|----------|
| `kyc_gated_cashout` | KYC-Gated Cashout Pipeline | Critical |
| `loan_stacking` | Loan Stacking | High |
| `bust_out_acceleration` | Bust-Out Acceleration | High |
| `authorized_push_payment` | Authorized Push Payment Scam | Critical |
| `sanctions_evasion_layering` | Sanctions Evasion via Layering | Critical |
| `deepfake_fast_cashout` | Deepfake Document + Fast Cashout | Critical |

### Tier 3: Sector-Specific

| ID | Name | Severity |
|----|------|----------|
| `crypto_mixer_layering` | Crypto Mixer Layering | Critical |
| `ghost_broking` | Ghost Broking (Insurance) | High |
| `claims_farming` | Claims Farming (Insurance) | High |
| `bin_enumeration_escalation` | BIN Enumeration Escalation | Critical |
| `ach_kiting` | ACH Kiting | High |
| `cross_institution_fraud` | Cross-Institution Fraud | High |
| `inr_chargeback_abuse` | INR Chargeback Abuse | Medium |
| `income_fabrication` | Income Fabrication (Lending) | High |

### Using the Catalog

```bash
# Run a specific hunt category
atrosa hunt --hunt-id webhook_desync

# List available hunts for a tenant's connected sources
python -c "
from hunt_catalog import HuntCatalog
catalog = HuntCatalog()
for h in catalog.get_available_hunts(['api','db','mobile','webhooks','ip_risk']):
    print(f'  [{h.tier}] {h.hunt_id}: {h.name}')
"
```

---

## 12. Scoring System

### Development Mode (Ground Truth)

When ground truth labels exist (`.ground_truth.json`), scoring uses precision and recall:

- **Score = 0**: Script crashed, flagged nothing, or flagged >1% of traffic
- **Score = 100**: Found all anomalies with zero false positives
- Recall weighted 70%, precision weighted 30%

### Production Mode (No Labels)

When no ground truth exists, 4 strategies combine:

| Strategy | Weight | What It Measures |
|----------|--------|------------------|
| Statistical Anomaly | 30% | Flag rate (0.001-0.1%), cross-source depth, temporal clustering |
| Proxy Signals | 35% | Unmatched credits, reversal rates vs population, balance anomalies |
| Retroactive Labels | 25% | F1 against confirmed fraud (chargebacks, SARs) as they arrive |
| Peer Consistency | 10% | Agreement between multiple independent graduated rules |

Production graduation threshold: **70** (vs 100 in dev mode).

---

## 13. Production Mode

```bash
atrosa hunt --production --tenant acme --hunt-id webhook_desync
```

Production mode changes:
- **Scoring**: Multi-strategy (no ground truth needed)
- **LLM temperature**: 0.0 (deterministic output)
- **Audit trail**: Full provenance recorded
- **Graduation threshold**: 70 instead of 100

---

## 14. Multi-Tenancy

Each customer (tenant) gets isolated configuration:

```python
from tenant import Tenant

tenant = Tenant.create("acme_bank", data_sources=[
    "api", "db", "mobile", "webhooks",    # Tier 0
    "ip_risk", "device_intel",              # Tier 1
    "credit_bureau",                        # Tier 2
])

print(tenant.get_active_tiers())    # ['tier_0', 'tier_1', 'tier_2']
print(tenant.get_active_hunts())    # 17 categories
print(tenant.get_noise_budget())    # 0.001 (0.1% max flag rate)
```

Tenant config includes:
- Connected data sources → auto-resolves active tiers and hunt categories
- Noise budget (false positive tolerance)
- Graduation threshold
- Scoring strategy weights
- Isolated rules directory

---

## 15. Security Hardening

### AST Code Validation

LLM-generated code is parsed via Python's `ast` module before execution. Allowlist-based:

**Allowed**: pandas, numpy, json, re, datetime, collections, math, sys, statistics, hashlib, ingest

**Blocked**: os, subprocess, socket, urllib, eval, exec, compile, pickle, shutil, ctypes, multiprocessing, file writes

If the Hunter generates code that fails validation, the feedback loop tells it to try again without the blocked constructs.

### Path Validation + Hash Integrity

The Sentinel validates graduated rules before loading:
- Script path must be within `rules/` or `tenants/` directories
- No path traversal (`..` components rejected)
- Must be a `.py` file
- SHA-256 hash must match the graduation record in `active_rules.json`

### HTTPS Enforcement

All outbound webhook URLs validated: must be `https://` or `localhost`. Blocks `http://` with clear error.

### Code Extraction

Only accepts code in proper ``` fenced blocks from LLM responses. The previous fallback that accepted any text containing "import" and "def detect" was removed as an injection vector.

### Generated Artifacts

`active_rules.json` and `rules/` are gitignored — they're generated artifacts. This prevents supply chain attacks via malicious PRs that modify rule files. The demo rule is preserved in `examples/`.

---

## 16. Audit Trail

Full provenance for every graduated rule:

```python
from audit import AuditTrail

trail = AuditTrail(tenant_id="acme")
trail.start_hunt(hunt_id, prompt_path, provider, model, data_version)
trail.log_iteration(iteration, code, score, feedback)
trail.graduate_rule(rule_id, final_code, final_score)
```

Each graduation record includes:
- Which LLM provider and model generated the code
- SHA-256 hash of the hunt prompt used
- Data version identifier
- Every iteration's code, score, and feedback
- Human-readable rule explanation

### SAR Report Generation

```python
from audit import RuleExplainer

explainer = RuleExplainer()
report = explainer.generate_sar_supplement(transaction_id, rule_id, data)
```

Generates regulatory-ready narrative for Suspicious Activity Reports, including:
- Data sources consulted
- Detection logic steps
- Evidence from each source
- Provenance chain

Compliance targets: FATF Recommendation 20, CBN AML/CFT Framework, PCI-DSS 6.1.

---

## 17. LLM Providers

| Provider | Flag | Default Model | Env Variable | Cost/Hunt |
|----------|------|---------------|--------------|-----------|
| **Anthropic** | `--provider anthropic` | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` | ~$0.12 |
| **OpenAI** | `--provider openai` | `gpt-4o` | `OPENAI_API_KEY` | ~$0.10 |
| **Google Gemini** | `--provider gemini` | `gemini-2.5-flash` | `GEMINI_API_KEY` | ~$0.01 |
| **OpenRouter** | `--provider openrouter` | `anthropic/claude-sonnet-4` | `OPENROUTER_API_KEY` | Varies |
| **Local** | `--provider local` | `qwen2.5-coder:14b` | None | Free |

### Local Models

```bash
# Ollama (default local endpoint)
ollama pull qwen2.5-coder:14b
atrosa hunt --provider local

# LM Studio
atrosa hunt --provider local --base-url http://localhost:1234/v1

# vLLM
atrosa hunt --provider local --base-url http://localhost:8000/v1
```

### Cost Estimate Per Hunt

~3,000-4,000 input tokens + ~1,000-2,000 output tokens per iteration. With 20 iterations: ~$0.30 (Anthropic), ~$0.02 (Gemini Flash), free (local).

---

## 18. Test Run Results

ATROSA was tested against 3 public fraud datasets plus the built-in synthetic telemetry. The Hunter loop was improved based on [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) parameters across these runs.

### Results Summary

| Dataset | Type | Rows | Best Score | Fraud Found | Iterations | Key Finding |
|---------|------|------|-----------|-------------|-----------|-------------|
| **mock_telemetry** | Synthetic (purpose-built) | 26K | **100/100** | 3/3 (100%) | 1 | Architecture proven — cross-source signals work |
| **IEEE-CIS** | **Real** (Vesta e-commerce) | 590K | **18/100** | 420 users (24%) | 20 | Best on real data — scores improve with richer features |
| **Sparkov** | Synthetic (credit card) | 1.3M | 12/100 | 56 users | 10 | Multi-dim data helps, but no balances |
| **PaySim** | Synthetic (mobile money) | 6.3M | 2/100 | 25 txns | 10 | Single-source signal insufficient for cross-correlation |

### Score Progression (IEEE-CIS, 20 iterations)

```
Iter:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
Score: 0  0  0  8  0  0  8 11  -  -  -  -  -  -  -  - 11  - 5  -
```

Iterations marked `-` failed due to context saturation (LLM returned text instead of code) — fixed by conversation reset every 5 iterations.

### Key Insight

Detection quality scales directly with data richness across sources. ATROSA's cross-correlation architecture works when fraud leaves traces in multiple systems simultaneously — which real attacks do.

### Bugs Found and Fixed During Testing

| Bug | Impact | Fix |
|---|---|---|
| 10 iteration cap | Hunter still improving at iteration 10 | Increased to 50 (0=unlimited) |
| 30s execution timeout | Complex scripts on 50K rows timed out | Increased to 300s (5 min) |
| No experiment history | LLM couldn't learn from prior attempts | Added cumulative results table |
| No baseline run | No reference score to improve against | Run empty template first |
| Context saturation after 8 iterations | LLM stopped generating code blocks | Reset conversation every 5 iterations |
| Scorer hints hardcoded for webhook desync | Misled Hunter on non-mock datasets | Made hints generic |
| Code validator blocked `pandas.rename()` | False positive on legitimate operations | Removed from blocklist |
| Code validator blocked `numpy` | Hunter couldn't do statistical analysis | Added to allowlist |
| Independent sampling per DataFrame | Transaction IDs didn't overlap across sources | Sample at transaction level |
| `detect.py` subprocess didn't inherit `--data-dir` | Loaded wrong data directory | Use `ATROSA_DATA_DIR` env var |

### Running Tests

```bash
cd testrun

# Download a dataset
./download.sh paysim       # or: sparkov, ieee_cis, ccfraud, banksim, elliptic

# Transform to ATROSA format
python transform.py paysim --sample 50000

# Run the hunt
./run.sh paysim --hunt-only --provider anthropic
```

See `testrun/README.md` and `testrun/results/` for detailed run reports.

---

## 19. Fraud Landscape Research

ATROSA's threat categories are grounded in real-world fraud incidents. The research paper (`paper_fraud_landscape.md`, gitignored) documents:

- **22 real-world fraud cases** across fintech, banking, insurance, lending
- **$20M+ Revolut** webhook desync exploit (2022)
- **$25M Hong Kong** deepfake CFO video call (2024)
- **$661K+ JPMorgan Chase** "infinite money glitch" (2024)
- **$9.2B** synthetic identity fraud in auto lending (2024)
- **$33.79B** chargeback cost to eCommerce (2025)

Each case maps to specific ATROSA detection categories and includes the cross-correlation pattern the Hunter would use.

### External Data Sources Researched

22 categories of external data sources that customers may already use, mapped to which detection categories they enable when connected via ATROSA's OAuth tap model. Key providers:

- **IP Intelligence**: MaxMind ($28B+ fraud prevented), IPQS, IPinfo
- **Device Fingerprinting**: Fingerprint (23B events analyzed), Sardine, TrustDecision
- **Behavioral Biometrics**: BioCatch (17B sessions/month, 30+ of top 100 banks)
- **SIM/Telco**: Vonage (all US carriers), Telesign, Telefonica Open Gateway
- **Blockchain**: Chainalysis ($34B+ recovered), Elliptic (97% crypto market coverage)
- **Consortium**: CIFAS (UK), Early Warning (65% US bank accounts)

---

## 20. Project Structure

```
atrosa/
├── connectors/             # Data source connectors
│   ├── base.py             #   BaseConnector interface + ConnectorResult
│   ├── csv_import.py       #   CSV/JSONL file import with auto-discovery
│   ├── stripe.py           #   Direct Stripe API connector
│   ├── airweave_adapter.py #   Optional Airweave integration
│   └── auto_discover.py    #   Schema discovery + interactive mapping wizard
├── orchestrator.py         # Hunter autoresearch loop controller
├── sentinel.py             # Live stream enforcement + mitigation
├── ingest.py               # Data loading + SNR scoring harness
├── detect.py               # Detection script (rewritten by Hunter each iteration)
├── providers.py            # Multi-LLM abstraction (Anthropic, OpenAI, Gemini, local)
├── code_validator.py       # AST-based security validation for LLM code
├── scoring.py              # Production scoring (4 strategies, ground-truth-free)
├── schema_normalizer.py    # Customer schema mapping + auto-discovery (50+ aliases)
├── hunt_catalog.py         # 25 threat category definitions + prompt templates
├── audit.py                # Rule provenance tracking + SAR report generation
├── tenant.py               # Multi-tenant configuration + tier resolution
├── telemetry_engineer.py   # Active observability agent + gap analysis
├── mock_telemetry.py       # Synthetic telemetry generator (3 hidden anomalies)
├── hunt.md                 # Default hunt prompt (webhook desync)
├── pyproject.toml          # Python package config
├── examples/               # Example graduated rules
├── testrun/                # Real-world dataset testing pipeline
│   ├── download.sh         #   Dataset downloader (Kaggle)
│   ├── transform.py        #   Universal config-driven transformer
│   ├── run.sh              #   Pipeline runner
│   ├── hunt_generic.md     #   Generic hunt prompt (no pattern hints)
│   └── results/            #   Test run summaries
├── src/atrosa/             # Python package (pip install -e .)
│   └── cli.py              #   CLI entry point
└── node/                   # Node.js/TypeScript CLI (alternative)
```

---

## 21. Contributing

Open an issue or PR. Particularly interested in:

- **Data source connectors**: Paystack, Flutterwave, Adyen, Square, bank core APIs
- **Sentinel integrations**: Kafka consumer, PagerDuty, OpsGenie
- **Hunt prompts**: New financial exploit classes and threat hypotheses
- **Schema normalizer aliases**: Region-specific fintech platforms (African mobile money, SEA e-wallets, LATAM PIX)
- **Regulatory templates**: Jurisdiction-specific SAR formats (FATF, CBN, PCI-DSS, PSD2, MAS)
- **Test datasets**: Public or synthetic datasets with multi-source fraud signals

### License

MIT
