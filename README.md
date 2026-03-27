# ATROSA

**Autonomous Threat Response & Overwatch Swarm Agents**

An agentic cybersecurity platform that hunts for financial business logic flaws — the kind structural scanners miss. An AI agent writes, tests, and proves detection rules against real telemetry, then graduates them for live enforcement.

Built for fintech, banking, insurance, lending, and payments.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## The Problem

Traditional security tools fail against business logic exploits. SIEMs alert on known signatures. Structural scanners see packets, not transaction flows. Neither can detect that a CREDIT landed without a matching DEBIT, or that an account was drained via a race condition.

Real fintech attacks exploit webhook desyncs, TOCTOU gaps, KYC state machine bypasses, and balance manipulation. These are **logic flaws**, not CVEs.

## The Approach

ATROSA treats detection engineering as a code generation problem. An AI agent **writes executable Python detection scripts**, tests them against data, and iterates until the detection is proven. The output is deterministic, auditable Python — not a black-box risk score.

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) pattern.

## Architecture

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

| Component | Role |
|-----------|------|
| **Connectors** | Pull data from Stripe, CSV, Airweave, or any source into 4 DataFrames |
| **Hunter** | AI agent that writes and proves detection scripts iteratively |
| **Sentinel** | Executes graduated rules against live streams, triggers mitigation |
| **Telemetry Engineer** | Detects data gaps, generates observability requests |

## Installation

```bash
git clone https://github.com/obirije/atrosa.git
cd atrosa
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Set one LLM provider key:
export ANTHROPIC_API_KEY="sk-ant-..."    # or OPENAI_API_KEY, GEMINI_API_KEY
```

## Quickstart

```bash
# 1. Generate synthetic telemetry (3 hidden anomalies)
atrosa init

# 2. Run the Hunter — discovers fraud patterns autonomously
atrosa hunt

# 3. Enforce graduated rules against live streams
atrosa sentinel --dry-run
```

## Connecting Real Data

```bash
# From Stripe directly
atrosa hunt --source stripe --api-key sk_live_...

# From exported CSV/JSONL files
atrosa hunt --source csv --data-dir ./exports/

# Via Airweave (optional — for continuous sync)
atrosa hunt --source airweave --collection stripe-prod

# Interactive schema mapping for unknown formats
python -m connectors.auto_discover wizard --file transactions.csv
```

Connectors pull data, auto-discover the schema, transform to ATROSA's 4-DataFrame format, validate cross-source integrity, then feed the Hunter.

## How the Hunter Works

```
hunt.md (threat hypothesis)
    ↓
LLM generates detect.py  ←──── feedback loop
    ↓                              ↑
AST validation (security)          │
    ↓                              │
Execute in subprocess              │
    ↓                              │
Score (SNR 0-100) ─── < 100 ──────┘
    │
    └── = 100 → GRADUATE RULE → rules/*.py → Sentinel enforces
```

- Score = 0: crashed, flagged nothing, or >1% of traffic (too noisy)
- Score = 100: found all anomalies with zero false positives
- Graduated rules are deterministic Python — no LLM at runtime

## Data Source Tiers

ATROSA reads pre-enriched data from the customer's existing stack. More connected sources = more detection categories.

| Tier | What's Connected | Categories Unlocked |
|------|-----------------|-------------------|
| **0** | API gateway, ledger, mobile, webhooks | 5: webhook desync, TOCTOU, business logic, reversal abuse, velocity |
| **1** | + IP risk, device intel, email, SIM | +6: SIM swap ATO, device farms, impossible travel, synthetic ID, credential stuffing, promo abuse |
| **2** | + KYC/IDV, credit bureau, sanctions, behavioral biometrics | +6: KYC cashout, loan stacking, bust-out, push payment scams, sanctions evasion, deepfake |
| **3** | + blockchain, insurance, card networks, ACH, consortium | +8: crypto laundering, ghost broking, claims farming, BIN enumeration, ACH kiting, cross-FI fraud |

**5 rules at Tier 0 → 11 at Tier 1 → 17 at Tier 2 → 25 at Tier 3**

## Test Results (Real-World Datasets)

| Dataset | Type | Best Score | Fraud Found | Key Finding |
|---------|------|-----------|-------------|-------------|
| mock_telemetry | Synthetic (purpose-built) | **100/100** | 3/3 (100%) | Architecture proven |
| IEEE-CIS | **Real** (Vesta e-commerce) | **18/100** | 420 users (24%) | Best on real data — scores improve with richer features |
| Sparkov | Synthetic (credit card) | 12/100 | 56 users | Multi-dim data helps |
| PaySim | Synthetic (mobile money) | 2/100 | 25 txns | Single-source signal insufficient |

Detection quality scales with data richness. See `testrun/` for full results.

## Production Mode

```bash
# No ground truth needed — uses multi-strategy scoring
atrosa hunt --production --tenant acme

# Multi-tenant with automatic hunt category resolution
atrosa hunt --production --tenant acme_bank --hunt-id webhook_desync
```

Production scoring combines statistical anomaly, proxy signals, retroactive labels (chargebacks/SARs), and peer rule consistency. Rules graduate at score >= 70.

## Security

- **AST code validation**: LLM-generated code parsed before execution — blocks `os`, `subprocess`, `socket`, `eval`, network calls
- **Path validation + hash integrity**: Graduated rules verified at load time — modified files rejected
- **HTTPS enforcement**: All outbound webhooks require HTTPS
- **Audit trail**: Full rule provenance — which LLM, prompt, data version, every iteration

## Project Structure

```
atrosa/
├── connectors/             # Data source connectors
│   ├── base.py             #   BaseConnector interface
│   ├── csv_import.py       #   CSV/JSONL file import + auto-discovery
│   ├── stripe.py           #   Direct Stripe API connector
│   ├── airweave_adapter.py #   Optional Airweave integration
│   └── auto_discover.py    #   Schema discovery + mapping wizard CLI
├── orchestrator.py         # Hunter loop controller
├── sentinel.py             # Live stream enforcement
├── ingest.py               # Data loading + scoring
├── detect.py               # Detection script (rewritten by Hunter)
├── providers.py            # Multi-LLM abstraction (Anthropic, OpenAI, Gemini, local)
├── code_validator.py       # AST-based security validation
├── scoring.py              # Production scoring (ground-truth-free)
├── schema_normalizer.py    # Customer schema mapping
├── hunt_catalog.py         # 25 threat category definitions
├── audit.py                # Rule provenance + SAR reports
├── tenant.py               # Multi-tenant configuration
├── telemetry_engineer.py   # Active observability agent
├── hunt.md                 # Default hunt prompt
├── examples/               # Example graduated rules
├── testrun/                # Real-world dataset testing pipeline
└── node/                   # Node.js/TypeScript CLI
```

## Supported LLM Providers

| Provider | Flag | Default Model | Cost/Hunt |
|----------|------|---------------|-----------|
| Anthropic | `--provider anthropic` | Claude Sonnet 4 | ~$0.12 |
| OpenAI | `--provider openai` | GPT-4o | ~$0.10 |
| Google | `--provider gemini` | Gemini 2.5 Flash | ~$0.01 |
| OpenRouter | `--provider openrouter` | Any of 100+ models | Varies |
| Local | `--provider local` | Qwen 2.5 Coder 14B | Free |

## Design Principles

- **Explainable**: Every detection is readable Python, not a risk score
- **Deterministic**: No LLM at runtime — graduated rules are pure Python
- **Proven**: Rules must pass SNR scoring before graduation
- **Auditable**: Full provenance chain for regulatory compliance (FATF, CBN, PCI-DSS)
- **Read-only**: ATROSA taps into existing data — never modifies customer systems

## License

MIT

## Contributing

Open an issue or PR. Interested in:
- Data source connectors (Paystack, Flutterwave, Adyen, bank APIs)
- Sentinel integrations (Kafka, PagerDuty, OpsGenie)
- Hunt prompts for new financial exploit classes
- Regulatory templates for specific jurisdictions
