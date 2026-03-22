# ATROSA

**Autonomous Threat Response & Overwatch Swarm Agents**

An agentic cybersecurity platform that hunts for financial business logic flaws — the kind structural scanners miss. ATROSA uses an AI-driven iterative loop to hypothesize, write, test, and prove detection rules against real telemetry, then graduates those rules for live production enforcement.

Built for fintech, banking, and payments infrastructure.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## The Problem

Traditional security tools fail against business logic exploits in financial systems:

- **SIEMs** alert on known signatures — they can't reason about multi-step transaction flows
- **eBPF/structural scanners** see syscalls and network packets — they can't see that a CREDIT landed without a matching DEBIT
- **Manual threat hunting** doesn't scale when you process millions of transactions daily

Real fintech attacks exploit asynchronous race conditions, webhook desyncs, TOCTOU gaps, and KYC state machine bypasses. These are **logic flaws**, not CVEs. No scanner has a signature for them.

## The Approach

ATROSA treats detection engineering as a code generation problem. Instead of static rules, an AI agent **writes executable Python detection scripts**, tests them against historical data, and iterates until the detection is mathematically proven — zero false positives, zero missed anomalies.

The output is deterministic, human-readable Python — not a black-box risk score. Every graduated rule can be audited, version-controlled, and explained to a regulator.

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) iterative loop pattern.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ATROSA SWARM                                │
│                                                                      │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐        │
│  │ CARTOGRAPHER │───▶│ HUNTER SWARM │───▶│  SENTINEL SWARM  │        │
│  │  (Ingest)    │    │  (Detect)    │    │  (Enforce)       │        │
│  │              │    │              │    │                  │        │
│  │ API gateway  │    │ Hypothesize  │    │ Execute proven   │        │
│  │ Ledger DB    │    │ Write code   │    │ rules against    │        │
│  │ Mobile logs  │    │ Test & score │    │ live streams     │        │
│  │ Webhooks     │    │ Iterate      │    │ Trigger response │        │
│  └──────▲──────┘    │ Graduate     │    └──────────────────┘        │
│         │           └──────┬───────┘                                │
│         │                  │ Hunt blocked?                           │
│         │           ┌──────▼───────────────┐                        │
│         │           │  TELEMETRY ENGINEER   │                        │
│         │           │  (Active Observability)│                        │
│         │           │                       │                        │
│         │           │  Detect data gaps     │ ──▶ Slack / Jira /    │
│         │           │  Audit schema         │     GitHub Issues     │
│         │           │  Track requests       │                        │
│         │           └──────┬───────────────┘                        │
│         │                  │ Gap resolved                            │
│         └──────────────────┘                                        │
│              Enriched telemetry feeds next hunt                      │
└─────────────────────────────────────────────────────────────────────┘
```

| Swarm | Role | Status |
|-------|------|--------|
| **Cartographer** | Ingests fragmented telemetry into queryable DataFrames | MVP |
| **Hunter** | AI agent that writes & proves detection scripts iteratively | MVP |
| **Sentinel** | Executes graduated rules against live streams, triggers mitigation | MVP |
| **Telemetry Engineer** | Detects data gaps, generates observability requests for DevOps | MVP |

## How the Hunter Loop Works

```
         ┌──────────────────────────────┐
         │    hunt.md (System Prompt)    │
         └──────────────┬───────────────┘
                        │
                        ▼
              ┌───────────────────┐
         ┌───│   LLM generates   │
         │   │   detect.py code   │
         │   └────────┬──────────┘
         │            │
         │            ▼
         │   ┌───────────────────┐
         │   │  Execute detect.py │
         │   │  (subprocess)      │
         │   └────────┬──────────┘
         │            │
         │            ▼
         │   ┌───────────────────┐
  Score  │   │   SNR Scoring     │──── Score = 100 ──▶ GRADUATE RULE
  < 100  │   │   (0-100)         │                     ▶ active_rules.json
         │   └────────┬──────────┘                     ▶ rules/*.py
         │            │
         └────────────┘
        feedback loop
```

**Scoring (Signal-to-Noise Ratio):**
- **Score = 0**: Script crashed, flagged nothing, or flagged >1% of traffic (too noisy)
- **Score = 100**: Isolated exactly the anomalous events with zero false positives
- Partial credit for partial matches, weighted by recall and precision

## Installation

### Python (pip)

```bash
git clone https://github.com/obirije/atrosa.git
cd atrosa

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This gives you the `atrosa` CLI command.

### Node.js (npm)

```bash
cd atrosa/node
npm install
npm run build
```

Then use `npx atrosa` or `node dist/bin/atrosa.js`. Note: the Node.js CLI still requires Python installed for executing detection scripts.

### API Keys

```bash
# Pick ONE — whichever provider you want to use:
export ANTHROPIC_API_KEY="sk-ant-..."       # Anthropic (Claude)
export OPENAI_API_KEY="sk-..."              # OpenAI
export GEMINI_API_KEY="..."                 # Google Gemini
export OPENROUTER_API_KEY="sk-or-..."       # OpenRouter
# Local models (Ollama, LM Studio) need no key
```

## Quickstart

### 1. Generate synthetic telemetry

```bash
atrosa init
```

Creates a 24-hour fintech dataset (~26,000 events across 4 sources) with 3 hidden double-spend anomalies injected.

### 2. Run the Hunter

```bash
# Default: Anthropic Claude Sonnet
atrosa hunt

# OpenAI
atrosa hunt --provider openai
atrosa hunt --provider openai --model gpt-4.1

# Google Gemini
atrosa hunt --provider gemini

# OpenRouter (access 100+ models)
atrosa hunt --provider openrouter --model google/gemini-2.5-pro

# Local models (Ollama)
atrosa hunt --provider local --model qwen2.5-coder:14b

# Local models (LM Studio / vLLM)
atrosa hunt --provider local --model deepseek-coder-v2 --base-url http://localhost:1234/v1
```

The orchestrator will:
1. Load telemetry into DataFrames
2. Send the hunt prompt + schema to the LLM
3. Receive a `detect.py` rewrite
4. Execute it in an isolated subprocess
5. Score the output
6. Feed the score back for iteration
7. Graduate the rule on a perfect score

### 3. Run the Sentinel (live enforcement)

```bash
# Simulate a live stream by replaying telemetry in batches
atrosa sentinel

# Fast replay with smaller batches
atrosa sentinel --interval 0 --batch-size 1000

# Dry run — detect but skip mitigation
atrosa sentinel --dry-run
```

### 4. Audit telemetry coverage

```bash
# Check what data gaps exist in your telemetry
atrosa telemetry audit

# See all open observability requests
atrosa telemetry status
```

The Telemetry Engineer also fires automatically when Hunter iterations crash due to missing data — no manual step needed.

### 5. Inspect results

```bash
cat active_rules.json        # Graduated rule metadata
cat rules/fin_race_*.py      # The proven detection script
cat sentinel_alerts.jsonl     # Alerts triggered by the Sentinel
```

## Project Structure

```
atrosa/
├── src/atrosa/              # Python package (pip install -e .)
│   ├── cli.py               # CLI entry point — `atrosa` command
│   ├── orchestrator.py      # Hunter loop controller
│   ├── sentinel.py          # Live stream monitor & response
│   ├── telemetry_engineer.py# Active observability agent
│   ├── providers.py         # Multi-LLM provider abstraction
│   ├── ingest.py            # Data loading + SNR scoring harness
│   └── mock_telemetry.py    # Synthetic telemetry generator
├── node/                    # Node.js/TypeScript CLI
│   ├── src/
│   │   ├── cli.ts           # Commander.js entry point
│   │   ├── commands/        # hunt, sentinel, telemetry, init
│   │   ├── providers/       # Anthropic, OpenAI, Gemini, local
│   │   ├── engine/          # Ingest, scoring, rule engine
│   │   ├── telemetry/       # Gap analyzer, requests, delivery
│   │   └── mock/            # Synthetic data generator
│   └── package.json
├── pyproject.toml           # Python package config
├── hunt.md                  # System prompt for the Hunter LLM
├── detect.py                # The file the Hunter iteratively rewrites
├── active_rules.json        # Graduated rule registry
├── rules/                   # Proven detection scripts
├── logs/                    # Iteration logs (code + scores per run)
└── data/                    # Generated telemetry (gitignored)
```

## Example: Graduated Rule

The first hunt targets **double-spend via webhook desync** — a real attack pattern where:

1. User initiates a transfer via the API
2. User forces a network disconnect on their mobile device
3. The payment webhook arrives late, crediting the destination
4. The source account is never debited (the debit was lost in the race)
5. Result: money created from nothing

ATROSA's Hunter detected this by cross-correlating 4 data sources in a single pass:

```
Successful webhook (payment.completed)
  + CREDIT in ledger WITHOUT matching DEBIT
  + E_NETWORK_LOST on mobile transfer screen
  + API /transfer/initiate call in the same window
  = ANOMALY (3/3 detected, 0 false positives, Score: 100/100)
```

The graduated rule (`rules/fin_race_1934c9.py`) is a deterministic Python script — no LLM in the execution path. It can be audited line-by-line for regulatory compliance.

## Benchmarks

Results from the first end-to-end run on synthetic telemetry:

**Hunter (Rule Generation)**
| Metric | Result |
|--------|--------|
| Iterations to perfect score | 1 |
| SNR Score | 100/100 |
| Anomalies detected | 3/3 |
| False positives | 0 |
| Model used | Claude Sonnet 4 |

**Sentinel (Live Enforcement)**
| Metric | Result |
|--------|--------|
| Events scanned | 26,012 |
| Batches processed | 27 |
| Total runtime | 1.0s |
| Alerts triggered | 3 (all true positives) |
| Avg rule execution | ~35ms per batch |
| False positives | 0 |

**Telemetry Engineer (Schema Audit)**
| Metric | Result |
|--------|--------|
| Fields audited | 50+ across 4 sources |
| Gaps detected | 43 (4 medium, 39 recommended) |
| Critical gaps | 0 (all required sources present) |
| Requests generated | 43 with actionable DevOps instructions |

The Hunter writes the rule; the Sentinel runs it at production speed; the Telemetry Engineer closes the feedback loop. No LLM in the enforcement path.

## Sentinel Swarm (Live Enforcement)

Once the Hunter graduates a rule, the Sentinel executes it against live data streams. It watches for new events, runs every proven rule, and triggers automated mitigation when threats are detected.

```
          Live Events                    Graduated Rules
               │                              │
               ▼                              ▼
┌──────────────────────────────────────────────────┐
│                   SENTINEL                        │
│                                                   │
│  ┌─────────┐   ┌──────────┐   ┌──────────────┐  │
│  │ Ingest   │──▶│ Rule     │──▶│ Mitigation   │  │
│  │ Stream   │   │ Engine   │   │ Actions      │  │
│  └─────────┘   └──────────┘   └──────────────┘  │
│                                                   │
│  Sources:          Runs all         Actions:      │
│  • Kafka topic     rules/*.py       • Freeze user │
│  • Kinesis         against each     • Halt txn    │
│  • Webhook relay   event batch      • Slack alert │
│  • Log tail                         • Webhook     │
│  • Simulated                        • Custom      │
└──────────────────────────────────────────────────┘
```

### Running the Sentinel

```bash
# Simulated mode — replays mock telemetry as a live stream
atrosa sentinel

# With custom batch interval
atrosa sentinel --interval 5

# Watch mode — tail a directory for new events
atrosa sentinel --mode watch --watch-dir /var/log/fintech/

# Dry run — detect but don't execute mitigation actions
atrosa sentinel --dry-run
```

### Mitigation Actions

When a rule fires, the Sentinel executes the configured mitigation action. Built-in actions:

| Action | What it does |
|--------|-------------|
| `log_alert` | Logs the detection to `sentinel_alerts.jsonl` (default) |
| `suspend_user_id_and_flag_ledger` | Logs alert + prints suspension notice |
| `webhook` | POSTs alert payload to a configured URL |
| `slack` | Sends alert to a Slack webhook |

Custom actions can be added as Python functions in the mitigation registry.

### Alert Output

Every detection produces a structured alert:

```json
{
  "alert_id": "ALERT-a1b2c3d4",
  "rule_id": "FIN-RACE-1934C9",
  "threat_hypothesis": "Double-spend via webhook desync...",
  "flagged_tx_ids": ["TXN-CF1C238CF53D"],
  "flagged_user_ids": ["USR-D775472F"],
  "mitigation_action": "suspend_user_id_and_flag_ledger",
  "timestamp": "2026-03-21T22:15:00",
  "batch_size": 500,
  "execution_time_ms": 45
}
```

## Telemetry Engineer (Active Observability)

The feedback loop. When a Hunter can't prove a hypothesis because the data is incomplete, the Telemetry Engineer identifies exactly what's missing and generates actionable requests for your DevOps team.

```
┌──────────────────────────────────────────────────────────┐
│              TELEMETRY ENGINEER                           │
│                                                          │
│  Audit Mode          Error Analysis       Request Mgmt   │
│  ┌────────────┐     ┌──────────────┐     ┌───────────┐  │
│  │ Compare     │     │ Parse Hunter │     │ Track     │  │
│  │ schema vs   │     │ errors for   │     │ open /    │  │
│  │ ideal       │     │ data gaps    │     │ resolved  │  │
│  └──────┬─────┘     └──────┬───────┘     └───────────┘  │
│         │                  │                             │
│         ▼                  ▼                             │
│  ┌─────────────────────────────────────┐                 │
│  │          Delivery Channels          │                 │
│  │  Console • Slack • GitHub • Jira    │                 │
│  └─────────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Audit telemetry against the ideal fintech schema
atrosa telemetry audit

# Analyze a specific Hunter error
atrosa telemetry analyze --error "KeyError: 'jwt_claims'"

# Analyze with full context from iteration logs
atrosa telemetry analyze --hunt-log logs/iteration_03.py --error-log logs/error_03.txt

# Check status of all observability requests
atrosa telemetry status

# Mark a request as resolved (after DevOps enables the logging)
atrosa telemetry resolve TEL-REQ-A1B2C3

# Deliver requests to Slack and GitHub Issues
atrosa telemetry audit --channel slack --channel github
```

### How it works

**Schema Audit** compares your actual telemetry against an ideal fintech schema covering 50+ fields across all 4 sources. It flags:
- **Critical**: Entire log source missing
- **High**: Required fields missing
- **Medium**: Required fields >50% null (sparse data)
- **Low**: Recommended fields missing (limits future threat classes)

**Error Analysis** parses Hunter crash output and detection code to identify specific data gaps — e.g., if the Hunter tried to access `jwt_claims` and got a `KeyError`, the Telemetry Engineer creates an urgent request to enable JWT logging on the API gateway.

**Orchestrator Integration** — the Telemetry Engineer is automatically invoked when a Hunter iteration crashes. No manual intervention needed.

### Delivery Channels

| Channel | Env Variable | What it does |
|---------|-------------|-------------|
| `console` | — | Print to terminal (default) |
| `file` | — | Append to `telemetry_requests_log.jsonl` |
| `slack` | `TELEMETRY_SLACK_WEBHOOK` | Send formatted message to Slack |
| `github` | `TELEMETRY_GITHUB_REPO` | Create GitHub Issue with labels |
| `jira` | `TELEMETRY_JIRA_URL`, `_TOKEN`, `_PROJECT` | Create Jira ticket with priority |

## Extending ATROSA

### Writing new hunt prompts

Create a new `hunt_*.md` with a different hypothesis:

```markdown
# Hunt: KYC State Machine Bypass
You are hunting for users who reach "verified" status
without completing all required KYC steps...
```

Then point the orchestrator at it:

```bash
atrosa hunt --hunt-prompt hunt_kyc_bypass.md
```

### Adding real telemetry

Replace `mock_telemetry.py` with connectors to your actual log sources. The only contract is that `ingest.py:setup()` returns DataFrames with consistent column names. Plug in:

- **API gateway**: AWS ALB logs, Kong, Nginx
- **Ledger**: PostgreSQL CDC, DynamoDB streams
- **Mobile**: Firebase Crashlytics, Sentry
- **Webhooks**: Stripe/Paystack/Flutterwave event logs

### Adjusting the scoring

Modify `ingest.py:score_detections()` to match your environment. The current scorer checks against a ground truth file — in production, you'd use labeled incident data or anomaly review queues.

## Threat Classes (Roadmap)

| Class | Description | Status |
|-------|-------------|--------|
| `FIN-RACE-*` | Async race conditions / double-spend via webhook desync | Proven |
| `FIN-TOCTOU-*` | Time-of-check/time-of-use in balance verification | Planned |
| `FIN-KYC-*` | KYC state machine bypasses (skipping verification steps) | Planned |
| `FIN-REPLAY-*` | Idempotency key replay / transaction duplication | Planned |
| `FIN-PRIV-*` | Privilege escalation via role/permission desync | Planned |

## Design Principles

- **Explainable AI**: Every detection is a readable Python script, not a probability score. Ship it to your compliance team.
- **Deterministic execution**: No LLM in the hot path. Graduated rules are pure Python running against DataFrames.
- **Iterative proof**: Rules aren't deployed on vibes. They must achieve a perfect SNR score against historical data before graduation.
- **Separation of concerns**: Heavy LLM compute (Hunter) is decoupled from sub-second production execution (Sentinel).
- **Closed feedback loop**: The Telemetry Engineer ensures hunts are never permanently blocked by missing data — it identifies gaps, requests fixes, and tracks resolution.

## Supported Providers

| Provider | Flag | Default Model | Env Variable | Notes |
|----------|------|---------------|--------------|-------|
| **Anthropic** | `--provider anthropic` | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` | Default provider |
| **OpenAI** | `--provider openai` | `gpt-4o` | `OPENAI_API_KEY` | GPT-4o, GPT-4.1, o1, etc. |
| **Google Gemini** | `--provider gemini` | `gemini-2.5-flash` | `GEMINI_API_KEY` | Native Gemini API |
| **OpenRouter** | `--provider openrouter` | `anthropic/claude-sonnet-4` | `OPENROUTER_API_KEY` | Access 100+ models |
| **Local** | `--provider local` | `qwen2.5-coder:14b` | None | Ollama, LM Studio, vLLM |

Override the default model with `--model`:

```bash
atrosa hunt --provider openai --model gpt-4.1
atrosa hunt --provider local --model llama3.3:70b
```

For local models, set a custom endpoint with `--base-url`:

```bash
# Ollama (default)
atrosa hunt --provider local

# LM Studio
atrosa hunt --provider local --base-url http://localhost:1234/v1

# vLLM
atrosa hunt --provider local --base-url http://localhost:8000/v1
```

## Requirements

**Python CLI:**
- Python 3.12+
- At least one LLM provider (API key or local model server)

**Node.js CLI:**
- Node.js 18+
- Python 3.12+ (for executing detection scripts)
- At least one LLM provider

## License

MIT

## Contributing

Open an issue or PR. Particularly interested in:
- New hunt prompts for different financial exploit classes
- Real-world telemetry connectors (Kafka, Kinesis, CloudTrail)
- Sentinel integrations (Kafka consumer, Kinesis, PagerDuty, OpsGenie)
- Scoring improvements for production environments without ground truth
