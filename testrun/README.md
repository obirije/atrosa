# ATROSA Test Run — Real-World Dataset Testing

End-to-end pipeline for testing ATROSA's detection capabilities against public fraud datasets.

## Quick Start

```bash
# 1. Set up Kaggle API credentials (one-time)
#    Go to https://www.kaggle.com/settings → API → Create New Token
mkdir -p ~/.kaggle
mv ~/Downloads/kaggle.json ~/.kaggle/
chmod 600 ~/.kaggle/kaggle.json

# 2. Run the full pipeline (download → transform → hunt)
cd testrun
./run.sh --dataset paysim

# Or run just one phase
./run.sh --download-only
./run.sh --transform-only --sample 50000
./run.sh --hunt-only --dataset paysim --provider anthropic
```

## Directory Structure

```
testrun/
├── download.sh               # Dataset downloader (Kaggle + GitHub)
├── run.sh                    # Master pipeline runner
├── README.md                 # This file
├── datasets/                 # Raw downloaded data (gitignored)
│   ├── paysim/               # PaySim mobile money (6.3M txns)
│   ├── saml_d/               # SAML-D AML monitoring (9.5M txns)
│   ├── sparkov/              # Sparkov credit card (1.3M txns)
│   ├── ccfraud/              # ULB credit card fraud (284K txns)
│   ├── banksim/              # BankSim bank payments (594K txns)
│   ├── baf/                  # Feedzai BAF account fraud (6M rows)
│   ├── ieee_cis/             # IEEE-CIS e-commerce (590K txns)
│   ├── lending_club/         # Lending Club loans (2.26M records)
│   ├── insurance/            # Insurance claims fraud (15K records)
│   └── elliptic/             # Elliptic Bitcoin (200K txns)
├── scripts/                  # Transform scripts (raw → ATROSA format)
│   ├── transform_paysim.py
│   └── transform_saml_d.py
├── transformed/              # ATROSA-format JSONL files (gitignored)
│   ├── paysim/
│   │   ├── api_gateway.jsonl
│   │   ├── ledger_db_commits.jsonl
│   │   ├── mobile_client_errors.jsonl
│   │   ├── payment_webhooks.jsonl
│   │   └── .ground_truth.json
│   └── saml_d/
│       └── ...
└── results/                  # Hunt run logs (gitignored)
```

## Available Datasets

| Dataset | Size | Rows | Fraud Rate | Best For | License |
|---------|------|------|------------|----------|---------|
| **PaySim** | 186 MB | 6.3M | 0.13% | ATO, money mule, balance manipulation | CC BY-SA 4.0 |
| **SAML-D** | 193 MB | 9.5M | 0.1% | AML typologies, cross-border laundering | CC BY-NC-SA 4.0 |
| **Sparkov** | 212 MB | 1.3M | 0.58% | Card fraud, merchant-category patterns | CC0 Public Domain |
| **CC Fraud (ULB)** | 69 MB | 284K | 0.17% | Card fraud benchmark (PCA features) | ODbL |
| **BankSim** | 14 MB | 594K | 1.2% | Bank payment fraud | CC BY-NC-SA 4.0 |
| **Feedzai BAF** | 558 MB | 6M | varies | Account opening fraud, KYC bypass | CC BY-NC-SA 4.0 |
| **IEEE-CIS** | 500 MB | 590K | 3.5% | Card fraud with device/identity features | Research |
| **Lending Club** | 700 MB | 2.26M | ~15% default | Loan stacking, bust-out patterns | Public |
| **Insurance** | 3 MB | 15K | ~6% | Claims fraud, reversal abuse | Various |
| **Elliptic** | 60 MB | 200K | ~2% illicit | Crypto laundering, mixer detection | MIT |

Total download: ~2.5 GB

## Dataset → ATROSA Category Mapping

| Dataset | Webhook Desync | TOCTOU | Business Logic | ATO | Money Mule | Reversal Abuse | BIN Enum |
|---------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| PaySim | - | - | x | x | x | x | - |
| SAML-D | - | - | x | - | x | - | - |
| Sparkov | - | - | - | - | - | - | x |
| CC Fraud | - | - | - | - | - | - | x |
| BankSim | - | - | x | - | x | - | - |
| BAF | - | - | - | x | - | - | - |
| IEEE-CIS | - | - | x | x | - | - | x |
| Lending Club | - | - | x | - | - | - | - |
| Insurance | - | - | x | - | - | x | - |
| Elliptic | - | - | - | - | x | - | - |

## Transform Scripts

Each transform script converts a raw dataset into ATROSA's 4-DataFrame format:

- `api_gateway.jsonl` — API request logs (endpoint, status_code, ip_address, amount, etc.)
- `ledger_db_commits.jsonl` — Balance mutations (CREDIT/DEBIT, balance_before/after)
- `mobile_client_errors.jsonl` — Mobile client events (error_code, screen, device_os)
- `payment_webhooks.jsonl` — Payment callbacks (status, delivery_attempt, latency_ms)
- `.ground_truth.json` — Fraud labels for scoring

### Writing Your Own Transform

```python
# testrun/scripts/transform_mydata.py

def transform(df):
    return {
        "api": df_api,        # Must have: timestamp, user_id, endpoint, status_code, transaction_id
        "db": df_db,          # Must have: timestamp, user_id, operation, amount, transaction_id
        "mobile": df_mobile,  # Must have: timestamp, user_id, event_type
        "webhooks": df_webhooks,  # Must have: timestamp, transaction_id, status, provider
        "ground_truth": {
            "anomaly_count": N,
            "attacker_transaction_ids": [...],
            "attacker_user_ids": [...],
        },
    }
```

## Running Hunts

```bash
# Run the default webhook_desync hunt on PaySim data
./run.sh --hunt-only --dataset paysim

# Run a specific hunt category
./run.sh --hunt-only --dataset paysim --hunt-id velocity_anomaly

# Use a different LLM provider
./run.sh --hunt-only --dataset saml_d --provider openai --model gpt-4o

# Quick test with sampled data (50K rows per source)
./run.sh --dataset paysim --sample 50000

# Run with local model (no API key needed)
./run.sh --hunt-only --dataset paysim --provider local --model qwen2.5-coder:14b
```

### What Happens During a Hunt

1. Transformed data is symlinked into the project's `data/` directory
2. The orchestrator loads the 4 DataFrames
3. The Hunter LLM generates detection code (`detect.py`)
4. Code is validated by `code_validator.py` (AST safety check)
5. Code is executed in a subprocess with a 30s timeout
6. Results are scored against ground truth
7. The loop iterates until score=100 or max iterations reached
8. Results are saved to `testrun/results/`

## Run Script Options

```
./run.sh [OPTIONS]

  --download-only       Just download datasets
  --transform-only      Just transform (assumes downloaded)
  --hunt-only           Just run hunts (assumes transformed)
  --dataset NAME        Run for specific dataset (paysim, saml_d)
  --sample N            Limit each source to N rows for quick testing
  --hunt-id ID          Run specific hunt category
  --provider NAME       LLM provider (anthropic, openai, gemini, local)
  --model NAME          Model override
```

## Adding New Datasets

1. Add a download function to `download.sh`
2. Create `scripts/transform_<name>.py` with the standard transform interface
3. Add the entry to the `TRANSFORMS` map in `run.sh`
4. Run `./run.sh --dataset <name>`
