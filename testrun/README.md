# ATROSA Test Run — Real-World Dataset Testing

End-to-end pipeline for testing ATROSA against public fraud datasets.

## Quick Start

```bash
# 1. Set up Kaggle credentials (one-time)
#    https://www.kaggle.com/settings → API → Create New Token
mkdir -p ~/.kaggle
mv ~/Downloads/kaggle.json ~/.kaggle/
chmod 600 ~/.kaggle/kaggle.json

# 2. Run the full pipeline for a dataset
cd testrun
./run.sh paysim

# Quick test with sampled data
./run.sh paysim --sample 50000
```

## How It Works

```
download.sh          →  datasets/paysim/*.csv        (raw Kaggle data)
    ↓
transform.py paysim  →  transformed/paysim/*.jsonl   (ATROSA 4-DataFrame format)
    ↓
orchestrator.py      →  results/*.log                (hunt results)
  --data-dir transformed/paysim/
```

1. `download.sh` fetches the raw CSV from Kaggle
2. `transform.py` converts it to ATROSA's 4 JSONL files using the schema normalizer and a per-dataset config (column mappings, fraud labels, type→endpoint maps)
3. The orchestrator runs the Hunter against the transformed data via `--data-dir`

No symlinks, no temp files, no hacks.

## Directory Structure

```
testrun/
├── download.sh          # Fetches datasets from Kaggle
├── transform.py         # Universal transformer (config-driven, uses schema_normalizer)
├── run.sh               # Thin wrapper: download → transform → hunt
├── README.md
├── datasets/            # Raw downloads (gitignored)
├── transformed/         # ATROSA-format JSONL (gitignored)
└── results/             # Hunt run logs (gitignored)
```

## Available Datasets

```bash
./download.sh --list
```

| Dataset | Size | Rows | Fraud Rate | Best For | License |
|---------|------|------|------------|----------|---------|
| **paysim** | 186 MB | 6.3M | 0.13% | ATO, money mule, balance manipulation | CC BY-SA 4.0 |
| **saml_d** | 193 MB | 9.5M | 0.1% | AML typologies, cross-border laundering | CC BY-NC-SA 4.0 |
| **sparkov** | 212 MB | 1.3M | 0.58% | Card fraud, merchant-category patterns | CC0 |
| **ccfraud** | 69 MB | 284K | 0.17% | Card fraud benchmark (PCA features) | ODbL |
| **banksim** | 14 MB | 594K | 1.2% | Bank payment fraud | CC BY-NC-SA 4.0 |
| **baf** | 558 MB | 6M | varies | Account opening fraud, KYC bypass | CC BY-NC-SA 4.0 |
| **ieee_cis** | 500 MB | 590K | 3.5% | Card fraud + device/identity features | Research |
| **lending_club** | 700 MB | 2.26M | ~15% default | Loan stacking, bust-out patterns | Public |
| **insurance** | 3 MB | 15K | ~6% | Claims fraud, reversal abuse | Various |
| **elliptic** | 60 MB | 200K | ~2% illicit | Crypto laundering, mixer detection | MIT |

## Transform Architecture

`transform.py` uses **one universal transformer class** driven by per-dataset configs:

```python
DATASET_CONFIGS = {
    "paysim": {
        "fraud_column": "isFraud",
        "user_id_column": "nameOrig",
        "timestamp_mode": "step_hours",       # 1 step = 1 hour
        "type_to_endpoint": {                  # Raw type → ATROSA API endpoint
            "CASH_IN": "/api/v2/wallet/deposit",
            "TRANSFER": "/api/v2/transfer/initiate",
        },
        "type_to_operation": {                 # Raw type → ledger operation
            "CASH_IN": "CREDIT",
            "TRANSFER": "DEBIT",
        },
        "balance_before_column": "oldbalanceOrg",
        "balance_after_column": "newbalanceOrig",
    },
}
```

Each config tells the transformer:
- Where the fraud label is and what values mean "fraud"
- How to extract user IDs, timestamps, and amounts
- How to map raw transaction types to ATROSA endpoints and ledger operations
- Which columns have balance data (if any)

The transformer generates all 4 ATROSA DataFrames from this config, including synthetic mobile events for fraud transactions (network errors on the transfer screen) and webhook callbacks with appropriate latency patterns.

### Adding a New Dataset

1. Add a download function to `download.sh`
2. Add a config entry to `DATASET_CONFIGS` in `transform.py`
3. Run `./run.sh <name>`

No new script needed — the universal transformer handles it.

## Usage

```bash
# Full pipeline
./run.sh paysim
./run.sh saml_d --sample 100000

# Individual steps
./run.sh paysim --transform-only
./run.sh paysim --hunt-only

# With LLM options
./run.sh paysim --provider openai --model gpt-4o
./run.sh paysim --hunt-id velocity_anomaly
./run.sh paysim --provider local

# Transform directly (no shell wrapper)
python transform.py paysim --sample 50000
python transform.py --list
```
