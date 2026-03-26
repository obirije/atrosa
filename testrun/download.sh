#!/usr/bin/env bash
# =============================================================================
# ATROSA Test Run — Dataset Downloader
# =============================================================================
# Downloads public fraud detection datasets from Kaggle and GitHub.
# Requires: kaggle CLI configured with API credentials
#   mkdir -p ~/.kaggle
#   cp kaggle.json ~/.kaggle/ && chmod 600 ~/.kaggle/kaggle.json
#
# Usage:
#   ./download.sh              # Download all datasets
#   ./download.sh paysim       # Download specific dataset
#   ./download.sh --list       # List available datasets
# =============================================================================

set -euo pipefail

DATASET_DIR="$(cd "$(dirname "$0")" && pwd)/datasets"
mkdir -p "$DATASET_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[X]${NC} $1"; }

# Check kaggle CLI
check_kaggle() {
    if ! command -v kaggle &>/dev/null; then
        err "Kaggle CLI not found. Install with: pip install kaggle"
        exit 1
    fi
    if [ ! -f ~/.kaggle/kaggle.json ]; then
        err "Kaggle credentials not found at ~/.kaggle/kaggle.json"
        echo "  1. Go to https://www.kaggle.com/settings → API → Create New Token"
        echo "  2. mv ~/Downloads/kaggle.json ~/.kaggle/ && chmod 600 ~/.kaggle/kaggle.json"
        exit 1
    fi
}

# ===========================
# DATASET DOWNLOADERS
# ===========================

download_paysim() {
    local dir="$DATASET_DIR/paysim"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "PaySim already downloaded, skipping (use rm -rf $dir to re-download)"
        return
    fi
    log "Downloading PaySim (6.3M mobile money transactions, ~186 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d ealaxi/paysim1 -p "$dir" --unzip
    log "PaySim downloaded to $dir"
}

download_saml_d() {
    local dir="$DATASET_DIR/saml_d"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "SAML-D already downloaded, skipping"
        return
    fi
    log "Downloading SAML-D (9.5M AML transactions, ~193 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d berkanoztas/synthetic-transaction-monitoring-dataset-aml -p "$dir" --unzip
    log "SAML-D downloaded to $dir"
}

download_sparkov() {
    local dir="$DATASET_DIR/sparkov"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "Sparkov already downloaded, skipping"
        return
    fi
    log "Downloading Sparkov (1.3M credit card transactions, ~212 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d kartik2112/fraud-detection -p "$dir" --unzip
    log "Sparkov downloaded to $dir"
}

download_ccfraud() {
    local dir="$DATASET_DIR/ccfraud"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "CC Fraud (ULB) already downloaded, skipping"
        return
    fi
    log "Downloading Credit Card Fraud ULB (284K transactions, ~69 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d mlg-ulb/creditcardfraud -p "$dir" --unzip
    log "CC Fraud downloaded to $dir"
}

download_banksim() {
    local dir="$DATASET_DIR/banksim"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "BankSim already downloaded, skipping"
        return
    fi
    log "Downloading BankSim (594K bank payments, ~14 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d ealaxi/banksim1 -p "$dir" --unzip
    log "BankSim downloaded to $dir"
}

download_baf() {
    local dir="$DATASET_DIR/baf"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "BAF Suite already downloaded, skipping"
        return
    fi
    log "Downloading Feedzai BAF Suite (6x 1M rows, ~558 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d sgpjesus/bank-account-fraud-dataset-neurips-2022 -p "$dir" --unzip
    log "BAF Suite downloaded to $dir"
}

download_ieee_cis() {
    local dir="$DATASET_DIR/ieee_cis"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "IEEE-CIS already downloaded, skipping"
        return
    fi
    log "Downloading IEEE-CIS Fraud Detection (590K transactions, ~500 MB)..."
    mkdir -p "$dir"
    kaggle competitions download -c ieee-fraud-detection -p "$dir" --force
    cd "$dir" && unzip -qo "*.zip" 2>/dev/null; rm -f *.zip 2>/dev/null; cd - >/dev/null
    log "IEEE-CIS downloaded to $dir"
}

download_lending_club() {
    local dir="$DATASET_DIR/lending_club"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "Lending Club already downloaded, skipping"
        return
    fi
    log "Downloading Lending Club (2.26M loans, ~700 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d wordsforthewise/lending-club -p "$dir" --unzip
    log "Lending Club downloaded to $dir"
}

download_insurance() {
    local dir="$DATASET_DIR/insurance"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "Insurance Claims already downloaded, skipping"
        return
    fi
    log "Downloading Insurance Claims Fraud (15K records, ~3 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d shivamb/vehicle-claim-fraud-detection -p "$dir" --unzip
    log "Insurance Claims downloaded to $dir"
}

download_elliptic() {
    local dir="$DATASET_DIR/elliptic"
    if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        warn "Elliptic Bitcoin already downloaded, skipping"
        return
    fi
    log "Downloading Elliptic Bitcoin (200K transactions, ~60 MB)..."
    mkdir -p "$dir"
    kaggle datasets download -d ellipticco/elliptic-data-set -p "$dir" --unzip
    log "Elliptic downloaded to $dir"
}

# ===========================
# MAIN
# ===========================
list_datasets() {
    echo "Available datasets:"
    echo "  paysim        PaySim mobile money transactions (6.3M rows, ~186 MB)"
    echo "  saml_d        SAML-D AML transaction monitoring (9.5M rows, ~193 MB)"
    echo "  sparkov       Sparkov credit card transactions (1.3M rows, ~212 MB)"
    echo "  ccfraud       Credit Card Fraud ULB (284K rows, ~69 MB)"
    echo "  banksim       BankSim bank payments (594K rows, ~14 MB)"
    echo "  baf           Feedzai BAF Suite account fraud (6M rows, ~558 MB)"
    echo "  ieee_cis      IEEE-CIS e-commerce fraud (590K rows, ~500 MB)"
    echo "  lending_club  Lending Club loan data (2.26M rows, ~700 MB)"
    echo "  insurance     Insurance Claims Fraud (15K rows, ~3 MB)"
    echo "  elliptic      Elliptic Bitcoin transactions (200K rows, ~60 MB)"
    echo ""
    echo "Total: ~2.5 GB download"
}

download_all() {
    check_kaggle
    log "Downloading all datasets..."
    echo ""
    download_paysim
    download_saml_d
    download_sparkov
    download_ccfraud
    download_banksim
    download_baf
    download_ieee_cis
    download_lending_club
    download_insurance
    download_elliptic
    echo ""
    log "All datasets downloaded to $DATASET_DIR"
    du -sh "$DATASET_DIR"/*/ 2>/dev/null | sort -rh
}

case "${1:-all}" in
    --list|-l)       list_datasets ;;
    all)             download_all ;;
    paysim)          check_kaggle; download_paysim ;;
    saml_d)          check_kaggle; download_saml_d ;;
    sparkov)         check_kaggle; download_sparkov ;;
    ccfraud)         check_kaggle; download_ccfraud ;;
    banksim)         check_kaggle; download_banksim ;;
    baf)             check_kaggle; download_baf ;;
    ieee_cis)        check_kaggle; download_ieee_cis ;;
    lending_club)    check_kaggle; download_lending_club ;;
    insurance)       check_kaggle; download_insurance ;;
    elliptic)        check_kaggle; download_elliptic ;;
    *)               err "Unknown dataset: $1"; list_datasets; exit 1 ;;
esac
