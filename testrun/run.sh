#!/usr/bin/env bash
# =============================================================================
# ATROSA Test Run — Master Runner
# =============================================================================
# Downloads datasets, transforms them, and runs ATROSA hunts against each.
#
# Usage:
#   ./run.sh                           # Full pipeline: download + transform + hunt
#   ./run.sh --download-only           # Just download datasets
#   ./run.sh --transform-only          # Just transform (assumes downloaded)
#   ./run.sh --hunt-only               # Just run hunts (assumes transformed)
#   ./run.sh --dataset paysim          # Run full pipeline for one dataset
#   ./run.sh --sample 50000            # Limit each source to 50K rows
#   ./run.sh --hunt-id webhook_desync  # Run specific hunt category
#   ./run.sh --provider openai         # Use a specific LLM provider
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/results"

# Defaults
DATASET="all"
SAMPLE=""
HUNT_ID=""
PROVIDER="anthropic"
MODEL=""
PHASE="all"  # all, download, transform, hunt

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
section() { echo -e "\n${CYAN}$1${NC}"; echo -e "${CYAN}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --download-only) PHASE="download"; shift ;;
        --transform-only) PHASE="transform"; shift ;;
        --hunt-only) PHASE="hunt"; shift ;;
        --dataset) DATASET="$2"; shift 2 ;;
        --sample) SAMPLE="$2"; shift 2 ;;
        --hunt-id) HUNT_ID="$2"; shift 2 ;;
        --provider) PROVIDER="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: ./run.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --download-only       Just download datasets"
            echo "  --transform-only      Just transform datasets"
            echo "  --hunt-only           Just run hunts"
            echo "  --dataset NAME        Run for specific dataset (paysim, saml_d, sparkov, etc.)"
            echo "  --sample N            Limit each source to N rows"
            echo "  --hunt-id ID          Run specific hunt category (e.g. webhook_desync)"
            echo "  --provider NAME       LLM provider (anthropic, openai, gemini, local)"
            echo "  --model NAME          Model override"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Available datasets and their transform scripts
declare -A TRANSFORMS=(
    [paysim]="scripts/transform_paysim.py"
    [saml_d]="scripts/transform_saml_d.py"
)

# ===========================
# PHASE 1: DOWNLOAD
# ===========================
phase_download() {
    section "Phase 1: Download Datasets"

    if [ "$DATASET" = "all" ]; then
        bash "$SCRIPT_DIR/download.sh"
    else
        bash "$SCRIPT_DIR/download.sh" "$DATASET"
    fi
}

# ===========================
# PHASE 2: TRANSFORM
# ===========================
phase_transform() {
    section "Phase 2: Transform to ATROSA Format"

    cd "$PROJECT_DIR"
    source .venv/bin/activate 2>/dev/null || true

    local sample_args=""
    [ -n "$SAMPLE" ] && sample_args="--sample $SAMPLE"

    if [ "$DATASET" = "all" ]; then
        for ds in "${!TRANSFORMS[@]}"; do
            local script="${TRANSFORMS[$ds]}"
            if [ -f "$SCRIPT_DIR/$script" ]; then
                log "Transforming $ds..."
                python "$SCRIPT_DIR/$script" $sample_args
            fi
        done
    else
        local script="${TRANSFORMS[$DATASET]:-}"
        if [ -z "$script" ] || [ ! -f "$SCRIPT_DIR/$script" ]; then
            echo "No transform script for dataset: $DATASET"
            echo "Available: ${!TRANSFORMS[*]}"
            exit 1
        fi
        log "Transforming $DATASET..."
        python "$SCRIPT_DIR/$script" $sample_args
    fi
}

# ===========================
# PHASE 3: HUNT
# ===========================
phase_hunt() {
    section "Phase 3: Run ATROSA Hunts"

    cd "$PROJECT_DIR"
    source .venv/bin/activate 2>/dev/null || true
    mkdir -p "$RESULTS_DIR"

    local provider_args="--provider $PROVIDER"
    [ -n "$MODEL" ] && provider_args="$provider_args --model $MODEL"

    run_hunt_on_dataset() {
        local ds_name="$1"
        local data_dir="$SCRIPT_DIR/transformed/$ds_name"

        if [ ! -d "$data_dir" ] || [ -z "$(ls -A "$data_dir" 2>/dev/null)" ]; then
            echo "  [!] No transformed data for $ds_name — skipping"
            return
        fi

        log "Running hunt on $ds_name..."

        # Symlink the transformed data into the project's data/ directory
        local backup_data=""
        if [ -d "$PROJECT_DIR/data" ]; then
            backup_data="$PROJECT_DIR/data.bak.$$"
            mv "$PROJECT_DIR/data" "$backup_data"
        fi
        ln -sfn "$data_dir" "$PROJECT_DIR/data"

        # Run the hunt
        local hunt_args="$provider_args"
        [ -n "$HUNT_ID" ] && hunt_args="$hunt_args --hunt-id $HUNT_ID"

        local result_file="$RESULTS_DIR/${ds_name}_$(date +%Y%m%d_%H%M%S).log"
        python orchestrator.py $hunt_args 2>&1 | tee "$result_file" || true

        # Restore original data
        rm -f "$PROJECT_DIR/data"
        if [ -n "$backup_data" ] && [ -d "$backup_data" ]; then
            mv "$backup_data" "$PROJECT_DIR/data"
        fi

        log "Results saved to $result_file"
    }

    if [ "$DATASET" = "all" ]; then
        for ds in "${!TRANSFORMS[@]}"; do
            run_hunt_on_dataset "$ds"
        done
    else
        run_hunt_on_dataset "$DATASET"
    fi
}

# ===========================
# MAIN
# ===========================
echo "============================================================"
echo "  ATROSA — Test Run Pipeline"
echo "============================================================"
echo "  Dataset:  $DATASET"
echo "  Phase:    $PHASE"
echo "  Provider: $PROVIDER"
[ -n "$SAMPLE" ] && echo "  Sample:   $SAMPLE rows"
[ -n "$HUNT_ID" ] && echo "  Hunt:     $HUNT_ID"
echo "============================================================"

case "$PHASE" in
    all)
        phase_download
        phase_transform
        phase_hunt
        ;;
    download)  phase_download ;;
    transform) phase_transform ;;
    hunt)      phase_hunt ;;
esac

section "Complete"
log "Results in $RESULTS_DIR/"
ls -la "$RESULTS_DIR"/*.log 2>/dev/null || echo "  (no results yet)"
