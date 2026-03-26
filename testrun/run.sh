#!/usr/bin/env bash
# =============================================================================
# ATROSA Test Run — Pipeline Runner
# =============================================================================
# Usage:
#   ./run.sh paysim                              # Download + transform + hunt
#   ./run.sh paysim --sample 50000               # Quick test with 50K rows
#   ./run.sh paysim --transform-only             # Just download and transform
#   ./run.sh paysim --hunt-only                  # Just hunt (assumes transformed)
#   ./run.sh paysim --provider openai            # Use OpenAI
#   ./run.sh paysim --hunt-id velocity_anomaly   # Specific hunt category
#   ./run.sh --list                              # List available datasets
# =============================================================================

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$DIR")"

if [ "${1:-}" = "--list" ] || [ "${1:-}" = "-l" ]; then
    bash "$DIR/download.sh" --list
    exit 0
fi

if [ -z "${1:-}" ]; then
    echo "Usage: ./run.sh <dataset> [OPTIONS]"
    echo "       ./run.sh --list"
    exit 1
fi

DATASET="$1"; shift

# Parse remaining flags
TRANSFORM_ONLY=false
HUNT_ONLY=false
SAMPLE_ARG=""
HUNT_ARGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --transform-only) TRANSFORM_ONLY=true; shift ;;
        --hunt-only) HUNT_ONLY=true; shift ;;
        --sample) SAMPLE_ARG="--sample $2"; shift 2 ;;
        --provider|--model|--hunt-id)
            HUNT_ARGS="$HUNT_ARGS $1 $2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$PROJECT"
source .venv/bin/activate 2>/dev/null || true

# Step 1: Download
if [ "$HUNT_ONLY" = false ]; then
    echo ""
    echo "=== Download ==="
    bash "$DIR/download.sh" "$DATASET"
fi

# Step 2: Transform
if [ "$HUNT_ONLY" = false ]; then
    echo ""
    echo "=== Transform ==="
    python "$DIR/transform.py" "$DATASET" $SAMPLE_ARG
fi

# Step 3: Hunt
if [ "$TRANSFORM_ONLY" = false ]; then
    echo ""
    echo "=== Hunt ==="
    DATA_DIR="$DIR/transformed/$DATASET"
    if [ ! -d "$DATA_DIR" ]; then
        echo "[!] No transformed data at $DATA_DIR"
        exit 1
    fi

    # Point orchestrator at the transformed data
    python orchestrator.py --data-dir "$DATA_DIR" $HUNT_ARGS 2>&1 | \
        tee "$DIR/results/${DATASET}_$(date +%Y%m%d_%H%M%S).log"
fi
