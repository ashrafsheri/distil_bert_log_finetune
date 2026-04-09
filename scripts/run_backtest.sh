#!/usr/bin/env bash
# scripts/run_backtest.sh
# Convenience runner for backtest harness with common configurations.
# Usage:
#   bash scripts/run_backtest.sh <dataset> [ablation]
#   bash scripts/run_backtest.sh hdfs            # full stack
#   bash scripts/run_backtest.sh hdfs rule_only   # ablation
#   bash scripts/run_backtest.sh all_ablations    # run all ablations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODEL_DIR="${MODEL_DIR:-$REPO_ROOT/artifacts/ensemble_model_export}"
DATASETS_DIR="${DATASETS_DIR:-$REPO_ROOT/artifacts/datasets}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/artifacts/backtest_results}"
DEVICE="${DEVICE:-cpu}"

mkdir -p "$OUTPUT_DIR"

run_backtest() {
    local dataset="$1"
    local input_path="$2"
    local ablation="${3:-none}"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local output="$OUTPUT_DIR/${dataset}_${ablation}_${timestamp}.json"

    echo "=== Running backtest: dataset=$dataset ablation=$ablation ==="
    python "$SCRIPT_DIR/backtest_harness.py" \
        --input "$input_path" \
        --mode multi_tenant \
        --model-dir "$MODEL_DIR" \
        --device "$DEVICE" \
        --ablation "$ablation" \
        --output "$output"

    echo "Results saved to: $output"
    echo ""
}

ABLATIONS=(
    none
    rule_only
    iso_only
    transformer_only
    no_manifest
    no_canonicalization
    student_only
    teacher_only
)

DATASET="${1:-}"
ABLATION="${2:-none}"

if [ -z "$DATASET" ]; then
    echo "Usage: $0 <dataset|all_ablations> [ablation]"
    echo ""
    echo "Datasets: hdfs, bgl, thunderbird, openstack, custom (set CUSTOM_INPUT)"
    echo "Ablations: ${ABLATIONS[*]}"
    echo ""
    echo "Examples:"
    echo "  $0 hdfs                 # Run full stack on HDFS"
    echo "  $0 hdfs rule_only       # HDFS with only rule-based detection"
    echo "  $0 all_ablations        # Run all ablations on all available datasets"
    exit 1
fi

if [ "$DATASET" = "all_ablations" ]; then
    for ds in hdfs bgl thunderbird; do
        input_path="$DATASETS_DIR/$ds"
        # Find the first .jsonl, .json, or .csv file
        input_file=$(find "$input_path" -maxdepth 1 -name "*.jsonl" -o -name "*.json" -o -name "*.csv" 2>/dev/null | head -1)
        if [ -z "$input_file" ]; then
            echo "SKIP: No input file found in $input_path"
            continue
        fi
        for abl in "${ABLATIONS[@]}"; do
            run_backtest "$ds" "$input_file" "$abl" || true
        done
    done
else
    input_path="${CUSTOM_INPUT:-$DATASETS_DIR/$DATASET}"
    if [ -d "$input_path" ]; then
        input_file=$(find "$input_path" -maxdepth 1 -name "*.jsonl" -o -name "*.json" -o -name "*.csv" 2>/dev/null | head -1)
    else
        input_file="$input_path"
    fi
    if [ -z "$input_file" ] || [ ! -f "$input_file" ]; then
        echo "ERROR: No input file found at $input_path"
        exit 1
    fi
    run_backtest "$DATASET" "$input_file" "$ABLATION"
fi

echo "=== All backtests complete. Results in $OUTPUT_DIR ==="
