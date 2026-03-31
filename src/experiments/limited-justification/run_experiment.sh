#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DB="$SCRIPT_DIR/../../common/primevul.duckdb"

RUN_NUM="$1"
if [ -z "$RUN_NUM" ]; then
    echo "Usage: $0 <run_number>"
    exit 1
fi

RUN_DIR="$REPO_ROOT/data/experiments/limited-justification/runs/$RUN_NUM"
mkdir -p "$RUN_DIR"

cd "$SCRIPT_DIR"

# Symlink duckdb into working directory so hardcoded paths work
ln -sf "$DB" primevul.duckdb

echo "=== Phase 1: Analysis ==="
OUTPUT_FILE="$RUN_DIR/analysis.json" uv run python analyze.py

echo "=== Phase 2: Diff Judge ==="
ANALYSIS_FILE="$RUN_DIR/analysis.json" OUTPUT_FILE="$RUN_DIR/diffed.json" uv run python diff_judge.py

echo "=== Phase 3: Judge ==="
DIFF_FILE="$RUN_DIR/diffed.json" OUTPUT_FILE="$RUN_DIR/judged.json" uv run python judge.py

echo "=== Done: $RUN_DIR ==="
