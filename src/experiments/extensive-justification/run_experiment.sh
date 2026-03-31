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

RUN_DIR="$REPO_ROOT/data/experiments/extensive-justification/runs/$RUN_NUM"
mkdir -p "$RUN_DIR"

cd "$SCRIPT_DIR"

echo "=== Phase 1: Analysis ==="
uv run python analyze.py --db "$DB" --output "$RUN_DIR/analysis.json"

echo "=== Phase 2: Diff Judge ==="
uv run python diff_judge.py --db "$DB" --analysis "$RUN_DIR/analysis.json" --output "$RUN_DIR/diffed.json"

echo "=== Phase 3: Judge ==="
uv run python judge.py --db "$DB" --diff-results "$RUN_DIR/diffed.json" --output "$RUN_DIR/judged.json"

echo "=== Done: $RUN_DIR ==="
