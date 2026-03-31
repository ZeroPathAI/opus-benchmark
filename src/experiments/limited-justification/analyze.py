import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
from pydantic_ai import Agent, ModelSettings

from models import AnalysisResult, RecordResult

SYSTEM_PROMPT = """\
You are a security auditor reviewing C/C++ source code for vulnerabilities.

Analyze the provided function and identify any security vulnerabilities present.

For each vulnerability you find, you must provide a full justification:
1. Identify the undesired operation — what specific bad thing can happen (e.g. out-of-bounds write, use-after-free, command injection). Include the exact code that performs the undesired operation and the relevant CWE(s).
2. Trace the step-by-step execution from the beginning of the function that leads to the undesired operation. At each step, track the relevant program state (variable names and their values/ranges).
3. Only report the vulnerability if you can demonstrate a concrete path from function entry to the undesired operation with specific variable states.

If you cannot trace a concrete execution path to an undesired operation, do not report it.
If the code has no security vulnerabilities, return an empty list.

Do NOT report:
- Style issues, code quality concerns, or theoretical risks without a concrete path
- Issues that are prevented by checks already present in the code
- Vulnerabilities in code that is unreachable under the function's constraints\
"""

import os

DB_FILE = Path("primevul.duckdb")
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "results/opus_4_6_v2.json"))

MAX_RETRIES = 12
INITIAL_BACKOFF = 5
MAX_BACKOFF = 120
CONCURRENCY = 50


def func_sha256(func: str) -> str:
    return hashlib.sha256(func.encode()).hexdigest()


agent = Agent(
    "anthropic:claude-opus-4-6",
    instructions=SYSTEM_PROMPT,
    output_type=AnalysisResult,
    model_settings=ModelSettings(thinking="medium", max_tokens=32000),
)


async def analyze_record(record: dict) -> RecordResult:
    result = await agent.run(record["func"])
    return RecordResult(
        func_sha256=func_sha256(record["func"]),
        commit_id=record["commit_id"],
        project=record["project"],
        project_url=record.get("project_url", ""),
        commit_url=record.get("commit_url", ""),
        commit_message=record.get("commit_message", ""),
        target=record["target"],
        file_name=record.get("file_name", ""),
        cwe=record.get("cwe", ""),
        cve=record.get("cve", ""),
        cve_desc=record.get("cve_desc", ""),
        nvd_url=record.get("nvd_url", ""),
        analysis=result.output,
    )


async def analyze_with_retry(record: dict, label: str, semaphore: asyncio.Semaphore) -> RecordResult:
    async with semaphore:
        backoff = INITIAL_BACKOFF
        for attempt in range(MAX_RETRIES):
            try:
                return await analyze_record(record)
            except Exception as e:
                err = str(e)
                if "rate_limit" in err or "429" in err or "overloaded" in err.lower():
                    jitter = backoff * (0.5 + (hash(label) % 100) / 100)
                    print(f"  [{label}] Rate limited, waiting {jitter:.0f}s (attempt {attempt + 1}/{MAX_RETRIES})...")
                    await asyncio.sleep(jitter)
                    backoff = min(backoff * 2, MAX_BACKOFF)
                else:
                    raise
        raise RuntimeError(f"Failed after {MAX_RETRIES} retries for {label}")


write_lock = asyncio.Lock()


async def process_record(
    i: int,
    total: int,
    record: dict,
    results: list[dict],
    semaphore: asyncio.Semaphore,
):
    sha = func_sha256(record["func"])
    label = f"sha={sha[:12]} project={record['project']} target={record['target']}"
    print(f"[{i + 1}/{total}] Analyzing {label}...")

    try:
        result = await analyze_with_retry(record, label, semaphore)
        result_dict = result.model_dump()

        async with write_lock:
            results.append(result_dict)
            OUTPUT_FILE.write_text(json.dumps(results, indent=2))

        n_vulns = len(result.analysis.vulnerabilities)
        print(f"  [{label}] -> Found {n_vulns} vulnerabilities")
    except Exception as e:
        print(f"  [{label}] -> FAILED: {e}", file=sys.stderr)


async def main():
    db = duckdb.connect(str(DB_FILE), read_only=True)
    rows = db.execute("SELECT * FROM paired_test").fetchdf().to_dict(orient="records")
    db.close()
    print(f"Loaded {len(rows)} records from {DB_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Resume support
    existing_results: list[dict] = []
    done_shas: set[str] = set()
    if OUTPUT_FILE.exists():
        existing_results = json.loads(OUTPUT_FILE.read_text())
        done_shas = {r["func_sha256"] for r in existing_results}
        print(f"Resuming — {len(done_shas)} already done")

    results = list(existing_results)

    todo = [(i, r) for i, r in enumerate(rows) if func_sha256(r["func"]) not in done_shas]
    print(f"{len(todo)} records to process with concurrency={CONCURRENCY}")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    start_time = time.time()

    tasks = [process_record(i, len(rows), r, results, semaphore) for i, r in todo]
    await asyncio.gather(*tasks)

    elapsed = time.time() - start_time
    print(f"\nDone. {len(results)} results written to {OUTPUT_FILE}")
    print(f"Elapsed: {elapsed:.0f}s ({elapsed/60:.1f}m)")


if __name__ == "__main__":
    asyncio.run(main())
