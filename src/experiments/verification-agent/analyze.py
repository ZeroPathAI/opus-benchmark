import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
from pydantic_ai import Agent, ModelSettings, RunContext

from models import AnalysisResult, RecordResult
import verifier

SYSTEM_PROMPT = """\
You are a security auditor reviewing C/C++ source code for vulnerabilities.

Analyze the provided function and identify security vulnerabilities. For each vulnerability, you must build a rigorous proof that it is real and reachable.

For each vulnerability, provide:

1. **Undesired operation**: What specifically goes wrong? Identify:
   - The exact code that performs the bad operation
   - The CWE(s) that classify it
   - The impact to an attacker (code execution, crash, info leak, etc.)
   - The variable states required for it to trigger (e.g. "len must be > buf_size")

2. **Initial state**: For every variable mentioned in the required state above, what is its value at function entry? (can be "unset", a range, or "attacker-controlled via parameter X")

3. **Step-by-step trace**: Walk from function entry to the undesired operation, showing how both control flow and data flow lead there:
   - For data transformations: show in_state and out_state of relevant variables
   - For conditionals: show the condition, which branch must be taken, and prove from current variable state that this branch IS taken
   - The final variable states at the end of the trace must match the required states from the undesired operation

Only report the vulnerability if your trace is complete — every conditional is justified, every variable transformation is shown, and the final state matches the preconditions for the undesired operation.

If the code has no vulnerabilities you can fully justify, return an empty list.

Do NOT report:
- Issues where you cannot trace a complete path from function entry to the undesired operation
- Issues that are prevented by checks already present in the code
- Style issues, code quality concerns, or theoretical risks
- Vulnerabilities in code that is unreachable given the function's constraints

## Example

Given this function:

```c
static int nfs_readlink_reply(unsigned char *pkt, unsigned len)
{
    uint32_t *data;
    char *path;
    int rlen;
    int ret;

    ret = rpc_check_reply(pkt, 1);
    if (ret)
        return ret;

    data = (uint32_t *)(pkt + sizeof(struct rpc_reply));
    data++;

    rlen = ntohl(net_read_uint32(data)); /* new path length */

    data++;
    path = (char *)data;

    memcpy(nfs_path, path, rlen);
    nfs_path[rlen] = 0;
}
```

A good analysis would identify:

**Undesired operation:**
- description: "memcpy copies rlen bytes from network packet into fixed-size nfs_path buffer with no bounds check on rlen"
- code_snippets: ["memcpy(nfs_path, path, rlen);"]
- cwes: ["CWE-119", "CWE-120"]
- impact: "Remote code execution or crash — attacker controls rlen via crafted NFS reply packet"
- state: [rlen = "any value larger than sizeof(nfs_path)", nfs_path = "fixed-size global buffer"]

**Initial state:**
- rlen = "unset"
- nfs_path = "fixed-size global buffer"
- pkt = "attacker-controlled network packet data"

**Step-by-step trace:**
1. DataTransformation: rpc_check_reply validates packet header
   - in_state: [pkt = "attacker-controlled"]
   - out_state: [ret = 0 (valid reply)]
2. ConditionalStep: condition "ret != 0", branch taken: false
   - reasoning: "ret is 0 because attacker sends a well-formed RPC reply header"
   - relevant_state: [ret = 0]
3. DataTransformation: rlen is read from network packet
   - in_state: [rlen = "unset", data = "points into attacker-controlled pkt"]
   - out_state: [rlen = "attacker-controlled value, e.g. 0xFFFF"]
4. DataTransformation: memcpy copies rlen bytes into nfs_path
   - in_state: [rlen = "0xFFFF (attacker-controlled)", nfs_path = "fixed-size buffer"]
   - out_state: [nfs_path = "overflowed — rlen bytes written past buffer boundary"]

## Verification

After constructing each vulnerability finding, you MUST call the verify_finding tool to have it independently checked. The tool returns VERIFIED or UNVERIFIED with an explanation.

- If UNVERIFIED: read the explanation, revise your finding to address the issues, and resubmit. You may attempt verification up to 2 times per finding.
- If you cannot get a finding verified after 2 attempts, discard it.
- Only include findings in your final output that have been VERIFIED.
- You may also discard a finding at any time if you realize it is incorrect.\
"""

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
    deps_type=str,
    model_settings=ModelSettings(thinking="medium", max_tokens=64000),
)


@agent.tool
async def verify_finding(ctx: RunContext[str], finding_json: str) -> str:
    """Submit a vulnerability finding for independent verification.

    Args:
        finding_json: The finding as a JSON string (serialize your VulnerabilityFinding to JSON).

    Returns a VERIFIED or UNVERIFIED verdict with explanation. If UNVERIFIED, revise and resubmit (max 2 attempts per finding)."""
    result = await verifier.verify(finding_json, ctx.deps)
    return f"{'VERIFIED' if result.verified else 'UNVERIFIED'}: {result.explanation}"


async def analyze_record(record: dict) -> RecordResult:
    result = await agent.run(record["func"], deps=record["func"])
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
    output_file: Path,
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
            output_file.write_text(json.dumps(results, indent=2))

        n_vulns = len(result.analysis.vulnerabilities)
        print(f"  [{label}] -> Found {n_vulns} vulnerabilities")
    except Exception as e:
        print(f"  [{label}] -> FAILED: {e}", file=sys.stderr)


async def main():
    parser = argparse.ArgumentParser(description="Analyze functions for vulnerabilities")
    parser.add_argument("--db", required=True, help="Path to DuckDB database")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help="Max concurrent API calls")
    args = parser.parse_args()

    db_file = Path(args.db)
    output_file = Path(args.output)

    db = duckdb.connect(str(db_file), read_only=True)
    rows = db.execute("SELECT * FROM paired_test").fetchdf().to_dict(orient="records")
    db.close()
    print(f"Loaded {len(rows)} records from {db_file}")

    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Resume support
    existing_results: list[dict] = []
    done_shas: set[str] = set()
    if output_file.exists():
        existing_results = json.loads(output_file.read_text())
        done_shas = {r["func_sha256"] for r in existing_results}
        print(f"Resuming — {len(done_shas)} already done")

    results = list(existing_results)

    todo = [(i, r) for i, r in enumerate(rows) if func_sha256(r["func"]) not in done_shas]
    print(f"{len(todo)} records to process with concurrency={args.concurrency}")

    semaphore = asyncio.Semaphore(args.concurrency)
    start_time = time.time()

    tasks = [process_record(i, len(rows), r, results, output_file, semaphore) for i, r in todo]
    await asyncio.gather(*tasks)

    elapsed = time.time() - start_time
    print(f"\nDone. {len(results)} results written to {output_file}")
    print(f"Elapsed: {elapsed:.0f}s ({elapsed/60:.1f}m)")


if __name__ == "__main__":
    asyncio.run(main())
