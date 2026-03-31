import asyncio
import hashlib
import json
import sys
from pathlib import Path

from pydantic_ai import Agent, ModelSettings

from models import DiffResult

SYSTEM_PROMPT = """\
You are an expert security code reviewer comparing vulnerability findings between two versions of the same function: a vulnerable version (before a fix) and a benign version (after the fix).

You will be given:
1. Findings from analyzing the vulnerable version
2. Findings from analyzing the benign version

Your job is to match findings that describe the same underlying issue across the two versions. Two findings match if they describe essentially the same vulnerability or concern, even if the wording, CWEs, or code snippets differ slightly.

Then categorize all findings into three groups:
- **vuln_only**: Findings from the vulnerable version that have no match in the benign version
- **benign_only**: Findings from the benign version that have no match in the vulnerable version
- **shared**: Pairs of findings (one from each side) that describe the same issue

Rules:
- Every finding must appear exactly once — either in vuln_only, benign_only, or as part of a shared pair.
- Don't force matches. If two findings are about genuinely different issues, they are not a pair.
- A finding about buffer overflow in function X is not the same as a finding about buffer overflow in function Y unless they describe the same root cause.\
"""

import os

DB_FILE = Path("primevul.duckdb")
ANALYSIS_FILE = Path(os.environ.get("ANALYSIS_FILE", "results/opus_4_6_v2.json"))
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "results/opus_4_6_v2_diffed.json"))

MAX_RETRIES = 12
INITIAL_BACKOFF = 5
MAX_BACKOFF = 120
CONCURRENCY = 10


def func_sha256(func: str) -> str:
    return hashlib.sha256(func.encode()).hexdigest()


agent = Agent(
    "anthropic:claude-opus-4-6",
    instructions=SYSTEM_PROMPT,
    output_type=DiffResult,
    model_settings=ModelSettings(thinking="medium", max_tokens=16000),
)


def _format_finding(f: dict) -> str:
    """Format a finding for the prompt, handling both v1 and v2 finding formats."""
    lines = []
    # v2 format: CWEs inside justification.undesired_operation
    justification = f.get("justification")
    if justification:
        cwes = justification.get("undesired_operation", {}).get("cwes", [])
        lines.append(f"- CWEs: {', '.join(cwes)}")
        lines.append(f"- Description: {f.get('description', '')}")
        lines.append(f"- Code snippets: {f.get('code_snippets', [])}")
        lines.append(f"- Undesired operation: {justification.get('undesired_operation', {}).get('code_snippets', [])}")
    else:
        # v1 format: top-level cwes
        lines.append(f"- CWEs: {', '.join(f.get('cwes', []))}")
        lines.append(f"- Short description: {f.get('short_description', f.get('description', ''))}")
        lines.append(f"- Long description: {f.get('long_description', '')}")
        lines.append(f"- Code snippets: {f.get('code_snippets', [])}")
    return "\n".join(lines)


def build_diff_prompt(vuln_findings: list[dict], benign_findings: list[dict]) -> str:
    vuln_text = ""
    for i, f in enumerate(vuln_findings):
        vuln_text += f"\n### Vulnerable Finding {i}\n"
        vuln_text += _format_finding(f) + "\n"

    benign_text = ""
    for i, f in enumerate(benign_findings):
        benign_text += f"\n### Benign Finding {i}\n"
        benign_text += _format_finding(f) + "\n"

    return f"""\
## Findings from VULNERABLE version ({len(vuln_findings)} findings)
{vuln_text if vuln_text else "(none)"}

## Findings from BENIGN version ({len(benign_findings)} findings)
{benign_text if benign_text else "(none)"}
"""


async def diff_with_retry(prompt: str, label: str, semaphore: asyncio.Semaphore) -> DiffResult:
    async with semaphore:
        backoff = INITIAL_BACKOFF
        for attempt in range(MAX_RETRIES):
            try:
                result = await agent.run(prompt)
                return result.output
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


async def main():
    import duckdb
    db = duckdb.connect(str(DB_FILE), read_only=True)
    samples = db.execute("SELECT * FROM paired_test").fetchdf().to_dict(orient="records")
    db.close()

    analysis_results = json.loads(ANALYSIS_FILE.read_text())
    result_by_sha = {r["func_sha256"]: r for r in analysis_results}

    # Build pairs: (vulnerable, benign)
    pairs = []
    for i in range(0, len(samples), 2):
        a, b = samples[i], samples[i + 1]
        if a["target"] == 1:
            pairs.append((a, b))
        else:
            pairs.append((b, a))

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Resume support
    existing: list[dict] = []
    done_commits: set[str] = set()
    if OUTPUT_FILE.exists():
        existing = json.loads(OUTPUT_FILE.read_text())
        done_commits = {r["commit_id"] for r in existing}
        print(f"Resuming — {len(done_commits)} already done")

    results = list(existing)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def process_pair(pair_num: int, vuln: dict, fixed: dict):
        commit_id = vuln["commit_id"]
        if commit_id in done_commits:
            return

        vuln_sha = func_sha256(vuln["func"])
        fixed_sha = func_sha256(fixed["func"])

        vuln_result = result_by_sha.get(vuln_sha)
        fixed_result = result_by_sha.get(fixed_sha)

        if vuln_result is None or fixed_result is None:
            print(f"[{pair_num + 1}/{len(pairs)}] {vuln['project']} — missing analysis, skipping")
            return

        vuln_findings = vuln_result["analysis"]["vulnerabilities"]
        benign_findings = fixed_result["analysis"]["vulnerabilities"]

        # If neither side has findings, nothing to diff
        if not vuln_findings and not benign_findings:
            entry = {
                "commit_id": commit_id,
                "project": vuln["project"],
                "vuln_sha256": vuln_sha,
                "benign_sha256": fixed_sha,
                "num_vuln_findings": 0,
                "num_benign_findings": 0,
                "vuln_only": [],
                "benign_only": [],
                "shared": [],
            }
            async with write_lock:
                results.append(entry)
                OUTPUT_FILE.write_text(json.dumps(results, indent=2))
            print(f"[{pair_num + 1}/{len(pairs)}] {vuln['project']} — no findings on either side")
            return

        # If only one side has findings, no need to call LLM
        if not vuln_findings:
            entry = {
                "commit_id": commit_id,
                "project": vuln["project"],
                "vuln_sha256": vuln_sha,
                "benign_sha256": fixed_sha,
                "num_vuln_findings": 0,
                "num_benign_findings": len(benign_findings),
                "vuln_only": [],
                "benign_only": benign_findings,
                "shared": [],
            }
            async with write_lock:
                results.append(entry)
                OUTPUT_FILE.write_text(json.dumps(results, indent=2))
            print(f"[{pair_num + 1}/{len(pairs)}] {vuln['project']} — 0 vuln, {len(benign_findings)} benign only")
            return

        if not benign_findings:
            entry = {
                "commit_id": commit_id,
                "project": vuln["project"],
                "vuln_sha256": vuln_sha,
                "benign_sha256": fixed_sha,
                "num_vuln_findings": len(vuln_findings),
                "num_benign_findings": 0,
                "vuln_only": vuln_findings,
                "benign_only": [],
                "shared": [],
            }
            async with write_lock:
                results.append(entry)
                OUTPUT_FILE.write_text(json.dumps(results, indent=2))
            print(f"[{pair_num + 1}/{len(pairs)}] {vuln['project']} — {len(vuln_findings)} vuln only, 0 benign")
            return

        # Both sides have findings — use LLM to match them
        prompt = build_diff_prompt(vuln_findings, benign_findings)
        label = f"{vuln['project']} commit={commit_id[:12]}"
        print(f"[{pair_num + 1}/{len(pairs)}] Diffing {label} ({len(vuln_findings)}v / {len(benign_findings)}b)...")

        try:
            diff_result = await diff_with_retry(prompt, label, semaphore)
            entry = {
                "commit_id": commit_id,
                "project": vuln["project"],
                "vuln_sha256": vuln_sha,
                "benign_sha256": fixed_sha,
                "num_vuln_findings": len(vuln_findings),
                "num_benign_findings": len(benign_findings),
                "vuln_only": [f.model_dump() for f in diff_result.vuln_only],
                "benign_only": [f.model_dump() for f in diff_result.benign_only],
                "shared": [p.model_dump() for p in diff_result.shared],
            }
            async with write_lock:
                results.append(entry)
                OUTPUT_FILE.write_text(json.dumps(results, indent=2))
            print(f"  [{label}] -> {len(diff_result.vuln_only)} vuln-only, {len(diff_result.benign_only)} benign-only, {len(diff_result.shared)} shared")
        except Exception as e:
            print(f"  [{label}] -> FAILED: {e}", file=sys.stderr)

    tasks = [process_pair(i, vuln, fixed) for i, (vuln, fixed) in enumerate(pairs)]
    await asyncio.gather(*tasks)

    print(f"\nDone. {len(results)} pairs written to {OUTPUT_FILE}")

    # Summary
    total_vuln_only = sum(len(r["vuln_only"]) for r in results)
    total_benign_only = sum(len(r["benign_only"]) for r in results)
    total_shared = sum(len(r["shared"]) for r in results)
    print(f"\nTotal vuln-only findings:   {total_vuln_only}")
    print(f"Total benign-only findings: {total_benign_only}")
    print(f"Total shared findings:      {total_shared}")


if __name__ == "__main__":
    asyncio.run(main())
