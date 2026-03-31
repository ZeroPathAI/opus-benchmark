import asyncio
import difflib
import hashlib
import json
import sys
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from pydantic_ai import Agent, ModelSettings, RunContext

from models import JudgeResult

SYSTEM_PROMPT = """\
You are an expert security code reviewer acting as a judge.

You will be given:
1. A known CVE (identifier, description, CWE, and NVD URL) — this is the ground truth vulnerability
2. A vulnerable C/C++ function (before the fix) and the fixed version (after the fix)
3. A unified diff showing what changed
4. A list of vulnerability findings that were detected ONLY in the vulnerable version (not in the fixed version)

Your job is to judge each finding: does it correctly identify the CVE, or describe a component of the CVE?

Before judging, use the provided tools to research the CVE so you fully understand it:
1. Fetch the NVD URL to get the full CVE description and severity details
2. If helpful, fetch the commit URL to see the full change
3. Search for additional context if the CVE description is unclear

Then judge each finding:
- A finding is "correct" if it describes the same vulnerability as the CVE, or a specific component/consequence of it, even if the CWE or wording differs.
- A finding is "incorrect" if it describes a different issue unrelated to the CVE.

Be fair but rigorous. The finding doesn't need to name the CVE — it just needs to describe the same underlying problem.\
"""

DB_FILE = Path("primevul.duckdb")
DIFF_FILE = Path("results/opus_4_6_nojustification_diffed.json")
OUTPUT_DIR = Path("results")
OUTPUT_FILE = OUTPUT_DIR / "opus_4_6_nojustification_judged.json"

MAX_RETRIES = 12
INITIAL_BACKOFF = 5
MAX_BACKOFF = 120
CONCURRENCY = 10


def func_sha256(func: str) -> str:
    return hashlib.sha256(func.encode()).hexdigest()


def _html_to_text(html: str, max_len: int = 15000) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    return text[:max_len]


agent = Agent(
    "anthropic:claude-opus-4-6",
    instructions=SYSTEM_PROMPT,
    output_type=JudgeResult,
    model_settings=ModelSettings(thinking="medium", max_tokens=16000),
)


@agent.tool
async def fetch_url(ctx: RunContext, url: str) -> str:
    """Fetch a URL and return its content as text. Works for NVD pages, GitHub, CVE databases, etc."""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            resp = await client.get(url, headers={"Accept": "text/html, application/json"})
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                return resp.text[:15000]
            return _html_to_text(resp.text)
    except Exception as e:
        return f"Error fetching {url}: {e}"


@agent.tool
async def search_web(ctx: RunContext, query: str) -> str:
    """Search the web for additional context about a CVE or vulnerability."""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for r in soup.select(".result")[:5]:
                title_el = r.select_one(".result__title")
                snippet_el = r.select_one(".result__snippet")
                link_el = r.select_one(".result__url")
                title = title_el.get_text(strip=True) if title_el else ""
                snippet = snippet_el.get_text(strip=True) if snippet_el else ""
                link = link_el.get_text(strip=True) if link_el else ""
                if title:
                    results.append(f"- {title}\n  {link}\n  {snippet}")
            return "\n".join(results) if results else "No results found."
    except Exception as e:
        return f"Error searching web: {e}"


def make_diff(vuln_func: str, fixed_func: str) -> str:
    vuln_lines = vuln_func.splitlines()
    fixed_lines = fixed_func.splitlines()
    diff = difflib.unified_diff(vuln_lines, fixed_lines, fromfile="vulnerable", tofile="fixed", lineterm="")
    return "\n".join(diff)


def build_judge_prompt(
    vuln_func: str,
    fixed_func: str,
    diff: str,
    findings: list[dict],
    project: str,
    commit_id: str,
    commit_url: str,
    commit_message: str,
    cve: str,
    cwe: str,
    cve_desc: str,
    nvd_url: str,
) -> str:
    findings_text = ""
    for i, f in enumerate(findings):
        findings_text += f"\n### Finding {i}\n"
        justification = f.get("justification")
        if justification:
            cwes = justification.get("undesired_operation", {}).get("cwes", [])
            findings_text += f"- CWEs: {', '.join(cwes)}\n"
            findings_text += f"- Description: {f.get('description', '')}\n"
            findings_text += f"- Undesired operation: {justification.get('undesired_operation', {}).get('code_snippets', [])}\n"
        else:
            findings_text += f"- CWEs: {', '.join(f.get('cwes', []))}\n"
            findings_text += f"- Short description: {f.get('short_description', f.get('description', ''))}\n"
            findings_text += f"- Long description: {f.get('long_description', '')}\n"

    return f"""\
## Known CVE (ground truth)
- **CVE:** {cve}
- **CWE:** {cwe}
- **Description:** {cve_desc}
- **NVD URL:** {nvd_url}

## Commit
- **Project:** {project}
- **Commit ID:** {commit_id}
- **Commit URL:** {commit_url}
- **Commit message:** {commit_message}

Please research the CVE before judging:
1. Fetch the NVD URL to get full details
2. If needed, fetch the commit URL or search the web for more context

## Vulnerable function (before fix)
```c
{vuln_func}
```

## Fixed function (after fix)
```c
{fixed_func}
```

## Diff (vulnerable → fixed)
```diff
{diff}
```

## Findings to judge (detected ONLY in the vulnerable version)
{findings_text}
"""


write_lock = asyncio.Lock()


async def judge_with_retry(prompt: str, label: str, semaphore: asyncio.Semaphore) -> JudgeResult:
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


async def main():
    import duckdb
    db = duckdb.connect(str(DB_FILE), read_only=True)
    samples = db.execute("SELECT * FROM paired_test").fetchdf().to_dict(orient="records")
    db.close()

    # Build pairs keyed by commit_id
    pairs_by_commit = {}
    for i in range(0, len(samples), 2):
        a, b = samples[i], samples[i + 1]
        if a["target"] == 1:
            pairs_by_commit[a["commit_id"]] = (a, b)
        else:
            pairs_by_commit[b["commit_id"]] = (b, a)

    # Load diff results — only process entries with vuln-only findings
    diff_results = json.loads(DIFF_FILE.read_text())
    to_judge = [d for d in diff_results if len(d["vuln_only"]) > 0]
    print(f"Loaded {len(diff_results)} diff results, {len(to_judge)} have vuln-only findings to judge")

    OUTPUT_DIR.mkdir(exist_ok=True)

    # Resume support
    existing: list[dict] = []
    done_commits: set[str] = set()
    if OUTPUT_FILE.exists():
        existing = json.loads(OUTPUT_FILE.read_text())
        done_commits = {r["commit_id"] for r in existing}
        print(f"Resuming — {len(done_commits)} already done")

    results = list(existing)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def process_entry(idx: int, entry: dict):
        commit_id = entry["commit_id"]
        if commit_id in done_commits:
            return

        project = entry["project"]
        vuln_only = entry["vuln_only"]

        pair = pairs_by_commit.get(commit_id)
        if not pair:
            print(f"[{idx + 1}/{len(to_judge)}] {project} — can't find pair, skipping")
            return

        vuln_sample, fixed_sample = pair
        diff = make_diff(vuln_sample["func"], fixed_sample["func"])

        cve = vuln_sample.get("cve", "")
        cwe = vuln_sample.get("cwe", "")
        cve_desc = vuln_sample.get("cve_desc", "")
        nvd_url = vuln_sample.get("nvd_url", "")
        commit_url = vuln_sample.get("commit_url", "")
        commit_message = vuln_sample.get("commit_message", "")

        label = f"{project} {cve} commit={commit_id[:12]}"
        print(f"[{idx + 1}/{len(to_judge)}] Judging {label} ({len(vuln_only)} vuln-only findings)...")

        prompt = build_judge_prompt(
            vuln_sample["func"], fixed_sample["func"], diff, vuln_only,
            project, commit_id, commit_url, commit_message,
            cve, cwe, cve_desc, nvd_url,
        )

        try:
            judge_result = await judge_with_retry(prompt, label, semaphore)

            num_correct = sum(1 for j in judge_result.judgments if j.verdict == "correct")
            classification = "correct" if num_correct > 0 else "incorrect"

            result_entry = {
                "commit_id": commit_id,
                "project": project,
                "cve": cve,
                "cwe": cwe,
                "cve_desc": cve_desc,
                "nvd_url": nvd_url,
                "vuln_sha256": entry["vuln_sha256"],
                "benign_sha256": entry["benign_sha256"],
                "diff": diff,
                "classification": classification,
                "num_findings": len(vuln_only),
                "num_correct": num_correct,
                "judgments": [j.model_dump() for j in judge_result.judgments],
                "actual_issue_summary": judge_result.actual_issue_summary,
            }

            async with write_lock:
                results.append(result_entry)
                OUTPUT_FILE.write_text(json.dumps(results, indent=2))

            print(f"  [{label}] -> {classification}: {num_correct}/{len(vuln_only)} correct")
        except Exception as e:
            print(f"  [{label}] -> FAILED: {e}", file=sys.stderr)

    tasks = [process_entry(i, entry) for i, entry in enumerate(to_judge)]
    await asyncio.gather(*tasks)

    print(f"\nDone. {len(results)} entries written to {OUTPUT_FILE}")

    # Summary
    correct_count = sum(1 for r in results if r["classification"] == "correct")
    incorrect_count = sum(1 for r in results if r["classification"] == "incorrect")
    total = len(results)
    if total:
        print(f"\n=== Vuln-only findings judged ===")
        print(f"  correct:   {correct_count}/{total} ({100*correct_count/total:.1f}%)")
        print(f"  incorrect: {incorrect_count}/{total} ({100*incorrect_count/total:.1f}%)")


if __name__ == "__main__":
    asyncio.run(main())
