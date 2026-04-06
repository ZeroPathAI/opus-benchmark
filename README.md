# Benchmarking Claude Opus 4.6 Vulnerability Detection

Benchmarking Claude Opus 4.6's ability to detect real-world C/C++ vulnerabilities across four prompting and agent strategies. We evaluate on the [PrimeVul](https://huggingface.co/datasets/colin/PrimeVul) paired test set (435 vulnerability/fix pairs from open-source projects), measuring precision, recall, and CVE-correctness to understand how structured reasoning, justification depth, and verification agents affect detection quality.

## Key Finding

Requiring the model to produce increasingly rigorous justifications (execution traces, state proofs) improves pair-correct precision (P-C) from **13.6%** to **20.3%**, with rigorous precision nearly doubling from **8.7%** to **15.8%**. Adding a verification agent pushes P-C to **23.3%** and CVE recall to **28.9%**.

## Experiments

Each experiment uses Claude Opus 4.6 as the analyzer and runs 3 times for consistency. All experiments share the same three-phase pipeline but differ in the structured output the model must produce.

| # | Experiment | P-C | P-C Rigorous | P-C Flexible | CVE Recall | Vuln Findings | Benign Findings | Benign-Only Findings |
|---|-----------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 1 | [No Justification](#1-no-justification) | 13.6% | 8.7% | 13.6% | 27.6% | 63.4% | 52.4% | 27.4% |
| 2 | [Limited Justification](#2-limited-justification) | 19.3% | 14.5% | 17.7% | 25.5% | 52.2% | 36.6% | 15.6% |
| 3 | [Extensive Justification](#3-extensive-justification) | 20.3% | 15.8% | 17.7% | 28.5% | 54.6% | 37.7% | 18.6% |
| 4 | [Verification Agent](#4-verification-agent) | 23.3% | 16.2% | 18.5% | 28.9% | 57.2% | 43.2% | 24.7% |

*All values are medians across 3 runs. Reference baseline: GPT-4 CoT = 12.94% P-C.*

### Cross-Run Consistency

Each experiment runs 3 times. "All 3" means the result held in every run; "Any" means it held in at least one. This captures how stable the results were across runs.

| # | Experiment | CVE Recall All 3 | CVE Recall Any | P-C Rigorous All 3 | P-C Rigorous Any | P-C Flexible All 3 | P-C Flexible Any |
|---|-----------|:-:|:-:|:-:|:-:|:-:|:-:|
| 1 | No Justification | 22.0% | 33.1% | 5.9% | 11.1% | 7.6% | 19.6% |
| 2 | Limited Justification | 21.7% | 30.0% | 12.5% | 17.5% | 14.2% | 22.2% |
| 3 | Extensive Justification | 23.6% | 33.3% | 11.6% | 20.1% | 12.8% | 24.3% |
| 4 | Verification Agent | 19.4% | 37.6% | 9.9% | 23.4% | 10.6% | 27.2% |

### 1. No Justification

Simple vulnerability analysis. The model reports CWEs, code snippets, and descriptions with no structured reasoning required.

### 2. Limited Justification

Requires a `Justification` with an `UndesiredOperation` (code + CWEs) and `step_by_step_execution` tracking variable state through `ProgramStep`s. The model must demonstrate a concrete execution path from function entry to the undesired operation.

### 3. Extensive Justification

Full proof of reachability. The model must provide:
- **UndesiredOperation**: description, code, CWEs, impact, and the variable states required to trigger it
- **Justification**: initial variable state at function entry, then a trace of `DataTransformation` steps (in_state -> out_state) and `ConditionalStep` steps (prove each branch is taken given current state)

### 4. Verification Agent

Same structured reasoning as experiment 3, plus a Claude Sonnet 4.6 **verifier agent** that checks each finding before inclusion. The verifier validates: is the undesired operation real, is the initial state correct, do steps follow logically, are conditionals justified, and does the final state match the preconditions. Findings get up to 2 verification attempts; unverified findings are discarded.

## Pipeline

Each experiment follows the same three-phase pipeline:

```
analyze.py -> diff_judge.py -> judge.py
```

1. **Analyze** (`analyze.py`): Claude Opus 4.6 analyzes each of the 870 functions independently, producing structured vulnerability findings.
2. **Diff Judge** (`diff_judge.py`): For each commit pair (vulnerable + fixed), matches findings across versions and categorizes them as `vuln_only`, `benign_only`, or `shared`.
3. **Judge** (`judge.py`): Evaluates `vuln_only` findings against ground-truth CVE data to determine correctness.

## Metrics

All metrics are computed over the 435 vulnerability/fix pairs. After analysis, the **diff judge** categorizes each finding as `vuln_only` (unique to vulnerable version), `benign_only` (unique to fixed version), or `shared` (present in both). The **judge** then evaluates whether each `vuln_only` finding correctly identifies the ground-truth CVE.

| Metric | Definition |
|--------|------------|
| **P-C** | % of pairs where the vulnerable side has at least one finding and the benign side has zero findings (no `benign_only`, no `shared`). Measures raw discrimination: can the model tell vulnerable code from fixed code? |
| **P-C Rigorous** | P-C with the additional requirement that *all* `vuln_only` findings are judged as related to the ground-truth CVE. The strictest metric — the model must flag only the real vulnerability and nothing else, with a clean benign side. |
| **P-C Flexible** | % of pairs where all `vuln_only` findings are CVE-correct (at least one exists) and there are no `benign_only` findings. `shared` findings are permitted — these represent underlying issues not addressed by the patch. Every benign-side finding must have a corresponding linked vulnerable-side finding. |
| **CVE Recall** | % of pairs where the vulnerable side has at least one finding judged as related to the ground-truth CVE, regardless of what appears on the benign side. Measures the model's ability to detect the actual vulnerability. |
| **Vuln Findings** | % of vulnerable functions that have at least one finding (any category). |
| **Benign Findings** | % of benign functions that have at least one finding (any category). |
| **Benign-Only Findings** | % of benign functions that have at least one finding *not* also found on the vulnerable side (i.e., a `benign_only` finding with no linked `shared` counterpart). |

## Dataset

The [PrimeVul paired test set](https://huggingface.co/datasets/colin/PrimeVul) contains 435 pairs (870 functions) from real security fixes across open-source C/C++ projects including Linux, TensorFlow, ImageMagick, FFmpeg, OpenSSL, mruby, and others. Each pair consists of:
- A **vulnerable** function (before the fix, `target=0`)
- A **benign** function (after the fix, `target=1`)

Ground truth includes CVE ID, CWE classification, NVD URL, and commit message.

## Project Structure

```
src/
  experiments/
    no-justification/        # Experiment 1
    limited-justification/   # Experiment 2
    extensive-justification/  # Experiment 3
    verification-agent/       # Experiment 4
  common/
    primevul.duckdb           # Dataset in DuckDB format

data/
  experiments/
    */experiment.json         # Experiment metadata
    */runs/{1,2,3}/           # Per-run outputs (analysis, diffed, judged, stats)
  experiment_comparison.json  # Cross-experiment metrics comparison
```

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-...
```

### Running an experiment

Each experiment has a `run_experiment.sh` script:

```bash
cd src/experiments/extensive-justification
bash run_experiment.sh 1  # run number
```

## Dependencies

- [pydantic-ai](https://ai.pydantic.dev/) - Claude agent framework with structured outputs
- [duckdb](https://duckdb.org/) - Dataset storage and querying
- [datasets](https://huggingface.co/docs/datasets/) - HuggingFace dataset loading
