from enum import Enum

from pydantic import BaseModel, Field


# --- Analysis models ---


class ProgramState(BaseModel):
    """Program state relevant to the vulnerability at a particular point in the program execution"""
    variable: str = Field(description="Name of the variable being tracked")
    value: str = Field(description="Value of the variable at this point in the program — can be a range or a description of possible values")


class DataTransformation(BaseModel):
    """A step where data is read, computed, assigned, or passed — changing the state of a variable relevant to the vulnerability"""
    description: str = Field(description="What happens at this step, e.g. 'pck_size is read from untrusted packet header'")
    in_state: list[ProgramState] = Field(description="Relevant variable states before this step executes")
    out_state: list[ProgramState] = Field(description="Relevant variable states after this step executes — should show what changed")


class ConditionalStep(BaseModel):
    """A branch point where execution must take a specific path for the vulnerability to be reachable. Use this to document 'for the undesired operation to occur, this branch must be taken' — e.g. a missing bounds check, a null check that is absent, or a loop condition that allows too many iterations."""
    condition: str = Field(description="The condition being evaluated, e.g. 'remain >= 5', 'ptr != NULL'")
    branch_taken: str = Field(description="Which branch is taken: 'true' or 'false'")
    reasoning: str = Field(description="Why this branch is taken given the current program state — this is where you prove the dangerous path is reachable")
    relevant_state: list[ProgramState] = Field(description="Variable states at the point of the branch decision")


# Union type for steps in the execution trace
ProgramStep = DataTransformation | ConditionalStep


class UndesiredOperation(BaseModel):
    """An operation that an attacker can perform due to the vulnerability, which should not happen in the intended program behavior"""
    description: str = Field(description="What specifically happens, e.g. 'memcpy writes 200 bytes into a 100-byte stack buffer'")
    code_snippets: list[str] = Field(description="Parts of the code that directly perform the undesired operation")
    cwes: list[str] = Field(description="CWE identifiers for the type of undesired operation, e.g. ['CWE-78'] for OS command injection")
    impact: str = Field(description="What an attacker gains — e.g. 'arbitrary code execution', 'denial of service via crash', 'information disclosure of heap contents'")
    state: list[ProgramState] = Field(description="Variable states required for the undesired operation to occur, e.g. 'len must be > buf_size'")


class Justification(BaseModel):
    initial_state: list[ProgramState] = Field(description="Values of all variables from undesired_operation.state at the first line of the function. Values can be 'unset', a concrete value, or a description of possible values from caller/input. Must include every variable referenced in undesired_operation.state.")
    step_by_step_execution: list[DataTransformation | ConditionalStep] = Field(description="Step-by-step trace from function entry to the undesired operation. Must fully capture both: (1) how control flow reaches the undesired operation (via ConditionalSteps showing each branch that must be taken) and (2) how variable state transitions from initial_state to the preconditions required by undesired_operation.state (via DataTransformations showing each mutation).")


class VulnerabilityFinding(BaseModel):
    undesired_operation: UndesiredOperation = Field(description="The undesired operation — what goes wrong and under what conditions")
    justification: Justification = Field(description="Proof that the undesired operation is reachable from function entry")


class AnalysisResult(BaseModel):
    vulnerabilities: list[VulnerabilityFinding] = Field(description="List of identified security vulnerabilities. Empty list if no vulnerabilities found.")


class RecordResult(BaseModel):
    func_sha256: str
    commit_id: str
    project: str
    project_url: str = ""
    commit_url: str = ""
    commit_message: str = ""
    target: int
    file_name: str = ""
    cwe: str = ""
    cve: str = ""
    cve_desc: str = ""
    nvd_url: str = ""
    analysis: AnalysisResult


# --- Judge models ---


class FindingVerdict(str, Enum):
    correct = "correct"
    incorrect = "incorrect"


class JudgedFinding(BaseModel):
    finding: VulnerabilityFinding = Field(description="The finding being judged")
    verdict: FindingVerdict = Field(description="Whether this finding correctly identifies the actual vulnerability that was fixed")
    reasoning: str = Field(description="Brief explanation of why this finding is correct or incorrect")


class JudgeResult(BaseModel):
    judgments: list[JudgedFinding] = Field(description="One judgment per finding submitted for review")
    actual_issue_summary: str = Field(description="Brief summary of what the actual vulnerability/fix was, based on the diff")


# --- Diff judge models ---


class FindingPair(BaseModel):
    vuln_finding: VulnerabilityFinding = Field(description="The finding from the vulnerable version")
    benign_finding: VulnerabilityFinding = Field(description="The matching finding from the benign version")
    reasoning: str = Field(description="Why these two findings describe the same issue")


class DiffResult(BaseModel):
    vuln_only: list[VulnerabilityFinding] = Field(description="Findings present only in the vulnerable version — not matched to any benign finding")
    benign_only: list[VulnerabilityFinding] = Field(description="Findings present only in the benign version — not matched to any vulnerable finding")
    shared: list[FindingPair] = Field(description="Findings that appear in both versions, paired together")
