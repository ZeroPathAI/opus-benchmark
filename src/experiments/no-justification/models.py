from enum import Enum

from pydantic import BaseModel, Field


# --- Analysis models ---


class VulnerabilityFinding(BaseModel):
    cwes: list[str] = Field(description="CWE identifiers, e.g. ['CWE-787', 'CWE-125']")
    code_snippets: list[str] = Field(description="Relevant code excerpts from the function that relate to the vulnerability")
    short_description: str = Field(description="One-line summary of the vulnerability")
    long_description: str = Field(description="Detailed explanation of the vulnerability, how it could be exploited, and potential impact")


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
