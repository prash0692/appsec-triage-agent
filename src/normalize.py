"""Day 3: normalize SARIF results into a fixed Finding schema and remove exact duplicates."""
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "unknown"]


class Finding(BaseModel):
    id: str
    tool: str
    repo: str
    rule_id: str
    severity: Severity
    security_severity_score: Optional[float]
    file: str
    line: int
    start_column: int
    message: str
    has_code_flow: bool


def severity_band(score):
    """Map a 0-10 security-severity score to GitHub's bands."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def build_rule_index(run):
    """Collect rule definitions from tool.driver AND every tool.extensions entry."""
    rules = {}
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + tool.get("extensions", [])
    for component in components:
        for rule in component.get("rules", []):
            rules[rule["id"]] = rule
    return rules


def repo_name(run):
    """Read 'owner/repo' from versionControlProvenance."""
    for entry in run.get("versionControlProvenance", []):
        uri = entry.get("repositoryUri", "")
        if "github.com/" in uri:
            return uri.split("github.com/")[1].removesuffix(".git")
    return "unknown"


def make_id(tool, repo, rule_id, file, line, start_column, line_hash):
    """Stable ID: line hash + rule + file + column; fall back to line number if no hash."""
    if line_hash:
        parts = [rule_id, file, line_hash, str(start_column)]
    else:
        parts = [tool, repo, rule_id, file, str(line), str(start_column)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def normalize_codeql(sarif):
    findings = []
    for run in sarif.get("runs", []):
        tool = run["tool"]["driver"]["name"].lower()
        repo = repo_name(run)
        rules = build_rule_index(run)
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if not locations:
                continue  # no location: skip (Block 4 decision)
            physical = locations[0]["physicalLocation"]
            region = physical.get("region", {})
            rule_id = result["ruleId"]
            score_text = rules.get(rule_id, {}).get("properties", {}).get("security-severity")
            score = float(score_text) if score_text is not None else None
            file = physical["artifactLocation"]["uri"]
            line = region.get("startLine", 0)
            start_column = region.get("startColumn", 1)
            line_hash = result.get("partialFingerprints", {}).get("primaryLocationLineHash")
            findings.append(Finding(
                id=make_id(tool, repo, rule_id, file, line, start_column, line_hash),
                tool=tool,
                repo=repo,
                rule_id=rule_id,
                severity=severity_band(score),
                security_severity_score=score,
                file=file,
                line=line,
                start_column=start_column,
                message=result["message"]["text"],
                has_code_flow="codeFlows" in result,
            ))
    return findings


def dedupe_exact(findings):
    """Remove findings identical on all six fields; keep the first copy."""
    seen, unique = set(), []
    for finding in findings:
        key = (finding.tool, finding.rule_id, finding.file,
               finding.line, finding.start_column, finding.message)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def main(paths):
    all_findings, raw = [], 0
    for path in paths:
        sarif = json.loads(Path(path).read_text())
        raw += sum(len(run.get("results", [])) for run in sarif.get("runs", []))
        all_findings += normalize_codeql(sarif)

    unique = dedupe_exact(all_findings)

    out = Path("data/processed/findings.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as file:
        for finding in unique:
            file.write(finding.model_dump_json() + "\n")

    print(f"raw results:        {raw}")
    print(f"normalized:         {len(all_findings)}  (skipped {raw - len(all_findings)})")
    print(f"removed duplicates: {len(all_findings) - len(unique)}")
    print(f"written:            {len(unique)} -> {out}")


if __name__ == "__main__":
    main(sys.argv[1:])