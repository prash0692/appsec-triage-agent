"""Day 2: read a SARIF file and print a clean findings list."""
import json
import sys


def load_findings(sarif_path):
    with open(sarif_path) as file:
        sarif = json.load(file)

    findings = []
    for result in sarif["runs"][0]["results"]:
        location = result["locations"][0]["physicalLocation"]
        findings.append({
            "alert": result.get("properties", {}).get("github/alertNumber"),
            "rule": result["ruleId"],
            "file": location["artifactLocation"]["uri"],
            "line": location["region"]["startLine"],
            "has_path": "codeFlows" in result,
        })
    return findings


if __name__ == "__main__":
    findings = load_findings(sys.argv[1])
    for item in findings:
        flag = "path" if item["has_path"] else "-"
        print(f"#{item['alert']}  {item['rule']}  {item['file']}:{item['line']}  {flag}")
    print(f"\n{len(findings)} findings")