## Baseline — Oct 27, 2026

- Target: OWASP Juice Shop (fork: prash0692/juice-shop)
- Scanner: CodeQL, security-extended suite, advanced setup, no filters
- Findings: 405 total (JS/TS 372, Actions 31, Python 2)
- Same code with the maintainers' filtered config (paths-ignore + query-filters): 59 JS/TS findings
- Same code with the default suite: 80 JS/TS findings
- Takeaway: path + rule suppression cut volume 84%, but volume reduction ≠ accuracy.
  Pipeline will be measured against labeled ground truth.

  ## Day 2
- Built src/ingest.py: reads SARIF, prints 372 findings (rule, file:line, path yes/no).
- Noticed: most volume is three.js (third-party) and data/static/codefixes (challenge snippets).

## Day 3: Finding schema

| Field | Example | Source in SARIF | Why I need it |
|---|---|---|---|
| id | sha256(...) | computed | Stable name tag for one finding, so labels and results stay attached across runs |
| tool | codeql | tool.driver.name | Tells findings apart once a second scanner is added (Day 12) |
| repo | prash0692/juice-shop | versionControlProvenance | Which codebase the finding belongs to |
| rule_id | js/sql-injection | result.ruleId | What kind of problem it is; filters work on this |
| severity | critical | band from score | Simple urgency level for sorting and routing |
| security_severity_score | 8.8 | rule properties | Keeps the exact number so no information is lost when banding |
| file | routes/search.ts | locations → uri | Where to look; test and vendor paths get filtered on this |
| line | 23 | locations → startLine | Needed to find the code when labeling on Day 4 |
| start_column | 34 | locations → startColumn | Separates multiple findings on the same line; used in ID and dedupe |
| message | ... | message.text | What the scanner says is wrong; needed to label |
| has_code_flow | true | codeFlows present? | Marks findings with a source-to-sink path; starting point for reachability (Day 13) |

Not in the schema (enrichment, Day 14): EPSS, KEV, owner, exposure.
Why: this information isn't in the SARIF file. Enrichment needs API calls to pull it and map it to each finding, so it's part of enrichment, not normalization.

ID strategy: sha256(rule_id + file + primaryLocationLineHash + start_column).
Start column is added because findings on the same line share the same line hash (e.g., unused variables in `var a, b, c, d` give 4 findings with one hash); the column makes each spot unique. The line number is left out so the ID doesn't change when code shifts up or down.
Evidence: 39 line hashes are shared by 136 findings, so the hash alone isn't a unique ID.

Exact duplicate = same tool, rule_id, file, line, start_column, and message. All six identical. Anything less is a different finding (or a grouping question for Day 5).

### Evidence: line hash alone is not a unique ID

Command 1: how many line hashes repeat?
```bash
jq -r '.runs[0].results[].partialFingerprints.primaryLocationLineHash' data/raw/juice-shop-javascript-typescript.sarif | sort | uniq -d | wc -l
```
Result: **39**. Lists every finding's line hash, sorts them, keeps one copy of each hash that appears more than once (`uniq -d`), and counts them.

Command 2: how many findings share a repeated hash?
```bash
jq -r '.runs[0].results[].partialFingerprints.primaryLocationLineHash' data/raw/juice-shop-javascript-typescript.sarif | sort | uniq -D | wc -l
```
Result: **136**. Same as above, but `uniq -D` keeps every copy of each hash that appears more than once, and drops hashes that appear only once, so this counts the findings affected.

Why it matters: 136 of 372 findings (about 37%) share their line hash with another finding. If the hash alone were the ID, those findings would collide, and a Day 4 label written for one would apply to the others. Adding rule_id, file, and start_column gives each finding its own ID.

Day 3 result: 405 raw → 405 normalized → 0 exact duplicates. Volume reduction has to come from filters (Day 5), not dedupe.

To test normalize.py:
jq -r .severity data/processed/findings.jsonl | sort | uniq -c
jq -r .repo data/processed/findings.jsonl | sort | uniq -c
jq 'select(.rule_id=="js/request-forgery")' data/processed/findings.jsonl