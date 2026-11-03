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

Not in the schema (enrichment, Day 14): EPSS, KEV, owner, exposure. Why: becuase this is not the information available in SARIF file itself, the enrichment will require me to make API calls to pull all the above enrichment data and map it to each of the findings thats part of enrichment not normalization.
ID strategy: sha256(rule_id + file + primaryLocationLineHash + start_column) choosing start column coz for cases like unused variable on var a,b,c,d; we get same hash for 4 different findings(a, b, c, d) when we only use line which is already included in "primaryLocationLineHash"  but when we use start column the hash created will different for each spot. and would not confused as the line keeps it all same. Also, the line number is left out: so the ID doesn’t change when code shifts up or down. That’s the first follow-up question an interviewer would ask.
Exact duplicate means: same : Exact duplicate = same tool, rule_id, file, line, start_column, and message. All six are identical. Anything less is a different finding (or a grouping question for Day 5).
