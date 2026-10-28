## Baseline — Oct 27, 2026

- Target: OWASP Juice Shop (fork: prash0692/juice-shop)
- Scanner: CodeQL, security-extended suite, advanced setup, no filters
- Findings: 405 total (JS/TS 372, Actions 31, Python 2)
- Same code with the maintainers' filtered config (paths-ignore + query-filters): 59 JS/TS findings
- Same code with the default suite: 80 JS/TS findings
- Takeaway: path + rule suppression cut volume 84%, but volume reduction ≠ accuracy.
  Pipeline will be measured against labeled ground truth.