# Requirements coverage

Requirements source: [approved scope](scope.md), course handout and supplied professor correspondence. This maps completed local work and verified GitHub publication; submission and the eventual grade are separate.

| Requirement | Included implementation / evidence | Status |
|---|---|---|
| Solo website testing TLS, cipher suites and ECH | `web/`, `main.go`, `clienthello.go`, `scripts/suite-fixtures.cjs`; design sections 1–3 | Complete locally |
| More browsers, including older Chrome and Firefox | Seven builds in `results/comparison-data.json`; 36 observations each, all 252 retained | Complete |
| Webpage generates individual results | `web/app.js` runs real browser requests and renders normalized results; `results.go` persists registration/completion | Complete; recorded runs originated in real browsers |
| Persistent log identifies client IP | `results.go`, tests in `results_test.go`; fresh runs create `evidence/runs.jsonl`; packaged `results/results.jsonl` retains observed 127.0.0.1 | Complete |
| Overall results for all browsers | Offline `results/comparison.html`, CSV/JSONL and report section 4 | Complete |
| Local demo; external access preferred | `REPRODUCE.md`, `DEMO.md`, full source and controls | Local implementation verified; optional external hosting not deployed |
| Written report with motivation, background, results, conclusions | `documents/CSE4402_TLS_ECH_Report.pdf`, `report.md`; all twelve measurement motivations included | Prepared |
| Documentation and reproducibility | Setup/cleanup, pinned archive acquisition, fresh profiles, trust/policy handling, tests, result verification, limitations | Included; exact installed Edge build may change on a new host |
| November 22 design/methods | `documents/CSE4402_TLS_ECH_Design_Nov22.pdf`, `design.md` | Prepared, not submitted |
| December 18 final report and GitHub code link | Report included; [public GitHub repository](https://github.com/mtkabir7443/cse4402-browser-tls-ech) | Publication verified; graded submission pending |

All three repetitions agree in every cell. Totals: 42 protocol rejections, 147 modern version/suite connections, 21 valid-ECH acceptances, 21 non-ECH baselines, 21 stale-key recoveries. See the report for configured-settings, loopback, shared-engine and limited-sample caveats.

`results/evidence-summary.json` contains selected observations and provenance from the completed private raw-evidence audit. `verify-public-results.cjs` checks the sanitized package's internal consistency and complete coverage; it does not replay omitted private logs. New controls run from a checkout are fixture/software tests, not a new 252-run browser study.
