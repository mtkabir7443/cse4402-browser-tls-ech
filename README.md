# Browser TLS and ECH Compatibility Testbed

**Mohammed Kabir · mtk21002 · UConn CSE 4402 · Fall 2026 · Solo project**

A browser-driven website that measures controlled TLS versions, cipher suites, and Encrypted Client Hello (ECH), logs each result with the server-observed client IP, and compares all tested browser builds.

**Completed local study:** 252 measurements = 7 browser builds × 12 configurations × 3 fresh-state repetitions. All builds rejected TLS 1.0/1.1, negotiated the tested modern suites, accepted valid ECH, and recovered from a stale ECH key under the documented settings. See the [written report](documents/CSE4402_TLS_ECH_Report.pdf) for motivation, methods, results and limitations.

## Start here

1. Open [results/comparison.html](results/comparison.html) in a browser. It works offline, with browser/case filters and downloadable data.
2. Read the [November 22 design](documents/CSE4402_TLS_ECH_Design_Nov22.pdf) and [report source](report.md).
3. Check the packaged data with `node scripts/verify-public-results.cjs results`.
4. Follow [REPRODUCE.md](REPRODUCE.md) to build, validate and run a new local experiment. See [DEMO.md](DEMO.md) for the shortest demonstration.

The website is in `web/`; Go provides TLS/ECH/DoH and persistent result logging; Node provides exact TLS 1.3 suite fixtures and browser automation. No npm dependencies are needed for measurements. Browser binaries, generated keys and profiles are acquired or generated locally and are not shipped.

| Browser build | Runs |
|---|---:|
| Chrome for Testing 157.0.8103.78 | 36 |
| Firefox 160.0 | 36 |
| Microsoft Edge 157.0.4341.60 | 36 |
| Brave 1.99.57 / Chromium 157.0.8103.79 | 36 |
| Opera 140.0.6074.18 / Chromium 157.0.8103.39 | 36 |
| Chrome for Testing 116.0.5845.96 | 36 |
| Firefox 115.0.3 ESR | 36 |

These are measured builds, not a claim about the latest releases. Edge's underlying Chromium patch version is unknown. Several builds share Chromium. The study used Windows 11, loopback, headless execution, explicitly configured DoH/ECH, normal certificate verification and fresh profiles; it does not establish untouched browser defaults or overall security rankings.

## Results and evidence boundary

The included results preserve all 252 observations, exact build identities, negotiated parameters, ECH summaries and loopback client IPs. They are an allowlisted, sanitized export. Raw profiles, packet/browser diagnostics, machine paths, private keys and correspondence are excluded. [Results documentation](results/README.md) distinguishes included evidence summaries from the complete raw-evidence audit retained in the research workspace. Portable consistency checks do not independently replay omitted raw evidence.

The live program creates private append-only logs in `evidence/`; the packaged historical study is in `results/`. A fresh experiment uses a new batch and generated `browsers.json`. Do not replace the fixed historical results with a different cohort under the same study label.

[Requirements coverage](requirements-coverage.md) maps every professor requirement to code, evidence or documentation. [SUBMISSION.md](SUBMISSION.md) separates the two deadlines and remaining delivery actions. Local demo is accepted; external hosting is optional.

The [four-page final report](documents/CSE4402_TLS_ECH_Report.pdf) and its [Markdown source](report.md) accompany the five-page design. The report links to the revision used to verify the implementation and the 252 published observations.
