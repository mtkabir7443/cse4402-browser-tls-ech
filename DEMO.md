# Demonstration guide

## Offline results (no setup or trust changes)

1. Open `results/comparison.html` in any browser. Point to the seven builds, twelve cases and 252 completed measurements.
2. Filter to V1/V2: each build rejected deprecated TLS. Change to C1–C5: each negotiated the one permitted suite.
3. Compare E1, E2 and E3: actual ECH acceptance, baseline without accepted ECH, and stale-key recovery from configuration 16 to 17. An ECH-shaped extension or GREASE alone does not establish acceptance.
4. Inspect a run and its logged loopback client IP. Download the available filtered data and compare it with the displayed rows.
5. Explain the boundary: configured capability on one Windows host, fresh profiles, normal certificate checks, shared Chromium ancestry; no claim about untouched defaults or general security rankings.

## Live browser measurements

Complete the prerequisite acquisition, fixture controls and trust setup in `REPRODUCE.md` first. The live website is `https://127.0.0.1:8443/` and requires both local services. The runner opens an isolated browser profile with controlled DoH/ECH settings; merely opening the page in a personal browser does not reproduce these conditions.

From the repository root in PowerShell 7:

```powershell
$demoBatch = 'demo-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
node './scripts/run-matrix.cjs' --browser chrome-current --case V1,C4,E1,E2,E3 --repeats 1 --batch $demoBatch
if ($LASTEXITCODE -ne 0) { throw 'Inspect the recorded run before proceeding' }
node './scripts/export-results.cjs' --batch $demoBatch --out './output/demo.html' --allow-incomplete
```

This is intentionally a five-case, one-browser demonstration; the export is labeled incomplete relative to the full study. It does not replace the completed packaged results. Show that each result appears in the page and the durable `evidence/runs.jsonl`, including a protocol rejection before a successful probe HTTP request. `results.go` obtains the client IP from the socket rather than trusting a submitted address.

Finish by stopping the suite fixtures and Go lab as documented. Confirm removal of the temporary Windows lab CA and restoration of any Edge policy lease. The Chrome-only demonstration does not require an Edge policy lease.
