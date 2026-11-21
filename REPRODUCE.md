# Reproduce the local experiment

## Prerequisites and pinned tools

Use Windows 11, PowerShell 7.2+, Node.js, 7-Zip, and OpenSSL. Verified locally: Node 26.13.0 with embedded OpenSSL 3.5.9, external OpenSSL 3.5.0 at `C:\msys64\mingw64\bin\openssl.exe`, and Go 1.27.4. Use the tested Node version (the runner requires the global WebSocket API). Both `7z` and `openssl` must resolve on PATH; add their installation directories to PATH if needed. Set `$env:SUITE_TEST_OPENSSL = (Get-Command openssl).Source` before Node fixture tests. `Test-TlsFixtures.ps1` and `Renew-LabCertificate.ps1` accept `-OpenSslPath (Get-Command openssl).Source`. The Go and Node programs use their standard libraries; no npm packages are required for the measurement runner.

```powershell
Set-Location (Join-Path $env:USERPROFILE 'source/cse4402-browser-tls-ech')
```

On a fresh checkout, download the pinned Go archive from its official release directory, verify the published SHA-256, and extract the `go` directory into `.tools`:

```powershell
New-Item -ItemType Directory -Path '.tools' -Force | Out-Null
Invoke-WebRequest 'https://go.dev/dl/go1.27.4.windows-amd64.zip' -OutFile '.tools/go1.27.4.windows-amd64.zip'
$expectedGoHash = '178AB98950AC69AB25069307DC6ADE79F3816E414CCE95B4DA166A115CDE1E7E'
if ((Get-FileHash '.tools/go1.27.4.windows-amd64.zip').Hash -ne $expectedGoHash) { throw 'Go archive hash mismatch' }
Expand-Archive '.tools/go1.27.4.windows-amd64.zip' -DestinationPath '.tools'
& '.tools/go/bin/go.exe' version
& './scripts/Get-Browsers.ps1'
```

`Get-Browsers.ps1` obtains official browser distributions, verifies the recorded provenance/hashes and versions, and creates local `browsers.json` (ignored by Git because it contains absolute paths). It requires 7-Zip for installer extraction. It does not replace personal browser installations. Publisher-provided hashes and locally observed archive hashes are identified separately; Chrome for Testing provenance includes its official manifest and Storage MD5 rather than treating an observed SHA-256 as a publisher-signed value.

| Runner ID | Pinned build / distribution |
|---|---|
| `chrome-current` | Chrome for Testing 157.0.8103.78 |
| `firefox-current` | Firefox 160.0 |
| `edge-current` | Installed Microsoft Edge 157.0.4341.60 |
| `brave-current` | Brave 1.99.57 / Chromium 157.0.8103.79 |
| `opera-current` | Opera 140.0.6074.18 / Chromium 157.0.8103.39 |
| `chrome-116` | Chrome for Testing 116.0.5845.96 |
| `firefox-115` | Firefox 115.0.3 ESR |

Current Chrome uses [this official CfT manifest](https://googlechromelabs.github.io/chrome-for-testing/157.0.8103.78.json) and `.tools/chrome-157.0.8103.78/chrome-win64/chrome.exe`. Historical Chrome uses its separate `.tools/chrome-116.0.5845.96` directory. The measured Chrome distribution is explicitly CfT; it is not the user's personal Chrome installation. Edge can auto-update, so the runner checks the pinned executable/version before running. Several products share Chromium; this is seven builds, not seven independent engines.

On this Windows machine, sandboxed Chromium processes needed read/execute access to the extracted public browser files. The following narrow ACL grants were applied; apply them to these four binary directories when reproducing that setup. Do not grant access to `.runtime`, private keys, profiles, or evidence.

```powershell
foreach ($browserDir in @(
    '.tools/chrome-157.0.8103.78/chrome-win64',
    '.tools/chrome-116.0.5845.96/chrome-win64',
    '.tools/brave-1.99.57',
    '.tools/opera-140.0.6074.18'
)) {
    & icacls.exe $browserDir /grant '*S-1-15-2-2:(OI)(CI)(RX)'
    if ($LASTEXITCODE -ne 0) { throw "Browser sandbox ACL failed: $browserDir" }
}
```

## Start the lab and validate fixtures

```powershell
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
& './scripts/Start-Lab.ps1' -TrustLabCA
& '.tools/go/bin/go.exe' test -v .
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
& './.runtime/tlslab.exe' -mode probe
if ($LASTEXITCODE -ne 0) { throw 'Independent ECH controls failed' }
node --test './scripts/suite-fixtures.test.cjs'
if ($LASTEXITCODE -ne 0) { throw 'Node suite controls failed' }
& './scripts/Start-SuiteFixtures.ps1'
```

`Start-Lab.ps1` builds Go and initializes the local CA, server certificate and ECH keys only when absent. Reuse existing material. Stop the project's running services before rebuilding/restarting; do not start a second listener on occupied ports. Tests need the generated certificates, so initialize before testing on a fresh checkout.

`-TrustLabCA` temporarily imports the lab CA into the Windows **CurrentUser Root** store for Chromium; Windows may show its certificate confirmation. Firefox uses application-local certificate policies in the two dedicated distributions, with trust details/policy hashes saved by the runner. No measurement bypasses certificate verification. Independent Go/OpenSSL controls use the explicit `.runtime/ca.pem` file and do not require OS trust.

Each fresh checkout generates its own CA, ECH keys and server certificate; none are distributed. The original study leaf expires January 9, 2027. Fresh initialization creates a two-month CA and one-month leaf. Check their dates; stop services before using `scripts/Renew-LabCertificate.ps1 -OpenSslPath (Get-Command openssl).Source` if leaf renewal is needed. An expired CA requires new fixtures and trust rather than leaf renewal alone.

The Node tests use ephemeral ports and verify positive negotiation, incompatible-suite rejection, CORS, logging/correlation, and resumption behavior with an independent OpenSSL client. The persistent server disables stateless tickets and declines stateful resumption; tickets can still be issued, so logs record actual `resumed` status and each measured repetition starts with a new browser profile. The older `Test-TlsFixtures.ps1` separately checks all version/suite fixtures using temporary OpenSSL servers; run it **before starting the persistent Node fixtures**, or stop Node first, because both use ports 9451–9453.

All listeners bind to `127.0.0.1`. Dashboard/control page: **https://127.0.0.1:8443/**. DoH: `https://127.0.0.1:8443/dns-query`.

| Cases | Hostname prefix | Port | Restriction |
|---|---|---:|---|
| V1–V4 | `tls10`, `tls11`, `tls12`, `tls13` | 9440, 9441, 9442, 9443 | Exactly TLS 1.0, 1.1, 1.2, 1.3 respectively |
| C1 | `tls12-aes128` | 9445 | TLS 1.2 ECDHE-RSA AES-128-GCM/SHA-256 |
| C2 | `tls12-chacha` | 9446 | TLS 1.2 ECDHE-RSA ChaCha20-Poly1305/SHA-256 |
| C3–C5 | `tls13-aes128`, `tls13-aes256`, `tls13-chacha` | 9451, 9452, 9453 | Node HTTPS; exactly one corresponding TLS 1.3 suite |
| E1–E3 | `valid`, `baseline`, `stale` | 9443 | Current ECH; no advertised ECH; stale ECH with replacement for retry |

Append `.tlslab.test` to each prefix. Controlled DoH provides A/HTTPS records, explicit service target names, endpoint ports and ECH configuration where applicable. Unknown names are not forwarded. Do not substitute hosts-file entries or browser address overrides: these can bypass HTTPS-record discovery. QUIC/HTTP3 is disabled for this TCP-only experiment.

## Run the seven-browser comparison

The planned matrix is **7 builds × 12 cases × 3 fresh-state repetitions = 252 runs**. The runner accepts comma-separated `--browser` and `--case` filters, `--repeats` (default 3), and `--batch`. `--dry-run` prints the plan without browser/network activity or writes:

```powershell
node './scripts/run-matrix.cjs' --browser chrome-current --case V1,V3,C4,E1,E2,E3 --repeats 1 --batch smoke --dry-run
```

Use one batch for the six non-Edge builds, then the Edge wrapper. This workflow produced the complete `study-20261115` dataset; a new reproduction should use a fresh batch:

```powershell
$batch = 'comparison-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
node './scripts/run-matrix.cjs' --browser chrome-current,firefox-current,brave-current,opera-current,chrome-116,firefox-115 --repeats 3 --batch $batch
if ($LASTEXITCODE -ne 0) { throw 'Matrix interrupted: inspect evidence before resuming' }
# This machine protects HKCU\Software\Policies against ordinary-user writes:
& './scripts/Run-EdgeMatrix.ps1' -Batch $batch -Repeats 3 -UseAdministratorLease
```

The runner can append/resume the same batch, skipping completed case/repetition cells when the pinned manifest is unchanged. A browser/version mismatch or runner failure stops execution; an evidence-supported browser rejection of a legacy TLS endpoint is a legitimate result, not a runner failure. Do not edit the manifest midway through a batch.

The Edge wrapper requires **no existing `msedge` process**; close Edge yourself before invoking it. It temporarily sets only the original user's Edge policy values `DnsOverHttpsMode` and `DnsOverHttpsTemplates`, refuses conflicting HKLM policy, and restores their prior values/types. It does not close personal Edge processes. `-Cases 'V1,E1'` supports a subset.

### Edge on Windows with protected policy keys

Run the command above from **normal, unelevated PowerShell**. `-UseAdministratorLease` opens a Windows UAC prompt for `Edge-PolicyLease.ps1`; approve it yourself if proceeding. Only that helper is elevated. Node and the measured Edge process remain unelevated. The helper receives the original user's explicit SID and opens that loaded `HKEY_USERS` hive, avoiding an administrator's separate HKCU. It changes exactly the two DoH values, preserves their original values/types, and never changes HKLM or ACLs.

The wrapper waits up to 60 seconds after UAC for active status, runs Edge, then requests release in `finally` and waits up to 60 seconds for verified restoration. The helper also expires after **10 minutes**. Its actual UTC expiry is passed to the runner. Startup waits are bounded; after page readiness, the runner and page recheck the deadline before registration. With fewer than **180 seconds** remaining, the runner pauses, cleans up any owned startup browser, saves the next cell and lets the wrapper restore policy. Active control waits retain a 30-second cleanup reserve. Resume the same batch with a fresh approved lease; completed cells are preserved. Slow fresh-profile runs may require multiple leases. Do not terminate the helper; use its recorded release file if needed. Forced termination or power loss can interrupt `finally`, so inspect the backup before another run after an abnormal stop. A lease timeout is reported as an error requiring review.

Each invocation has a fresh lease ID separate from the shared measurement batch. Status/backup: `.runtime/edge-policy-lease-<lease-id>.json`; release: the same prefix with `.release`; retained evidence: `evidence/edge-policy-lease-<lease-id>.json`. The temporary `.runtime/edge-policy-lease.lock` identifies the helper PID and is removed after cleanup. The wrapper verifies restored registry values/types as well as helper status.

If the user's policy key is writable without elevation, omit `-UseAdministratorLease` to use the original direct route; its restoration evidence is `evidence/edge-policy-<batch>.json`. The protected-key route supported all 36 Edge measurements across two approved leases, both restored and verified. The final lease completed the remaining 15 cases/repetitions with the deadline guard active. Focused tests cover delayed startup and readiness without registration; a real deadline-triggered automatic pause has not been needed in the completed dataset.

Every run creates an isolated profile and owned browser process, preserving retries within that run. Chromium uses CDP and Firefox uses Marionette; the measured HTTPS connection comes from that browser, not from a backend scanner. Metadata records executable hashes, actual browser version/UA, OS, settings, trust, certificate hash and evidence paths. `--screenshots representative|all|none` defaults to representative first repetitions and anomalies; `--timeout 60` sets the per-case limit (20–90 seconds). Profiles remain under `.runtime/profiles` for audit and are not personal browsing profiles.

## Results, offline export, and cleanup

- `evidence/runs.jsonl`: registered/completed attempts, including failures before an HTTP probe can be sent; server-observed client IP is retained.
- `evidence/server-events.jsonl` and `evidence/suite-events.jsonl`: DNS/handshake/HTTP evidence from Go and Node.
- `evidence/matrix/<batch>/matrix.json`: progress and run references. Each `runs/<run-id>/` subdirectory preserves runner metadata, browser logs, page evidence and selected screenshots.
- The dashboard displays per-run outcomes and aggregate browser/case results; API exports support JSONL and CSV.

Match the registered run, fixture, time, client address and connection identity. An ECH extension or GREASE alone is insufficient: acceptance requires actual server acceptance. Stale recovery needs the initial configuration, rejection/retry evidence and final outcome. Classify DNS/trust/service/runner failures separately from supported/unsupported TLS behavior. A local `127.0.0.1` client address is the correct observation; do not invent a public IP.

While Go is running, export a self-contained comparison:

```powershell
node './scripts/export-results.cjs' --batch $batch
if ($LASTEXITCODE -ne 0) { throw 'Comparison coverage needs review; inspect the generated HTML' }
```

The default output is `output/comparison.html`; `--out` selects another file. It embeds the data for offline viewing and filtered CSV/JSONL or complete-bundle downloads. `--batch-id` is an alias for `--batch`. Incomplete, duplicate or version-mismatched coverage produces exit code 2 even though HTML is written; `--allow-incomplete` is only for explicitly partial previews. The exporter does not write research conclusions. Raw exports include client IPs and are local review artifacts, not sanitized public reports.

After testing/export:

```powershell
& './scripts/Stop-SuiteFixtures.ps1'
& './scripts/Stop-Lab.ps1'
```

The suite stop script validates its recorded process identity; the Go stop script checks its recorded executable before stopping it. `Stop-Lab.ps1` then invokes Windows certificate removal for only the recorded lab CA. **If Windows displays a Root Certificate Store dialog, click Yes only for DELETE of the CSE4402 isolated TLS lab certificate.** The script verifies absence afterward and fails if removal was canceled or incomplete. PowerShell's certificate provider cannot perform this user-root operation in a noninteractive host, so the script uses the normal `certutil -user -delstore` confirmation flow. Firefox application-local policies and imported certificates in the private profiles remain as evidence; do not reuse those profiles for ordinary browsing. Keep `.runtime`, browser distributions, private keys, profiles and sensitive raw logs out of public source/export bundles.

The included written report and design are separate deliverables; see [SUBMISSION.md](SUBMISSION.md). The bundled [sanitized comparison](results/comparison.html) is immediately viewable offline. Running the commands above creates a new private dataset; it does not overwrite the packaged `results/` directory. `audit-study.cjs` is the original, study-specific full raw-evidence auditor and needs the retained raw workspace, original executable/certificate material and batch; it cannot replay that audit from this sanitized package. Use `node scripts/verify-public-results.cjs results` for portable consistency checks. New runs should undergo an equivalently complete raw-evidence review before being reported.



## Clean-checkout checks without Windows trust

After installing the tools, run `./scripts/Verify-Checkout.ps1 -OpenSslPath (Get-Command openssl).Source`. It builds and initializes new private fixtures, runs Go tests/vet and Node controls, and checks the included results. It uses ephemeral loopback test servers and explicit CA files; it does not install trust, launch browsers, or rerun the study. PDF regeneration additionally requires Python with ReportLab and pypdf; the reviewed PDFs are already included. Run `python scripts/build_design.py --label "Project specifications and design"` for the design or `python scripts/build_design.py --source report.md --output CSE4402_TLS_ECH_Report.pdf --label "Measurement report"` for the report; output goes to ignored `output/pdf/` for review before replacing a deliverable.

Extract or clone beneath your Windows user-profile directory (the example uses `source/cse4402-browser-tls-ech`). The bounded Edge policy helper intentionally rejects checkouts outside that directory. Edge acquisition uses the version currently installed and signed on the reproduction machine. An updated Edge will be a new study cohort, not an exact replay of the original pinned Edge. Keep each newly generated manifest fixed for its entire batch.
