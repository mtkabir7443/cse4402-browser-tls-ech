# Browser TLS and ECH Compatibility Testbed

**Project specifications and design | November 21, 2026**

Mohammed Kabir | NetID mtk21002 | CSE 4402, SEC001 | Solo project

## 1. Purpose and approved scope

This website measures browser behavior at controlled HTTPS endpoints. It separates the ability to establish a connection from the security properties actually negotiated. The study asks which TLS versions and selected cipher suites work, whether browsers use a valid Encrypted Client Hello (ECH) configuration, and how they recover when the advertised ECH key is stale.

Professor Herzberg approved a solo study with several browsers, including older Chrome and Firefox. The local testbed displays each result and logs the client's IP. The [public dashboard](https://mtkabir7443.github.io/cse4402-browser-tls-ech/) compares **252 measurements** completed and verified locally on November 15. Batch `study-20261115` covers seven builds, 12 configurations and three fresh-state repetitions. The written report explains the motivation and findings.

## 2. Measurements and interpretation

| ID | Controlled endpoint | Question answered |
| --- | --- | --- |
| V1-V4 | TLS 1.0, 1.1, 1.2 and 1.3, each separately | Does the connection succeed, and which version is negotiated? Diagnosed rejection of obsolete TLS is an expected security result. |
| C1 | TLS 1.2, ECDHE-RSA with AES-128-GCM/SHA-256 | Can this exact suite work with the trusted RSA certificate? |
| C2 | TLS 1.2, ECDHE-RSA with ChaCha20-Poly1305/SHA-256 | Compare another authenticated-encryption algorithm under the same version and certificate conditions. |
| C3-C5 | TLS 1.3, one suite per endpoint: AES-128-GCM/SHA-256 (C3), AES-256-GCM/SHA-384 (C4), ChaCha20-Poly1305/SHA-256 (C5) | Does the browser negotiate the sole permitted suite? The server records the version and suite from the connection. |
| E1 | Current ECH configuration in the HTTPS DNS record | Does the server accept genuine ECH and deliver the requested page? |
| E2 | No advertised ECH configuration | Establish the baseline. An ECH-shaped GREASE extension does not establish ECH acceptance. |
| E3 | Stale advertised ECH key; server offers its current replacement | Observe initial non-acceptance, retry evidence and the final connection/ECH outcome separately. |

The implementation retains canonical suite names in its configuration and exports. Certificate-validation attacks, a separate DNSSEC suite and HTTP/3 are outside this scope. Valid certificates and controlled DNS are prerequisites for interpreting these tests.

<!-- PAGEBREAK -->

## 3. Software specification

The implementation uses Go 1.27.4, Node.js 26.13.0, browser JavaScript, HTML/CSS and PowerShell 7. Go's standard libraries provide TLS, certificate handling, HTTP and JSON. Node uses built-in networking, cryptography, filesystem and child-process modules. Node's OpenSSL 3.5.9 implementation can restrict TLS 1.3 cipher suites individually. Go's public cipher-suite setting covers TLS 1.2 and earlier. Independent fixture checks use the OpenSSL 3.5.0 command-line client.

| Component and source | Functions, methods and data flow |
| --- | --- |
| TLS and DNS (Go) in `main.go` | `setup()` creates the lab CA, certificate and ECH material. `serve()` configures listeners. `dnsResponse()` builds address and HTTPS records with service target, port and ECH information. `probeHandler()` records the HTTP run ID and negotiated state. |
| Handshake observation (Go) in `main.go` and `clienthello.go` | `auditedListener.pump()` records TLS outcomes. `helloConn.Read()`, `parseClientHello()` and `decodeHello()` extract the versions and ECH configuration ID offered by the browser. `stateFields()` reads actual acceptance and negotiated parameters from the TLS connection. |
| Single-suite fixtures (Node) in `scripts/suite-fixtures.cjs` | `createFixtureServers()` uses `node:https` and the `FIXTURES` definitions to start one TLS 1.3 listener per suite. The `secureConnection` and `tlsClientError` handlers log success or failure. Successful HTTP probes include the run ID. |
| Browser controllers (Node) in `scripts/run-matrix.cjs` | `main()` selects the batch and repetitions. `runOne()` checks the executable hash, opens a fresh profile and invokes the page. The `CDP` class uses `connect()`, `send()` and `close()` to control Chromium. The `Marionette` class uses `connect()`, `send()`, `evaluate()` and `close()` for Firefox. `MarionetteFrames.push()` assembles messages. |
| Website (HTML/CSS/JS) in `web/index.html`, `web/style.css`, `web/app.js` | `window.labRun()` registers a case, calls the browser Fetch API against the test endpoint and posts the browser outcome. `renderResult()` displays the individual record. `refreshResults()` retrieves records for `renderComparison()`. |
| Journal and API (Go) in `results.go` | `measurementCases()` specifies endpoint restrictions. Methods on the `resultsStore` struct handle registration (`runs()`), completion (`run()`), persistent writes (`appendRun()`) and replay (`loadRuns()`). `classifyRun()` matches evidence. `buildResultSummary()` aggregates records. |
| Analysis and export (Node) in `scripts/` | In `export-results.cjs`, `analyzeCoverage()` checks the matrix and `renderReport()` creates offline HTML. `auditStudy()` in `audit-study.cjs` checks private evidence. `prepareData()` in `prepare-public-results.cjs` selects shareable fields. `verifyDirectory()` in `verify-public-results.cjs` checks the public package. |

**Operational tools.** `Get-Browsers.ps1` acquires and inventories builds. `Start-Lab.ps1` and `Start-SuiteFixtures.ps1` launch the services. `Run-EdgeMatrix.ps1` temporarily configures and restores Edge's lab DNS policy. Stop scripts close the services and remove temporary Windows lab trust.

<!-- PAGEBREAK -->

## 4. Architecture and experimental protocol

<!-- ARCHITECTURE -->

All listeners bind to loopback. Go serves the control page and DNS-over-HTTPS (DoH) on port 8443, V1-V4 on 9440-9443 and C1-C2 on 9445-9446. Node serves C3-C5 on 9451-9453. E1-E3 share 9443 and use distinct hostnames. HTTPS DNS records supply explicit service target names for nondefault ports. [1-3]

1. **Check the fixtures.** Independent Go/OpenSSL clients verify certificate chain, names and validity, correct protocol/suite negotiation, incompatible-suite rejection and current/stale ECH behavior. These controls are separate from browser measurements.

2. **Use a fresh browser.** Launch a new isolated profile and process for every case and repetition. Use strict lab DoH, disable QUIC, retain certificate validation and record exact settings. ECH is explicitly enabled where the build exposes the setting; results describe this configuration rather than untouched consumer defaults.

3. **Register before testing.** Through the working control page, persist the run ID, build, distribution, OS, settings, case and repetition. The server records the socket-observed client IP and certificate fingerprint. It permits one outstanding run per client IP.

4. **Measure from the browser.** After registration at `/api/runs`, the browser fetches `/probe?run=<id>` on the restricted endpoint. The page posts to `/api/runs/<id>/complete` on the working control connection even if the measured TLS request failed. Server TLS/HTTP records establish negotiation.

5. **Classify with evidence.** Successful probe requests carry the run ID. Before HTTP, match handshake events by endpoint, observed IP and the registered time window. An explicit protocol or cipher incompatibility supports rejection. A correlated certificate error can identify an infrastructure failure. If a fetch fails or times out without matching server evidence, retain the browser symptom and leave the cause inconclusive.

6. **Repeat, retain and compare.** Record all three outcomes, including failed or inconclusive ones. Completed cells are preserved on resume. Export the full browser-by-case comparison and per-run JSONL/CSV. Fresh processes prevent cross-run reuse; server logs independently record resumption. Retries within E3 remain allowed.

Go disables session tickets. Node may issue TLS 1.3 stateful tickets and declines resumption lookups. The fixture control presents a prior session and checks the server's resumption flag on the new connection.

The server appends registration and completion events to the JSONL journal, synchronizes writes before acknowledgment and checks the journal on reopening. It reports write failures to the page. Both the browser and server run on the same host, so the client IP observed at the socket is 127.0.0.1.

<!-- PAGEBREAK -->

## 5. Browser selection, analysis and verified results

| Browser | Pinned build and distribution |
| --- | --- |
| Current Chrome | Chrome for Testing 157.0.8103.78, official Windows x64 archive |
| Current Firefox | Firefox 160.0, official Windows x64 release extracted locally |
| Microsoft Edge | Installed signed Edge 157.0.4341.60, isolated test profiles |
| Brave | Official Brave 1.99.57, Chromium 157.0.8103.79 |
| Opera | Official Opera 140.0.6074.18, Chromium 157.0.8103.39 |
| Older Chrome | Chrome for Testing 116.0.5845.96, official archive |
| Older Firefox | Firefox 115.0.3 ESR, official release extracted locally |

All runs use Windows 11 build 26300. Browser distributions are pinned in browsers.json with provenance and hashes; runtime versions and user agents are recorded. These seven builds represent two principal engine families. Edge reports its exact Edg product/version; its underlying Chromium patch version remains unknown. Older builds use dedicated profiles and controlled endpoints.

| Evidence check | Verified observation |
| --- | --- |
| Independent TLS controls after certificate renewal | Nine positive version/suite checks and five incompatible-suite controls passed. Persistent Node fixtures also passed three positives, three negatives, HTTP/log checks and a resumption control. |
| Independent ECH controls | Valid ECH accepted; baseline without ECH; stale key rejected with a 71-byte replacement list, followed by accepted ECH. |
| Complete seven-build browser study | All 252 runs passed the raw-evidence audit: 42 obsolete-TLS rejections, 147 modern version/suite connections, 21 valid-ECH acceptances, 21 non-ECH baselines and 21 stale-key recoveries. No missing cells or inconsistent repetitions. |
| Real dashboard workflow | The page displayed and persisted successful negotiation, obsolete-TLS rejection and all three ECH outcomes. Tests also cover journal integrity, logging errors and result correlation. |

Explicit DNS service TargetNames corrected Chrome's association of HTTPS records with nondefault-port endpoints. Selected NetLog records a restart with configuration 17 after stale 16; server ClientHello/HTTP evidence confirms acceptance. Parallel connections are not counted as sequential retries. [2]

Certificate verification stays enabled. Firefox uses project-local CA policy; Chromium uses temporary Windows user-root trust with explicit removal during cleanup. The renewed leaf covers the December deadline. Both Edge DNS policy leases restored the original settings. Startup and registration guards retain a 180-second lease reserve. Opera uses its custom-DoH preference.

**Analysis rule.** Key each observation by build, case and repetition. Compare repeats across all 84 build-case pairs and compare builds within each case. Flag missing slots, duplicates, build mismatches, resumption and disagreements. C4 requires a fresh TLS 1.3 handshake with `TLS_AES_256_GCM_SHA384` and the matching HTTP probe.

**Worked example (E2).** DNS advertised no ECH configuration. Match each HTTP probe to the successful handshake on the same connection. Chrome 157 sent an ECH extension on its first run. Firefox 115 ESR omitted it. Both connections succeeded without ECH. Across seven builds, the extension appeared in 18 of 21 runs, Firefox 115 ESR omitted it in all three, and the server accepted ECH in 0 of 21. This pattern is consistent with GREASE. [Inspect the 21 recorded runs](https://mtkabir7443.github.io/cse4402-browser-tls-ech/#ech-baseline).

<!-- PAGEBREAK -->

## 6. Deliverables and acceptance

| Professor's requirement | Implementation and acceptance evidence |
| --- | --- |
| Additional browsers and older Chrome/Firefox | Pinned seven-build manifest; one recorded entry for every case and repetition; acquisition alone is not measurement. |
| Webpage produces results | The live dashboard registers and executes a browser request, then displays the server-normalized result. Verify both a connection and an intentional TLS rejection. |
| Results also enter a log with client IP | evidence/runs.jsonl retains registration and completion. Handshake/HTTP logs supply protocol evidence. Check persistence, IP origin and visible log failures. |
| Overall results for all tested browsers | A complete matrix, per-run view, filters and CSV/JSONL exports. A self-contained comparison page remains usable after the lab stops. |
| Local demo and public access | The controlled DNS and TLS endpoints run locally. GitHub Pages displays the recorded comparison and the [per-run ECH dataset](https://mtkabir7443.github.io/cse4402-browser-tls-ech/ech-baseline.json). The ZIP includes the same data in `examples/ech-baseline.json`. |
| Written report with motivation, results and conclusions | Explain each measurement family, identify the dataset and methods, compare all builds and state limitations. A slide deck does not replace the report. |
| Good documentation and complete coverage | Source, pinned browser manifest, fixture checks, runner, result exports, setup/cleanup commands and requirement-by-requirement review. |

**November 22 milestone.** This specification documents goals, source modules, functions, classes, methods and the experimental protocol. The design is due Sunday, November 22, 2026, at 11:59 PM EST.

**December 18 milestone.** The written final report introduces and motivates each measurement, presents the comparison and draws conclusions. The [published implementation and dataset](https://github.com/mtkabir7443/cse4402-browser-tls-ech/tree/136afa761880e79b340a621cf99b2ff8f49aa6cd) include the source, reproduction instructions and sanitized per-run results. The raw diagnostics and cryptographic keys remain in the local research workspace.

The main limitations are a single Windows host, loopback networking, headless automation, explicitly configured DoH/ECH, a small number of builds and only three repetitions. Similar outcomes across Chromium products are legitimate results. The study measures compatibility under documented conditions; it does not rank overall browser security or estimate population-level failure probabilities.

## References

[1] Go, crypto/tls and ECH support: https://pkg.go.dev/crypto/tls and https://go.dev/doc/go1.24

[2] IETF, ECH and HTTPS DNS records: https://www.rfc-editor.org/rfc/rfc9849.html and https://www.rfc-editor.org/rfc/rfc9460.html

[3] Node.js, TLS and cipher configuration: https://nodejs.org/api/tls.html

[4] Mozilla, certificate policy: https://firefox-admin-docs.mozilla.org/reference/policies/certificates/

[5] Microsoft, managed DoH policy: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/dnsoverhttpsmode

Project requirements follow the course handout, Professor Herzberg's project correspondence and the November 21 HuskyCT specification.
