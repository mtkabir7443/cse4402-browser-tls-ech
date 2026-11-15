# Browser TLS and ECH Compatibility Testbed

**Design and methods - November 22, 2026**

Mohammed Kabir | NetID: mtk21002 | CSE 4402 | Solo project

## 1. Purpose and approved scope

This website measures browser behavior at controlled HTTPS endpoints. It separates the ability to establish a connection from the security properties actually negotiated. The study asks which TLS versions and selected cipher suites work, whether browsers use a valid Encrypted Client Hello (ECH) configuration, and how they recover when the advertised ECH key is stale.

Professor Herzberg approved a solo TLS/ECH project with additional browsers, including older Chrome and Firefox. Required outputs are a result webpage, a persistent log identifying the client's IP, an overall browser comparison, and a written report that motivates the measurements and discusses results. A local demonstration is acceptable; external hosting is optional. The 12 configurations, seven pinned builds and three fresh-state repetitions produce **252 measurements, all completed and verified locally on November 15**.

## 2. Measurements and interpretation

| ID | Controlled endpoint | Question answered |
| --- | --- | --- |
| V1-V4 | TLS 1.0, 1.1, 1.2 and 1.3, each separately | Does the connection succeed, and which version is negotiated? Diagnosed rejection of obsolete TLS is an expected security result. |
| C1 | TLS 1.2, ECDHE-RSA with AES-128-GCM/SHA-256 | Can this exact suite work with the trusted RSA certificate? |
| C2 | TLS 1.2, ECDHE-RSA with ChaCha20-Poly1305/SHA-256 | Compare another authenticated-encryption algorithm under the same version and certificate conditions. |
| C3-C5 | TLS 1.3, AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, each separately | Does the browser negotiate the sole permitted suite? These suite names do not specify authentication or key exchange. |
| E1 | Current ECH configuration in the HTTPS DNS record | Does the server accept genuine ECH and deliver the requested page? |
| E2 | No advertised ECH configuration | Establish the baseline. An ECH-shaped GREASE extension does not establish ECH acceptance. |
| E3 | Stale advertised ECH key; server offers its current replacement | Observe initial non-acceptance, retry evidence and the final connection/ECH outcome separately. |

The implementation retains canonical suite names in its configuration and exports. Certificate-validation attacks, a separate DNSSEC suite and HTTP/3 are outside this scope. Valid certificates and controlled DNS are prerequisites for interpreting these tests.

<!-- PAGEBREAK -->

## 3. Architecture and controls

<!-- ARCHITECTURE -->

Go serves the control page, private DNS-over-HTTPS (DoH), TLS-version fixtures, TLS 1.2 suite fixtures and ECH. Node's OpenSSL-backed TLS server supplies three persistent single-suite TLS 1.3 endpoints because Go does not expose TLS 1.3 suite selection through its public configuration. All listeners bind to loopback. HTTPS DNS records name the explicit service hostname, including when the question uses a non-default-port prefix. [1-3]

1. **Check the fixtures.** Independent Go/OpenSSL clients verify certificate chain, names and validity, correct protocol/suite negotiation, incompatible-suite rejection and current/stale ECH behavior. These controls are separate from browser measurements.

2. **Use a fresh browser.** Launch a new isolated profile and process for every case and repetition. Use strict lab DoH, disable QUIC, retain certificate validation and record exact settings. ECH is explicitly enabled where the build exposes the setting; results describe this configuration rather than untouched consumer defaults.

3. **Register before testing.** Through the working control page, persist the run ID, build, distribution, OS, settings, case and repetition. The server records the socket-observed client IP and certificate fingerprint. It permits one outstanding run per client IP.

4. **Measure from the browser.** The page fetches the selected endpoint, then completes the registered run even if that request fails. Server TLS/HTTP records establish negotiation. The runner does not substitute a backend TLS client for the browser.

5. **Classify with evidence.** A generic JavaScript fetch error is inconclusive. Explicit correlated protocol/cipher errors establish rejection; certificate, DNS, setup and unexplained timeout failures remain distinct. Successful requests carry the run ID. Pre-HTTP evidence is limited by endpoint, IP and the registered time window.

6. **Repeat, retain and compare.** Record all three outcomes, including failed or inconclusive ones. Completed cells are preserved on resume. Export the full browser-by-case comparison and per-run JSONL/CSV. Fresh processes prevent cross-run reuse; server logs independently record resumption. Retries within E3 remain allowed.

Go disables session tickets. Node declines resumption lookups and retains no resumable session state, although TLS 1.3 stateful ticket messages may still be issued. The fixture control verifies that a presented session is not resumed. No zero-ticket claim is required.

The JSONL journal is append-only, synchronized before acknowledgement and checked on reopening. Log-write failures are reported to the page. Client IP comes from the connection rather than a client-supplied field. The correct local value is 127.0.0.1; this experiment does not pretend to observe an external client address.

<!-- PAGEBREAK -->

## 4. Browser selection and verified results

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

Batch `study-20261115` has 252 verified runs and zero audit findings. The comparison export and written report retain the results and limitations; publication and submission remain pending.

<!-- PAGEBREAK -->

## 5. Deliverables and acceptance

| Professor's requirement | Implementation and acceptance evidence |
| --- | --- |
| Additional browsers and older Chrome/Firefox | Pinned seven-build manifest; one recorded entry for every case and repetition; acquisition alone is not measurement. |
| Webpage produces results | The live dashboard registers and executes a browser request, then displays the server-normalized result. Verify both a connection and an intentional TLS rejection. |
| Results also enter a log with client IP | evidence/runs.jsonl retains registration and completion. Handshake/HTTP logs supply protocol evidence. Check persistence, IP origin and visible log failures. |
| Overall results for all tested browsers | A complete matrix, per-run view, filters and CSV/JSONL exports. A self-contained comparison page remains usable after the lab stops. |
| Local demo; external access preferred | Reproduce the documented local setup and cleanup. External hosting remains optional and must preserve DNS/TLS test conditions and protect private logs. |
| Written report with motivation, results and conclusions | Explain each measurement family, identify the dataset and methods, compare all builds and state limitations. A slide deck does not replace the report. |
| Good documentation and complete coverage | Source, pinned browser manifest, fixture checks, runner, result exports, setup/cleanup commands and requirement-by-requirement review. |

**November 22 design deliverable:** this design/methods document, with the implemented architecture, controls and completed study evidence. It is prepared locally; submission is a separate action.

**December 18 final deliverable:** the written report and GitHub code link, supported by the measured comparison and reproducible setup. Before submission, rerun appropriate controls, check exact artifact hashes and complete the three-lens coursework review. Publish only the intended source/results package; private keys, browser profiles and raw network logs stay outside the public code repository.

The main limitations are a single Windows host, loopback networking, headless automation, explicitly configured DoH/ECH, a small number of builds and only three repetitions. Similar outcomes across Chromium products are legitimate results. The study measures compatibility under documented conditions; it does not rank overall browser security or estimate population-level failure probabilities.

## References

[1] Go, crypto/tls and ECH support: https://pkg.go.dev/crypto/tls and https://go.dev/doc/go1.24

[2] IETF, ECH and HTTPS DNS records: https://www.rfc-editor.org/rfc/rfc9849.html and https://www.rfc-editor.org/rfc/rfc9460.html

[3] Node.js, TLS and cipher configuration: https://nodejs.org/api/tls.html

[4] Mozilla, certificate policy: https://firefox-admin-docs.mozilla.org/reference/policies/certificates/

[5] Microsoft, managed DoH policy: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/dnsoverhttpsmode

Requirements source: Professor Herzberg's correspondence and the project handout supplied in this course chat. Exact report length and historical builds were not prescribed. The grading criterion is conditional; this document does not claim an awarded grade.
