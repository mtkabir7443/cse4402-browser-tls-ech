# Browser TLS and ECH Compatibility Testbed

**Mohammed Kabir | mtk21002 | CSE 4402, SEC001 | Solo project**

**Measurement report - November 15, 2026.** All 252 planned measurements are complete and verified: seven browser builds, 12 cases and three repetitions per case. This report presents the local study; code publication and graded submission remain separate.

## 1. Purpose and research questions

I built a local website to compare how seven browser builds handle controlled TLS versions, cipher suites, and Encrypted Client Hello (ECH). The website generates results, writes a persistent log containing the client's observed IP address, and presents an overall browser comparison. The experiment asks which configurations each build can negotiate, whether ECH is actually accepted, and whether a browser recovers from a stale ECH configuration.

TLS protects application traffic, but compatibility and privacy depend on the handshake. Rejecting obsolete protocols can be a desirable security result: RFC 8996 prohibits negotiating TLS 1.0 and 1.1. The TLS 1.2 and 1.3 cases provide supported-version comparisons. These are compatibility measurements under documented settings, not a ranking of overall browser security. [1–2]

## 2. Measurements and motivation

| Case | Controlled condition | Why measure it? |
|---|---|---|
| V1 | TLS 1.0 only | Check rejection of a deprecated protocol. |
| V2 | TLS 1.1 only | Check whether the next deprecated version is also rejected. |
| V3 | TLS 1.2 only | Establish a modern compatibility baseline. |
| V4 | TLS 1.3 only | Check negotiation of the newer handshake protocol. |
| C1 | TLS 1.2; ECDHE-RSA, AES-128-GCM/SHA-256 | Establish support for this exact authenticated-encryption combination. |
| C2 | TLS 1.2; ECDHE-RSA, ChaCha20-Poly1305/SHA-256 | Change the encryption algorithm while retaining key exchange and authentication type. |
| C3 | TLS 1.3; AES-128-GCM/SHA-256 | Check the TLS 1.3 mandatory-to-implement suite. |
| C4 | TLS 1.3; AES-256-GCM/SHA-384 | Compare a different AES key size and hash. |
| C5 | TLS 1.3; ChaCha20-Poly1305/SHA-256 | Compare a non-AES authenticated-encryption option. |
| E1 | Valid advertised ECH configuration | Check actual acceptance of encrypted ClientHello information. |
| E2 | No advertised ECH configuration | Establish the non-ECH baseline, including possible GREASE. |
| E3 | Stale advertised ECH key; replacement available | Check rejection/recovery and the final connection outcome separately. |

Each cipher endpoint allows exactly one listed suite. TLS 1.3 suite names describe encryption and hash choices separately from key exchange and certificate authentication; they are not interchangeable with TLS 1.2 suites. Canonical identifiers are preserved in the code and exports. [2]

ECH protects the inner ClientHello, including the requested hostname. GREASE extension presence does not prove acceptance. E3 deliberately advertises configuration 16 while the server accepts and offers configuration 17 for retry. This tests recovery from a controlled mismatch. [3]

<!-- PAGEBREAK -->

## 3. Browser selection and experimental method

The frozen manifest records distribution, executable hash, product/version, and engine information. The seven selected Windows builds are:

| Table code | Browser build |
|---|---|
| Ch | Chrome for Testing 157.0.8103.78 |
| FF | Firefox 160.0 |
| Ed | Microsoft Edge 157.0.4341.60 |
| Br | Brave 1.99.57; Chromium 157.0.8103.79 |
| Op | Opera 140.0.6074.18; Chromium 157.0.8103.39 |
| Ch16 | Chrome for Testing 116.0.5845.96 |
| FF15 | Firefox 115.0.3 ESR |

The target is **7 builds × 12 cases × 3 repetitions = 252 browser runs**. Three repeats check consistency in this setup; they do not estimate a population-wide failure rate. Historical releases are measured rather than assumed to lack ECH. Edge is checked against its pinned executable because its installed distribution can update.

**Architecture.** All services bind to loopback on Windows 11. Go 1.27.4 provides the control website, DNS-over-HTTPS (DoH), version-restricted TLS endpoints, TLS 1.2 suite controls, and ECH. Node 26.13.0 supplies the three persistent single-suite TLS 1.3 endpoints, because Go's public configuration does not expose TLS 1.3 suite restrictions. The Node runtime uses OpenSSL 3.5.9; independent command-line controls use OpenSSL 3.5.0. [5–6]

Controlled HTTPS DNS records supply the ECH configuration, service hostname, and nondefault port. Explicit service target names ensure browsers associate those records with the correct address. DNS answers are obtained through the configured local DoH endpoint rather than hosts-file substitutions. Certificate validation remains enabled; the server certificate issued by the local CA covers the control endpoint and the inner/outer test names. The renewed leaf expires January 9, 2027. [4]

**Run procedure.** First, independent positive and negative controls verify certificates, endpoint versions/suites, and ECH configuration. The runner then starts a fresh browser process/profile, configures DoH and trust, disables QUIC, and registers the case through the working control connection. The browser itself makes the measured HTTPS request. The control page records the outcome even if TLS fails before an HTTP request reaches the fixture. Cases are serialized, repeated three times, and compared against the endpoint's intended restriction.

Fresh profiles separate DNS/ECH and session state between repetitions while preserving retries within each run. Go disables session tickets. Node disables stateless tickets and declines stateful resumption; it can still issue tickets. Actual resumption status is logged and reviewed rather than inferred from configuration alone. Chromium uses temporary user-root trust; dedicated Firefox distributions use application-local policies. The documented cleanup procedure removes the project's temporary Windows trust after testing.

<!-- PAGEBREAK -->

## 4. Evidence and results

**Observed dataset: 252 of 252 planned runs.** Batch `study-20261115` contains every browser/case/repetition cell exactly once. The independent raw-evidence audit passed with zero findings and no missing cells. All three repetitions agreed for every case. One earlier startup stopped before registration created no measurement; resuming preserved completed results.

`OK` = intended TLS connection; `R` = diagnosed protocol rejection; `E` = ECH accepted; `N` = connected without ECH; `REC` = stale-ECH recovery. Counts show observations out of three.

| Case | Ch | FF | Ed | Br | Op | Ch16 | FF15 |
|---|---|---|---|---|---|---|---|
| V1 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 |
| V2 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 | R 3/3 |
| V3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| V4 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| C1 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| C2 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| C3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| C4 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| C5 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 | OK 3/3 |
| E1 | E 3/3 | E 3/3 | E 3/3 | E 3/3 | E 3/3 | E 3/3 | E 3/3 |
| E2 | N 3/3 | N 3/3 | N 3/3 | N 3/3 | N 3/3 | N 3/3 | N 3/3 |
| E3 | REC 3/3 | REC 3/3 | REC 3/3 | REC 3/3 | REC 3/3 | REC 3/3 | REC 3/3 |

**Versions and suites.** All seven builds rejected TLS 1.0 and 1.1 (42 rejections). TLS 1.2, TLS 1.3 and the five restricted-suite cases produced 147 connections with the intended parameters. No measured cell was inconclusive or inconsistent.

**ECH.** Valid advertisements produced 21 accepted ECH requests; the 21 baseline requests connected without accepted ECH. All 21 stale-key runs recovered to an accepted ECH request. The wire observer distinguishes the initial configuration 16 from the subsequent accepted configuration 17. Chrome's selected NetLog trace explicitly records a restart with the replacement list. Parallel connection jobs are not multiple sequential retries of one connection. An ECH-shaped extension alone is insufficient evidence.

**Controls and interpretation.** Fourteen OpenSSL checks, three independent Go ECH controls and the Node suite/resumption checks passed; these are separate from browser runs. Registration and observed-IP logging precede testing, including pre-HTTP failures. Server evidence establishes negotiation; a generic fetch error cannot establish unsupported TLS. The export retains browser metadata, raw event references and every repetition.
<!-- PAGEBREAK -->

## 5. Limitations and conclusions

This study measures explicitly configured DoH/ECH and trust settings. It does not establish behavior under each browser's untouched consumer defaults. Measurements use pinned builds in headless mode on one Windows machine; different platforms, releases, policies, or interactive modes may differ. Chrome is the Chrome for Testing distribution. Several products share Chromium. Edge reports its exact Edg product/version; its underlying Chromium patch version remains unknown.

The endpoints are local and use a private CA. The recorded client address is correctly 127.0.0.1; the experiment does not measure public-path latency, resolver diversity, or deployment reachability. Three repetitions can expose inconsistent local behavior but support no broad statistical reliability claim. ECH acceptance does not hide every source of metadata, such as the destination IP. No performance ranking, vulnerability discovery, or complete browser-security evaluation is claimed.

HTTP/3, broad certificate/revocation-validation experiments, and a separate DNSSEC suite remain outside the approved scope. Valid certificates and DNS are prerequisites. External hosting is a preferred optional extension; the professor accepted a local demonstration, and this version has not been publicly deployed.

**Conclusions for the measured builds.** All seven configured builds consistently rejected deprecated TLS, negotiated every tested suite, accepted valid ECH and recovered from stale ECH. Older Chrome and Firefox also accepted ECH when explicitly enabled. No browser differed on these measured outcomes; the similarities do not imply equivalent overall security or default settings.

## 6. Reproduction and delivery

The repository's `README.md` documents pinned tools/browsers, trust, fixture controls, the runner, exports and cleanup. The runner bounds startup and rechecks its lease before registration, retaining a 180-second reserve. Resuming preserves completed cells. Both Edge policy leases restored the original settings. The manifest, journals and per-run records retain provenance and evidence.

The website provides individual results and an aggregate comparison. A standalone HTML export supports viewing and CSV/JSONL downloads after services stop. Missing, duplicate, or version-mismatched coverage must be resolved before accepting the final comparison. Raw logs/exports include client IPs; private keys, profiles, and sensitive raw diagnostics are kept separate from public artifacts.

Before final submission, publish the intended code on GitHub and perform the final delivery review. The November 22 design document is separate from the December 18 code/report deadline. The local comparison is complete; no code publication, external hosting, email or LMS submission has occurred.

## References

[1] IETF. [RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html), §§4–5.

[2] IETF. [RFC 8446: The Transport Layer Security Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html), §9.1 and Appendix B.4.

[3] IETF. [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html), client/server processing, retry and GREASE behavior.

[4] IETF. [RFC 9460: Service Binding and Parameter Specification via the DNS](https://www.rfc-editor.org/rfc/rfc9460.html), HTTPS records and service target names.

[5] Go. [crypto/tls documentation](https://pkg.go.dev/crypto/tls), configuration, ECH and connection state.

[6] Node.js. [TLS documentation](https://nodejs.org/api/tls.html), cipher-suite configuration, session resumption and connection events.

Requirements source: project handout and Professor Herzberg's correspondence, recorded in `scope.md`. Local evidence includes the fixture/ECH controls, `study-audit.json`, the comparison export and retained browser/server logs. All 252 planned measurements are verified; publication and submission remain pending.
