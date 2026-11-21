# Browser TLS and ECH Compatibility Testbed

**Mohammed Kabir | mtk21002 | CSE 4402, SEC001 | Solo project**

Final report for December 18, 2026. Measurements taken November 15, 2026. [Explore the recorded results](https://mtkabir7443.github.io/cse4402-browser-tls-ech/).

## 1. Research question and findings

When a browser connects to an HTTPS site, which TLS versions and cipher suites can it negotiate, and when does it protect the requested hostname with Encrypted Client Hello (ECH)? I built a website that answers these questions from the handshake observed by the server. I tested seven Windows browser builds, including older releases of Chrome and Firefox, across 12 configurations with three repetitions each.

All seven rejected TLS 1.0 and 1.1, negotiated all five selected suites, and recovered when DNS advertised a stale ECH key. One difference emerged when DNS advertised no key. Six builds sent an ECH-shaped extension and Firefox 115 ESR omitted it. All 21 baseline connections completed without accepted ECH.

## 2. Measurements and motivation

| Case | Controlled condition | Why measure it? |
|---|---|---|
| V1 | TLS 1.0 only | Check rejection of a deprecated protocol. |
| V2 | TLS 1.1 only | Check whether the next deprecated version is also rejected. |
| V3 | TLS 1.2 only | Establish a modern compatibility baseline. |
| V4 | TLS 1.3 only | Check negotiation of the newer handshake protocol. |
| C1 | TLS 1.2, ECDHE-RSA, AES-128-GCM/SHA-256 | Establish support for this exact authenticated-encryption combination. |
| C2 | TLS 1.2, ECDHE-RSA, ChaCha20-Poly1305/SHA-256 | Change the encryption algorithm while retaining key exchange and authentication type. |
| C3 | TLS 1.3, AES-128-GCM/SHA-256 | Check the suite required by the base TLS 1.3 specification. |
| C4 | TLS 1.3, AES-256-GCM/SHA-384 | Compare a different AES key size and hash. |
| C5 | TLS 1.3, ChaCha20-Poly1305/SHA-256 | Compare a non-AES authenticated-encryption option. |
| E1 | Valid advertised ECH configuration | Check actual acceptance of encrypted ClientHello information. |
| E2 | No advertised ECH configuration | Test whether an encrypted connection succeeds without ECH. Inspect any ECH-shaped extension. |
| E3 | Stale advertised ECH key, replacement available | Check rejection/recovery and the final connection outcome separately. |

TLS version tests isolate which protocol a browser will negotiate. RFC 8996 prohibits negotiating TLS 1.0 or 1.1. A successful modern handshake can select only one cipher suite, so each cipher test offered exactly one. TLS 1.3 suite names specify authenticated encryption and a hash. Key exchange and certificate authentication are negotiated separately. [1, 2]

ECH encrypts the inner ClientHello, which carries the requested hostname. A browser can send a dummy extension (GREASE) to keep the protocol extensible. Server acceptance tells us whether the real inner ClientHello was used. [3]

<!-- PAGEBREAK -->

## 3. Browsers and experimental method

| Table code | Browser build |
|---|---|
| Ch | Chrome for Testing 157.0.8103.78 |
| FF | Firefox 160.0 |
| Ed | Microsoft Edge 157.0.4341.60 |
| Br | Brave 1.99.57, Chromium 157.0.8103.79 |
| Op | Opera 140.0.6074.18, Chromium 157.0.8103.39 |
| Ch116 | Chrome for Testing 116.0.5845.96 |
| FF115 | Firefox 115.0.3 ESR |

Five builds use Chromium. The two Firefox releases provide a second browser family. Three fresh runs of each case give 36 observations per build and 252 overall. Each ran headless on the same Windows 11 host (build 26300) with DNS over HTTPS (DoH), ECH enabled and normal certificate checks. These settings also applied to the two historical releases.

<!-- ARCHITECTURE -->

**Endpoints.** Go 1.27.4 served the website, local DoH, TLS version tests, TLS 1.2 suite tests and ECH. Go lets the server select suites through TLS 1.2. For C3-C5 I used Node.js 26.13.0 with OpenSSL 3.5.9 to restrict each TLS 1.3 endpoint to one suite. DNS HTTPS records identified the service target and port and, for E1 and E3, supplied the ECH configuration. The local certificate authority signed the certificate covering the control and test names. [4-7]

**One run.** The runner opened a fresh browser profile with QUIC disabled so the request used HTTPS over TCP. Before the browser contacted the test endpoint, the control page registered the run. The server appended the run ID and socket-observed client IP to its JSONL log. That left a record even if the handshake failed before HTTP. I ran one test at a time, matched its browser result to server events and displayed the result on the page. The dashboard also aggregates all builds and cases.

**Controls.** An independent OpenSSL 3.5.0 client produced the expected results in 14 version and suite checks. Three Go controls exercised the valid, absent and stale ECH cases. The persistent Node endpoints passed three positive and three negative suite checks and a resumption test. These checks are separate from the 252 browser runs.

<!-- PAGEBREAK -->

## 4. Results across all seven builds

Each entry counts runs that produced the indicated outcome, out of three. R = protocol rejection, OK = intended version or suite negotiated, E = ECH accepted, N = connected without ECH, REC = recovered from stale ECH. Browser versions and column labels appear on page 2.

| Case | Ch | FF | Ed | Br | Op | Ch116 | FF115 |
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

**Versions and suites.** The 42 TLS 1.0/1.1 attempts ended in explicit protocol rejection before HTTP. All 147 attempts across V3-V4 and C1-C5 negotiated the intended version or suite. For example, all 21 TLS 1.3 version-only connections (V4) selected AES-128-GCM/SHA-256. All 21 C4 connections selected AES-256-GCM/SHA-384 when it was the sole option. V4 alone would have missed that capability.

**ECH.** All 21 valid-key runs reached the requested endpoint with ECH accepted. All 21 runs without an advertised key reached it without ECH. In all 21 stale-key runs the first observed attempt with configuration 16 lacked ECH acceptance. A later connection using configuration 17 delivered the requested HTTP probe with ECH accepted. A separate Chrome feasibility trace recorded a restart with the replacement configuration. Browsers can open parallel connections, so the number of handshake records cannot give an exact sequential retry count. [3]

**Did the browser actually use ECH?** I matched each E2 HTTP probe to the successful TLS handshake on the same connection. In the first repetition, Chrome 157 sent an ECH extension and Firefox 115 ESR omitted it. The server accepted ECH in neither connection. Across all 21 runs, six builds sent the extension every time (18/21), Firefox 115 ESR omitted it three times, and the server accepted ECH zero times (0/21). This pattern is consistent with GREASE. Counting the extension alone would give 18 false positives. [Inspect all 21 baseline runs](https://mtkabir7443.github.io/cse4402-browser-tls-ech/#ech-baseline).

<!-- PAGEBREAK -->

## 5. Interpretation and reproducibility

The browser could load the site in all three ECH conditions, yet the site observed three different sequences: immediate ECH acceptance, an ordinary TLS connection, or recovery to ECH after rejection of a stale key. A page-load test alone would have reported success in all three. Likewise, a failed fetch alone cannot diagnose protocol rejection. For example, Chrome 157's first V1 run reported a fetch error, and the matched TLS server event identified an unsupported version before any HTTP probe arrived.

The seven builds agreed on every classified endpoint outcome across all 84 browser/case combinations. The E2 wire evidence shows why that agreement can coexist with different ClientHello behavior. It establishes configured capability on one machine. Fresh profiles, explicitly enabled ECH, local DNS and a trusted local certificate authority limit what these results say about default installations and public networks. The server saw the loopback address 127.0.0.1 for all 252 runs. Three repetitions establish local consistency. They cannot estimate a population failure rate. ECH still exposes the destination IP. [3]

**Evidence check.** The November 15 audit matched all 252 records to the retained evidence. On November 21 I checked the saved runs again. The installed Edge executable had updated from 157.0.4341.60 to 158.0.4370.33, so the check of its current path flagged all 36 Edge runs. The retained 157.0.4341.60 executable still matched the study's SHA-256. The recorded sessions and measured outcomes remained verifiable. A new experiment with Edge 158 would measure a different build.

**Code and data.** The [public dashboard](https://mtkabir7443.github.io/cse4402-browser-tls-ech/) lets readers filter the 252 recorded runs and inspect or download individual results. The [study code and data](https://github.com/mtkabir7443/cse4402-browser-tls-ech/tree/5e1e7350317645291c707c28d9433307d585eaa7) include an offline comparison. The [reproduction guide](https://github.com/mtkabir7443/cse4402-browser-tls-ech/blob/5e1e7350317645291c707c28d9433307d585eaa7/REPRODUCE.md) explains how to collect a new batch with the local DNS and TLS endpoints.

From the repository root, run `node scripts/verify-public-results.cjs results` to check all 252 observations against the published evidence summaries. The [21-run baseline dataset](https://mtkabir7443.github.io/cse4402-browser-tls-ech/ech-baseline.json), also in the ZIP as `examples/ech-baseline.json`, gives the run ID, build, repetition, extension presence and server acceptance. In the retained server log, lines 2642-2643 record the first Chrome 157 baseline handshake and HTTP probe. Lines 9138 and 9141 record the corresponding Firefox 115 ESR events.

## References

[1] IETF. [RFC 8996, Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html), §§4-5.

[2] IETF. [RFC 8446, The Transport Layer Security Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html), §9.1 and Appendix B.4.

[3] IETF. [RFC 9849, TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html), §§6.1.6 and 6.2.

[4] IETF. [RFC 9460, Service Binding and Parameter Specification via the DNS](https://www.rfc-editor.org/rfc/rfc9460.html).

[5] Go. [crypto/tls configuration and connection state](https://pkg.go.dev/crypto/tls#Config).

[6] Node.js. [TLS cipher-suite configuration and session resumption](https://nodejs.org/api/tls.html).

[7] IETF. [RFC 9848, Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings](https://www.rfc-editor.org/rfc/rfc9848.html).
