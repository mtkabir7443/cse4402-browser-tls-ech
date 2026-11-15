# Public browser TLS/ECH results

This portable derivative preserves all **252 genuine recorded observations** from batch study-20261115: seven pinned builds, twelve cases, three repetitions. It creates no new measurements. Open comparison.html directly; it embeds its data and makes no network requests.

From the repository root, verify the included package with Node.js (built-in modules only):

```powershell
node scripts/verify-public-results.cjs ./results
```

If this directory has a different location, pass that directory instead. The verifier does not require browsers, private files, lab services, a certificate store, or network access.

## Files and schema

- comparison-data.json: public schema version 1; artifact_kind cse4402-public-results. The browsers array retains product/version, distribution, engine family/version (Edge Chromium patch is null), and pinned executable SHA-256. Cases retain IDs, meanings and expected TLS/suite/ECH values, without endpoint addresses.
- results.jsonl and results.csv: the same 252 allowlisted records, in the same order. CSV objects/arrays are JSON inside quoted cells; null is an empty CSV cell. JSON is authoritative for types. Spreadsheet formula prefixes are escaped.
- evidence-summary.json: selected normalized server observations plus one private-audit assertion per run. These are summaries, not raw server or network logs. Each summary_evidence_ids entry resolves to a summary- ID in this file. They are deliberately different from omitted raw-file/line references. Name roles and protocol-error categories are reduced descriptions; configuration 16-to-17 recovery is explicitly attributed to the private raw-audit assertion.
- comparison.html: offline matrix, filters, individual record details and JSON/CSV/JSONL downloads. The HTML contains the same public dataset; filtered downloads are subsets and are not complete verifier inputs.
- manifest.json: SHA-256 of the six companion files, for detecting accidental changes. It is not a signature or proof of authenticity.

Records retain run/build/case/repetition identity, pinned binary hash, timestamps, observed loopback IP, browser and server outcomes, negotiated TLS/suite/ECH state, resumption state, explicit controls, retry summary and included evidence-summary references. Rejected pre-HTTP runs have null negotiated fields: no successful negotiated session is invented. Their selected failed-handshake observations report no resumption. Every successful recorded handshake reports resumed=false. E3 has initial configuration 16, accepted configuration 17, and a null exact retry count; parallel connections are not counted as retries.

## What verification means

Internal consistency, included summary references, and complete coverage only; no replay of the private raw audit or independent proof of measurement authenticity.

The verifier checks an exact field allowlist, no filesystem paths/endpoints/key material in the structured public data, 252 unique planned slots, per-build versions/hashes, expected negotiation/outcomes, timestamps, included summary IDs, complete summary use, and agreement of JSON/JSONL/CSV/HTML. It checks artifact hashes. A passing result does not reproduce ClientHello parsing, certificate validation, browser execution, policy restoration, or raw audit findings, and does not independently authenticate a publisher who can edit all files together.

The preparation script required a completed private audit that named the exact source comparison hash, then copied only allowed fields. Original source SHA-256 values are immutable identifiers for this export; checking the omitted originals requires access to the private archive:

- Original comparison: 45a4c326f8572feec634c293c3f572a24154ae4cc4d447722854477b48540986
- Full original private raw-audit artifact: 2081a6789de55c6e548d6e0f9f7138700dc02e853636be75cabecdf3d2673bb8
- Recorded private-audit time: 2026-11-15T19:20:49.722Z

The original observations and private audit are retained separately. This public package excludes absolute/relative machine paths, raw server logs and network diagnostics, user-agent strings, launch arguments, profiles, private CA/certificate/key material, fixture hosts/ports, and registry details. It retains only 127.0.0.1 as the intentionally documented client IP. Source hashes, binary hashes and public summary IDs are identifiers, not private-file download links.

The findings apply to explicitly configured DoH/ECH, normal trust validation, fresh profiles, headless operation and one Windows host. They do not establish untouched consumer defaults, a security ranking, a population reliability rate, publication, submission, or a grade.
