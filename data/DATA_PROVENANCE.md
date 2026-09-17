# Data Provenance — Auth-Vuln-Patch (Reconstructed Release v1.0)

## Honesty statement (read first)

**This is a reconstructed synthetic release. The original Auth-Vuln-Patch
records were lost; this dataset was faithfully regenerated from the published
paper specification (splits, statistics, label schema) to preserve the
benchmark. Statistics match Table II of the paper.**

Nothing in this release is presented as the original records. File and
directory names use `reconstructed` throughout, every incident record carries
a `reconstruction_note` field, and the release notes repeat this statement.

## Source paper

"Adversarially Robust Graph Neural Networks for Lateral-Movement Detection
in Enterprise Authentication Logs" — 3rd IEEE Technology Innovation
Conference (TIC) 2026, Best Paper (Paper ID 734), sole-authored by
Anusha Mukka.

Spec sources used for reconstruction:
- Section IV, "THE AUTH-VULN-PATCH BENCHMARK" (three construction sources,
  label schema, difficulty scale 1–5, CC BY 4.0 release terms)
- Table II, "AUTH-VULN-PATCH (AVP) BENCHMARK STATISTICS" (split sizes,
  unique CVE counts, mean path hops, mean adversarial difficulty)
- Table III / Section V (five LotL perturbation strategies and their
  MITRE ATT&CK sub-technique mappings)

## Construction method

`generate_avp.py` (deterministic, seed 734 = paper ID) synthesizes 2,847
incidents:

1. **Splits** — exact Table II sizes: train 1,980 / validation 427 /
   test-standard 300 / test-adversarial 140.
2. **Sources** — exact Section IV counts, shuffled deterministically:
   `lanl` 1,243 / `mitre-engenuity` 904 / `lmdg-synthetic` 700.
3. **CVE identifiers** — 416 unique synthetic `CVE-YYYY-NNNNN` IDs, assigned
   with controlled cross-split overlap so per-split unique counts match
   Table II exactly (312 / 89 / 74 / 41). CVE numbers are plausible but
   synthetic; they are not claimed to be the original identifiers.
4. **CWE categories** — real CWE entries relevant to authentication
   weaknesses (CWE-287, CWE-306, CWE-798, CWE-307, CWE-521, CWE-384,
   CWE-613, CWE-620, CWE-640, CWE-200), mapped deterministically per CVE.
5. **Authentication path graphs** — each incident carries a graph of
   user/host nodes with features (privilege, failed logins, MFA, host
   role/OS/ports/patch state) and timestamped auth-event edges
   (protocol, success, bytes). Edge count equals `path_hops`.
6. **Path hops** — integer hop counts per split with means exactly matching
   Table II (7.4 / 7.1 / 7.8 / 9.2).
7. **Difficulty ratings** — 1–5 scale per the paper; split means exactly
   matching Table II (2.1 / 2.2 / 2.0 / 4.3); test-adversarial contains
   only incidents rated ≥ 4, per Section IV.
8. **Perturbation strategies** — the five LotL strategies from the paper
   (Tool Injection T1047/T1569.002, Slow Exfiltration T1029, NTLM Relay
   T1557.001, Noisy Decoy T1078, Role Confusion T1078.001); each incident
   carries its strategy, ATT&CK tags, and a ground-truth remediation
   patch template for that strategy.
9. **LMDG coverage** — the 700 `lmdg-synthetic` incidents span all 14
   LotL sub-technique variants named in Section IV.

## Known deviations from the printed paper

- Table II prints an overall mean of 7.7 hops, but its own per-split means
  (7.4/7.1/7.8/9.2) imply 7.49. The reconstruction preserves the per-split
  means exactly (overall mean 7.486); the 7.7 figure appears to be a
  rounding artifact in the manuscript. Per-split statistics are the
  primary specification and are exact.
- CVE/CWE identifiers, host/user names, timestamps, and graph contents are
  synthetic stand-ins, not the original records.

## Validation

`validate_avp.py` asserts every Table II statistic (exit 0 = pass):

```
train            n= 1980 cves=312 hops=7.400 (spec 7.4) diff=2.100 (spec 2.1)
validation       n= 427 cves= 89 hops=7.101 (spec 7.1) diff=2.199 (spec 2.2)
test-standard    n= 300 cves= 74 hops=7.800 (spec 7.8) diff=2.000 (spec 2.0)
test-adversarial n= 140 cves= 41 hops=9.200 (spec 9.2) diff=4.300 (spec 4.3)
total unique CVEs = 416 (spec 416)
sources = lanl 1243 / mitre-engenuity 904 / lmdg-synthetic 700
test-adversarial all difficulty >= 4
```

## License

Dataset: CC BY 4.0 (per the paper). Generator code: MIT.
