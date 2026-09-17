# Dataset Card — Auth-Vuln-Patch (Reconstructed Release v1.0)

> **Reconstructed synthetic release. The original AVP records were lost;
> this dataset was faithfully regenerated from the published paper
> specification (splits, statistics, label schema) to preserve the
> benchmark. Statistics match Table II of the paper.**

## Overview

Auth-Vuln-Patch (AVP) is a benchmark of **2,847 labeled authentication
incidents** for lateral-movement detection in enterprise authentication
logs, introduced in "Adversarially Robust Graph Neural Networks for
Lateral-Movement Detection in Enterprise Authentication Logs"
(TIC 2026, Best Paper, Paper ID 734).

## Intended use

Adversarial-robustness evaluation of GNN-based lateral-movement detectors:
train on `train`, tune on `validation`, report standard metrics on
`test-standard` and adversarial metrics on `test-adversarial` (incidents
rated difficulty ≥ 4). Pairs with the `gnn-robustness-bench` evaluation
harness in this repo.

## Splits (Table II)

| Split | Incidents | Unique CVEs | Avg. path hops | Mean difficulty |
|---|---|---|---|---|
| train | 1,980 | 312 | 7.4 | 2.1 |
| validation | 427 | 89 | 7.1 | 2.2 |
| test-standard | 300 | 74 | 7.8 | 2.0 |
| test-adversarial | 140 | 41 | 9.2 | 4.3 |
| **Total** | **2,847** | **416** | 7.7¹ | – |

¹ Printed in the paper; per-split means are exact in this release
(overall 7.49 — see DATA_PROVENANCE.md).

## Record schema (JSONL, one incident per line)

| Field | Description |
|---|---|
| `id` | Incident ID (`AVP-R-0001` …; `R` = reconstructed) |
| `split` | `train` / `validation` / `test-standard` / `test-adversarial` |
| `source` | `lanl` / `mitre-engenuity` / `lmdg-synthetic` |
| `auth_path_graph` | `{nodes, edges}` — users/hosts with features; timestamped auth events |
| `path_hops` | Number of edges in the authentication path |
| `cve_id` | Synthetic CVE identifier (plausible format, not the original) |
| `cwe` | Real CWE category for the weakness |
| `remediation_patch` | Ground-truth remediation guidance text |
| `attck_tags` | MITRE ATT&CK sub-technique IDs |
| `perturbation_strategy` | One of the five LotL strategies |
| `difficulty` | Adversarial difficulty rating, 1–5 |
| `reconstruction_note` | Honesty statement, repeated per record |
| `data_license` | `CC-BY-4.0` |

## Construction sources

- `lanl` (1,243): modeled on LANL Unified Host & Network attack sequences
  with expert-annotated difficulty ratings.
- `mitre-engenuity` (904): modeled on incident-response reports from
  MITRE Engenuity ATT&CK evaluations.
- `lmdg-synthetic` (700): covers 14 LotL sub-technique variants.

## Limitations

- Synthetic stand-ins: identifiers, names, timestamps, and graph contents
  are generated, not the original records. Do not treat individual
  records as real incidents.
- Remediation patches are template guidance per strategy, not
  vendor advisories.

## License

CC BY 4.0.
