# gnn-robustness-bench

[![CI](https://github.com/anushamukka9/gnn-robustness-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/anushamukka9/gnn-robustness-bench/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Adversarial robustness benchmark for Graph Neural Networks.**

A numpy-first evaluation harness implementing the attack suite and metrics
from the companion research on adversarial-robust GNNs
(**TIC 2026 — Best Paper**, sole-authored). Compare GNN architectures on
equal footing: same threat model, same budgets, same metrics.

## Companion paper

**"Adversarially Robust Graph Neural Networks for Lateral-Movement
Detection in Enterprise Authentication Logs"** — 3rd IEEE Technology
Innovation Conference (TIC) 2026, Best Paper (Paper ID 734).

> Lateral movement (LM) through enterprise authentication paths represents
> one of the most persistent and difficult-to-detect phases of advanced
> persistent threat (APT) operations. Graph Neural Networks (GNNs) have
> emerged as the leading paradigm for LM detection from authentication
> logs, yet their adversarial robustness against realistic
> living-off-the-land (LotL) evasion tactics remains critically
> understudied. We present ROBGNN-LMD, a Temporal Relational Graph
> Convolutional Network with a LotL-realistic adversarial training
> framework derived from five MITRE ATT&CK sub-technique perturbation
> strategies. ROBGNN-LMD is evaluated on the Los Alamos National
> Laboratory (LANL) Unified Host & Network dataset and our newly released
> Auth-Vuln-Patch (AVP) benchmark of 2,847 labeled authentication
> incidents, achieving an F1-score of 95.1% on standard evaluation and
> 94.3% under adversarial perturbation — a 23.1-point improvement over
> the strongest baseline — while maintaining a false-positive rate of
> only 2.9%.

This repo is the runnable companion to that work: the same threat model
and metrics, packaged so anyone can evaluate their own GNN.

## Why

Graph Neural Networks are deployed in fraud detection, recommendation,
and knowledge graphs — all adversarial settings. Yet most GNN papers
report only clean accuracy. This benchmark makes robustness a
first-class, CI-enforceable property:

- **Two attack families** — PGD feature perturbation (L_inf) and
  structural edge-drop (uniform / high-degree)
- **Three metrics** — robust accuracy, attack success rate, and a
  randomized-smoothing certified-radius estimate
- **Zero heavy deps** — numpy + scipy only; torch optional, never required
- **CI gate** — `grbench evaluate` exits non-zero when a model is fragile

## Install

```bash
pip install gnn-robustness-bench
```

From source:

```bash
git clone https://github.com/anushamukka9/gnn-robustness-bench
cd gnn-robustness-bench
pip install -e ".[dev]"
```

## Quickstart

```python
import numpy as np
from gnn_robustness.attacks import pgd_feature_attack, edge_drop_attack
from gnn_robustness.metrics import robust_accuracy, attack_success_rate

x_adv, log = pgd_feature_attack(features, labels, weights, epsilon=0.1, steps=20)
print("robust acc:", robust_accuracy(x_adv, labels, weights))
print("ASR:", attack_success_rate(features, x_adv, labels, weights))

adj_adv, drop_log = edge_drop_attack(adj, drop_fraction=0.1, strategy="high-degree")
print("edges dropped:", drop_log.perturbed_edges)
```

Or run the full suite from the CLI (`.npy`, `.npz`, or CSV inputs):

```bash
grbench evaluate \
  --adj data/adj.npy \
  --features data/features.npy \
  --labels data/labels.npy \
  --weights data/surrogate_weights.npy \
  --epsilon 0.1 --drop-fraction 0.1 --format json
```

See [`examples/quickstart.py`](examples/quickstart.py) for a self-contained
synthetic-graph demo.

## Method

Full protocol details — threat model, PGD hyperparameters, edge-drop
strategies, and the certified-radius estimator — are in
[`docs/METHOD.md`](docs/METHOD.md).

## Dataset — Auth-Vuln-Patch (reconstructed v1.0)

> **Reconstructed synthetic release. The original AVP records were lost;
> this dataset was faithfully regenerated from the published paper
> specification (splits, statistics, label schema) to preserve the
> benchmark. Statistics match Table II of the paper.**

**[Download: release avp-v1.0](https://github.com/anushamukka9/gnn-robustness-bench/releases/tag/avp-v1.0)**

Auth-Vuln-Patch (AVP) is the companion benchmark from the TIC 2026 Best
Paper: **2,847 labeled authentication incidents** for lateral-movement
detection, adversarially stratified by expert difficulty ratings (1–5).

| Split | Incidents | Unique CVEs | Avg hops | Mean difficulty |
|---|---|---|---|---|
| train | 1,980 | 312 | 7.4 | 2.1 |
| validation | 427 | 89 | 7.1 | 2.2 |
| test-standard | 300 | 74 | 7.8 | 2.0 |
| test-adversarial | 140 | 41 | 9.2 | 4.3 |

Each incident carries an authentication path graph (users/hosts with
features, timestamped auth-event edges), CVE/CWE identifiers, a
ground-truth remediation patch, MITRE ATT&CK sub-technique tags, and one
of five LotL perturbation strategies. Construction sources: LANL-derived
(1,243), MITRE Engenuity incident reports (904), LMDG synthetic (700,
spanning 14 LotL sub-technique variants). License: CC BY 4.0. Full
schema and provenance: [`data/DATASET_CARD.md`](data/DATASET_CARD.md),
[`data/DATA_PROVENANCE.md`](data/DATA_PROVENANCE.md).

```python
import json

with open("auth-vuln-patch-reconstructed-v1.jsonl") as f:
    incidents = [json.loads(line) for line in f]

adv = [i for i in incidents if i["split"] == "test-adversarial"]
print(len(incidents), "incidents |", len(adv), "adversarial test")
print(adv[0]["cve_id"], adv[0]["attck_tags"], adv[0]["perturbation_strategy"])
# -> CVE-2023-14795 ['T1078'] Noisy Decoy  (synthetic identifiers)

# Regenerate the dataset byte-identically from the paper spec:
#   python3 data/generate_avp.py --out-dir data
# Validate against Table II:
#   python3 data/validate_avp.py data/auth-vuln-patch-reconstructed-v1.jsonl
```

## Roadmap

- [ ] White-box attacks against message-passing layers (GCN/GAT gradients)
- [ ] Node-injection attack family
- [ ] Leaderboard harness over Cora / CiteSeer / OGB subsets
- [ ] Export to RobustBench-style model zoo format

Contributions welcome — open an issue with the attack or dataset you need.

## Citation

If you use this benchmark, please cite the companion paper (TIC 2026).

## License

MIT — see [LICENSE](LICENSE).
