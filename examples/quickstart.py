"""Quickstart: run the full attack suite on a synthetic graph."""

import numpy as np

from gnn_robustness.attacks import edge_drop_attack, pgd_feature_attack
from gnn_robustness.metrics import (attack_success_rate, certified_radius_estimate,
                                    clean_accuracy, robust_accuracy)

rng = np.random.default_rng(42)
N, D, C = 60, 16, 3

# Synthetic stochastic-block-ish graph: 3 communities.
labels = np.repeat(np.arange(C), N // C)
adj = np.zeros((N, N))
for i in range(N):
    for j in range(i + 1, N):
        p = 0.25 if labels[i] == labels[j] else 0.03
        if rng.random() < p:
            adj[i, j] = adj[j, i] = 1.0

# Features cluster around class centroids.
centroids = rng.normal(0, 1, size=(C, D))
features = centroids[labels] + rng.normal(0, 0.4, size=(N, D))

# Surrogate linear head: least-squares fit (stand-in for a trained GNN head).
onehot = np.eye(C)[labels]
weights = np.linalg.lstsq(features, onehot, rcond=None)[0]

print(f"clean accuracy: {clean_accuracy(features, labels, weights):.3f}")

x_adv, pgd_log = pgd_feature_attack(features, labels, weights, epsilon=0.3, steps=20)
print(f"PGD(eps=0.3): robust acc={robust_accuracy(x_adv, labels, weights):.3f} "
      f"ASR={attack_success_rate(features, x_adv, labels, weights):.3f} "
      f"perturbed={pgd_log.perturbed_features}")

adj_adv, drop_log = edge_drop_attack(adj, drop_fraction=0.15, strategy="high-degree")
n_edges = int((adj > 0).sum() // 2)
print(f"edge-drop(15%, high-degree): dropped {drop_log.perturbed_edges}/{n_edges} edges")

print(f"mean certified radius (sigma=0.25): "
      f"{certified_radius_estimate(features, weights, sigma=0.25, n_samples=100):.4f}")
