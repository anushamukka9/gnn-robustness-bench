"""Adversarial attacks on graph structure and node features.

Implements the two perturbation families used in the companion benchmark:

1. PGD-style feature perturbation: projected gradient descent on node features
   under an L_inf budget, using a simple linear surrogate head. This mirrors
   the feature-space attack protocol from the TIC 2026 Best Paper evaluation.

2. Edge-drop attack: random / greedy removal of edges from the adjacency
   matrix under a budget, modeling structural perturbations an adversary can
   introduce (e.g. dropped citations, hidden transactions).

Both attacks are numpy-first so the benchmark runs without a deep-learning
stack; they operate on (adjacency, features) pairs and return perturbed
copies plus an attack log describing the applied budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class AttackLog:
    name: str
    budget: float
    perturbed_edges: int = 0
    perturbed_features: int = 0
    details: dict = field(default_factory=dict)


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def pgd_feature_attack(
    features: np.ndarray,
    labels: np.ndarray,
    weights: np.ndarray,
    epsilon: float = 0.1,
    steps: int = 20,
    step_size: float | None = None,
    seed: int = 0,
) -> tuple[np.ndarray, AttackLog]:
    """PGD attack on node features under an L_inf budget.

    Args:
        features: (N, D) node feature matrix.
        labels: (N,) true class indices.
        weights: (D, C) linear surrogate classifier weights.
        epsilon: maximum per-coordinate perturbation (L_inf ball).
        steps: number of PGD iterations.
        step_size: per-step size; defaults to epsilon / steps * 2.5.
        seed: RNG seed for the random start.

    Returns:
        (perturbed_features, log)
    """
    rng = np.random.default_rng(seed)
    x_adv = features.astype(float).copy()
    # Random start inside the L_inf ball (standard PGD practice).
    x_adv += rng.uniform(-epsilon, epsilon, size=x_adv.shape)
    if step_size is None:
        step_size = epsilon / max(steps, 1) * 2.5

    n_classes = weights.shape[1]
    for _ in range(steps):
        logits = x_adv @ weights
        probs = _softmax(logits)
        # Gradient of cross-entropy w.r.t. logits, then w.r.t. features.
        grad_logits = probs
        grad_logits[np.arange(len(labels)), labels] -= 1.0
        grad_logits /= len(labels)
        grad_x = grad_logits @ weights.T
        x_adv += step_size * np.sign(grad_x)
        # Project back onto the L_inf ball around the original features.
        x_adv = np.clip(x_adv, features - epsilon, features + epsilon)

    perturbed = int(np.count_nonzero(np.abs(x_adv - features) > 1e-12))
    return x_adv, AttackLog(
        name="pgd-feature",
        budget=epsilon,
        perturbed_features=perturbed,
        details={"steps": steps, "step_size": step_size, "n_classes": n_classes},
    )


def edge_drop_attack(
    adj: np.ndarray,
    drop_fraction: float = 0.1,
    strategy: str = "uniform",
    seed: int = 0,
) -> tuple[np.ndarray, AttackLog]:
    """Drop edges from an adjacency matrix under a budget.

    Args:
        adj: (N, N) adjacency matrix (binary or weighted, symmetric assumed).
        drop_fraction: fraction of existing edges to remove.
        strategy: "uniform" (random) or "high-degree" (prefer edges incident
            to high-degree nodes, a stronger structural attack).
        seed: RNG seed.

    Returns:
        (perturbed_adj, log). The matrix stays symmetric.
    """
    rng = np.random.default_rng(seed)
    a = adj.astype(float).copy()
    # Upper triangle edge list (undirected graphs).
    iu = np.triu_indices(a.shape[0], k=1)
    edge_mask = a[iu] > 0
    edge_idx = np.flatnonzero(edge_mask)
    n_drop = int(round(len(edge_idx) * drop_fraction))
    if n_drop <= 0 or len(edge_idx) == 0:
        return a, AttackLog(name="edge-drop", budget=drop_fraction, perturbed_edges=0)

    if strategy == "high-degree":
        degrees = a.sum(axis=1)
        scores = degrees[iu[0][edge_idx]] + degrees[iu[1][edge_idx]]
        order = np.argsort(-scores, kind="stable")
        chosen = edge_idx[order[:n_drop]]
    elif strategy == "uniform":
        chosen = rng.choice(edge_idx, size=n_drop, replace=False)
    else:
        raise ValueError(f"unknown strategy: {strategy!r}")

    rows, cols = iu[0][chosen], iu[1][chosen]
    a[rows, cols] = 0.0
    a[cols, rows] = 0.0
    return a, AttackLog(
        name="edge-drop",
        budget=drop_fraction,
        perturbed_edges=n_drop,
        details={"strategy": strategy},
    )
