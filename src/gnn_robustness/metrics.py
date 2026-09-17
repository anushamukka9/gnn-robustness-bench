"""Robustness metrics for adversarial GNN evaluation.

Metrics implemented:

- robust_accuracy: fraction of nodes still classified correctly *after* the
  attack. This is the headline number reported in the benchmark tables.
- attack_success_rate: fraction of originally-correct nodes that the attack
  flips. Complements robust accuracy (ASR = 1 - robust_acc / clean_acc).
- certified_radius_estimate: a lightweight randomized-smoothing style
  estimate of the average L2 perturbation radius within which predictions
  are stable, computed by Monte-Carlo noise sampling around each node
  feature vector (Cohen et al., 2019).
"""

from __future__ import annotations

import numpy as np


def _predict(features: np.ndarray, weights: np.ndarray) -> np.ndarray:
    return np.argmax(features @ weights, axis=1)


def robust_accuracy(
    features_adv: np.ndarray,
    labels: np.ndarray,
    weights: np.ndarray,
) -> float:
    """Fraction of nodes correctly classified after the attack."""
    preds = _predict(features_adv, weights)
    return float(np.mean(preds == labels))


def clean_accuracy(
    features: np.ndarray,
    labels: np.ndarray,
    weights: np.ndarray,
) -> float:
    """Fraction of nodes correctly classified before the attack."""
    return robust_accuracy(features, labels, weights)


def attack_success_rate(
    features: np.ndarray,
    features_adv: np.ndarray,
    labels: np.ndarray,
    weights: np.ndarray,
) -> float:
    """Fraction of originally-correct nodes flipped by the attack."""
    clean_preds = _predict(features, weights)
    adv_preds = _predict(features_adv, weights)
    originally_correct = clean_preds == labels
    n_correct = int(originally_correct.sum())
    if n_correct == 0:
        return 0.0
    flipped = (adv_preds != labels) & originally_correct
    return float(flipped.sum() / n_correct)


def certified_radius_estimate(
    features: np.ndarray,
    weights: np.ndarray,
    sigma: float = 0.1,
    n_samples: int = 200,
    alpha: float = 0.05,
    seed: int = 0,
) -> float:
    """Estimate the mean certified L2 radius via randomized smoothing.

    For each node, draws Gaussian-noised copies of its feature vector, takes
    the majority predicted class, and applies the Cohen et al. radius
    formula ``r = sigma * Phi^{-1}(p_A)`` where ``p_A`` is a Clopper-Pearson
    lower bound on the top-class probability. Nodes that cannot be certified
    (p_A <= 0.5) contribute 0.
    """
    from scipy.stats import beta, norm

    rng = np.random.default_rng(seed)
    n_nodes = features.shape[0]
    radii = np.zeros(n_nodes)
    for i in range(n_nodes):
        noisy = features[i] + rng.normal(0.0, sigma, size=(n_samples, features.shape[1]))
        preds = np.argmax(noisy @ weights, axis=1)
        _, counts = np.unique(preds, return_counts=True)
        top_count = int(counts.max())
        p_lower = float(beta.ppf(alpha, top_count, n_samples - top_count + 1))
        if p_lower > 0.5:
            radii[i] = sigma * norm.ppf(p_lower)
    return float(radii.mean())
