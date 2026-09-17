"""Tests for robustness metrics and attacks."""

import numpy as np
import pytest

from gnn_robustness.attacks import edge_drop_attack, pgd_feature_attack
from gnn_robustness.metrics import (attack_success_rate, certified_radius_estimate,
                                    clean_accuracy, robust_accuracy)


@pytest.fixture
def toy():
    rng = np.random.default_rng(0)
    N, D, C = 30, 8, 2
    labels = np.repeat(np.arange(C), N // C)
    centroids = rng.normal(0, 1, size=(C, D))
    features = centroids[labels] + rng.normal(0, 0.3, size=(N, D))
    onehot = np.eye(C)[labels]
    weights = np.linalg.lstsq(features, onehot, rcond=None)[0]
    adj = (rng.random((N, N)) < 0.2).astype(float)
    adj = np.triu(adj, 1)
    adj = adj + adj.T
    return features, labels, weights, adj


def test_clean_accuracy_high_on_separable_data(toy):
    features, labels, weights, _ = toy
    assert clean_accuracy(features, labels, weights) > 0.9


def test_robust_accuracy_bounded(toy):
    features, labels, weights, _ = toy
    x_adv, _ = pgd_feature_attack(features, labels, weights, epsilon=0.2, steps=10)
    acc = robust_accuracy(x_adv, labels, weights)
    assert 0.0 <= acc <= 1.0
    assert acc <= clean_accuracy(features, labels, weights) + 1e-9


def test_pgd_respects_linf_budget(toy):
    features, labels, weights, _ = toy
    eps = 0.15
    x_adv, _ = pgd_feature_attack(features, labels, weights, epsilon=eps, steps=10)
    assert np.all(np.abs(x_adv - features) <= eps + 1e-9)


def test_pgd_zero_epsilon_is_identity(toy):
    features, labels, weights, _ = toy
    x_adv, log = pgd_feature_attack(features, labels, weights, epsilon=0.0, steps=5)
    assert np.allclose(x_adv, features)
    assert log.perturbed_features == 0


def test_attack_success_rate_consistency(toy):
    features, labels, weights, _ = toy
    x_adv, _ = pgd_feature_attack(features, labels, weights, epsilon=0.3, steps=15)
    asr = attack_success_rate(features, x_adv, labels, weights)
    clean = clean_accuracy(features, labels, weights)
    robust = robust_accuracy(x_adv, labels, weights)
    assert 0.0 <= asr <= 1.0
    if clean > 0:
        assert abs(asr - (1 - robust / clean)) < 1e-9


def test_edge_drop_removes_expected_edges(toy):
    _, _, _, adj = toy
    n_edges = int((adj > 0).sum() // 2)
    frac = 0.2
    adj_adv, log = edge_drop_attack(adj, drop_fraction=frac, strategy="uniform", seed=1)
    n_edges_after = int((adj_adv > 0).sum() // 2)
    assert log.perturbed_edges == int(round(n_edges * frac))
    assert n_edges_after == n_edges - log.perturbed_edges


def test_edge_drop_keeps_symmetry(toy):
    _, _, _, adj = toy
    adj_adv, _ = edge_drop_attack(adj, drop_fraction=0.3, strategy="high-degree")
    assert np.allclose(adj_adv, adj_adv.T)


def test_edge_drop_zero_fraction_is_identity(toy):
    _, _, _, adj = toy
    adj_adv, log = edge_drop_attack(adj, drop_fraction=0.0)
    assert np.allclose(adj_adv, adj)
    assert log.perturbed_edges == 0


def test_certified_radius_nonnegative(toy):
    features, _, weights, _ = toy
    r = certified_radius_estimate(features, weights, sigma=0.2, n_samples=50, seed=0)
    assert r >= 0.0
    assert np.isfinite(r)
