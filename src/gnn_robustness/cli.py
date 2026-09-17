"""CLI: grbench evaluate --adj ... --features ... --labels ..."""

from __future__ import annotations

import json
import sys

import click
import numpy as np


def _load_matrix(path: str) -> np.ndarray:
    if path.endswith(".npy"):
        return np.load(path)
    if path.endswith(".npz"):
        with np.load(path) as z:
            key = "arr_0" if "arr_0" in z else list(z.keys())[0]
            return z[key]
        # unreachable
    # CSV / whitespace-delimited fallback
    try:
        return np.loadtxt(path, delimiter=",")
    except ValueError:
        return np.loadtxt(path)


def _load_labels(path: str) -> np.ndarray:
    arr = _load_matrix(path)
    return arr.astype(int).ravel()


@click.group()
def main() -> None:
    """Adversarial robustness benchmark for Graph Neural Networks."""


@main.command("evaluate")
@click.option("--adj", "adj_path", required=True, type=click.Path(exists=True),
              help="Adjacency matrix (.npy, .npz, or CSV).")
@click.option("--features", "features_path", required=True, type=click.Path(exists=True),
              help="Node feature matrix (.npy, .npz, or CSV).")
@click.option("--labels", "labels_path", required=True, type=click.Path(exists=True),
              help="Node labels (.npy or CSV).")
@click.option("--weights", "weights_path", required=True, type=click.Path(exists=True),
              help="Linear surrogate classifier weights, shape (D, C).")
@click.option("--epsilon", default=0.1, show_default=True,
              help="L_inf budget for the PGD feature attack.")
@click.option("--pgd-steps", default=20, show_default=True)
@click.option("--drop-fraction", default=0.1, show_default=True,
              help="Fraction of edges to drop in the structural attack.")
@click.option("--edge-strategy", default="uniform",
              type=click.Choice(["uniform", "high-degree"]), show_default=True)
@click.option("--sigma", default=0.1, show_default=True,
              help="Smoothing noise std for the certified-radius estimate.")
@click.option("--format", "out_format", type=click.Choice(["text", "json"]),
              default="text", show_default=True)
def evaluate(adj_path, features_path, labels_path, weights_path, epsilon,
             pgd_steps, drop_fraction, edge_strategy, sigma, out_format):
    """Run the attack suite and print a robustness report."""
    from .attacks import edge_drop_attack, pgd_feature_attack
    from .metrics import (attack_success_rate, certified_radius_estimate,
                          clean_accuracy, robust_accuracy)

    adj = _load_matrix(adj_path)
    features = _load_matrix(features_path)
    labels = _load_labels(labels_path)
    weights = _load_matrix(weights_path)

    clean_acc = clean_accuracy(features, labels, weights)

    x_adv, pgd_log = pgd_feature_attack(features, labels, weights,
                                        epsilon=epsilon, steps=pgd_steps)
    rob_acc_feat = robust_accuracy(x_adv, labels, weights)
    asr_feat = attack_success_rate(features, x_adv, labels, weights)

    adj_adv, drop_log = edge_drop_attack(adj, drop_fraction=drop_fraction,
                                         strategy=edge_strategy)
    edges_dropped = int(drop_log.perturbed_edges)

    radius = certified_radius_estimate(features, weights, sigma=sigma)

    report = {
        "clean_accuracy": round(clean_acc, 4),
        "pgd_feature_attack": {
            "epsilon": epsilon,
            "steps": pgd_steps,
            "robust_accuracy": round(rob_acc_feat, 4),
            "attack_success_rate": round(asr_feat, 4),
            "perturbed_features": pgd_log.perturbed_features,
        },
        "edge_drop_attack": {
            "drop_fraction": drop_fraction,
            "strategy": edge_strategy,
            "edges_dropped": edges_dropped,
            "edges_total": int((adj > 0).sum() // 2),
        },
        "certified_radius_mean": round(radius, 4),
    }

    if out_format == "json":
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo("\nGNN Robustness Report")
        click.echo("=====================")
        click.echo(f"Clean accuracy:            {report['clean_accuracy']:.4f}")
        click.echo(f"PGD (eps={epsilon}) robust acc: {rob_acc_feat:.4f}")
        click.echo(f"PGD attack success rate:   {asr_feat:.4f}")
        click.echo(f"Edges dropped:             {edges_dropped} "
                   f"(strategy={edge_strategy})")
        click.echo(f"Mean certified radius:     {radius:.4f} (sigma={sigma})")

    # Non-zero exit when the model is fragile: robust accuracy < 50% of clean.
    fragile = rob_acc_feat < 0.5 * clean_acc if clean_acc > 0 else False
    sys.exit(2 if fragile else 0)


if __name__ == "__main__":
    main()
