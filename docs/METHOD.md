# Method

This benchmark implements the adversarial evaluation protocol from the
companion work on adversarial-robust Graph Neural Networks
(TIC 2026, Best Paper).

## Threat model

We consider an adversary that can perturb the inputs to a trained GNN
*after* training (evasion setting), within a bounded budget:

| Attack | Perturbation set | Budget |
|---|---|---|
| PGD feature attack | L_inf ball around node features | `epsilon` |
| Edge-drop attack | Remove up to a fraction of edges | `drop_fraction` |

The attacks operate on the `(adjacency, features)` pair — the same
interface every message-passing GNN consumes — so results are comparable
across architectures (GCN, GAT, GraphSAGE, ...).

## Feature attack: PGD

Projected gradient descent on the cross-entropy loss of a linear surrogate
head, following Madry et al. (2018), adapted to the node-classification
setting:

1. Random initialization inside the L_inf ball (uniform).
2. `steps` iterations of signed-gradient ascent with step size
   `2.5 * epsilon / steps` (standard heuristic).
3. Projection back onto the L_inf ball after each step.

The surrogate head is a least-squares linear probe in the reference
implementation; swap in your trained GNN's logits for a white-box
evaluation of the full model.

## Structural attack: edge drop

Two strategies:

- **uniform**: edges dropped uniformly at random (baseline structural noise).
- **high-degree**: edges incident to high-degree nodes dropped first —
  a stronger attack, since hub edges carry the most messages.

The perturbed adjacency is kept symmetric (undirected graphs).

## Metrics

- **Robust accuracy**: accuracy on perturbed inputs. Headline number.
- **Attack success rate (ASR)**: fraction of originally-correct nodes
  flipped. `ASR = 1 - robust_acc / clean_acc`.
- **Certified radius**: randomized-smoothing estimate (Cohen et al., 2019)
  of the mean L2 radius within which predictions are provably stable,
  using a Clopper–Pearson lower bound at confidence `1 - alpha`.

## Interpreting results

A robust model keeps `robust_accuracy` close to `clean_accuracy`
(ASR near 0) *and* reports a non-trivial certified radius. The CLI exits
non-zero (code 2) when PGD robust accuracy falls below half of clean
accuracy — a convenient CI gate for model promotion.
