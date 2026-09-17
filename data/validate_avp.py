#!/usr/bin/env python3
"""Validate the reconstructed AVP dataset against Table II of the paper.

Asserts split sizes, unique CVE counts, mean hops (tol 0.15), mean difficulty
(tol 0.15), adversarial split difficulty >= 4, total 2,847 incidents,
and required label fields. Exits 0 on success, 1 on failure.
"""

import json
import sys

EXPECTED = {
    "train":           {"n": 1980, "cves": 312, "hops": 7.4, "diff": 2.1},
    "validation":      {"n": 427,  "cves": 89,  "hops": 7.1, "diff": 2.2},
    "test-standard":   {"n": 300,  "cves": 74,  "hops": 7.8, "diff": 2.0},
    "test-adversarial":{"n": 140,  "cves": 41,  "hops": 9.2, "diff": 4.3},
}

REQUIRED_FIELDS = ["id", "split", "source", "auth_path_graph", "path_hops",
                   "cve_id", "cwe", "remediation_patch", "attck_tags",
                   "perturbation_strategy", "difficulty",
                   "reconstruction_note", "data_license"]

KNOWN_SOURCES = {"lanl", "mitre-engenuity", "lmdg-synthetic"}
KNOWN_SPLITS = set(EXPECTED)


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main(path):
    incidents = [json.loads(line) for line in open(path) if line.strip()]
    if len(incidents) != 2847:
        fail(f"expected 2847 incidents, got {len(incidents)}")

    by_split = {}
    for inc in incidents:
        for f in REQUIRED_FIELDS:
            if f not in inc:
                fail(f"incident {inc.get('id')} missing field {f}")
        if inc["split"] not in KNOWN_SPLITS:
            fail(f"unknown split {inc['split']}")
        if inc["source"] not in KNOWN_SOURCES:
            fail(f"unknown source {inc['source']}")
        g = inc["auth_path_graph"]
        if len(g["edges"]) != inc["path_hops"]:
            fail(f"{inc['id']}: edges {len(g['edges'])} != path_hops {inc['path_hops']}")
        if len(g["nodes"]) != inc["path_hops"] + 1:
            fail(f"{inc['id']}: nodes {len(g['nodes'])} != hops+1")
        if not (1 <= inc["difficulty"] <= 5):
            fail(f"{inc['id']}: difficulty out of range")
        by_split.setdefault(inc["split"], []).append(inc)

    all_cves = set()
    for split, exp in EXPECTED.items():
        group = by_split.get(split, [])
        if len(group) != exp["n"]:
            fail(f"{split}: expected {exp['n']} incidents, got {len(group)}")
        cves = {i["cve_id"] for i in group}
        if len(cves) != exp["cves"]:
            fail(f"{split}: expected {exp['cves']} unique CVEs, got {len(cves)}")
        mean_hops = sum(i["path_hops"] for i in group) / len(group)
        if abs(mean_hops - exp["hops"]) > 0.15:
            fail(f"{split}: mean hops {mean_hops:.3f} vs {exp['hops']}")
        mean_diff = sum(i["difficulty"] for i in group) / len(group)
        if abs(mean_diff - exp["diff"]) > 0.15:
            fail(f"{split}: mean difficulty {mean_diff:.3f} vs {exp['diff']}")
        all_cves |= cves
        print(f"OK  {split:16s} n={len(group):5d} cves={len(cves):3d} "
              f"hops={mean_hops:.3f} (spec {exp['hops']}) "
              f"diff={mean_diff:.3f} (spec {exp['diff']})")

    if len(all_cves) != 416:
        fail(f"expected 416 unique CVEs total, got {len(all_cves)}")

    adv = by_split["test-adversarial"]
    if any(i["difficulty"] < 4 for i in adv):
        fail("test-adversarial contains difficulty < 4")

    src_counts = {}
    for inc in incidents:
        src_counts[inc["source"]] = src_counts.get(inc["source"], 0) + 1
    if src_counts != {"lanl": 1243, "mitre-engenuity": 904, "lmdg-synthetic": 700}:
        fail(f"source counts mismatch: {src_counts}")

    total_hops = sum(i["path_hops"] for i in incidents) / len(incidents)
    print(f"OK  total unique CVEs = {len(all_cves)} (spec 416)")
    print(f"OK  sources = {src_counts}")
    print(f"OK  test-adversarial all difficulty >= 4")
    print(f"NOTE overall mean hops = {total_hops:.3f} (paper Table II prints 7.7; "
          f"per-split means are exact per spec — see DATA_PROVENANCE.md)")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main(sys.argv[1])
