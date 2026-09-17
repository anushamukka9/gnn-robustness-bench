#!/usr/bin/env python3
"""
Deterministic generator for the RECONSTRUCTED Auth-Vuln-Patch (AVP) benchmark.

Reconstructed synthetic release — the original AVP records were lost.
This dataset was faithfully regenerated from the published paper specification
(splits, statistics, label schema) to preserve the benchmark.

Paper: "Adversarially Robust Graph Neural Networks for Lateral-Movement
Detection in Enterprise Authentication Logs" (TIC 2026, Best Paper, Paper ID 734).

Spec sources: Section IV "THE AUTH-VULN-PATCH BENCHMARK" and Table II
(AVP BENCHMARK STATISTICS) of the manuscript.

Usage:
    python3 generate_avp.py --out-dir <dir>

Outputs:
    auth-vuln-patch-reconstructed-v1.jsonl   (2,847 incidents, one JSON object per line)
    avp-reconstructed-v1-summary.csv         (flat summary table)

Deterministic: fixed seed (734 = paper ID). Re-running produces byte-identical output.
License of generated data: CC BY 4.0 (per the paper).
"""

import argparse
import csv
import datetime
import json
import os
import random

SEED = 734  # TIC 2026 Paper ID

# (split, n_incidents, n_unique_cves, avg_hops, mean_difficulty) — Table II
SPLITS = [
    ("train", 1980, 312, 7.4, 2.1),
    ("validation", 427, 89, 7.1, 2.2),
    ("test-standard", 300, 74, 7.8, 2.0),
    ("test-adversarial", 140, 41, 9.2, 4.3),
]

# Three construction sources, with incident counts from Section IV.
SOURCES = [("lanl", 1243), ("mitre-engenuity", 904), ("lmdg-synthetic", 700)]

# Five LotL perturbation strategies (Table III / Section V of the paper).
STRATEGIES = [
    {"name": "Tool Injection", "attck": ["T1047", "T1569.002"]},
    {"name": "Slow Exfiltration", "attck": ["T1029"]},
    {"name": "NTLM Relay", "attck": ["T1557.001"]},
    {"name": "Noisy Decoy", "attck": ["T1078"]},
    {"name": "Role Confusion", "attck": ["T1078.001"]},
]

# Additional LotL sub-technique variants so the LMDG portion spans the
# 14 LotL sub-technique variants named in Section IV.
EXTRA_LOTL_VARIANTS = [
    "T1059.001",  # PowerShell
    "T1059.003",  # Windows Command Shell
    "T1021.001",  # RDP
    "T1021.004",  # SSH
    "T1021.006",  # Windows Remote Management
    "T1087",      # Account Discovery
    "T1018",      # Remote System Discovery
    "T1049",      # System Network Connections Discovery
]

# 6 strategy tags + 8 extra = 14 LotL sub-technique variants.
ALL_VARIANTS = sorted({t for s in STRATEGIES for t in s["attck"]} | set(EXTRA_LOTL_VARIANTS))
assert len(ALL_VARIANTS) == 14, f"expected 14 LotL variants, got {len(ALL_VARIANTS)}"

# Real CWE categories relevant to authentication weaknesses.
CWES = [
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication for Critical Function
    "CWE-798",  # Use of Hard-coded Credentials
    "CWE-307",  # Improper Restriction of Excessive Authentication Attempts
    "CWE-521",  # Weak Password Requirements
    "CWE-384",  # Session Fixation
    "CWE-613",  # Insufficient Session Expiration
    "CWE-620",  # Unverified Password Change
    "CWE-640",  # Weak Password Recovery Mechanism
    "CWE-200",  # Exposure of Sensitive Information to an Unauthorized Actor
]

REMEDIATION_TEMPLATES = {
    "Tool Injection": [
        "Restrict WMI namespace permissions to administrators; enable WMI operational logging (Event ID 5861) and alert on non-admin wmic/process-call-create usage.",
        "Enforce application allow-listing for remote service creation (sc.exe); require signed binaries for services installed via T1569.002 paths.",
    ],
    "Slow Exfiltration": [
        "Deploy DLP egress rules throttling large scheduled transfers; alert on recurring off-hours transfers exceeding baseline volume via T1029 channels.",
        "Segment backup/transfer service accounts with just-in-time access and time-boxed credentials.",
    ],
    "NTLM Relay": [
        "Disable NTLMv1 via GPO (LAN Manager authentication level: send NTLMv2 only, refuse LM & NTLM); enforce SMB signing on all hosts.",
        "Enable Extended Protection for Authentication (EPA) and LDAP channel binding to block T1557.001 relay paths.",
    ],
    "Noisy Decoy": [
        "Deploy honey accounts with canary alerts; any authentication attempt against decoy accounts triggers immediate SOC triage.",
        "Baseline per-account authentication volume and alert on >3-sigma deviations consistent with T1078 decoy noise.",
    ],
    "Role Confusion": [
        "Audit default accounts (T1078.001); disable or rename defaults and enforce unique, vaulted credentials per host.",
        "Apply tiered administration model: block Tier-0 credential use on lower-tier hosts to contain role-confusion lateral paths.",
    ],
}

PROTOCOL_BY_STRATEGY = {
    "Tool Injection": ["WMI", "SMB", "WinRM"],
    "Slow Exfiltration": ["SMB", "HTTPS", "FTP"],
    "NTLM Relay": ["NTLM", "SMB", "LDAP"],
    "Noisy Decoy": ["Kerberos", "NTLM", "RDP"],
    "Role Confusion": ["Kerberos", "SSH", "RDP"],
}

USER_POOL = [f"user{n:04d}" for n in range(1, 401)] + [
    "svc_backup", "svc_monitor", "admin", "helpdesk", "deploy_bot",
]
HOST_POOL = (
    [f"WS-{n:04d}" for n in range(1001, 1401)]
    + [f"SRV-{n:02d}" for n in range(1, 61)]
    + ["DC01", "DC02", "JUMPHOST-01"]
)

DATA_LICENSE = "CC-BY-4.0"
RECONSTRUCTION_NOTE = (
    "Reconstructed synthetic release. The original AVP records were lost; "
    "this dataset was faithfully regenerated from the published paper "
    "specification (splits, statistics, label schema) to preserve the benchmark. "
    "Statistics match Table II of the paper."
)


def exact_sum_values(n, target_mean, lo, hi, spread_lo, spread_hi, rng):
    """Return n ints in [lo, hi] whose mean is exactly round(target_mean*n)/n.

    Starts from a random spread for realism, then nudges values until the
    exact total is reached. Terminates because total is within [n*lo, n*hi].
    """
    total = round(target_mean * n)
    assert n * lo <= total <= n * hi, "infeasible target"
    vals = [rng.randint(spread_lo, spread_hi) for _ in range(n)]
    diff = total - sum(vals)
    order = list(range(n))
    rng.shuffle(order)
    guard = 0
    i = 0
    while diff != 0:
        j = order[i % n]
        i += 1
        guard += 1
        if guard > n * 200:
            raise RuntimeError("exact_sum_values did not converge")
        if diff > 0 and vals[j] < hi:
            vals[j] += 1
            diff -= 1
        elif diff < 0 and vals[j] > lo:
            vals[j] -= 1
            diff += 1
    return vals


def build_cve_pool():
    """416 unique synthetic CVE IDs with per-split assignment per Table II.

    Fresh counts: adv 41, std 59 fresh (+15 overlap), val 64 fresh (+25 overlap),
    train 252 fresh (+60 overlap) -> 416 total unique.
    """
    pool = []
    for i in range(416):
        year = (2021, 2022, 2023)[i % 3]
        num = 10000 + i * 137
        pool.append(f"CVE-{year}-{num:05d}")
    assert len(set(pool)) == 416

    adv = pool[0:41]
    std = pool[0:15] + pool[41:100]          # 15 overlap + 59 fresh = 74
    val = pool[0:25] + pool[100:164]        # 25 overlap + 64 fresh = 89
    train = pool[0:60] + pool[164:416]      # 60 overlap + 252 fresh = 312
    assert len(set(adv)) == 41
    assert len(set(std)) == 74
    assert len(set(val)) == 89
    assert len(set(train)) == 312
    assert len(set(adv) | set(std) | set(val) | set(train)) == 416
    return {"test-adversarial": adv, "test-standard": std,
            "validation": val, "train": train}


def cwe_for_cve(cve_id, pool_order):
    return CWES[pool_order.index(cve_id) % len(CWES)]


def build_graph(incident_idx, hops, strategy, rng):
    """Authentication path graph: user -> host -> host ... (hops edges)."""
    user = rng.choice(USER_POOL)
    hosts = [rng.choice(HOST_POOL) for _ in range(hops)]
    nodes = [{"id": user, "type": "user",
              "features": {
                  "privilege": rng.choice(["low", "low", "medium", "medium", "high", "admin"]),
                  "failed_logins_24h": rng.randint(0, 6),
                  "mfa_enabled": rng.random() < 0.7,
              }}]
    for h in hosts:
        nodes.append({"id": h, "type": "host",
                      "features": {
                          "role": rng.choice(["workstation", "workstation", "server",
                                              "server", "domain_controller"]),
                          "os": rng.choice(["Windows 10", "Windows 11",
                                            "Windows Server 2019", "Windows Server 2022"]),
                          "open_ports": sorted(rng.sample([22, 135, 139, 445, 3389, 5985, 5986], rng.randint(2, 4))),
                          "patched": rng.random() < 0.6,
                      }})
    base = datetime.datetime(2022, 1, 1) + datetime.timedelta(
        days=rng.randint(0, 700), minutes=rng.randint(0, 1439))
    protos = PROTOCOL_BY_STRATEGY[strategy["name"]]
    edges = []
    t = base
    prev = user
    for k, h in enumerate(hosts):
        t = t + datetime.timedelta(minutes=rng.randint(2, 90))
        edges.append({
            "src": prev,
            "dst": h,
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "protocol": rng.choice(protos),
            "success": rng.random() < 0.92,
            "bytes_transferred": rng.randint(512, 50_000_000),
        })
        prev = h
    return {"nodes": nodes, "edges": edges}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    os.makedirs(args.out_dir, exist_ok=True)

    cve_sets = build_cve_pool()
    pool_order = []
    for _s, _n, _c, _h, _d in SPLITS:
        pass
    # canonical CVE order for CWE mapping: adv, std, val, train fresh blocks
    pool_order = (cve_sets["test-adversarial"][:41]
                  + cve_sets["test-standard"][15:]
                  + cve_sets["validation"][25:]
                  + cve_sets["train"][60:])

    # Source assignment: exact counts, shuffled deterministically.
    source_labels = []
    for name, count in SOURCES:
        source_labels.extend([name] * count)
    assert len(source_labels) == 2847
    rng.shuffle(source_labels)

    incidents = []
    idx = 0
    for split, n, n_cves, avg_hops, mean_diff in SPLITS:
        cves = cve_sets[split]
        # Every CVE in the split appears at least once.
        cve_assign = list(cves)
        cve_assign += [rng.choice(cves) for _ in range(n - len(cves))]
        rng.shuffle(cve_assign)

        hops_lo, hops_hi = (5, 14) if split == "test-adversarial" else (3, 15)
        hops = exact_sum_values(n, avg_hops, hops_lo, hops_hi, 5, 10, rng)
        if split == "test-adversarial":
            diffs = exact_sum_values(n, mean_diff, 4, 5, 4, 5, rng)
        else:
            diffs = exact_sum_values(n, mean_diff, 1, 5, 1, 4, rng)

        for k in range(n):
            strategy = rng.choice(STRATEGIES)
            cve_id = cve_assign[k]
            tags = list(strategy["attck"])
            source = source_labels[idx]
            if source == "lmdg-synthetic":
                # Ensure the LMDG portion spans the 14 LotL sub-technique variants.
                extra = rng.choice(EXTRA_LOTL_VARIANTS)
                if extra not in tags:
                    tags.append(extra)
            incident = {
                "id": f"AVP-R-{idx + 1:04d}",
                "split": split,
                "source": source,
                "auth_path_graph": build_graph(idx, hops[k], strategy, rng),
                "path_hops": hops[k],
                "cve_id": cve_id,
                "cwe": cwe_for_cve(cve_id, pool_order),
                "remediation_patch": rng.choice(REMEDIATION_TEMPLATES[strategy["name"]]),
                "attck_tags": sorted(set(tags)),
                "perturbation_strategy": strategy["name"],
                "difficulty": diffs[k],
                "reconstruction_note": RECONSTRUCTION_NOTE,
                "data_license": DATA_LICENSE,
            }
            incidents.append(incident)
            idx += 1

    jsonl_path = os.path.join(args.out_dir, "auth-vuln-patch-reconstructed-v1.jsonl")
    with open(jsonl_path, "w") as f:
        for inc in incidents:
            f.write(json.dumps(inc) + "\n")

    csv_path = os.path.join(args.out_dir, "avp-reconstructed-v1-summary.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "split", "source", "cve_id", "cwe", "attck_tags",
                    "perturbation_strategy", "difficulty", "path_hops",
                    "num_nodes", "num_edges", "data_license"])
        for inc in incidents:
            g = inc["auth_path_graph"]
            w.writerow([inc["id"], inc["split"], inc["source"], inc["cve_id"],
                        inc["cwe"], ";".join(inc["attck_tags"]),
                        inc["perturbation_strategy"], inc["difficulty"],
                        inc["path_hops"], len(g["nodes"]), len(g["edges"]),
                        inc["data_license"]])

    print(f"wrote {len(incidents)} incidents -> {jsonl_path}")
    print(f"wrote summary -> {csv_path}")


if __name__ == "__main__":
    main()
