#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scorer for cyber-agent-eval.

Reads ground truth (answers/ground_truth.jsonl) and a predictions jsonl, computes per-task
metrics and an overall report. NEVER runs a model; it only compares files.

Prediction record (one JSON per line):
  {case_id, severity, is_malicious, techniques[], iocs[{type,value}],
   correlation_keys[], campaign_id, campaign_stage}

Metrics:
  severity:      exact accuracy + ordinal-partial score (1 - |rank diff|/4)
  malicious:     accuracy over all cases
  fp_trap:       accuracy over is_fp_trap cases (correct = predicted benign)
  techniques:    macro P/R/F1 with parent partial credit (0.5 for parent-only)
  iocs:          macro P/R/F1 on normalized (type,value)
  correlation:   macro P/R/F1 of correlation_keys (cases that have gold keys)
  campaign:      id accuracy, stage exact accuracy, per-campaign stage-order score

Usage: python3 scorer.py --pred answers/predictions_oracle.jsonl
       [--gold answers/ground_truth.jsonl]

Revoked/renamed ATT&CK ids are canonicalised before scoring (alias map).
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEV = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEV)}

# Revoked / renamed ATT&CK ids -> current id (ATT&CK v19, revocations 2026-04).
ATTACK_ALIASES = {
    "T1070.001": "T1685.005",   # Clear Windows Event Logs
    "T1562.001": "T1685",       # Disable or Modify Tools -> Impair Defenses
}


def canon_tech(tid):
    return ATTACK_ALIASES.get(tid, tid)


def parent(tid):
    return tid.split(".")[0]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def technique_prf(pred, gold):
    pred = set(canon_tech(t) for t in pred)
    gold = set(canon_tech(t) for t in gold)
    exact = pred & gold
    pr = pred - exact
    gr = gold - exact
    # greedy parent matching on the remainders
    gold_parents = {}
    for g in gr:
        gold_parents.setdefault(parent(g), []).append(g)
    partial = 0
    used = set()
    for p in sorted(pr):
        cands = gold_parents.get(parent(p), [])
        for g in cands:
            if g not in used:
                used.add(g)
                partial += 1
                break
    # parent-only match: 0.5 credit as TP, remaining 0.5 counts against both
    # precision and recall so it scores below an exact match.
    tp = len(exact) + 0.5 * partial
    fp = (len(pred) - len(exact) - partial) + 0.5 * partial
    fn = (len(gold) - len(exact) - partial) + 0.5 * partial
    return prf(max(tp, 0.0), max(fp, 0.0), max(fn, 0.0))


def ioc_key(io):
    return (io["type"].strip().lower(), io["value"].strip().lower())


def set_prf(pred, gold):
    pred, gold = set(pred), set(gold)
    tp = len(pred & gold)
    return prf(tp, len(pred - gold), len(gold - pred))


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def order_score(pairs):
    """pairs: list of (pred_stage, gold_stage). Fraction of correctly ordered
    gold pairs by predicted stage (Kendall-tau-like, normalized to [0,1])."""
    total_gold = len(pairs)
    pairs = [(p, g) for p, g in pairs if p is not None]
    n = len(pairs)
    if n == 0:
        return 0.0 if total_gold >= 2 else 1.0
    if n < 2:
        return 1.0
    good = tot = 0
    for i in range(n):
        for j in range(i + 1, n):
            gi, gj = pairs[i][1], pairs[j][1]
            pi, pj = pairs[i][0], pairs[j][0]
            if gi == gj:
                continue
            tot += 1
            if (pi - pj) * (gi - gj) > 0:
                good += 1
    return good / tot if tot else 1.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", required=True)
    ap.add_argument("--gold", default=os.path.join(HERE, "answers", "ground_truth.jsonl"))
    ap.add_argument("--inputs", default=os.path.join(HERE, "inputs", "cases_input.jsonl"),
                    help="cases_input.jsonl (for task_type grouping)")
    ap.add_argument("--json", action="store_true", help="print full json report")
    args = ap.parse_args()

    gold = {c["case_id"]: c for c in
            (json.loads(l) for l in open(args.gold, encoding="utf-8") if l.strip())}
    preds = {p["case_id"]: p for p in
             (json.loads(l) for l in open(args.pred, encoding="utf-8") if l.strip())}
    task_of = {}
    try:
        for l in open(args.inputs, encoding="utf-8"):
            if l.strip():
                ci = json.loads(l)
                task_of[ci["case_id"]] = ci.get("task_type")
    except FileNotFoundError:
        pass

    percase = {}   # case_id -> metric dict (None = not applicable)
    missing = 0
    for cid, ex in gold.items():
        p = preds.get(cid)
        m = {"sev_exact": 0, "sev_ord": 0.0, "mal": 0, "fp": None,
             "tech_f": None, "tech_p": None, "tech_r": None,
             "ioc_f": None, "ioc_p": None, "ioc_r": None, "corr_f": None,
             "camp_id": None, "camp_stage": None, "decoy": None}
        is_decoy = bool(ex.get("is_decoy"))
        if p is None:
            missing += 1
            if ex["is_fp_trap"]:
                m["fp"] = 0
            if ex["techniques"]:
                m["tech_f"] = m["tech_p"] = m["tech_r"] = 0.0
            if ex["iocs"]:
                m["ioc_f"] = m["ioc_p"] = m["ioc_r"] = 0.0
            if ex["correlation_keys"]:
                m["corr_f"] = 0.0
            if ex["campaign_id"]:
                m["camp_id"] = 0; m["camp_stage"] = 0
            if is_decoy:
                m["decoy"] = 0
            percase[cid] = m
            continue

        m["sev_exact"] = 1 if p.get("severity") == ex["severity"] else 0
        if p.get("severity") in SEV_RANK:
            m["sev_ord"] = 1 - abs(SEV_RANK[p["severity"]] - SEV_RANK[ex["severity"]]) / 4
        m["mal"] = 1 if bool(p.get("is_malicious")) == ex["is_malicious"] else 0
        if ex["is_fp_trap"]:
            m["fp"] = 1 if bool(p.get("is_malicious")) is False else 0
        if ex["techniques"] or p.get("techniques"):
            pp, rr, ff = technique_prf(p.get("techniques", []), ex["techniques"])
            if ex["techniques"]:
                m["tech_p"] = pp; m["tech_r"] = rr; m["tech_f"] = ff
        if ex["iocs"] or p.get("iocs"):
            pk = [ioc_key(x) for x in p.get("iocs", [])]
            gk = [ioc_key(x) for x in ex["iocs"]]
            pp, rr, ff = set_prf(pk, gk)
            if ex["iocs"]:
                m["ioc_p"] = pp; m["ioc_r"] = rr; m["ioc_f"] = ff
        if ex["correlation_keys"]:
            _, _, ff = set_prf(p.get("correlation_keys", []), ex["correlation_keys"])
            m["corr_f"] = ff
        if ex["campaign_id"]:
            m["camp_id"] = 1 if p.get("campaign_id") == ex["campaign_id"] else 0
            m["camp_stage"] = 1 if p.get("campaign_stage") == ex["campaign_stage"] else 0
        if is_decoy:
            # decoy done right = recognised as NOT a real campaign and benign
            m["decoy"] = 1 if (p.get("campaign_id") in (None, "", "null")
                               and bool(p.get("is_malicious")) is False) else 0
        percase[cid] = m

    # campaign stage ordering (needs per-campaign pairs)
    camp_pairs = {}
    for cid, ex in gold.items():
        if ex["campaign_id"]:
            p = preds.get(cid) or {}
            camp_pairs.setdefault(ex["campaign_id"], []).append(
                (p.get("campaign_stage"), ex["campaign_stage"]))
    camp_order = mean([order_score(v) for v in camp_pairs.values()])

    def agg(cids):
        """Aggregate a metric report over a set of case ids (ignoring None)."""
        def col(key):
            return [percase[c][key] for c in cids if percase[c].get(key) is not None]
        r = {
            "n": len(cids),
            "severity_exact_acc": round(mean(col("sev_exact")), 4),
            "severity_ordinal_score": round(mean(col("sev_ord")), 4),
            "malicious_acc": round(mean(col("mal")), 4),
            "fp_trap_acc": round(mean(col("fp")), 4) if col("fp") else None,
            "technique_f1": round(mean(col("tech_f")), 4) if col("tech_f") else None,
            "ioc_f1": round(mean(col("ioc_f")), 4) if col("ioc_f") else None,
            "correlation_f1": round(mean(col("corr_f")), 4) if col("corr_f") else None,
            "campaign_id_acc": round(mean(col("camp_id")), 4) if col("camp_id") else None,
            "campaign_stage_exact_acc": round(mean(col("camp_stage")), 4) if col("camp_stage") else None,
            "decoy_acc": round(mean(col("decoy")), 4) if col("decoy") else None,
        }
        return r

    all_ids = list(gold.keys())
    report = agg(all_ids)
    report["n_cases"] = len(gold)
    report["n_predicted"] = len(preds)
    report["n_missing_predictions"] = missing
    report["technique_precision"] = round(mean(
        [percase[c]["tech_p"] for c in all_ids if percase[c]["tech_p"] is not None]), 4)
    report["technique_recall"] = round(mean(
        [percase[c]["tech_r"] for c in all_ids if percase[c]["tech_r"] is not None]), 4)
    report["ioc_precision"] = round(mean(
        [percase[c]["ioc_p"] for c in all_ids if percase[c]["ioc_p"] is not None]), 4)
    report["ioc_recall"] = round(mean(
        [percase[c]["ioc_r"] for c in all_ids if percase[c]["ioc_r"] is not None]), 4)
    report["campaign_stage_order_score"] = round(camp_order, 4)

    headline = [report[k] for k in (
        "severity_ordinal_score", "malicious_acc", "fp_trap_acc",
        "technique_f1", "ioc_f1", "correlation_f1",
        "campaign_id_acc", "campaign_stage_order_score") if report.get(k) is not None]
    report["overall_score"] = round(mean(headline), 4)

    # ---- per-group breakdown (by task_type, label, severity, trap, decoy) ----
    from collections import defaultdict
    groups = defaultdict(lambda: defaultdict(list))
    for cid, ex in gold.items():
        groups["task_type"][task_of.get(cid, "unknown")].append(cid)
        groups["label"]["malicious" if ex["is_malicious"] else "benign"].append(cid)
        groups["severity"][ex["severity"]].append(cid)
        groups["trap"]["fp_trap" if ex["is_fp_trap"] else "normal"].append(cid)
        groups["decoy"]["decoy" if ex.get("is_decoy") else "non_decoy"].append(cid)
    breakdown = {dim: {val: agg(ids) for val, ids in sorted(vals.items())}
                 for dim, vals in groups.items()}
    report["by_group"] = breakdown

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for k, v in report.items():
            if k == "by_group":
                continue
            print(f"  {k:32s} {v}")
        print("  --- per-group (malicious_acc | sev_ord | overall n) ---")
        for dim, vals in breakdown.items():
            print(f"  [{dim}]")
            for val, r in vals.items():
                print(f"    {val:24s} n={r['n']:<3d} mal_acc={r['malicious_acc']} "
                      f"sev_ord={r['severity_ordinal_score']}")
    return report


if __name__ == "__main__":
    main()
