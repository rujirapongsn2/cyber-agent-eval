#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber-agent-eval v4.2.1 deterministic dataset generator (pure python3 stdlib).

Usage:  python3 generator.py --seed 20261113 --out .

Layout (de-leaked: agent input separate from answers):
    inputs/logs/<source>/...       native-format raw logs (incl. benign noise)
    inputs/cases_input.jsonl       one case input per line (prompt + log refs only)
    inputs/campaigns_input.json    campaign ids the agent must reconstruct
    answers/ground_truth.jsonl     labels / techniques / iocs / rationale (TH)
    answers/campaigns.json         campaign stage ordering + techniques
    answers/predictions_oracle.jsonl  perfect predictions (scorer self-test = 1.0)
    answers/predictions_dumb.jsonl    dumb baseline (all high + malicious)
    dataset_meta.json              counts / distribution / benign-event %
    tz_conventions.json            per-source timezone rendering conventions

NEVER runs any model. Generation is fully offline and deterministic.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen.build import Build, SOURCE_FILES, XML_SOURCES
from gen import timeutil as T
from gen import scenarios, noise, attack, timeutil


HINT_HOURS = {            # label-blind time-of-day classes (local ICT)
    "biz": (8.0, 18.5),      # a human at a desk (benign or malicious)
    "evening": (19.0, 23.5),
    "night": (0.5, 5.0),     # batch jobs / maintenance / off-hours ops
    "any": (0.0, 23.99),
}
MIN_SEP_H = 18.0             # groups sharing a principal stay >= 18 h apart


def make_schedule(b0, seed):
    """N8 fix: assign every time group (case or campaign) a start slot that is
    independent of its label. Groups are stratified by kind (malicious /
    fp-trap / other benign) and dealt round-robin over the 4 days, so every
    day carries a similar label mix; the hour comes only from the activity's
    time-of-day class (hint), never from the label."""
    import random
    import datetime as _dt
    from gen.build import WINDOW_START, WINDOW_END
    srng = random.Random(seed ^ 0x0BADC0DE)
    kinds = {"mal": [], "trap": [], "ben": []}
    for gid in sorted(b0.groups):
        g = b0.groups[gid]
        if not g["cases"]:
            continue
        gts = [b0.cases[i]["gt"] for i in g["cases"]]
        k = ("mal" if any(x["is_malicious"] for x in gts) else
             "trap" if any(x["is_fp_trap"] or x.get("is_decoy") for x in gts)
             else "ben")
        kinds[k].append(gid)
    day0 = T.local(WINDOW_START).replace(hour=0, minute=0, second=0, microsecond=0)
    placed = []                      # (slot_utc, who set)
    sched = {}
    # weighted round-robin: big groups first, each to the day whose
    # malicious/benign case counts stay closest to an even 4-way split
    cnt = {}
    for k in kinds:
        for gid in kinds[k]:
            gts = [b0.cases[i]["gt"] for i in b0.groups[gid]["cases"]]
            cnt[gid] = (sum(1 for x in gts if x["is_malicious"]),
                        sum(1 for x in gts if not x["is_malicious"]))
    tm = sum(v[0] for v in cnt.values()) / 4.0
    tb = sum(v[1] for v in cnt.values()) / 4.0
    gl = sorted(cnt)
    srng.shuffle(gl)
    gl.sort(key=lambda g: -(cnt[g][0] + cnt[g][1]))
    load_m = [0] * 4
    load_b = [0] * 4
    order = []
    for gid in gl:
        m, n_ = cnt[gid]
        best_d, best_c = None, None
        days = list(range(4))
        srng.shuffle(days)
        for d in days:
            cost = 0.0
            for dd in range(4):
                lm = load_m[dd] + (m if dd == d else 0)
                lb = load_b[dd] + (n_ if dd == d else 0)
                cost += (lm - tm) ** 2 / max(tm, 1) + (lb - tb) ** 2 / max(tb, 1)
            if best_c is None or cost < best_c - 1e-9:
                best_d, best_c = d, cost
        load_m[best_d] += m
        load_b[best_d] += n_
        order.append((gid, best_d))
    srng.shuffle(order)              # placement order independent of kind
    # stratified hour targets: within each time-of-day class, malicious and
    # benign groups each get evenly spread hours (Latin-hypercube style), so
    # neither label clusters in a part of the class window
    target = {}
    strata = defaultdict(list)
    for gid, _d in order:
        g = b0.groups[gid]
        strata[(g.get("hint", "any"), cnt[gid][0] > 0)].append(gid)
    for key in sorted(strata, key=str):
        gl2 = strata[key]
        lo_h, hi_h = HINT_HOURS.get(key[0], HINT_HOURS["any"])
        srng.shuffle(gl2)
        for i, gid in enumerate(gl2):
            target[gid] = lo_h + (i + srng.random()) / len(gl2) * (hi_h - lo_h)
    for gid, day_i in order:
        g = b0.groups[gid]
        anchor = g["orig"][0]
        rel_min = min(o - anchor for o in g["orig"])
        rel_max = max(o - anchor for o in g["orig"])
        scale = srng.uniform(0.78, 1.32)
        lo_h, hi_h = HINT_HOURS.get(g.get("hint", "any"), HINT_HOURS["any"])
        who = set(g.get("who") or [])
        best = None
        for attempt in range(2000):
            di = day_i if attempt < 300 else srng.randrange(4)
            sep = MIN_SEP_H if attempt < 1800 else 12.0
            if attempt < 300:
                hour = min(hi_h, max(lo_h, target[gid] + srng.uniform(-0.4, 0.4)))
            else:
                hour = srng.uniform(lo_h, hi_h)
            local = day0 + _dt.timedelta(days=di, hours=hour,
                                         seconds=srng.randint(0, 59))
            slot = local.astimezone(T.UTC)
            if slot + rel_min * scale < WINDOW_START + _dt.timedelta(minutes=10):
                continue
            if slot + rel_max * scale > WINDOW_END - _dt.timedelta(minutes=10):
                continue
            ok = all(not (who & w) or
                     abs((slot - s).total_seconds()) >= sep * 3600
                     for s, w in placed)
            if ok:
                best = slot
                break
        assert best is not None, f"cannot schedule group {gid}"
        placed.append((best, who))
        sched[gid] = (best, scale)
    return sched


def build_dataset(seed):
    # pass 1 (dry run, scenarios only): learn the time groups
    b0 = Build(seed=seed)
    scenarios.build_all(b0)
    sched = make_schedule(b0, seed)
    # pass 2: real build with the label-blind schedule
    b = Build(seed=seed, schedule=sched)
    scenarios.build_all(b)           # cases + campaigns (reference only these)
    assert sorted(b.groups) == sorted(b0.groups)
    noise.generate(b)                # multi-day benign background noise
    for c in b.cases:                # integrity: ATT&CK ids must be whitelisted
        for tid in c["gt"]["techniques"]:
            assert attack.is_valid(tid), \
                f"invalid ATT&CK id {tid} in {c['gt']['case_id']}"
    return b


def oracle_prediction(gt):
    return {"case_id": gt["case_id"], "severity": gt["severity"],
            "is_malicious": gt["is_malicious"],
            "is_fp_trap": gt["is_fp_trap"],
            "is_decoy": gt.get("is_decoy", False),
            "techniques": list(gt["techniques"]), "iocs": list(gt["iocs"]),
            "correlation_keys": list(gt["correlation_keys"]),
            "campaign_id": gt["campaign_id"],
            "campaign_stage": gt["campaign_stage"]}


def dumb_prediction(gt):
    return {"case_id": gt["case_id"], "severity": "high", "is_malicious": True,
            "is_fp_trap": False, "is_decoy": False, "techniques": [], "iocs": [],
            "correlation_keys": [], "campaign_id": None, "campaign_stage": None}


def event_counts(b):
    """Total log records per source and overall."""
    per = {}
    for src in SOURCE_FILES:
        if src in XML_SOURCES:
            per[src] = len(b._xml[src])
        else:
            per[src] = len(b._txt[src])
    return per


def malicious_event_count(b):
    """Unique log records referenced by malicious cases."""
    seen = set()
    for c in b.cases:
        if not c["gt"]["is_malicious"]:
            continue
        for r in c["input"]["input_log_refs"]:
            if r["source"] in XML_SOURCES:
                seen.add((r["source"], r["event_record_id"]))
            else:
                seen.add((r["source"], r["line"]))
    return len(seen)


def _day_label(b):
    from gen.build import XML_SOURCES as _X
    out = Counter()
    for c in b.cases:
        g = b.groups.get(c.get("gid"))
        if not g:
            continue
        slot, scale = b.schedule[c["gid"]]
        anchor = g["orig"][0]
        st = min(slot + (o - anchor) * scale for o in g["orig"])
        out[(timeutil.local(st).strftime("%Y-%m-%d"),
             "malicious" if c["gt"]["is_malicious"] else "benign")] += 1
    return {f"{k[0]}|{k[1]}": v for k, v in sorted(out.items())}


def write_meta(b, outdir):
    sev = Counter(c["gt"]["severity"] for c in b.cases)
    tasks = Counter(c["input"]["task_type"] for c in b.cases)
    mal = Counter("malicious" if c["gt"]["is_malicious"] else "benign"
                  for c in b.cases)
    traps = Counter(c["gt"]["fp_trap_kind"] for c in b.cases
                    if c["gt"]["is_fp_trap"])
    sev_label = Counter((c["gt"]["severity"],
                         "malicious" if c["gt"]["is_malicious"] else "benign")
                        for c in b.cases)
    decoys = sum(1 for c in b.cases if c["gt"].get("is_decoy"))
    task_label = Counter((c["input"]["task_type"],
                          "malicious" if c["gt"]["is_malicious"] else "benign")
                         for c in b.cases)
    tactics = Counter()
    for c in b.cases:
        seen = set()
        for tid in c["gt"]["techniques"]:
            for ta in attack.tactics(tid):
                seen.add(ta)
        for ta in seen:
            tactics[ta] += 1
    per_src = event_counts(b)
    total_ev = sum(per_src.values())
    mal_ev = malicious_event_count(b)
    benign_ev = total_ev - mal_ev
    meta = {
        "generator_version": "v4.2.1",
        "seed_note": "deterministic; same --seed yields byte-identical output",
        "org_timezone": timeutil.ORG_TZ_NAME,
        "total_cases": len(b.cases),
        "total_campaigns": len(b.campaigns),
        "campaign_stage_cases": sum(1 for c in b.cases
                                    if c["gt"]["campaign_id"]),
        "by_severity": dict(sorted(sev.items())),
        "severity_x_label": {f"{k[0]}|{k[1]}": v
                             for k, v in sorted(sev_label.items())},
        "task_type_x_label": {f"{k[0]}|{k[1]}": v
                              for k, v in sorted(task_label.items())},
        "decoy_cases": decoys,
        "by_task_type": dict(sorted(tasks.items())),
        "malicious_vs_benign": dict(sorted(mal.items())),
        "fp_traps_total": sum(traps.values()),
        "fp_trap_kinds": dict(sorted(traps.items())),
        "cases_by_tactic": dict(sorted(tactics.items())),
        "total_log_events": total_ev,
        "malicious_referenced_events": mal_ev,
        "benign_events": benign_ev,
        "benign_event_pct": round(100.0 * benign_ev / total_ev, 2),
        "events_per_source": dict(sorted(per_src.items())),
        "attack_whitelist_size": len(attack.WHITELIST),
        "synthesized_sysmon_eid1": getattr(b, "synth_count", 0),
        "case_start_by_day_x_label": _day_label(b),
    }
    with open(os.path.join(outdir, "dataset_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, sort_keys=True)
    return meta


def write_tz(outdir):
    for d in (outdir, os.path.join(outdir, "inputs")):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "tz_conventions.json"), "w",
                  encoding="utf-8") as f:
            json.dump(timeutil.TZ_CONVENTIONS, f, ensure_ascii=False,
                      indent=2, sort_keys=True)


def write_environment(b, outdir):
    from gen import assets as A
    users = {}
    for sam, u in sorted(A.USERS.items()):
        rec = {"sid": u.get("sid"), "kind": u.get("kind"), "upn": u.get("upn"),
               "home_host": A.HOME.get(sam)}
        if sam in b.created_accounts:
            rec["hire_date"] = timeutil.local(b.created_accounts[sam]).strftime("%Y-%m-%d")
            rec["note_th"] = "พนักงานใหม่ บัญชีสร้างระหว่างช่วง log (ดู onboarding)"
        users[sam] = rec
    env = {
        "org_timezone": timeutil.ORG_TZ_NAME,
        "utc_offset": "+07:00",
        "dst": False,
        "log_window": {"start": "2026-11-09", "end": "2026-11-12"},
        "note_th": ("แต่ละแหล่ง log ใช้รูปแบบเวลาของตัวเอง: บางแหล่งเป็น UTC "
                    "(Windows Event XML, Sysmon UtcTime, Squid, Docker, K8s, auditd epoch) "
                    "บางแหล่งเป็นเวลาท้องถิ่น ICT ของอุปกรณ์ (syslog RFC3164, PAN-OS, F5, "
                    "BIND, Windows DNS, FortiGate date/time) ดู tz_conventions.json; "
                    "เวลาท้องถิ่นองค์กรคือ Asia/Bangkok (UTC+07, ไม่มี DST) ; "
                    "change_calendar คือรายการ change/งานที่อนุมัติ (ไม่ใช่คำเฉลย: "
                    "มีทั้งงานที่เกี่ยวและไม่เกี่ยวกับเคส และบางกิจกรรมของแอดมินไม่มี ticket)"),
        "domain": {"netbios": "CORP", "dns_suffix": A.DNS_SUFFIX,
                   "domain_sid": A.DOMAIN_SID},
        "network_topology_th": ("ผู้ใช้ภายใน → PA-CORE (แบ่งโซนภายใน ไม่ทำ NAT) → "
                                "FGT-EDGE (ขอบอินเทอร์เน็ต ทำ SNAT เป็น 203.0.113.2) ; "
                                "FGT-CORE กรองทราฟฟิกแอดมิน east-west (ไม่ทำ NAT) ; "
                                "ทราฟฟิกขาเข้าจากอินเทอร์เน็ตเข้า FGT-EDGE ที่ VIP (DNAT: 203.0.113.3→SRV-WEB01, "
                                "203.0.113.4→SRV-WEB02, 203.0.113.5→SRV-RDS01) แล้วส่งต่อให้ PA-DMZ ซึ่งบังคับ policy ของ DMZ "
                                "(เว็บผ่าน F5 bigip-dmz-01: vs_shop_https→SRV-WEB01, vs_partner_https→SRV-WEB02 ; "
                                "RDP ของ SRV-RDS01 เปิดที่ tcp/3389) ; "
                                "interface ของ FortiGate: wan1=wan, dmz=dmz, portN/internal=lan ; "
                                "proxy01 (Squid) ออกอินเทอร์เน็ตผ่าน FGT-EDGE"),
        "hosts": {name: {"ip": h.get("ip"), "os": h.get("os"),
                         "role": h.get("role"), "fqdn": h.get("fqdn")}
                  for name, h in sorted(A.HOSTS.items())},
        "users": users,
        "network_devices": {k: v for k, v in sorted(A.DEVICES.items())},
        "change_calendar": sorted(b.changes, key=lambda c: (c["start_local"], c["id"])),
        "approved_pentest_source_ips": sorted(b.pentest_ips),
    }
    os.makedirs(os.path.join(outdir, "inputs"), exist_ok=True)
    with open(os.path.join(outdir, "inputs", "environment.json"), "w",
              encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261113)
    ap.add_argument("--out", default=".")
    args = ap.parse_args()
    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)

    b = build_dataset(args.seed)
    inp, ans = b.write(outdir)   # writes inputs/ and answers/ trees

    with open(os.path.join(ans, "predictions_oracle.jsonl"), "w",
              encoding="utf-8") as f:
        for c in b.cases:
            f.write(json.dumps(oracle_prediction(c["gt"]),
                               ensure_ascii=False) + "\n")
    with open(os.path.join(ans, "predictions_dumb.jsonl"), "w",
              encoding="utf-8") as f:
        for c in b.cases:
            f.write(json.dumps(dumb_prediction(c["gt"]),
                               ensure_ascii=False) + "\n")
    write_tz(outdir)
    write_environment(b, outdir)
    meta = write_meta(b, outdir)
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
