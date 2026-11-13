#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Input-only shortcut / leakage checks for cyber-agent-eval (v4).

Stdlib only; NEVER runs a model. Every feature below uses ONLY what an agent
sees (inputs/), and we measure how well a single feature predicts
is_malicious, both in-sample (optimistic) and leave-one-out (LOO, the fair
number), against the majority-class baseline.

Features: case_id ordinal, record position in file, task_type, severity (GT,
diagnostic only), rare-value tokens, vendor alert strength, case start time,
start hour, start day, set of sources, set of event types (EIDs).

Usage: python3 leakcheck.py [dataset_dir] [--json]
"""
import datetime
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gen.build import SOURCE_FILES, XML_SOURCES  # noqa: E402

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
ET.register_namespace("", NS[1:-1])     # serialize records without ns0: prefixes
ICT = datetime.timezone(datetime.timedelta(hours=7))
UTC = datetime.timezone.utc
MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], 1)}
YEAR = 2026
SEV_WORD = {"informational": 0, "information": 0, "info": 0, "unknown": 0,
            "low": 1, "notice": 1, "medium": 2, "moderate": 2, "warning": 2,
            "high": 3, "error": 3, "alert": 3, "critical": 4, "very-high": 4,
            "very high": 4}


# ---------------------------------------------------------------- parsing
def _loc(y, mo, d, h, mi, s, us=0):
    return datetime.datetime(y, mo, d, h, mi, s, us, tzinfo=ICT).timestamp()


def parse_time(src, text):
    """UTC epoch seconds of a record (first line for multi-line records)."""
    try:
        if src in XML_SOURCES:
            m = re.search(r'SystemTime="([^"]+)"', text)
            v = m.group(1).rstrip("Z")
            return datetime.datetime.fromisoformat(v).replace(tzinfo=UTC).timestamp()
        if src in ("auth", "syslog"):
            m = re.match(r"^<\d+>1 (\S+)", text)
            if m:
                return datetime.datetime.fromisoformat(m.group(1)).timestamp()
            m = re.match(r"^(\w{3})\s+(\d+) (\d+):(\d+):(\d+)", text)
            return _loc(YEAR, MON[m.group(1)], int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)))
        if src == "auditd":
            m = re.search(r"audit\((\d+\.\d+):", text)
            return float(m.group(1))
        if src in ("pan_traffic", "pan_threat"):
            m = re.search(r" 1,(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d),", text)
            g = [int(x) for x in m.groups()]
            return _loc(*g)
        if src == "fortigate":
            m = re.search(r"eventtime=(\d+)", text)
            return int(m.group(1)) / 1e9
        if src == "checkpoint":
            m = re.search(r"rt=(\d+)", text)
            return int(m.group(1)) / 1e3
        if src == "f5":
            m = re.search(r'date_time="(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)"', text)
            return _loc(*[int(x) for x in m.groups()])
        if src == "bind":
            m = re.match(r"^(\d\d)-(\w{3})-(\d{4}) (\d\d):(\d\d):(\d\d)\.(\d{3})", text)
            return _loc(int(m.group(3)), MON[m.group(2)], int(m.group(1)),
                        int(m.group(4)), int(m.group(5)), int(m.group(6)),
                        int(m.group(7)) * 1000)
        if src == "windns":
            m = re.match(r"^(\d+)/(\d+)/(\d{4}) (\d+):(\d\d):(\d\d) (AM|PM)", text)
            h = int(m.group(4)) % 12 + (12 if m.group(7) == "PM" else 0)
            return _loc(int(m.group(3)), int(m.group(1)), int(m.group(2)), h,
                        int(m.group(5)), int(m.group(6)))
        if src == "squid":
            return float(text.split()[0])
        if src == "docker":
            v = json.loads(text)["time"]
            return datetime.datetime.fromisoformat(v[:26]).replace(tzinfo=UTC).timestamp()
        if src == "k8s":
            v = json.loads(text)["requestReceivedTimestamp"].rstrip("Z")
            return datetime.datetime.fromisoformat(v).replace(tzinfo=UTC).timestamp()
    except Exception:  # noqa
        return None
    return None


def event_type(src, text):
    """Coarse event-type signature (what an analyst would call 'event ID')."""
    if src in XML_SOURCES:
        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", text)
        return f"{src}:{m.group(1) if m else '?'}"
    if src == "pan_traffic":
        f = text[text.find(" 1,") + 3:].split(",")
        return f"pan_traffic:{f[3]}:{f[29] if len(f) > 29 else '?'}"
    if src == "pan_threat":
        f = text[text.find(" 1,") + 3:].split(",")
        return f"pan_threat:{f[3]}"
    if src == "fortigate":
        t = re.search(r'type="([^"]+)"', text); st = re.search(r'subtype="([^"]+)"', text)
        return f"fortigate:{t.group(1) if t else '?'}:{st.group(1) if st else '?'}"
    if src == "checkpoint":
        m = re.search(r"\|Log\|([^|]+)\|", text)
        return f"checkpoint:{m.group(1) if m else '?'}"
    if src == "f5":
        m = re.search(r'request_status="([^"]+)"', text)
        return f"f5:{m.group(1) if m else '?'}"
    if src == "squid":
        p = text.split()
        return f"squid:{p[3].split('/')[0]}:{p[5]}"
    if src == "auth":
        for k in ("Failed password", "Accepted password", "Accepted publickey",
                  "Invalid user", "session opened", "sudo"):
            if k in text:
                return f"auth:{k}"
        return "auth:other"
    if src == "syslog":
        m = re.match(r"^(?:<\d+>1 \S+ \S+ (\S+)|\w{3}\s+\d+ [\d:]+ \S+ ([^\[:]+))", text)
        prog = (m.group(1) or m.group(2)) if m else "?"
        return f"syslog:{prog}"
    if src == "auditd":
        m = re.search(r'key="([^"]+)"', text)
        return f"auditd:{m.group(1) if m else '?'}"
    if src == "bind":
        m = re.search(r" IN (\w+) ", text)
        return f"bind:{m.group(1) if m else '?'}"
    if src == "windns":
        return "windns:" + ("NXDOMAIN" if "NXDOMAIN" in text else "NOERROR")
    if src == "docker":
        m = re.search(r'\\"level\\":\\"(\w+)', text)
        return f"docker:{m.group(1) if m else '?'}"
    if src == "k8s":
        o = json.loads(text)
        return f"k8s:{o.get('verb')}:{o.get('objectRef', {}).get('subresource', '')}"
    return src


def alert_strength(src, text):
    """Vendor/security-product alert severity carried by the record (0..4),
    or None when the record is not an alert."""
    if src == "pan_threat":
        f = text[text.find(" 1,") + 3:].split(",")
        return SEV_WORD.get(f[33].lower(), 0) if len(f) > 33 else 0
    if src == "f5":
        m = re.search(r'severity="([^"]+)"', text)
        return SEV_WORD.get(m.group(1).lower(), 0) if m else None
    if src == "fortigate":
        if 'type="utm"' not in text:
            return None
        m = re.search(r'crlevel="([^"]+)"', text) or re.search(r'level="([^"]+)"', text)
        return SEV_WORD.get(m.group(1).lower(), 0) if m else 0
    if src == "checkpoint":
        m = re.search(r"\|Log\|[^|]+\|([^|]+)\|", text)
        if not m or m.group(1).lower() == "unknown":
            return None
        return SEV_WORD.get(m.group(1).lower(), 0)
    if src == "application" and "Severity:" in text:
        m = re.search(r"Severity: (\w+)", text)
        return SEV_WORD.get(m.group(1).lower(), 0)
    if src == "powershell":
        m = re.search(r"<Level>(\d)</Level>", text)
        if m and m.group(1) in ("1", "2", "3"):
            return {"1": 4, "2": 3, "3": 2}[m.group(1)]
    return None


def load(base):
    inp = os.path.join(base, "inputs")
    logs = {}
    for src, rel in SOURCE_FILES.items():
        p = os.path.join(inp, "logs", rel)
        if src in XML_SOURCES:
            tree = ET.parse(p).getroot()
            recs = []
            for ev in tree.findall(f"{NS}Event"):
                rid = int(ev.find(f"{NS}System/{NS}EventRecordID").text)
                recs.append((rid, ET.tostring(ev, encoding="unicode")))
            logs[src] = {"kind": "xml", "recs": recs,
                         "by_rid": {r: (i, t) for i, (r, t) in enumerate(recs)}}
        else:
            lines = open(p, encoding="utf-8").read().split("\n")
            while lines and lines[-1] == "":
                lines.pop()
            logs[src] = {"kind": "lines", "recs": lines}
    cases = [json.loads(l) for l in open(os.path.join(inp, "cases_input.jsonl"),
                                         encoding="utf-8") if l.strip()]
    gts = {g["case_id"]: g for g in (json.loads(l) for l in open(
        os.path.join(base, "answers", "ground_truth.jsonl"), encoding="utf-8")
        if l.strip())}
    return logs, cases, gts


def ref_record(logs, r):
    """(position_fraction, text, source) of one input_log_ref."""
    L = logs[r["source"]]
    if L["kind"] == "xml":
        i, t = L["by_rid"][r["event_record_id"]]
        return i / max(1, len(L["recs"]) - 1), t
    i = r["line"] - 1
    return i / max(1, len(L["recs"]) - 1), L["recs"][i]




# ---------------------------------------------------------------- hosts (v4.1)
def _host_maps():
    from gen import assets as A
    fq = {}
    for name, h in A.HOSTS.items():
        fq[name.lower()] = name
        if h.get("fqdn"):
            fq[h["fqdn"].lower()] = name
    ip2 = {h["ip"]: name for name, h in A.HOSTS.items() if h.get("ip")}
    return fq, ip2


_IP_RE = re.compile(r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
_NAME_RE = re.compile(r"\b(wks-[a-z]+-\d+|srv-[a-z]+\d+|jump01|vulnscan01|lnx-[a-z]+\d+|k8s-[a-z]+\d+)\b", re.I)


def record_hosts(src, text, maps):
    fq, ip2 = maps
    hs = set()
    if src in XML_SOURCES:
        m = re.search(r"<Computer>([^<]+)</Computer>", text)
        if m and m.group(1).lower() in fq:
            hs.add(fq[m.group(1).lower()])
        return hs
    for ip in _IP_RE.findall(text):
        if ip in ip2:
            hs.add(ip2[ip])
    for nm in _NAME_RE.findall(text):
        if nm.lower() in fq:
            hs.add(fq[nm.lower()])
    return hs


def host_stats(logs, cases):
    """records per host (all logs) and case-referenced records per host."""
    maps = _host_maps()
    vol = Counter()
    for src, L in logs.items():
        recs = [t for _, t in L["recs"]] if L["kind"] == "xml" else L["recs"]
        for t in recs:
            for h in record_hosts(src, t, maps):
                vol[h] += 1
    case_hosts = []
    refvol = Counter()
    seen = set()
    for c in cases:
        hs = set()
        for r in c["input_log_refs"]:
            _, t = ref_record(logs, r)
            rh = record_hosts(r["source"], t, maps)
            hs |= rh
            key = (r["source"], r.get("event_record_id") or r.get("line"))
            if key not in seen:
                seen.add(key)
                for h in rh:
                    refvol[h] += 1
        case_hosts.append(hs)
    return vol, refvol, case_hosts

# ---------------------------------------------------------------- classifiers
def thr_fit(vals, ys):
    best = (-1, None, None)
    n = len(ys)
    for t in sorted(set(vals)):
        for pol in (1, -1):
            acc = sum(1 for v, y in zip(vals, ys)
                      if (1 if pol * v >= pol * t else 0) == y) / n
            if acc > best[0]:
                best = (acc, t, pol)
    maj = 1 if sum(ys) * 2 >= n else 0
    base = max(sum(ys), n - sum(ys)) / n
    if base >= best[0]:
        return base, None, maj
    return best


def thr_in(vals, ys):
    return thr_fit(vals, ys)[0]


def thr_loo(vals, ys):
    ok = 0
    for i in range(len(ys)):
        v2 = vals[:i] + vals[i + 1:]; y2 = ys[:i] + ys[i + 1:]
        acc, t, pol = thr_fit(v2, y2)
        pred = pol if t is None else (1 if pol * vals[i] >= pol * t else 0)
        ok += (pred == ys[i])
    return ok / len(ys)


def maj_in(keys, ys):
    g = defaultdict(list)
    for k, y in zip(keys, ys):
        g[k].append(y)
    return sum(max(sum(v), len(v) - sum(v)) for v in g.values()) / len(ys)


def maj_loo(keys, ys):
    ok = 0
    tot1 = sum(ys)
    g = defaultdict(list)
    for k, y in zip(keys, ys):
        g[k].append(y)
    for k, y in zip(keys, ys):
        others = list(g[k]); others.remove(y)
        if others:
            s1 = sum(others); s0 = len(others) - s1
            pred = 1 if s1 > s0 else 0 if s0 > s1 else (1 if (tot1 - y) * 2 >= len(ys) - 1 else 0)
        else:
            pred = 1 if (tot1 - y) * 2 >= len(ys) - 1 else 0
        ok += (pred == y)
    return ok / len(ys)


def token_scores(case_tokens, ys, loo):
    mal, ben = Counter(), Counter()
    for toks, y in zip(case_tokens, ys):
        for t in toks:
            (mal if y else ben)[t] += 1
    ok = 0
    for toks, y in zip(case_tokens, ys):
        s = 0
        for t in toks:
            m, b_ = mal[t], ben[t]
            if loo:
                if y: m -= 1
                else: b_ -= 1
            s += m - b_
        ok += ((1 if s > 0 else 0) == y)
    return ok / len(ys)


# ---------------------------------------------------------------- main
LIMITS = {   # feature -> (kind, max allowed LOO gap over baseline)
    "case_id_ordinal": ("structural", 0.10),
    "record_position": ("structural", 0.10),
    "start_time": ("time", 0.10),
    "start_hour": ("time", 0.10),
    "start_day": ("time", 0.10),
    "source_set": ("content-shape", 0.10),
    "event_type_set": ("content-shape", 0.10),
    "host_set": ("host", 0.10),
    "host_wks_number": ("host", 0.10),
    "host_event_volume": ("host", 0.10),
    "host_case_share": ("host", 0.10),
    "task_type": ("semantic", 0.10),
    "alert_strength": ("vendor-alert", None),   # absolute cap below
    "rare_value_tokens": ("semantic", None),
    "severity_GT": ("answer-diagnostic", None),
}
ALERT_ABS_MAX = 0.75


def run(base):
    logs, cases, gts = load(base)
    ids = [c["case_id"] for c in cases]
    y = [1 if gts[i]["is_malicious"] else 0 for i in ids]
    n = len(y)
    base_acc = max(sum(y), n - sum(y)) / n
    feats = defaultdict(list)
    tok_re = re.compile(r"[a-z0-9_.:\\-]{4,}")
    toks_all = []
    for c in cases:
        pos, times, srcs, ets, al, toks = [], [], set(), set(), [], set()
        for r in c["input_log_refs"]:
            p, t = ref_record(logs, r)
            pos.append(p)
            tt = parse_time(r["source"], t)
            if tt is not None:
                times.append(tt)
            srcs.add(r["source"])
            ets.add(event_type(r["source"], t))
            a = alert_strength(r["source"], t)
            if a is not None:
                al.append(a)
            toks |= set(tok_re.findall(t.lower()))
        st = min(times)
        loc = datetime.datetime.fromtimestamp(st, ICT)
        feats["case_id_ordinal"].append(int(c["case_id"].split("-")[1]))
        feats["record_position"].append(min(pos))
        feats["start_time"].append(st)
        feats["start_hour"].append(loc.hour + loc.minute / 60.0)
        feats["start_day"].append(loc.strftime("%Y-%m-%d"))
        feats["source_set"].append(tuple(sorted(srcs)))
        feats["event_type_set"].append(tuple(sorted(ets)))
        feats["task_type"].append(c["task_type"])
        feats["alert_strength"].append(max(al) if al else -1)
        feats["severity_GT"].append(gts[c["case_id"]]["severity"])
        toks_all.append(toks)
    vol, refvol, case_hosts = host_stats(logs, cases)
    for hs in case_hosts:
        feats["host_set"].append(tuple(sorted(hs)))
        nums = [int(h.split("-")[-1]) for h in hs if h.startswith("WKS-GEN-")]
        feats["host_wks_number"].append(max(nums) if nums else -1)
        feats["host_event_volume"].append(min((vol[h] for h in hs), default=0))
        feats["host_case_share"].append(max((refvol[h] / max(1, vol[h]) for h in hs),
                                            default=0.0))
    rows = []
    for name in ("case_id_ordinal", "record_position", "start_time",
                 "start_hour", "alert_strength", "host_wks_number",
                 "host_event_volume", "host_case_share"):
        v = feats[name]
        rows.append((name, thr_in(v, y), thr_loo(v, y)))
    for name in ("start_day", "source_set", "event_type_set", "task_type",
                 "severity_GT", "host_set"):
        v = feats[name]
        rows.append((name, maj_in(v, y), maj_loo(v, y)))
    rows.append(("rare_value_tokens", token_scores(toks_all, y, False),
                 token_scores(toks_all, y, True)))
    order = list(LIMITS)
    rows.sort(key=lambda r: order.index(r[0]))
    fails = []
    for name, ins, loo in rows:
        kind, lim = LIMITS[name]
        if lim is not None and loo - base_acc > lim:
            fails.append(f"LEAK {name}: LOO {loo:.3f} > baseline {base_acc:.3f} + {lim:.2f}")
    al_row = [r for r in rows if r[0] == "alert_strength"][0]
    if al_row[1] > ALERT_ABS_MAX:
        fails.append(f"LEAK alert_strength: in-sample {al_row[1]:.3f} > {ALERT_ABS_MAX}")
    sev_row = [r for r in rows if r[0] == "severity_GT"][0]
    if sev_row[1] >= 0.97:
        fails.append(f"LEAK severity_GT {sev_row[1]:.3f} ~ determines label")
    al_x = Counter((feats["alert_strength"][i], "mal" if y[i] else "ben") for i in range(n))
    hours = Counter((int(feats["start_hour"][i]) // 6, "mal" if y[i] else "ben") for i in range(n))
    days = Counter((feats["start_day"][i], "mal" if y[i] else "ben") for i in range(n))
    return {"n": n, "malicious": sum(y), "baseline": base_acc,
            "rows": rows, "fails": fails,
            "alert_x_label": {f"{k[0]}|{k[1]}": v for k, v in sorted(al_x.items())},
            "hour6_x_label": {f"{k[0]*6:02d}-{k[0]*6+5:02d}h|{k[1]}": v for k, v in sorted(hours.items())},
            "day_x_label": {f"{k[0]}|{k[1]}": v for k, v in sorted(days.items())}}


def print_report(res):
    print("LEAK-CHECK (single input feature -> is_malicious; n=%d, malicious=%d, "
          "majority baseline %.3f)" % (res["n"], res["malicious"], res["baseline"]))
    print("  %-20s %-18s %9s %9s %8s  %s" % ("feature", "kind", "in-sample",
                                              "LOO", "LOO-gap", "rule"))
    for name, ins, loo in res["rows"]:
        kind, lim = LIMITS[name]
        rule = (f"fail if gap>{lim:.2f}" if lim is not None else
                f"fail if in-sample>{ALERT_ABS_MAX}" if name == "alert_strength" else
                "fail if in-sample>=0.97" if name == "severity_GT" else "report")
        print("  %-20s %-18s %9.3f %9.3f %+8.3f  %s" % (
            name, kind, ins, loo, loo - res["baseline"], rule))
    print("  alert_strength x label (-1=no vendor alert, 0 info .. 4 critical):",
          res["alert_x_label"])
    print("  start day x label:", res["day_x_label"])
    print("  start hour(6h) x label:", res["hour6_x_label"])


if __name__ == "__main__":
    base = HERE
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        base = os.path.abspath(args[0])
    res = run(base)
    if "--json" in sys.argv:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print_report(res)
        for f in res["fails"]:
            print("  FAIL", f)
    sys.exit(1 if res["fails"] else 0)


# ================================================================ realism
SECOND_RES = {"auth", "syslog", "pan_traffic", "pan_threat", "f5", "windns"}
ROOT_PARENTS = {"system", "smss.exe", "wininit.exe", "services.exe",
                "winlogon.exe", "lsass.exe", "csrss.exe", "registry"}


def _data(ev):
    d = {}
    for x in ev.iter(f"{NS}Data"):
        d[x.get("Name")] = x.text or ""
    return d


def integrity(base):
    """v4 realism regression guards. Returns (errors, stats)."""
    logs, cases, gts = load(base)
    errs, st = [], {}
    # ---- Sysmon process tree
    guid_id = {}
    eid1 = {}
    lsass_pid = defaultdict(set)
    nonguid_missing = 0
    nonguid_total = 0
    for rid, txt in logs["sysmon"]["recs"]:
        ev = ET.fromstring(txt)
        eid = ev.find(f"{NS}System/{NS}EventID").text
        host = ev.find(f"{NS}System/{NS}Computer").text.lower()
        sec = ev.find(f"{NS}System/{NS}Security")
        if sec is None or not sec.get("UserID"):
            errs.append(f"sysmon RID {rid}: missing Security UserID")
        d = _data(ev)
        pairs = []
        if eid == "10":
            pairs = [(d.get("SourceProcessGUID"), d.get("SourceProcessId"), d.get("SourceImage")),
                     (d.get("TargetProcessGUID"), d.get("TargetProcessId"), d.get("TargetImage"))]
            if d.get("TargetImage", "").lower().endswith("\\lsass.exe"):
                lsass_pid[host].add(d.get("TargetProcessId"))
        elif d.get("ProcessGuid"):
            pairs = [(d["ProcessGuid"], d.get("ProcessId"), d.get("Image"))]
        if eid == "1":
            eid1[(host, d["ProcessGuid"])] = d
            if d.get("Image", "").lower().endswith("\\lsass.exe"):
                lsass_pid[host].add(d.get("ProcessId"))
        for g, pid, img in pairs:
            if not g:
                continue
            key = (host, g)
            val = (pid, (img or "").lower())
            if key in guid_id and guid_id[key] != val:
                errs.append(f"sysmon GUID {g} on {host} maps to {guid_id[key]} and {val}")
            guid_id[key] = val
    for (host, g), (pid, img) in guid_id.items():
        if img.endswith("\\lsass.exe") or img == "system":
            continue
        nonguid_total += 1
        if (host, g) not in eid1:
            nonguid_missing += 1
    par_ok = par_tot = 0
    for (host, g), d in eid1.items():
        par_tot += 1
        pg = d.get("ParentProcessGuid")
        pimg = d.get("ParentImage", "").lower().split("\\")[-1]
        if (host, pg) in eid1 or pimg in ROOT_PARENTS:
            par_ok += 1
            if (host, pg) in eid1:
                pd = eid1[(host, pg)]
                if pd.get("ProcessId") != d.get("ParentProcessId"):
                    errs.append(f"sysmon parent PID mismatch {g} on {host}")
    multi = {h: sorted(v) for h, v in lsass_pid.items() if len(v) > 1}
    if multi:
        errs.append(f"lsass PID not constant per host: {multi}")
    st["sysmon_guids"] = len(guid_id)
    st["sysmon_guid_without_eid1"] = nonguid_missing
    st["sysmon_eid1_parent_resolved_pct"] = round(100.0 * par_ok / max(1, par_tot), 2)
    if nonguid_missing:
        errs.append(f"{nonguid_missing} Sysmon ProcessGuids never created by EID 1")
    if par_ok < par_tot:
        errs.append(f"{par_tot - par_ok} EID1 ParentProcessGuid not resolvable")
    # ---- 7045 UserID
    for rid, txt in logs["system"]["recs"]:
        if "<EventID>7045</EventID>" in txt or ">7045</EventID>" in txt:
            if 'UserID="' not in txt:
                errs.append(f"System 7045 RID {rid}: missing UserID")
    # ---- NAT: PA-CORE outbound allow vs FGT-EDGE twin
    fg = {}
    for line in logs["fortigate"]["recs"]:
        if 'devname="FGT-EDGE-01"' not in line or 'type="traffic"' not in line:
            continue
        kv = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', line))
        kv = {k: v.strip('"') for k, v in kv.items()}
        fg[(kv["srcip"], kv["srcport"], kv["dstip"], kv["dstport"])] = kv
    pan_out = matched = 0
    nat_bad = 0
    for line in logs["pan_traffic"]["recs"]:
        f = line[line.find(" 1,") + 3:].split(",")
        if f[1] != "FAKE0000PA01" and "PA-CORE" not in line[:40]:
            pass
        dev = line.split()[3] if len(line.split()) > 3 else ""
        if dev != "PA-CORE" or f[29] != "allow":
            continue
        if f[8] != "0.0.0.0" or f[25] != "0":
            nat_bad += 1
        src, dst, sport, dport = f[6], f[7], f[23], f[24]
        if dst.startswith("10."):
            continue
        pan_out += 1
        tw = fg.get((src, sport, dst, dport))
        if tw and tw.get("transip") == "203.0.113.2" and \
                tw.get("sentbyte") == f[31] and tw.get("rcvdbyte") == f[32] and \
                tw.get("duration") == f[35]:
            matched += 1
    st["pan_core_outbound_flows"] = pan_out
    st["pan_fgt_twin_matched"] = matched
    if matched != pan_out:
        errs.append(f"NAT/twin mismatch: {pan_out - matched}/{pan_out} PA-CORE "
                    f"outbound flows lack an identical FGT-EDGE SNAT record")
    if nat_bad:
        errs.append(f"{nat_bad} PA-CORE records claim NAT (PA does not NAT in v4)")
    snat_bad = sum(1 for v in fg.values() if v.get("trandisp") == "snat"
                   and v.get("transip") != "203.0.113.2")
    if snat_bad:
        errs.append(f"{snat_bad} FGT-EDGE snat records with wrong transip")
    # ---- v4.1: DMZ inbound passes FGT-EDGE (DNAT twin)
    dn = {}
    for v in fg.values():
        if v.get("trandisp") == "dnat":
            dn[(v["srcip"], v["srcport"], v["dstport"])] = v
    dmz_in = dmz_ok = 0
    for line in logs["pan_traffic"]["recs"]:
        f = line[line.find(" 1,") + 3:].split(",")
        dev = line.split()[3] if len(line.split()) > 3 else ""
        if dev != "PA-DMZ" or f[6].startswith("10.") or not f[7].startswith("10.20.40."):
            continue
        dmz_in += 1
        tw = dn.get((f[6], f[23], f[24]))
        if tw and tw.get("tranip") == f[7] and tw.get("dstip", "").startswith("203.0.113."):
            dmz_ok += 1
    st["pa_dmz_inbound_flows"] = dmz_in
    st["pa_dmz_fgt_dnat_twin_matched"] = dmz_ok
    if dmz_ok != dmz_in:
        errs.append(f"DMZ inbound: {dmz_in - dmz_ok}/{dmz_in} PA-DMZ flows lack an FGT-EDGE DNAT twin")
    # ---- v4.2: FortiGate interface role must follow the interface
    exp_role = {"wan1": "wan", "wan2": "wan", "dmz": "dmz"}
    role_bad = fgt_lines = 0
    for line in logs["fortigate"]["recs"]:
        kv = dict(re.findall(r'(\w+)="?([^"\s]*)"?', line))
        for side in ("src", "dst"):
            intf, role = kv.get(side + "intf"), kv.get(side + "intfrole")
            if intf is None:
                continue
            fgt_lines += side == "src"
            if role != exp_role.get(intf, "lan"):
                role_bad += 1
    st["fgt_intfrole_mismatch"] = role_bad
    if role_bad:
        errs.append(f"FortiGate: {role_bad} srcintf/dstintf with a wrong *intfrole")
    # ---- v4.2: internet logons on DMZ hosts must have the inbound flow
    #      (PA-DMZ allow, same client IP + source port = IpPort)
    pa_dmz_allow = set()
    pa_dmz_pairs = set()
    for line in logs["pan_traffic"]["recs"]:
        f = line[line.find(" 1,") + 3:].split(",")
        dev = line.split()[3] if len(line.split()) > 3 else ""
        if dev == "PA-DMZ" and f[29] == "allow":
            pa_dmz_allow.add((f[6], f[7], f[23]))
            pa_dmz_pairs.add((f[6], f[7]))
    _fq, _ip2 = _host_maps()
    from gen import assets as _A
    dmz_auth = dmz_auth_ok = 0
    for rid, txt in logs["security"]["recs"]:
        if ">4624</EventID>" not in txt and ">4625</EventID>" not in txt:
            continue
        ev = ET.fromstring(txt)
        hname = _fq.get(ev.find(f"{NS}System/{NS}Computer").text.lower())
        hip = _A.HOSTS.get(hname, {}).get("ip", "")
        if not hip.startswith("10.20.40."):
            continue
        d = _data(ev)
        ipa = d.get("IpAddress", "-")
        if ipa in ("-", "127.0.0.1", "::1") or ipa.startswith("10."):
            continue
        dmz_auth += 1
        if (ipa, hip, d.get("IpPort", "")) in pa_dmz_allow:
            dmz_auth_ok += 1
    st["dmz_internet_logons"] = dmz_auth
    st["dmz_internet_logons_with_flow"] = dmz_auth_ok
    if dmz_auth_ok != dmz_auth:
        errs.append(f"DMZ: {dmz_auth - dmz_auth_ok}/{dmz_auth} internet 4624/4625 on DMZ hosts "
                    f"lack a PA-DMZ flow (client IP + port)")
    # ---- v4.2: every F5 request (pool member known) has its client in PA-DMZ
    f5_n = f5_ok = 0
    for line in logs["f5"]["recs"]:
        kv = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if "dest_ip" not in kv:
            continue
        f5_n += 1
        if (kv.get("ip_client"), kv["dest_ip"]) in pa_dmz_pairs:
            f5_ok += 1
    st["f5_requests"] = f5_n
    st["f5_client_seen_in_pa_dmz"] = f5_ok
    if f5_ok != f5_n:
        errs.append(f"F5: {f5_n - f5_ok}/{f5_n} requests whose client never appears in PA-DMZ")
    # ---- v4.1: logon sessions (one LogonId per session, subjects resolve)
    SPECIAL = {"0x0", "0x3e7", "0x3e5", "0x3e4"}
    sessions = {}
    dup_lid = 0
    subj = []
    for rid, txt in logs["security"]["recs"]:
        ev = ET.fromstring(txt)
        eid = ev.find(f"{NS}System/{NS}EventID").text
        host = ev.find(f"{NS}System/{NS}Computer").text.lower()
        d = _data(ev)
        t = parse_time("security", txt)
        if eid == "4624":
            k = (host, d["TargetLogonId"])
            if k in sessions:
                dup_lid += 1
            sessions[k] = [d["TargetUserName"].lower(), t, None]
        elif eid == "4634":
            k = (host, d["TargetLogonId"])
            if k in sessions:
                sessions[k][2] = t
        sl = d.get("SubjectLogonId")
        if sl and sl not in SPECIAL and eid != "4634":
            subj.append((host, sl, d.get("SubjectUserName", "").lower(), t, f"security {eid} RID {rid}"))
    for (host, g), d in eid1.items():
        lid = d.get("LogonId")
        if lid and lid not in SPECIAL:
            u = d.get("User", "").split("\\")[-1].lower()
            tt = datetime.datetime.strptime(d["UtcTime"], "%Y-%m-%d %H:%M:%S.%f").replace(
                tzinfo=datetime.timezone.utc).timestamp()
            subj.append((host, lid, u, tt, f"sysmon EID1 {g}"))
    bad_subj = 0
    for host, lid, u, t, where in subj:
        s_ = sessions.get((host, lid))
        ok = s_ is not None and s_[0] == u
        if ok and t is not None:
            ok = (s_[1] - 1 <= t) and (s_[2] is None or t <= s_[2] + 1)
        if not ok:
            bad_subj += 1
            if bad_subj <= 5:
                errs.append(f"LogonId {lid} on {host} ({where}, user {u}) has no matching open 4624 session")
    st["security_logon_sessions"] = len(sessions)
    st["subject_logonids_checked"] = len(subj)
    st["subject_logonids_unresolved"] = bad_subj
    if dup_lid:
        errs.append(f"{dup_lid} 4624 TargetLogonIds reused on the same host")
    if bad_subj > 5:
        errs.append(f"... {bad_subj} unresolved LogonIds in total")
    # ---- v4.1: process timeline (parent created before child)
    def _ut(x):
        return datetime.datetime.strptime(x, "%Y-%m-%d %H:%M:%S.%f")
    tl_bad = 0
    for (host, g), d in eid1.items():
        pd = eid1.get((host, d.get("ParentProcessGuid")))
        if pd and _ut(pd["UtcTime"]) > _ut(d["UtcTime"]):
            tl_bad += 1
            if tl_bad <= 5:
                errs.append(f"process {d.get('Image')} on {host} created before its parent {pd.get('Image')}")
    ev_bad = 0
    for rid, txt in logs["sysmon"]["recs"]:
        ev = ET.fromstring(txt)
        eid = ev.find(f"{NS}System/{NS}EventID").text
        if eid == "1":
            continue
        host = ev.find(f"{NS}System/{NS}Computer").text.lower()
        d = _data(ev)
        g = d.get("ProcessGuid") or d.get("SourceProcessGuid")
        c = eid1.get((host, g))
        if c and d.get("UtcTime") and _ut(d["UtcTime"]) < _ut(c["UtcTime"]):
            ev_bad += 1
            if ev_bad <= 5:
                errs.append(f"sysmon EID{eid} RID {rid} precedes creation of its process {c.get('Image')}")
    st["eid1_created_before_parent"] = tl_bad
    st["sysmon_event_before_process_start"] = ev_bad
    if tl_bad > 5 or ev_bad > 5:
        errs.append(f"timeline: {tl_bad} child-before-parent, {ev_bad} event-before-process")
    # ---- v4.1: host telemetry spread / case concentration
    vol, refvol, _ = host_stats(logs, cases)
    from gen import assets as A
    win = sorted(h for h, v in A.HOSTS.items() if v.get("os") == "windows")
    st["windows_hosts"] = len(win)
    st["windows_host_min_records"] = min(vol[h] for h in win)
    shares = {h: round(refvol[h] / vol[h], 3) for h in win if vol[h]}
    st["max_host_case_share"] = max(shares.values())
    st["max_host_case_share_host"] = max(shares, key=shares.get)
    quiet = [h for h in win if vol[h] < 50]
    if quiet:
        errs.append(f"Windows hosts with <50 records of telemetry: {quiet}")
    hot = {h: v for h, v in shares.items() if v > 0.10}
    if hot:
        errs.append(f"hosts where case evidence is >10% of all their records: {hot}")
    # ---- signal timestamps
    ref_times, dup_cases, round5 = [], 0, 0
    refset = defaultdict(set)
    case_types = Counter()
    for c in cases:
        ts = []
        for r in c["input_log_refs"]:
            _, t = ref_record(logs, r)
            tt = parse_time(r["source"], t)
            key = r.get("event_record_id") or r.get("line")
            refset[r["source"]].add(key)
            if tt is not None:
                ts.append(tt)
                x = datetime.datetime.fromtimestamp(tt, ICT)
                if x.second == 0 and x.minute % 5 == 0 and x.microsecond == 0:
                    round5 += 1
            case_types[event_type(r["source"], t)] += 1
        ref_times += ts
        # only sources with sub-second resolution can be compared at ms level
        ms = [round(parse_time(r["source"], ref_record(logs, r)[1]), 3)
              for r in c["input_log_refs"] if r["source"] not in SECOND_RES]
        if len(set(ms)) < len(ms):
            dup_cases += 1
    st["signal_refs"] = len(ref_times)
    st["signal_on_5min_boundary_pct"] = round(100.0 * round5 / max(1, len(ref_times)), 2)
    st["cases_with_duplicate_ref_timestamp"] = dup_cases
    if dup_cases:
        errs.append(f"{dup_cases} cases have evidence records sharing one ms timestamp")
    if round5 / max(1, len(ref_times)) > 0.03:
        errs.append(f"{round5} signal records sit exactly on a 5-minute boundary")
    # ---- case-only event types (exist only inside case evidence)
    noise_types = Counter()
    for src, L in logs.items():
        keys = refset.get(src, set())
        if L["kind"] == "xml":
            for rid, t in L["recs"]:
                if rid not in keys:
                    noise_types[event_type(src, t)] += 1
        else:
            for i, t in enumerate(L["recs"], 1):
                if i not in keys:
                    noise_types[event_type(src, t)] += 1
    only = sorted(k for k in case_types if noise_types[k] == 0)
    st["event_types_in_cases"] = len(case_types)
    st["case_only_event_types"] = only
    if only:
        errs.append(f"event types that appear only in case evidence: {only}")
    return errs, st
