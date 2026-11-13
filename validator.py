#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validator for cyber-agent-eval v2 (offline, stdlib only; NEVER runs a model).

Checks:
  1. Schema: inputs validate vs schema/case_input.schema.json; ground truth vs
     schema/ground_truth.schema.json; campaigns vs schema/campaign.schema.json.
  2. De-leak: inputs/cases_input.jsonl must NOT contain any answer fields.
  3. Per-source native-format parse checks on every inputs/logs/<source> file.
  4. Every input_log_ref resolves to a real record (line / EventRecordID).
  5. IoC-in-log: every IoC in ground truth must appear in its referenced records.
  6. Safety: IoC IPs RFC5737/RFC1918, domains allowed TLDs, hashes valid hex;
     no forbidden names; every IPv4 in any log is a safe reserved/private addr.
  7. ATT&CK: every technique id is in the verified whitelist.
  8. Host/IP map: single consistent map (no IP assigned to two hosts).
  9. Campaign/stage cross-references consistent.
 10. Benign events are >= 90% of all log events (dataset_meta.json).

Exit 0 = pass, 1 = failures.
"""
import json
import os
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gen import entities as ent
from gen import attack
from gen import assets as A
from gen.build import SOURCE_FILES, XML_SOURCES

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
ANSWER_FIELDS = {"severity", "is_malicious", "is_fp_trap", "fp_trap_kind",
                 "techniques", "iocs", "correlation_keys", "campaign_id",
                 "campaign_stage", "rationale_th", "expected", "gt"}


def _norm(s):
    return urllib.parse.unquote(str(s)).lower()


def _majority_acc(keys, labels):
    """Accuracy of predicting each group's majority label (optimistic/train=test)."""
    from collections import defaultdict
    grp = defaultdict(list)
    for k, y in zip(keys, labels):
        grp[k].append(y)
    correct = 0
    for k, ys in grp.items():
        maj = 1 if sum(ys) * 2 >= len(ys) else 0
        correct += sum(1 for y in ys if y == maj)
    return correct / len(labels) if labels else 0.0


def _best_threshold_acc(values, labels):
    """Best accuracy of a single-threshold rule on a numeric feature, trying
    both polarities (train=test, optimistic upper bound on leakage)."""
    n = len(labels)
    if n == 0:
        return 0.0
    cand = sorted(set(values))
    best = max(sum(labels), n - sum(labels)) / n   # majority fallback
    for t in cand:
        for pol in (1, -1):
            pred = [1 if (pol * v >= pol * t) else 0 for v in values]
            acc = sum(1 for p, y in zip(pred, labels) if p == y) / n
            best = max(best, acc)
    return best


def _majority_baseline(labels):
    n = len(labels)
    return max(sum(labels), n - sum(labels)) / n if n else 0.0


# ---------------- minimal JSON Schema subset validator ----------------

def _type_ok(value, typ):
    if typ == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if typ == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if typ == "boolean":
        return isinstance(value, bool)
    mapping = {"object": dict, "array": list, "string": str,
               "null": type(None)}
    return isinstance(value, mapping[typ])


def validate_schema(value, schema, path, errors):
    typ = schema.get("type")
    if typ is not None:
        types = typ if isinstance(typ, list) else [typ]
        if not any(_type_ok(value, t) for t in types):
            errors.append(f"{path}: expected {types}, got {type(value).__name__}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum {schema['enum']}")
    if "pattern" in schema and isinstance(value, str):
        if not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} !~ /{schema['pattern']}/")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required '{req}'")
        if schema.get("additionalProperties") is False:
            for k in value:
                if k not in props:
                    errors.append(f"{path}: unexpected property '{k}'")
        for k, v in value.items():
            if k in props:
                validate_schema(v, props[k], f"{path}.{k}", errors)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
        if "items" in schema:
            for i, item in enumerate(value):
                validate_schema(item, schema["items"], f"{path}[{i}]", errors)


# ---------------- per-source format parsers ----------------

def _strip_syslog(line):
    m = re.match(r"^<\d+>(\d\s+)?", line)
    return line[m.end():] if m else line


def check_pan(line, kind):
    body = _strip_syslog(line)
    idx = body.find(" 1,")
    assert idx != -1, "no PAN CSV marker"
    fields = body[idx + 3:].split(",")
    assert len(fields) >= 30, f"PAN {kind} too few fields ({len(fields)})"
    assert fields[2] == kind.upper(), f"PAN type {fields[2]} != {kind.upper()}"


def check_fortigate(line):
    for key in ("date=", "time=", 'type="', "srcip=", "dstip=", "eventtime=",
                "tz="):
        assert key in line, f"FortiGate missing {key}"


def check_checkpoint(line):
    assert "CEF:0|Check Point|" in line, "CheckPoint missing CEF header"
    assert "act=" in line and "rt=" in line, "CheckPoint missing act=/rt="


def check_f5(line):
    assert "ASM:" in line, "F5 missing ASM:"
    assert "support_id=" in line, "F5 missing support_id"


def check_bind(line):
    assert "client @" in line and "query:" in line, "BIND malformed"


def check_windns(line):
    assert "PACKET" in line and ("Rcv" in line or "Snd" in line), "WinDNS bad"


def check_squid(line):
    parts = line.split()
    assert len(parts) >= 10, f"Squid too few fields ({len(parts)})"
    float(parts[0])


def check_docker(line):
    o = json.loads(line)
    for k in ("log", "stream", "time"):
        assert k in o, f"docker missing {k}"


def check_k8s(line):
    o = json.loads(line)
    assert o.get("kind") == "Event" and o.get("apiVersion") == "audit.k8s.io/v1"
    assert "verb" in o and "user" in o


def check_syslog_line(line):
    assert len(line) > 10, "syslog line too short"


def check_auditd(line):
    assert "msg=audit(" in line and line.startswith("type="), "auditd malformed"


LINE_CHECKERS = {
    "pan_traffic": lambda l: check_pan(l, "traffic"),
    "pan_threat": lambda l: check_pan(l, "threat"),
    "fortigate": check_fortigate, "checkpoint": check_checkpoint,
    "f5": check_f5, "bind": check_bind, "windns": check_windns,
    "squid": check_squid, "docker": check_docker, "k8s": check_k8s,
    "auth": check_syslog_line, "syslog": check_syslog_line,
    "auditd": check_auditd,
}
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def main():
    base = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else HERE
    errors, warnings = [], []
    inp = os.path.join(base, "inputs")
    ans = os.path.join(base, "answers")
    logsdir = os.path.join(inp, "logs")

    def sload(name):
        return json.load(open(os.path.join(base, "schema", name),
                              encoding="utf-8"))
    ci_schema = sload("case_input.schema.json")
    gt_schema = sload("ground_truth.schema.json")
    camp_schema = sload("campaign.schema.json")

    inputs = [json.loads(l) for l in
              open(os.path.join(inp, "cases_input.jsonl"), encoding="utf-8")
              if l.strip()]
    gts = [json.loads(l) for l in
           open(os.path.join(ans, "ground_truth.jsonl"), encoding="utf-8")
           if l.strip()]
    campaigns = json.load(open(os.path.join(ans, "campaigns.json"),
                               encoding="utf-8"))
    gt_by_id = {g["case_id"]: g for g in gts}

    # 1. schema
    for c in inputs:
        validate_schema(c, ci_schema, c.get("case_id", "?"), errors)
    for g in gts:
        validate_schema(g, gt_schema, g.get("case_id", "?"), errors)
    for cp in campaigns:
        validate_schema(cp, camp_schema, cp.get("campaign_id", "?"), errors)

    # 2. de-leak: inputs must not carry answer fields
    for c in inputs:
        for k in c:
            if k in ANSWER_FIELDS:
                errors.append(f"{c.get('case_id')}: input leaks answer field '{k}'")

    # 3+4. parse logs, index records
    index = {}   # source -> ('xml', {rid: text}) | ('lines', [lines])
    for src, rel in SOURCE_FILES.items():
        path = os.path.join(logsdir, rel)
        if not os.path.exists(path):
            errors.append(f"missing log file {rel}")
            continue
        if src in XML_SOURCES:
            raw = open(path, encoding="utf-8").read()
            try:
                tree = ET.fromstring(raw)
            except ET.ParseError as ex:
                errors.append(f"{rel}: XML parse error {ex}")
                continue
            rid_text = {}
            for ev in tree.findall(f"{NS}Event"):
                rid_el = ev.find(f"{NS}System/{NS}EventRecordID")
                if rid_el is not None:
                    rid_text[int(rid_el.text)] = ET.tostring(
                        ev, encoding="unicode")
            index[src] = ("xml", rid_text)
            if not rid_text:
                warnings.append(f"{rel}: no <Event> records")
        else:
            lines = open(path, encoding="utf-8").read().split("\n")
            while lines and lines[-1] == "":
                lines.pop()
            checker = LINE_CHECKERS.get(src)
            for i, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                try:
                    checker(line)
                except Exception as ex:  # noqa
                    errors.append(f"{rel}:{i}: format check failed: {ex}")
            index[src] = ("lines", lines)

    def ref_text(refs):
        parts = []
        for r in refs:
            src = r["source"]
            if src not in index:
                continue
            kind, data = index[src]
            if kind == "xml":
                t = data.get(r.get("event_record_id"))
                if t:
                    parts.append(t)
            else:
                ln = r.get("line")
                if ln and 1 <= ln <= len(data):
                    for i in range(ln - 1, min(len(data), ln + 6)):
                        parts.append(data[i])
        return _norm("\n".join(parts))

    # 4. ref resolution
    for c in inputs:
        for r in c["input_log_refs"]:
            src = r["source"]
            if src not in index:
                errors.append(f"{c['case_id']}: ref to unknown source {src}")
                continue
            kind, data = index[src]
            if kind == "xml":
                if r.get("event_record_id") not in data:
                    errors.append(f"{c['case_id']}: EventRecordID "
                                  f"{r.get('event_record_id')} not in {src}")
            else:
                ln = r.get("line")
                if ln is None or not (1 <= ln <= len(data)):
                    errors.append(f"{c['case_id']}: line {ln} out of range {src}")

    # 5. IoC-in-log
    inp_by_id = {c["case_id"]: c for c in inputs}
    for g in gts:
        ci = inp_by_id.get(g["case_id"])
        if not ci:
            errors.append(f"{g['case_id']}: no matching input")
            continue
        blob = ref_text(ci["input_log_refs"])
        for io in g["iocs"]:
            if _norm(io["value"]) not in blob:
                errors.append(f"{g['case_id']}: IoC {io['type']}={io['value']!r} "
                              f"not present in referenced logs")

    # 6. safety (iocs)
    for g in gts:
        for io in g["iocs"]:
            t, v = io["type"], io["value"]
            if t == "ip" and not ent.ip_is_safe(v):
                errors.append(f"{g['case_id']}: unsafe IP ioc {v}")
            elif t == "domain" and not ent.domain_is_safe(v):
                errors.append(f"{g['case_id']}: unsafe domain ioc {v}")
            elif t in ("md5", "sha1", "sha256") and not ent.hash_is_safe(v, t):
                errors.append(f"{g['case_id']}: malformed {t} ioc {v}")
            elif t == "url":
                m = re.match(r"^[a-z]+://([^/]+)", v)
                if m:
                    host = m.group(1).split(":")[0]
                    if IPV4_RE.fullmatch(host):
                        if not ent.ip_is_safe(host):
                            errors.append(f"{g['case_id']}: unsafe url host {host}")
                    elif not ent.domain_is_safe(host):
                        errors.append(f"{g['case_id']}: unsafe url domain {host}")

    # forbidden names + unsafe IP scan over all logs
    for src, rel in SOURCE_FILES.items():
        p = os.path.join(logsdir, rel)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        for bad in ent.text_has_forbidden(text):
            errors.append(f"{rel}: contains forbidden name '{bad}'")
        for m in IPV4_RE.finditer(text):
            octets = [int(x) for x in m.groups()]
            if any(o > 255 for o in octets):
                continue
            # skip reverse-DNS names (e.g. 37.10.20.10.in-addr.arpa)
            if text[m.end():m.end() + 13].lower().startswith(".in-addr.arpa"):
                continue
            ip = ".".join(str(o) for o in octets)
            if not ent.ip_is_safe(ip):
                errors.append(f"{rel}: unsafe IPv4 '{ip}' in log content")

    # 7. ATT&CK
    for g in gts:
        for tid in g["techniques"]:
            if not attack.is_valid(tid):
                errors.append(f"{g['case_id']}: ATT&CK id {tid} not in whitelist")

    # 8. host/IP map single & consistent
    ip_to_host = {}
    for h, meta in A.HOSTS.items():
        ipx = meta["ip"]
        if ipx in ip_to_host and ip_to_host[ipx] != h:
            errors.append(f"host/IP collision: {ipx} -> {ip_to_host[ipx]} & {h}")
        ip_to_host[ipx] = h

    # 9. campaign cross-refs
    for cp in campaigns:
        stages = [s["stage"] for s in cp["stages"]]
        if stages != sorted(stages):
            errors.append(f"{cp['campaign_id']}: stages not ordered {stages}")
        for s in cp["stages"]:
            g = gt_by_id.get(s["case_id"])
            if g is None:
                errors.append(f"{cp['campaign_id']}: unknown case {s['case_id']}")
                continue
            if g["campaign_id"] != cp["campaign_id"]:
                errors.append(f"{cp['campaign_id']}: case {s['case_id']} camp mismatch")
            if g["campaign_stage"] != s["stage"]:
                errors.append(f"{cp['campaign_id']}: case {s['case_id']} stage mismatch")

    # 9b. INPUT-ONLY LEAKAGE CHECKS (v4; see leakcheck.py). Single input
    # features -> is_malicious, in-sample and leave-one-out vs the majority
    # baseline. Structural / time / source / event-type features fail at
    # LOO > baseline + 0.10 (N8 regression guard); vendor alert strength
    # fails above 0.75; severity fails if it near-determines the label.
    import leakcheck as _lc
    _res = _lc.run(base)
    _lc.print_report(_res)
    errors.extend(_res["fails"])

    # 9b2. REALISM REGRESSION GUARDS (v4): Sysmon ProcessGuid tree, constant
    # lsass PID, UserID on Sysmon/7045, PA-CORE <-> FGT-EDGE SNAT twins,
    # no 5-minute-rounded signal times, no case-only event types.
    _ierr, _ist = _lc.integrity(base)
    print("REALISM:", json.dumps(_ist, ensure_ascii=False, sort_keys=True))
    errors.extend("REALISM: " + e for e in _ierr)

    # 9c. environment.json + tz_conventions.json presence (N10)
    env_p = os.path.join(base, "inputs", "environment.json")
    if not os.path.exists(env_p):
        errors.append("inputs/environment.json missing (TZ + asset inventory)")
    else:
        try:
            env = json.load(open(env_p, encoding="utf-8"))
            for req in ("org_timezone", "hosts", "users"):
                if req not in env:
                    errors.append(f"environment.json missing '{req}'")
        except Exception as ex:  # noqa
            errors.append(f"environment.json not valid JSON: {ex}")
    if not os.path.exists(os.path.join(base, "inputs", "tz_conventions.json")):
        warnings.append("inputs/tz_conventions.json missing (per-source TZ)")

    # 10. benign %
    try:
        meta = json.load(open(os.path.join(base, "dataset_meta.json"),
                              encoding="utf-8"))
        bp = meta.get("benign_event_pct", 0)
        if bp < 90:
            errors.append(f"benign_event_pct {bp} < 90")
    except FileNotFoundError:
        warnings.append("dataset_meta.json not found; skipped benign% check")

    print(f"cases: {len(inputs)}  gt: {len(gts)}  campaigns: {len(campaigns)}  "
          f"sources: {len(index)}")
    print(f"warnings: {len(warnings)}")
    for w in warnings:
        print("  WARN", w)
    if errors:
        print(f"FAILED with {len(errors)} error(s):")
        for e in errors[:100]:
            print("  ERR", e)
        sys.exit(1)
    print("VALIDATION PASSED \u2713  (schema, de-leak, formats, refs, IoC-in-log, "
          "safety, ATT&CK, host/IP, campaigns, LOO leak-checks, realism, benign%)")


if __name__ == "__main__":
    main()
