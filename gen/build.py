# -*- coding: utf-8 -*-
"""Deterministic dataset builder v4.

Key anti-leakage properties:
- Records carry a stable internal uid; final EventRecordID / line numbers are
  assigned at write time AFTER merging signal+noise and sorting by time, so a
  case's events are never at the start of a file or at the lowest RecordID.
- EventRecordID is per (host, channel) and increases with time.
- case_id is assigned by a separate shuffle so id order carries no label/stage
  signal; output is sorted by the shuffled case_id.
- Process identity (ProcessGuid/PID), per-binary hashes, logon ids and lsass
  pid are stable so a reader can correlate events (N6).
v4 additions:
- N8: every case (or linked case group, e.g. a campaign) is a "group". Its
  events keep their relative timing but the group is re-anchored to a slot
  from a label-blind schedule spread over all 4 days (computed in a dry run,
  see generator.py). Relative offsets are scaled by a per-group factor so
  signal minutes are no longer multiples of 5.
- Process tree: every Sysmon process has exactly one ProcessGuid/PID; a
  process seen in Sysmon without an explicit EID 1 gets a synthesized EID 1
  (before its first event) whose ParentProcessGuid is a real, earlier process.
- Same-instant events inside a group get millisecond jitter.
- EventRecordID has realistic gaps (only some EIDs are exported).
"""
import datetime
import os
import re
import urllib.parse

from . import emit
from . import assets as A
from . import timeutil as T
from .entities import Entities

SOURCE_FILES = {
    "security": "windows/Security.xml",
    "system": "windows/System.xml",
    "application": "windows/Application.xml",
    "powershell": "windows/PowerShell-Operational.xml",
    "wmi": "windows/WMI-Activity-Operational.xml",
    "sysmon": "sysmon/Sysmon-Operational.xml",
    "auth": "linux/auth.log",
    "syslog": "linux/syslog",
    "auditd": "linux/audit.log",
    "pan_traffic": "paloalto/traffic.log",
    "pan_threat": "paloalto/threat.log",
    "fortigate": "fortigate/fortigate.log",
    "checkpoint": "checkpoint/checkpoint-cef.log",
    "f5": "f5/asm.log",
    "bind": "bind/named-query.log",
    "windns": "windows_dns/dns-debug.log",
    "squid": "squid/access.log",
    "docker": "docker/payments-api.json",
    "k8s": "k8s/kube-apiserver-audit.jsonl",
}
XML_SOURCES = {"security", "system", "application", "powershell", "wmi", "sysmon"}
XML_CHANNEL_PROVIDER = {"security": "Security", "system": "SCM",
                        "application": "Application", "powershell": "PowerShell",
                        "wmi": "WMI", "sysmon": "Sysmon"}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _norm(s):
    return urllib.parse.unquote(str(s)).lower()


def _stable_int(s):
    h = 0
    for ch in s:
        h = (h * 131 + ord(ch)) & 0xffffffff
    return h


WINDOW_START = datetime.datetime(2026, 11, 9, 0, 0, 0, tzinfo=T.ORG_TZ).astimezone(T.UTC)
WINDOW_END = datetime.datetime(2026, 11, 12, 23, 59, 59, tzinfo=T.ORG_TZ).astimezone(T.UTC)

# processes that started at boot (before the window): no EID 1 is expected
ROOT_IMAGES = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
               "services.exe", "lsass.exe", "lsass-proc"}


def _base(image):
    return image.rsplit("\\", 1)[-1].lower()


class Build:
    def __init__(self, seed=20261113, schedule=None):
        import random
        self.seed = seed
        self.rng = random.Random(seed)
        self.shuffle_rng = random.Random(seed ^ 0x5f3759df)
        self.trng = random.Random(seed ^ 0x13371337)   # jitter/RID gaps only
        # ---- N8 time-group machinery ----
        self.schedule = schedule or {}   # gid -> (slot_utc, scale)
        self.in_scen = True
        self._gid = 0
        self._anchor = None              # orig anchor of the open group
        self._hold = 0                   # >0 while a multi-case group is open
        self._used_t = set()
        self.groups = {}                 # gid -> {"orig": [...], "cases": [...]}
        self.changes = []                # change-calendar records (env.json)
        self.created_accounts = {}       # sam -> creation dt
        self.pentest_ips = []
        self.next_hint, self.next_who = "any", []
        self.ent = Entities(self.rng)
        A.reset_ext()
        # per-source record lists of dicts
        self._xml = {k: [] for k in sorted(XML_SOURCES)}     # {uid,dt,host,xml}
        self._txt = {k: [] for k in SOURCE_FILES if k not in XML_SOURCES}  # {uid,dt,lines}
        self._uid = 0
        self._uid_xml = {}       # uid -> xml string (pre-finalize lookup)
        self._uid_lines = {}     # uid -> [lines]
        self._pid = {}           # (host, role) -> stable pid
        self._procs = {}         # (host, image, tag) -> {guid, pid, image}
        self._img = {}           # image -> {md5, sha256}
        self._lsass = {}         # host -> pid
        self._logon = {}         # (host, key) -> hex logon id (legacy)
        self._sess = {}          # v4.1: (host, sam) -> [[start, end, lid, type]]
        self._lids = set()       # (host, lid) issued
        self._guid_seq = 0
        self._procmeta = {}      # (host,image,tag) -> metadata for EID1 synth
        self.cases = []
        self.campaigns = []

    # ---------- N8: label-blind time groups ----------
    def map_time(self, orig):
        """Map a scenario-authored instant into its group's scheduled slot."""
        orig = T.as_utc(orig)
        if not self.in_scen:
            return orig
        if self._anchor is None:
            self._gid += 1
            self._anchor = orig
            self._used_t = set()
            self.groups[self._gid] = {"orig": [], "cases": [],
                                      "hint": self.next_hint,
                                      "who": list(self.next_who)}
            self.next_hint, self.next_who = "any", []
        self.groups[self._gid]["orig"].append(orig)
        if self._gid in self.schedule:
            slot, scale = self.schedule[self._gid]
            return slot + (orig - self._anchor) * scale
        return orig

    def hint(self, tod="any", who=()):
        """Time-of-day class for the NEXT group (label-blind: chosen by what
        the activity is, e.g. a human at a desk vs. a nightly job) and the
        principals it involves (scheduler keeps groups that share a principal
        >= 18 h apart so no accidental cross-case chains appear)."""
        self.next_hint, self.next_who = tod, list(who)

    def begin_group(self):
        self._hold += 1

    def end_group(self):
        self._hold -= 1
        if self._hold == 0:
            self._anchor = None

    def tj(self, dt):
        """Millisecond jitter so no two events of one group share an instant."""
        dt = T.as_utc(dt)
        if not self.in_scen or self._anchor is None:
            return dt
        key = int(dt.timestamp() * 1000)
        while any(abs(key - u) <= 3 for u in self._used_t):
            key += self.trng.randint(25, 900)
        self._used_t.add(key)
        return datetime.datetime.fromtimestamp(key / 1000.0, tz=T.UTC)

    def add_change(self, change_id, start, end, hosts, summary_th, kind="change"):
        self.changes.append({"id": change_id, "kind": kind,
                             "start_local": T.local(start).strftime("%Y-%m-%d %H:%M"),
                             "end_local": T.local(end).strftime("%Y-%m-%d %H:%M"),
                             "hosts": list(hosts), "summary_th": summary_th})

    # ---------- identity / consistency helpers ----------
    def _mult4(self, lo, hi):
        return (self.rng.randint(lo // 4, hi // 4)) * 4

    def svc_pid(self, host, role):
        k = (host, role)
        if k not in self._pid:
            self._pid[k] = (self._mult4(400, 1600) if role in
                            ("lsass", "services", "sysmon")
                            else self._mult4(1600, 9000))
        return self._pid[k]

    def lsass_pid(self, host):
        if host not in self._lsass:
            self._lsass[host] = self._mult4(560, 1400)
        return self._lsass[host]

    def lsass(self, host):
        """lsass process identity: constant PID (== lsass_pid) and GUID."""
        p = self.proc(host, r"C:\Windows\System32\lsass.exe", "boot")
        p["pid"] = self.lsass_pid(host)
        return p

    def proc(self, host, image, tag="", user=None, parent=None,
             integrity=None, cmdline=None):
        """Stable {guid, pid} for a logical process. Same (host,image,tag)
        -> same identity, so EID 1/3/10/11/13 and 4688 can be correlated.
        Optional metadata is used to synthesize a missing EID 1."""
        k = (host, image, tag)
        if k in self._procs:
            m = self._procmeta[k]
            for nm, v in (("user", user), ("parent", parent),
                          ("integrity", integrity), ("cmdline", cmdline)):
                if v is not None and m.get(nm) is None:
                    m[nm] = v
        if k not in self._procs and image == "System":
            self._procs[k] = {"guid": "{%08x-0000-0000-0000-000000000004}" % (
                _stable_int(host) & 0xffffffff), "pid": 4, "image": "System",
                "key": k}
            self._procmeta[k] = {"root": True}
        if k not in self._procs:
            self._guid_seq += 1
            mid = (A.HOSTS.get(host, {}).get("machine_sid") or "1").split("-")[-1]
            mi = int(mid) if str(mid).isdigit() else _stable_int(host)
            pid = self._mult4(600, 40000)
            guid = "{%08x-%04x-%04x-%04x-%012x}" % (
                mi & 0xffffffff,
                (self._guid_seq * 7 + 0x1000) & 0xffff,
                _stable_int(image) & 0xffff,
                pid & 0xffff,
                (_stable_int(host + image + tag)) & 0xffffffffffff)
            self._procs[k] = {"guid": guid, "pid": pid, "image": image, "key": k}
            self._procmeta[k] = {"user": user, "parent": parent,
                                 "integrity": integrity, "cmdline": cmdline,
                                 "root": _base(image) in ROOT_IMAGES,
                                 "eid1": None, "first": None, "seq": len(self._procmeta)}
        return self._procs[k]

    def touch(self, proc, dt, eid1=False):
        """Record Sysmon activity of a process (for EID1 synthesis)."""
        m = self._procmeta[proc["key"]]
        dt = T.as_utc(dt)
        if eid1:
            m["eid1"] = dt if m.get("eid1") is None else min(m["eid1"], dt)
        if m.get("first") is None or dt < m["first"]:
            m["first"] = dt

    def img_hash(self, image):
        if image not in self._img:
            self._img[image] = {"md5": self.ent.md5(), "sha256": self.ent.sha256()}
        return self._img[image]

    # ---------- v4.1 logon sessions: one LogonId per 4624 ----------
    SPECIAL_LID = {"SYSTEM": "0x3e7", "LOCAL SERVICE": "0x3e5",
                   "NETWORK SERVICE": "0x3e4"}
    DEFAULT_LEN = {3: 120, 5: 36000, 2: 36000, 7: 36000, 11: 36000, 10: 36000}

    def new_lid(self, host):
        while True:
            v = "0x%x" % self.rng.randint(0x100000, 0x3fffffff)
            if (host, v) not in self._lids:
                self._lids.add((host, v))
                return v

    def logon_guid(self, host, lid):
        import hashlib
        h = hashlib.md5(f"logon|{host}|{lid}".encode()).hexdigest()
        return "{%s-%s-%s-%s-%s}" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])

    def open_session(self, host, sam, dt, ltype, lid):
        self._sess.setdefault((host, sam), []).append(
            [T.as_utc(dt), None, lid, ltype])

    def close_session(self, host, sam, lid, dt):
        for s_ in self._sess.get((host, sam), []):
            if s_[2] == lid and s_[1] is None:
                s_[1] = T.as_utc(dt)
                return

    def find_session(self, host, sam, dt):
        dt = T.as_utc(dt)
        best = None
        for s_ in self._sess.get((host, sam), []):
            end = s_[1] or s_[0] + datetime.timedelta(
                seconds=self.DEFAULT_LEN.get(s_[3], 36000))
            if s_[0] <= dt <= end and (best is None or s_[0] > best[0]):
                best = s_
        return best

    def _implicit_type(self, host, sam):
        meta = A.HOSTS.get(host, {})
        kind = A.USERS.get(sam, {}).get("kind", "user")
        if meta.get("role") == "wks":
            return (2, "-", "-") if A.HOME.get(sam) == host else \
                (3, A.ip(A.HOME[sam]) if sam in A.HOME else "-", A.HOME.get(sam, "-"))
        if kind == "service":
            return (5, "-", "-")
        if kind == "admin" or sam in ("administrator", "helpdesk"):
            return (10, A.ip("JUMP01"), "JUMP01")
        return (3, A.ip(A.HOME[sam]) if sam in A.HOME else "-", A.HOME.get(sam, "-"))

    def sess(self, host, sam, dt):
        """LogonId of the session `sam` has open on `host` at `dt`. If none is
        open, an implicit logon session (4624 [+4672] ... 4634) is created
        around dt, so every SubjectLogonId refers to a real open session."""
        if sam in self.SPECIAL_LID:
            return self.SPECIAL_LID[sam]
        if sam.endswith("$"):
            return "0x3e7"
        s_ = self.find_session(host, sam, dt)
        if s_:
            return s_[2]
        from . import evbuilders as EV
        dt = T.as_utc(dt)
        ltype, sip, swks = self._implicit_type(host, sam)
        start = dt - datetime.timedelta(seconds=self.rng.randint(90, 5400))
        if start < WINDOW_START:
            start = max(WINDOW_START, dt - datetime.timedelta(seconds=30))
        _r, lid = EV.sec_4624(self, start, host, sam, ltype, sip, swks,
                              auth="Negotiate" if ltype in (2, 10) else "Kerberos")
        if ltype == 10:
            st0 = self._sess[(host, sam)][-1][0]
            EV.sec_4672(self, st0 + datetime.timedelta(milliseconds=15), host, sam)
        end = dt + datetime.timedelta(seconds=self.rng.randint(600, 14400))
        EV.sec_4634(self, end, host, sam, ltype, lid)
        return lid

    def logon_id(self, host, key):
        k = (host, key)
        if k not in self._logon:
            self._logon[k] = "0x" + "".join(
                self.rng.choice("0123456789abcdef") for _ in range(6))
        return self._logon[k]

    # ---------- low-level add ----------
    def _new_uid(self):
        self._uid += 1
        return self._uid

    def add_lines(self, source, lines, dt=None):
        uid = self._new_uid()
        dtv = T.as_utc(dt) if dt is not None else T.as_utc(
            datetime.datetime(2026, 11, 10, tzinfo=T.UTC))
        self._txt[source].append({"uid": uid, "dt": dtv, "lines": list(lines)})
        self._uid_lines[uid] = list(lines)
        return {"source": source, "file": SOURCE_FILES[source], "_uid": uid}

    def add_line(self, source, line, dt=None):
        return self.add_lines(source, [line], dt=dt)

    def add_event(self, source, eid, host, dt, data, exec_role="lsass", **kw):
        uid = self._new_uid()
        if source == "sysmon" and not kw.get("security_userid"):
            kw["security_userid"] = "S-1-5-18"   # Sysmon runs as SYSTEM
        fqdn = A.fqdn(host) if host in A.HOSTS else host
        pid = self.svc_pid(host, "sysmon" if source == "sysmon" else exec_role)
        tid = pid + self.rng.randint(1, 60) * 4
        sysmon = (source == "sysmon")
        # render with uid as a placeholder EventRecordID; finalized at write
        xml = emit.win_event(eid, fqdn, uid, dt, data, pid, tid,
                             sysmon=sysmon, **kw)
        self._xml[source].append({"uid": uid, "dt": T.as_utc(dt),
                                  "host": host, "xml": xml})
        self._uid_xml[uid] = xml
        return {"source": source, "file": SOURCE_FILES[source], "_uid": uid,
                "event_id": eid, "host": host}

    def add_app_event(self, host, eid, dt, source_name, message, level=4):
        dt = self.tj(dt)
        uid = self._new_uid()
        fqdn = A.fqdn(host)
        pid = self.svc_pid(host, "app")
        xml = emit.app_event(eid, fqdn, uid, dt, source_name, message, pid,
                             pid + 12, level=level)
        self._xml["application"].append({"uid": uid, "dt": T.as_utc(dt),
                                         "host": host, "xml": xml})
        self._uid_xml[uid] = xml
        return {"source": "application", "file": SOURCE_FILES["application"],
                "_uid": uid, "event_id": eid, "host": host}

    # ---------- case add (with IoC-in-log guarantee) ----------
    def _refs_text(self, refs):
        parts = []
        for r in refs:
            uid = r.get("_uid")
            if uid in self._uid_xml:
                parts.append(self._uid_xml[uid])
            elif uid in self._uid_lines:
                parts.extend(self._uid_lines[uid])
        return _norm("\n".join(parts))

    def add_case(self, task_type, prompt_th, refs, severity, is_malicious,
                 techniques, iocs, rationale_th, is_fp_trap=False,
                 fp_trap_kind=None, correlation_keys=None, campaign_id=None,
                 campaign_stage=None, is_decoy=False):
        assert severity in SEVERITY_ORDER, severity
        blob = self._refs_text(refs)
        for io in iocs:
            if _norm(io["value"]) not in blob:
                raise AssertionError(
                    f"IoC {io['type']}={io['value']!r} not present in refs "
                    f"(task {task_type})")
        case_in = {"case_id": None, "task_type": task_type,
                   "prompt_th": prompt_th, "input_log_refs": refs}
        gt = {"case_id": None,
              "severity": severity, "is_malicious": bool(is_malicious),
              "is_fp_trap": bool(is_fp_trap), "fp_trap_kind": fp_trap_kind,
              "is_decoy": bool(is_decoy),
              "techniques": sorted(set(techniques)), "iocs": iocs,
              "correlation_keys": sorted(set(correlation_keys or [])),
              "campaign_id": campaign_id, "campaign_stage": campaign_stage,
              "rationale_th": rationale_th}
        self.cases.append({"input": case_in, "gt": gt, "gid": self._gid})
        idx = len(self.cases) - 1
        if self.in_scen and self._gid in self.groups:
            self.groups[self._gid]["cases"].append(idx)
        if self._hold == 0:
            self._anchor = None          # next dt() opens a new group
        return idx   # internal index

    def add_campaign(self, camp_id, name_th, description_th, stages):
        """Stages must have been built inside begin_group()/end_group()."""
        stage_recs = []
        from . import scenarios as _sc
        for st in stages:
            idx = self.add_case(
                "campaign_reconstruction", _sc.P("campaign_reconstruction"),
                st["refs"], st["severity"], True, st.get("techniques", []),
                st.get("iocs", []), st["rationale_th"],
                correlation_keys=st.get("correlation_keys"),
                campaign_id=camp_id, campaign_stage=st["stage"])
            stage_recs.append({
                "stage": st["stage"], "name_th": st["name_th"],
                "_case_idx": idx, "host": st.get("host"),
                "techniques": sorted(set(st.get("techniques", [])))})
        self.campaigns.append({
            "campaign_id": camp_id, "name_th": name_th,
            "description_th": description_th,
            "num_stages": len(stage_recs), "stages": stage_recs})

    # ---------- EID 1 synthesis (process tree) ----------
    def _default_parent(self, host, image, tag, user):
        b = _base(image)
        svc = r"C:\Windows\System32\services.exe"
        if b == "explorer.exe":
            return (host, r"C:\Windows\System32\userinit.exe", "logon:" + (user or "x"))
        if b == "userinit.exe":
            return (host, r"C:\Windows\System32\winlogon.exe", "boot")
        if b in ("svchost.exe", "msmpeng.exe", "veeamagent.exe", "ccmexec.exe",
                 "microsoftedgeupdate.exe", "sqlservr.exe", "inv.exe",
                 "spoolsv.exe", "searchindexer.exe"):
            return (host, svc, "boot")
        if b == "w3wp.exe":
            return (host, r"C:\Windows\System32\svchost.exe", "iis-was")
        if b == "wmiprvse.exe":
            return (host, r"C:\Windows\System32\svchost.exe", "dcomlaunch")
        if user in (None, "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return (host, svc, "boot")
        return (host, r"C:\Windows\explorer.exe", "shell-" + user)

    def _synth_eid1(self):
        from . import evbuilders as EV
        created = {}

        def ensure(k, before):
            """Make sure process k has a creation instant < before."""
            m = self._procmeta[k]
            if m.get("root"):
                return None
            if m.get("eid1") is not None:
                return m["eid1"]
            if k in created:
                return created[k]
            host, image, tag = k
            first = m.get("first") or before
            first = min(first, before)
            b = _base(image)
            if b in ("explorer.exe", "userinit.exe", "chrome.exe", "outlook.exe",
                     "teams.exe", "onedrive.exe", "msmpeng.exe", "veeamagent.exe",
                     "ccmexec.exe", "svchost.exe", "w3wp.exe", "runtimebroker.exe"):
                delta = datetime.timedelta(seconds=self.trng.randint(300, 4 * 3600))
            else:
                delta = datetime.timedelta(milliseconds=self.trng.randint(150, 20000))
            c = first - delta
            if c < WINDOW_START:
                c = WINDOW_START + datetime.timedelta(seconds=self.trng.randint(5, 900))
                if c >= first:
                    c = first - datetime.timedelta(milliseconds=self.trng.randint(50, 900))
            pk = m.get("parent") or self._default_parent(host, image, tag, m.get("user"))
            if pk not in self._procs:
                self.proc(*pk, user=m.get("user") if _base(pk[1]) in (
                    "explorer.exe", "userinit.exe") else None)
            pc = ensure(pk, c)
            if pc is not None and pc >= c:
                c = pc + datetime.timedelta(milliseconds=self.trng.randint(200, 5000))
                if c >= first:
                    c = first - datetime.timedelta(milliseconds=25)
            created[k] = c
            m["parent"] = pk
            EV.synth_eid1(self, k, pk, c)
            m["eid1"] = c
            return c

        keys = sorted((k for k, m in self._procmeta.items()
                       if not m.get("root") and m.get("eid1") is None
                       and m.get("first") is not None),
                      key=lambda k: self._procmeta[k]["seq"])
        # v4.1: a long-lived parent (e.g. one explorer.exe per user shell)
        # must be created before the earliest activity of ANY descendant,
        # so propagate each process' first activity up its ancestor chain
        for k in keys:
            t = self._procmeta[k]["first"]
            cur = k
            for _ in range(32):
                m = self._procmeta[cur]
                if m.get("root") or (cur != k and m.get("eid1") is not None):
                    break
                pk = m.get("parent") or self._default_parent(*cur, m.get("user"))
                if pk not in self._procs:
                    self.proc(*pk, user=m.get("user") if _base(pk[1]) in (
                        "explorer.exe", "userinit.exe") else None)
                m["parent"] = pk
                pm = self._procmeta[pk]
                if pm.get("root") or pm.get("eid1") is not None:
                    break
                if pm.get("first") is None or pm["first"] > t:
                    pm["first"] = t
                cur = pk
        for k in keys:
            ensure(k, self._procmeta[k]["first"])
        return len(created)

    # ---------- finalize: time-sort, per-host RID, ref rewrite, id shuffle ----------
    def finalize(self):
        self.in_scen = False
        self.synth_count = self._synth_eid1()
        # export window cut: drop background records after the window end
        # (e.g. logoffs of sessions still open at midnight); case evidence
        # is scheduled inside the window and is never dropped
        keep = {r["_uid"] for c in self.cases
                for r in c["input"]["input_log_refs"] if "_uid" in r}
        lim = WINDOW_END + datetime.timedelta(seconds=1)
        for src in list(self._xml):
            self._xml[src] = [r for r in self._xml[src]
                              if r["dt"] < lim or r["uid"] in keep]
        for src in list(self._txt):
            self._txt[src] = [r for r in self._txt[src]
                              if r["dt"] < lim or r["uid"] in keep]
        host_base = {}

        def base_for(host):
            if host not in host_base:
                host_base[host] = 1000 + (_stable_int(host) % 60000) * 1000
            return host_base[host]

        uid_rid = {}
        for src in sorted(XML_SOURCES):
            recs = sorted(self._xml[src], key=lambda r: (r["dt"], r["uid"]))
            counters = {}
            for r in recs:
                h = r["host"]
                if (src, h) not in counters:
                    counters[(src, h)] = base_for(h)
                # only some EIDs are forwarded -> realistic gaps in RIDs
                step = 1 if self.trng.random() < 0.9 else self.trng.randint(2, 40)
                counters[(src, h)] += step
                rid = counters[(src, h)]
                uid_rid[r["uid"]] = rid
                r["xml"] = r["xml"].replace(
                    f"<EventRecordID>{r['uid']}</EventRecordID>",
                    f"<EventRecordID>{rid}</EventRecordID>")
            self._xml[src] = recs

        uid_line = {}
        for src in self._txt:
            recs = sorted(self._txt[src], key=lambda r: (r["dt"], r["uid"]))
            flat = []
            for r in recs:
                uid_line[r["uid"]] = len(flat) + 1
                flat.extend(r["lines"])
            self._txt[src] = flat

        # rewrite refs in every case
        for c in self.cases:
            for r in c["input"]["input_log_refs"]:
                uid = r.pop("_uid", None)
                if uid is None:
                    continue
                if uid in uid_rid:
                    r["event_record_id"] = uid_rid[uid]
                elif uid in uid_line:
                    r["line"] = uid_line[uid]

        # shuffle case ids (decouple id<->label/stage)
        n = len(self.cases)
        ids = [f"CAE-{i:04d}" for i in range(1, n + 1)]
        perm = ids[:]
        self.shuffle_rng.shuffle(perm)
        for i, c in enumerate(self.cases):
            c["input"]["case_id"] = perm[i]
            c["gt"]["case_id"] = perm[i]
        # resolve campaign stage case ids and drop internal idx
        for cp in self.campaigns:
            for st in cp["stages"]:
                st["case_id"] = self.cases[st.pop("_case_idx")]["gt"]["case_id"]
            cp["stages"].sort(key=lambda s: s["stage"])
        # output order sorted by shuffled case id
        self.cases.sort(key=lambda c: c["gt"]["case_id"])

    # ---------- write ----------
    def write(self, outdir):
        import json
        self.finalize()
        inp = os.path.join(outdir, "inputs")
        ans = os.path.join(outdir, "answers")
        logsdir = os.path.join(inp, "logs")
        for src, rel in SOURCE_FILES.items():
            path = os.path.join(logsdir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if src in XML_SOURCES:
                ordered = [r["xml"] for r in self._xml[src]]
                content = ('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n'
                           + "\n".join(ordered) + "\n</Events>\n")
            else:
                content = "\n".join(self._txt[src]) + "\n"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        os.makedirs(ans, exist_ok=True)
        with open(os.path.join(inp, "cases_input.jsonl"), "w",
                  encoding="utf-8") as f:
            for c in self.cases:
                f.write(json.dumps(c["input"], ensure_ascii=False) + "\n")
        with open(os.path.join(ans, "ground_truth.jsonl"), "w",
                  encoding="utf-8") as f:
            for c in self.cases:
                f.write(json.dumps(c["gt"], ensure_ascii=False) + "\n")
        with open(os.path.join(ans, "campaigns.json"), "w",
                  encoding="utf-8") as f:
            json.dump(self.campaigns, f, ensure_ascii=False,
                      indent=2, sort_keys=True)
        with open(os.path.join(inp, "campaigns_input.json"), "w",
                  encoding="utf-8") as f:
            ci = [{"campaign_id": c["campaign_id"]} for c in
                  sorted(self.campaigns, key=lambda x: x["campaign_id"])]
            json.dump(ci, f, ensure_ascii=False, indent=2, sort_keys=True)
        return inp, ans
