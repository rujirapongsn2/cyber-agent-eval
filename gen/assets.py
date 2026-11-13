# -*- coding: utf-8 -*-
"""Single source of truth for hosts, users, network devices and IP mapping.

One consistent host<->IP map used by EVERY source, with no collisions. Windows
and Linux hosts are disjoint. External IPs are allocated deterministically and
uniquely from RFC5737 TEST-NET ranges.
"""
import ipaddress
import random as _random

DOMAIN = "CORP"
DNS_SUFFIX = "corp.example"
DOMAIN_SID = "S-1-5-21-1835023452-1944211108-3039928884"

# ---------------- hosts ----------------
# role: wks|srv|dmz|infra|linux|k8s ; os: windows|linux
HOSTS = {}


def _h(name, ip, os_, role, fqdn=None, rid=None):
    HOSTS[name] = {
        "name": name,
        "ip": ip,
        "os": os_,
        "role": role,
        "fqdn": fqdn or (f"{name.lower()}.{DNS_SUFFIX}" if os_ == "windows"
                         else f"{name}.{DNS_SUFFIX}"),
        "machine_sid": f"{DOMAIN_SID}-{rid}" if rid else None,
    }


# Windows workstations
_h("WKS-FIN-07", "10.20.10.37", "windows", "wks", rid=5107)
_h("WKS-HR-03", "10.20.10.33", "windows", "wks", rid=5103)
_h("WKS-DEV-11", "10.20.10.41", "windows", "wks", rid=5111)
_h("WKS-SALES-22", "10.20.10.52", "windows", "wks", rid=5122)
# Windows servers
_h("SRV-DC01", "10.20.30.10", "windows", "srv", rid=1001)
_h("SRV-FILE01", "10.20.30.21", "windows", "srv", rid=1021)
_h("SRV-SQL01", "10.20.30.31", "windows", "srv", rid=1031)
_h("SRV-APP01", "10.20.30.41", "windows", "srv", rid=1041)
_h("SRV-WEB01", "10.20.40.21", "windows", "dmz", rid=1121)  # IIS in DMZ (shop)
_h("SRV-WEB02", "10.20.40.22", "windows", "dmz", rid=1122)  # IIS in DMZ (partner portal)
_h("SRV-RDS01", "10.20.40.31", "windows", "dmz", rid=1131)  # RD gateway / RDS in DMZ
_h("SRV-MAIL01", "10.20.30.25", "windows", "srv", rid=1025)  # mail relay
# Infra / benign actors
_h("JUMP01", "10.20.50.11", "windows", "infra", rid=1211)
_h("SRV-SCCM01", "10.20.50.21", "windows", "infra", rid=1221)
_h("SRV-BACKUP01", "10.20.50.31", "windows", "infra", rid=1231)
_h("VULNSCAN01", "10.20.50.41", "windows", "infra", rid=1241)
_h("SRV-MON01", "10.20.50.51", "windows", "infra", rid=1251)  # monitoring
# Linux hosts (disjoint names)
_h("lnx-web01", "10.20.35.21", "linux", "linux")
_h("lnx-app01", "10.20.35.31", "linux", "linux")
_h("lnx-db01", "10.20.35.41", "linux", "linux")
_h("lnx-bastion01", "10.20.50.12", "linux", "linux")
# Kubernetes
_h("k8s-cp01", "10.20.60.5", "linux", "k8s")
_h("k8s-node01", "10.20.60.11", "linux", "k8s")
_h("k8s-node02", "10.20.60.12", "linux", "k8s")

# noise workstations (generated): WKS-N### at 10.20.10.100+
for i in range(1, 41):
    _h(f"WKS-GEN-{i:03d}", f"10.20.10.{99 + i}", "windows", "wks", rid=6000 + i)

IP_TO_HOST = {h["ip"]: name for name, h in HOSTS.items()}


def host(name):
    return HOSTS[name]


def ip(name):
    return HOSTS[name]["ip"]


def fqdn(name):
    return HOSTS[name]["fqdn"]


def host_by_ip(addr):
    return IP_TO_HOST.get(addr)


# ---------------- users ----------------
USERS = {}


def _u(sam, rid, kind="user", display=None):
    USERS[sam] = {
        "sam": sam,
        "sid": f"{DOMAIN_SID}-{rid}",
        "upn": f"{sam}@{DNS_SUFFIX}",
        "kind": kind,
        "display": display or sam,
    }


_u("jsmith", 1107); _u("apatel", 1103); _u("ddeep", 1111); _u("nwong", 1122)
_u("administrator", 500); _u("adm_kitti", 1150, kind="admin")  # fictional IT admin
_u("svc_sql", 1201, kind="service"); _u("svc_backup", 1202, kind="service")
_u("svc_sccm", 1203, kind="service"); _u("helpdesk", 1140)
_u("mwhite", 1160); _u("schan", 1161); _u("rlee", 1162); _u("bwong", 1163)
_u("scan_svc", 1241, kind="service")  # vuln scanner service account
_u("svc_report", 1204, kind="service"); _u("svc_deploy", 1205, kind="service")
_u("svc_etl", 1206, kind="service"); _u("svc_monitor", 1207, kind="service")
# v4: extra fictional staff so independent incidents use independent
# user/host pairs (no hidden cross-case chains); home host in HOME below.
for _sam, _rid in (("kchai", 1170), ("tnuch", 1171), ("pmali", 1172),
                   ("sboon", 1173), ("rsiri", 1174), ("jtana", 1175),
                   ("wpan", 1176), ("lkit", 1177), ("nporn", 1178),
                   ("cdao", 1179)):
    _u(_sam, _rid)
# pwadee: new hire created during the window (CAE onboarding trap). Listed in
# inventory with hire date; no activity exists before the 4720.
_u("pwadee", 1526)

# v4.1: every general workstation WKS-GEN-001..040 has exactly one primary
# user, and the user -> host map is a seeded shuffle, so hosts of malicious
# and benign cases come from ONE pool (v4 audit N9: victims sat on 031-039).
for _sam, _rid in (("achai", 1180), ("bnara", 1181), ("csiri", 1182),
                   ("dkan", 1183), ("eporn", 1184), ("fwan", 1185),
                   ("gtip", 1186), ("hsom", 1187), ("ipim", 1188),
                   ("jrat", 1189), ("kmon", 1190), ("lnoi", 1191),
                   ("mpra", 1192), ("nkul", 1193), ("opas", 1194),
                   ("psak", 1195), ("qwit", 1196), ("rkam", 1197),
                   ("stha", 1198), ("tyai", 1199), ("uthai", 1208),
                   ("vnin", 1209), ("wkla", 1210), ("ypat", 1212)):
    _u(_sam, _rid)
GEN_USERS = ["mwhite", "schan", "rlee", "bwong", "helpdesk", "pwadee",
             "kchai", "tnuch", "pmali", "sboon", "rsiri", "jtana", "wpan",
             "lkit", "nporn", "cdao", "achai", "bnara", "csiri", "dkan",
             "eporn", "fwan", "gtip", "hsom", "ipim", "jrat", "kmon", "lnoi",
             "mpra", "nkul", "opas", "psak", "qwit", "rkam", "stha", "tyai",
             "uthai", "vnin", "wkla", "ypat"]
_gen_hosts = [f"WKS-GEN-{i:03d}" for i in range(1, 41)]
_random.Random(4101).shuffle(_gen_hosts)
HOME = {"jsmith": "WKS-FIN-07", "apatel": "WKS-HR-03", "ddeep": "WKS-DEV-11",
        "nwong": "WKS-SALES-22"}
HOME.update(dict(zip(GEN_USERS, _gen_hosts)))
assert len(set(HOME.values())) == len(HOME)


def user(sam):
    return USERS[sam]


# ---------------- network devices ----------------
DEVICES = {
    # v4: serials are OBVIOUSLY FAKE placeholders (never real device serials)
    # Topology: users -> PA-CORE (internal segmentation, NO NAT) ->
    # FGT-EDGE (internet edge, SNAT to 203.0.113.2). FGT-CORE only filters
    # east-west admin traffic (no NAT). PA-DMZ fronts the DMZ (no SNAT).
    "PA-CORE": {"serial": "FAKE0000PA01", "model": "PA-3420", "vsys": "vsys1",
                "role": "internal segmentation (no NAT)"},
    "PA-DMZ": {"serial": "FAKE0000PA02", "model": "PA-1410", "vsys": "vsys1",
               "role": "DMZ ingress (no SNAT)"},
    "FGT-EDGE": {"devname": "FGT-EDGE-01", "devid": "FGFAKE0000000001",
                 "model": "FortiGate-201F", "natip": "203.0.113.2",
                 "role": "internet edge, SNAT to 203.0.113.2"},
    "FGT-CORE": {"devname": "FGT-CORE-01", "devid": "FGFAKE0000000002",
                 "model": "FortiGate-101F", "role": "east-west admin filter (no NAT)"},
    "cp-gw01": {"origin": "10.20.50.1", "version": "R81.20"},
    "bigip-dmz-01": {"mgmt": "10.20.50.60", "unit": "bigip-dmz-01.corp.example"},
    "dns-bind01": {"ip": "10.20.50.53"},
    "proxy01": {"ip": "10.20.50.8"},
}
# v4.1: FGT-EDGE publishes DMZ servers with VIPs (DNAT) and forwards to
# PA-DMZ, which enforces the DMZ policy. Not part of the RFC5737 alloc pool
# (pool starts at .10).
VIPS = {"SRV-WEB01": "203.0.113.3", "SRV-WEB02": "203.0.113.4",
        "SRV-RDS01": "203.0.113.5"}
BIND_SERVER_IP = "10.20.50.53"
PROXY_IP = "10.20.50.8"

# ---------------- deterministic external IP allocation (v4) ----------------
# One shuffled pool over all three RFC5737 nets. Case endpoints take UNIQUE
# addresses first; noise endpoints are hashed into the addresses never given
# to a case endpoint, so a case IoC IP can never re-appear as an unrelated
# benign endpoint (v3 bug: 389 collisions incl. every C2 IP). Edge NAT
# addresses 203.0.113.1/.2 are excluded.
_EXT_NETS = [ipaddress.ip_network("192.0.2.0/24"),
             ipaddress.ip_network("198.51.100.0/24"),
             ipaddress.ip_network("203.0.113.0/24")]
_POOL = [str(n.network_address + h) for n in _EXT_NETS for h in range(10, 251)]
_random.Random(5737).shuffle(_POOL)
_ext_alloc = {}
_case_ips = set()
_noise_ips = set()
_cursor = {"i": 0}


def _fnv(x):
    h = 2166136261
    for ch in str(x):
        h = ((h ^ ord(ch)) * 16777619) & 0xffffffff
    return h


def alloc_ext(name, noise=False):
    """Stable RFC5737 external IP for a named endpoint. noise=True endpoints
    share a hashed pool disjoint from every case endpoint."""
    if name in _ext_alloc:
        return _ext_alloc[name]
    if noise:
        free = [a for a in _POOL[300:] if a not in _case_ips]
        ipaddr = free[_fnv(name) % len(free)]
        _noise_ips.add(ipaddr)
    else:
        while True:
            ipaddr = _POOL[_cursor["i"]]
            _cursor["i"] += 1
            if ipaddr not in _noise_ips and ipaddr not in _case_ips:
                break
        assert _cursor["i"] < 300, "case endpoint pool exhausted"
        _case_ips.add(ipaddr)
    _ext_alloc[name] = ipaddr
    return ipaddr


def reset_ext():
    _ext_alloc.clear(); _case_ips.clear(); _noise_ips.clear()
    _cursor.update(i=0)
