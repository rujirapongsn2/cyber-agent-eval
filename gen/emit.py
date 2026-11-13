# -*- coding: utf-8 -*-
"""High-fidelity native-format log record emitters (v4).

Windows/Sysmon events carry correct per-EID envelope metadata (Version, Level,
Task, Opcode, Keywords, Provider/GUID, channel) and full EventData/UserData.
Network-device records use per-vendor-correct field sets. Timestamps come from
gen.timeutil (one UTC instant rendered per source convention).
"""
from xml.sax.saxutils import escape, quoteattr
from . import timeutil as T

# ---------------- Windows provider + per-EID metadata ----------------

PROVIDERS = {
    "Security": ("Microsoft-Windows-Security-Auditing",
                 "{54849625-5478-4994-a5ba-3e3b0328c30d}", "Security"),
    "Eventlog": ("Microsoft-Windows-Eventlog",
                 "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", "Security"),
    "SCM": ("Service Control Manager",
            "{555908d1-a6d7-4695-8e1e-26931d2012f4}", "System"),
    "PowerShell": ("Microsoft-Windows-PowerShell",
                   "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
                   "Microsoft-Windows-PowerShell/Operational"),
    "WMI": ("Microsoft-Windows-WMI-Activity",
            "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}",
            "Microsoft-Windows-WMI-Activity/Operational"),
    "Sysmon": ("Microsoft-Windows-Sysmon",
               "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
               "Microsoft-Windows-Sysmon/Operational"),
}
KW_AUDIT_SUCCESS = "0x8020000000000000"
KW_AUDIT_FAILURE = "0x8010000000000000"
KW_SYSMON = "0x8000000000000000"
KW_SCM = "0x8080000000000000"

# eid -> dict(version, level, task, opcode, keywords, provider)
_SEC = lambda v, task, kw=KW_AUDIT_SUCCESS: dict(
    version=v, level=0, task=task, opcode=0, keywords=kw, provider="Security")
EID_META = {
    4624: _SEC(2, 12544), 4625: _SEC(0, 12544, KW_AUDIT_FAILURE),
    4634: _SEC(0, 12545), 4647: _SEC(0, 12545), 4648: _SEC(0, 12544),
    4672: _SEC(0, 12548), 4688: _SEC(2, 13312), 4689: _SEC(0, 13313),
    4720: _SEC(0, 13824), 4722: _SEC(0, 13824), 4724: _SEC(0, 13824),
    4726: _SEC(0, 13824), 4732: _SEC(0, 13826), 4728: _SEC(0, 13826),
    4756: _SEC(0, 13827),
    4698: _SEC(0, 12805), 4697: _SEC(0, 12289), 4776: _SEC(0, 14336),
    1102: dict(version=0, level=4, task=104, opcode=0,
               keywords="0x4020000000000000", provider="Eventlog"),
    7045: dict(version=0, level=4, task=0, opcode=0, keywords=KW_SCM,
               provider="SCM"),
    7036: dict(version=0, level=4, task=0, opcode=0, keywords=KW_SCM,
               provider="SCM"),
    4103: dict(version=1, level=4, task=106, opcode=20, keywords="0x0",
               provider="PowerShell"),
    4104: dict(version=1, level=5, task=2, opcode=15, keywords="0x0",
               provider="PowerShell"),
    5861: dict(version=0, level=4, task=0, opcode=0, keywords="0x8000000000000000",
               provider="WMI"),
    5857: dict(version=0, level=4, task=0, opcode=0, keywords="0x8000000000000000",
               provider="WMI"),
}
# Sysmon EID -> version
SYSMON_VER = {1: 5, 3: 5, 5: 3, 7: 3, 8: 2, 10: 3, 11: 2, 12: 2, 13: 2, 22: 5}
for _eid, _ver in SYSMON_VER.items():
    EID_META[("sysmon", _eid)] = dict(version=_ver, level=4, task=_eid,
                                      opcode=0, keywords=KW_SYSMON,
                                      provider="Sysmon")


def _data_xml(data):
    return "".join(f'<Data Name={quoteattr(str(n))}>{escape(str(v))}</Data>'
                   for n, v in data)


def win_event(eid, computer_fqdn, record_id, dt, data, exec_pid, exec_tid,
              sysmon=False, userdata_xml=None, level=None, keywords=None,
              security_userid=None):
    key = ("sysmon", eid) if sysmon else eid
    meta = EID_META[key]
    pname, pguid, channel = PROVIDERS[meta["provider"]]
    lvl = meta["level"] if level is None else level
    kw = meta["keywords"] if keywords is None else keywords
    # classic Application/System providers (SCM) still carry a GUID; the
    # generic Application channel uses Name-only providers via app_event().
    prov = f'<Provider Name={quoteattr(pname)} Guid="{pguid}"'
    if meta["provider"] == "SCM":
        prov += ' EventSourceName="Service Control Manager"'
    prov += "/>"
    sec = (f'<Security UserID="{security_userid}"/>' if security_userid
           else "<Security/>")
    body = userdata_xml if userdata_xml is not None else \
        f"<EventData>{_data_xml(data)}</EventData>"
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f"{prov}"
        + (f'<EventID Qualifiers="16384">{eid}</EventID>' if meta["provider"] == "SCM"
           else f"<EventID>{eid}</EventID>")
        + f"<Version>{meta['version']}</Version>"
        f"<Level>{lvl}</Level><Task>{meta['task']}</Task>"
        f"<Opcode>{meta['opcode']}</Opcode><Keywords>{kw}</Keywords>"
        f'<TimeCreated SystemTime="{T.win_systemtime(dt)}"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Correlation/>"
        f'<Execution ProcessID="{exec_pid}" ThreadID="{exec_tid}"/>'
        f"<Channel>{escape(channel)}</Channel>"
        f"<Computer>{escape(computer_fqdn)}</Computer>{sec}"
        "</System>"
        f"{body}</Event>"
    )


def app_event(eid, computer_fqdn, record_id, dt, source_name, message,
              exec_pid, exec_tid, level=4, keywords="0x80000000000000"):
    """Classic Application-channel event (Name-only provider, EventSourceName)."""
    data = _data_xml([("Data", message)])
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name={quoteattr(source_name)}/>'
        f"<EventID Qualifiers=\"16384\">{eid}</EventID>"
        f"<Version>0</Version><Level>{level}</Level><Task>0</Task>"
        f"<Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
        f'<TimeCreated SystemTime="{T.win_systemtime(dt)}"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Correlation/>"
        f'<Execution ProcessID="{exec_pid}" ThreadID="{exec_tid}"/>'
        f"<Channel>Application</Channel>"
        f"<Computer>{escape(computer_fqdn)}</Computer>"
        f'<Security/></System>'
        f"<EventData>{data}</EventData></Event>"
    )


# ============================ Linux ==========================================

def syslog_rfc3164(dt, host, tag, pid, msg):
    p = f"[{pid}]" if pid is not None else ""
    return f"{T.rfc3164(dt)} {host} {tag}{p}: {msg}"


def syslog_rfc5424(dt, host, app, pid, msgid, msg, pri=14, sd="-"):
    return f"<{pri}>1 {T.rfc5424_ts(dt)} {host} {app} {pid} {msgid} {sd} {msg}"


def auditd(dt, event_id, *, arch="c000003e", syscall, success, exit_,
           a0, a1=None, a2=None, a3=None, ppid, pid, auid, uid, gid=0, euid,
           ses, tty, comm, exe, key, cwd=None, path_name=None, proctitle=None,
           execve_argv=None):
    stamp = f"audit({T.auditd_stamp(dt)}:{event_id})"
    # a0..a3 in SYSCALL are hex (pointers / raw arg values); human-readable
    # argv lives in the EXECVE record. Derive deterministic hex pointers.
    base_ptr = 0x7ffd00000000 + (pid * 0x1000 + event_id) % 0xffffff
    aregs = " ".join(f"a{i}={base_ptr + i * 0x20:x}" for i in range(4))
    # every syscall that touches a file produces at least one PATH record
    if path_name is None:
        path_name = exe
    syscall_line = (
        f"type=SYSCALL msg={stamp}: arch={arch} syscall={syscall} "
        f"success={success} exit={exit_} {aregs} items=1 "
        f"ppid={ppid} pid={pid} auid={auid} uid={uid} gid={gid} euid={euid} "
        f"suid={euid} fsuid={euid} egid={gid} sgid={gid} fsgid={gid} tty={tty} "
        f"ses={ses} comm={comm!r} exe={exe!r} "
        f'subj=unconfined key={key!r}'
    ).replace("'", '"')
    lines = [syscall_line]
    if execve_argv is not None:
        argc = len(execve_argv)
        args = " ".join(f'a{i}="{a}"' for i, a in enumerate(execve_argv))
        lines.append(f"type=EXECVE msg={stamp}: argc={argc} {args}")
    if cwd is not None:
        lines.append(f'type=CWD msg={stamp}: cwd="{cwd}"')
    if path_name is not None:
        lines.append(
            f'type=PATH msg={stamp}: item=0 name="{path_name}" '
            f'inode={100000 + (pid % 90000)} dev=08:01 mode=0100755 '
            f'ouid=0 ogid=0 rdev=00:00 nametype=NORMAL')
    if proctitle is not None:
        hexpt = proctitle.encode().hex()
        lines.append(f"type=PROCTITLE msg={stamp}: proctitle={hexpt}")
    return lines


# ============================ Palo Alto PAN-OS ===============================

def _pan_wrap(dt, host, csv, pri=14):
    return f"<{pri}>{T.pan_syslog_hdr(dt)} {host} 1,{csv}"


def panos_traffic(dt, host, serial, subtype, src, dst, natsrc, natdst, natsport,
                  natdport, rule, suser, duser, app, vsys, szone, dzone, iif,
                  oif, sess_id, sport, dport, proto, action, bytes_, bsent,
                  brecv, pkts_sent, pkts_recv, category, seq, scountry,
                  dcountry, end_reason, elapsed=0):
    import datetime as _d
    gen = T.pan_time(dt)
    start = T.pan_time(dt - _d.timedelta(seconds=elapsed))
    total_pkts = pkts_sent + pkts_recv
    total_bytes = bsent + brecv
    fields = [
        gen, serial, "TRAFFIC", subtype, "", gen, src, dst, natsrc, natdst,
        rule, suser, duser, app, vsys, szone, dzone, iif, oif, "log-forward",
        "", str(sess_id), "1", str(sport), str(dport), str(natsport),
        str(natdport), "0x400053", proto, action, str(total_bytes), str(bsent),
        str(brecv), str(total_pkts), start, str(elapsed), category, "", str(seq), "0x0",
        scountry, dcountry, "", str(pkts_sent), str(pkts_recv), end_reason,
    ]
    return _pan_wrap(dt, host, ",".join(str(f) for f in fields))


def panos_threat(dt, host, serial, subtype, src, dst, natsrc, natdst, rule,
                 suser, duser, app, vsys, szone, dzone, iif, oif, sess_id,
                 sport, dport, proto, action, misc, threat_name, threat_id,
                 category, severity, direction, seq, scountry, dcountry,
                 content_type):
    gen = T.pan_time(dt)
    dir_str = "client-to-server" if direction == 0 else "server-to-client"
    fields = [
        gen, serial, "THREAT", subtype, "", gen, src, dst, natsrc, natdst,
        rule, suser, duser, app, vsys, szone, dzone, iif, oif, "log-forward",
        "", str(sess_id), "1", str(sport), str(dport),
        "0" if natsrc == "0.0.0.0" else str(sport),
        "0" if natsrc == "0.0.0.0" else str(dport),
        "0x400053", proto, action, misc, f"{threat_name}({threat_id})",
        category, severity, dir_str, str(seq), "0x0", scountry, dcountry, "",
        content_type,
    ]
    return _pan_wrap(dt, host, ",".join(str(f) for f in fields))


# ============================ FortiGate (key=value) ==========================

# v4.2: interface role follows the physical interface (FortiOS semantics):
# wan1 = wan, dmz = dmz, internal/portN = lan (v4.1 hard-coded lan/wan)
FGT_INTF_ROLE = {"wan1": "wan", "wan2": "wan", "dmz": "dmz"}


def fgt_intf_role(intf):
    return FGT_INTF_ROLE.get(intf, "lan")


def fortigate(dt, dev, logid, type_, subtype, level, srcip, srcport, srcintf,
              dstip, dstport, dstintf, sessionid, proto, action, policyid,
              service, srccountry, dstcountry, app, appcat, sentbyte, rcvdbyte,
              sentpkt, rcvdpkt, duration, trandisp="noop", transip="0.0.0.0",
              transport=0, extra=""):
    d = dev
    base = (
        f'date={T.fgt_date(dt)} time={T.fgt_time(dt)} devname="{d["devname"]}" '
        f'devid="{d["devid"]}" logid="{logid}" type="{type_}" '
        f'subtype="{subtype}" level="{level}" vd="root" '
        f'eventtime={T.fgt_eventtime_ns(dt)} tz="{T.ORG_OFFSET_STR}" '
        f'srcip={srcip} srcport={srcport} srcintf="{srcintf}" '
        f'srcintfrole="{fgt_intf_role(srcintf)}" dstip={dstip} dstport={dstport} '
        f'dstintf="{dstintf}" dstintfrole="{fgt_intf_role(dstintf)}" sessionid={sessionid} '
        f'proto={proto} action="{action}" policyid={policyid} '
        f'policytype="policy" service="{service}" trandisp="{trandisp}" '
    )
    if trandisp == "dnat":
        base += f"tranip={transip} tranport={transport} "
    elif trandisp != "noop":
        base += f"transip={transip} transport={transport} "
    base += (
        f'duration={duration} srccountry="{srccountry}" '
        f'dstcountry="{dstcountry}" app="{app}" appcat="{appcat}" '
        f'sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt={sentpkt} '
        f'rcvdpkt={rcvdpkt}'
    )
    return base + ((" " + extra) if extra else "")


# ============================ Check Point CEF ================================

def checkpoint_cef(dt, host, name_, ext_pairs, origin="10.20.50.1",
                   loguid=None, severity="Unknown"):
    loguid = loguid or "{0x%x,0x1,0xfe65a8c0,0xc0000001}" % (int(T.epoch_s(dt)) & 0xffffffff)
    base = [("rt", str(T.cef_rt_ms(dt)))] + ext_pairs + [
        ("loguid", loguid), ("origin", origin),
        ("product", "VPN-1 & FireWall-1"), ("sequencenum", "1"), ("version", "5")]
    ext = " ".join(f"{k}={v}" for k, v in base)
    header = f"CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|{name_}|{severity}|"
    return f"<134>1 {T.cef_syslog_hdr(dt)} {host} CheckPoint - - - {header}{ext}"


# ============================ F5 BIG-IP ASM =================================

def f5_asm(dt, unit, mgmt, pairs):
    sid = int(T.as_utc(dt).timestamp() * 1000) % (10 ** 18)
    base = [("unit_hostname", unit), ("management_ip_address", mgmt),
            ("support_id", str(sid))] + pairs \
        + [("date_time", T.f5_datetime(dt))]
    body = ",".join(f'{k}="{v}"' for k, v in base)
    return f"<131>{T.rfc3164(dt)} {unit.split('.')[0]} ASM:{body}"


# ============================ DNS ===========================================

def bind_query(dt, client_ip, client_port, qname, qtype, mem="0x7f2a1c0b3d40",
               view="default", server="10.20.50.53", flags="+E(0)"):
    return (f"{T.bind_time(dt)} client @{mem} {client_ip}#{client_port} "
            f"({qname}): query: {qname} IN {qtype} {flags} ({server})")


def windns_pair(dt, client_ip, qname, qtype, xid, rcode="NOERROR", answers=0):
    enc = "".join(f"({len(l)}){l}" for l in qname.split(".")) + "(0)"
    x = int(xid, 16)
    # v4.1: the DNS service runs a pool of worker threads; which one picks a
    # packet varies over time, not with the query id alone
    pool = ["0ABC", "0B10", "0B14", "0C2C", "0D08", "0E4C", "0F18", "1034",
            "10A8", "1170", "11DC", "12F4", "13A0", "1488", "15C4", "1630"]
    thread = pool[(x * 31 + dt.hour * 60 + dt.minute + dt.second // 7) % len(pool)]
    ctx = (x * 2654435761) & 0xfffffff0
    rflag = "8081   DR " if rcode == "NOERROR" else "8183   DR "
    rcv = (f"{T.windns_time(dt)} {thread} PACKET  {ctx:016X} UDP Rcv {client_ip:<15} "
           f"{xid}   Q [0001   D   NOERROR] {qtype}    {enc}")
    snd = (f"{T.windns_time(dt)} {thread} PACKET  {ctx:016X} UDP Snd {client_ip:<15} "
           f"{xid} R Q [{rflag} {rcode}] {qtype}    {enc}")
    return [rcv, snd]


# ============================ Squid proxy ===================================

def squid(dt, elapsed, client_ip, result_status, bytes_to_client, method, url,
          user, peer_status, server_ip, content_type):
    return (f"{T.squid_epoch(dt)} {elapsed:6d} {client_ip} {result_status} "
            f"{bytes_to_client} {method} {url} {user} {peer_status}/{server_ip} "
            f"{content_type}")


# ============================ Docker JSON log ===============================

def docker_json(dt, stream, log_line):
    import json as _json
    return _json.dumps({"log": log_line + "\n", "stream": stream,
                        "time": T.docker_time(dt)}, ensure_ascii=False)


# ============================ Kubernetes audit ==============================

def k8s_audit(dt, audit_id, level, stage, request_uri, verb, username, groups,
              source_ips, object_ref, code, user_agent, decision="allow",
              reason="", request_obj=None, response_obj=None):
    import json as _json
    ann = {"authorization.k8s.io/decision": decision,
           "authorization.k8s.io/reason": reason}
    rec = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
        "auditID": audit_id, "stage": stage, "requestURI": request_uri,
        "verb": verb, "user": {"username": username, "groups": groups},
        "sourceIPs": source_ips, "userAgent": user_agent,
        "objectRef": object_ref,
        "responseStatus": {"metadata": {}, "code": code},
        "requestReceivedTimestamp": T.k8s_time(dt),
        "stageTimestamp": T.k8s_time(dt + __import__("datetime").timedelta(
            milliseconds=3 + (code % 5))),
        "annotations": ann,
    }
    if request_obj is not None:
        rec["requestObject"] = request_obj
    if response_obj is not None:
        rec["responseObject"] = response_obj
    return _json.dumps(rec, ensure_ascii=False)
