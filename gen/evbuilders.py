# -*- coding: utf-8 -*-
"""Full-fidelity high-level event builders. Each takes the Build instance `b`.

Field sets follow real Windows/Sysmon rendered-event schemas (the fields a SOC
analyst/agent actually parses). Values use the single asset/identity map.
"""
import datetime
from . import assets as A


_WELLKNOWN = {"SYSTEM": "S-1-5-18", "LOCAL SERVICE": "S-1-5-19",
              "NETWORK SERVICE": "S-1-5-20"}


def _sid(sam):
    if sam in A.USERS:
        return A.USERS[sam]["sid"]
    if sam in _WELLKNOWN:
        return _WELLKNOWN[sam]
    if sam.endswith("$"):
        return A.HOSTS.get(sam[:-1], {}).get("machine_sid") or "S-1-5-18"
    return new_acct_sid(sam)          # accounts created inside the window


def _acct(sam):
    """DOMAIN\\user rendering incl. well-known NT AUTHORITY principals."""
    if sam in _WELLKNOWN:
        return "NT AUTHORITY\\" + sam
    return "CORP\\" + sam


def _hexid(b):
    return "0x" + "".join(b.rng.choice("0123456789abcdef") for _ in range(6))


def _pguid(b, host, pid):
    mid = (A.HOSTS.get(host, {}).get("machine_sid") or "x").split("-")[-1]
    return ("{%08x-%04x-%04x-0000-%012x}" % (
        (int(mid) if str(mid).isdigit() else 1) & 0xffffffff,
        pid & 0xffff, b.rng.randrange(0x10000), b.rng.randrange(0x1000000000000)))


# ============================ Windows Security ============================
def _pid_hex(b, host, name):
    return "0x%x" % b.proc(host, name, "")["pid"]



def sec_4624(b, dt, host, target_sam, logon_type, src_ip="-", src_wks="-",
             auth="Kerberos", elevated=False, logon_id=None, target_domain="CORP",
             ip_port=None):
    dt = b.tj(dt)
    lid = logon_id or b.new_lid(host)          # v4.1: one LogonId per session
    b.open_session(host, target_sam, dt, logon_type, lid)
    pkg = {"Kerberos": "Kerberos", "NTLM": "NTLM V2", "Negotiate": "Negotiate"}.get(auth, auth)
    if logon_type in (3,):
        subj_sid, subj_name, subj_dom, subj_lid = "S-1-0-0", "-", "-", "0x0"
        lpn = "Kerberos" if auth == "Kerberos" else "NtLmSsp "
        proc_name, proc_id = "-", "0x0"
    elif logon_type == 10:
        subj_sid, subj_name, subj_dom, subj_lid = "S-1-5-18", host.split(".")[0] + "$", "CORP", "0x3e7"
        lpn, pkg = "User32 ", "Negotiate"
        proc_name, proc_id = r"C:\Windows\System32\winlogon.exe", _pid_hex(b, host, "winlogon")
    else:  # interactive 2
        subj_sid, subj_name, subj_dom, subj_lid = "S-1-5-18", host.split(".")[0] + "$", "CORP", "0x3e7"
        lpn = "User32 "
        proc_name, proc_id = r"C:\Windows\System32\winlogon.exe", _pid_hex(b, host, "winlogon")
    if logon_type == 2:
        src_ip, src_wks = "127.0.0.1", host.split(".")[0]
    data = [
        ("SubjectUserSid", subj_sid), ("SubjectUserName", subj_name),
        ("SubjectDomainName", subj_dom), ("SubjectLogonId", subj_lid),
        ("TargetUserSid", _sid(target_sam)), ("TargetUserName", target_sam),
        ("TargetDomainName", target_domain), ("TargetLogonId", lid),
        ("LogonType", str(logon_type)), ("LogonProcessName", lpn),
        ("AuthenticationPackageName", "Kerberos" if auth == "Kerberos" and logon_type == 3 else ("NTLM" if auth == "NTLM" else pkg)),
        ("WorkstationName", src_wks),
        ("LogonGuid", b.logon_guid(host, lid) if auth == "Kerberos" else "{00000000-0000-0000-0000-000000000000}"),
        ("TransmittedServices", "-"),
        ("LmPackageName", "-" if auth == "Kerberos" else pkg),
        ("KeyLength", "0"), ("ProcessId", proc_id), ("ProcessName", proc_name),
        ("IpAddress", src_ip), ("IpPort", "0" if src_ip in ("-", "127.0.0.1") else str(ip_port if ip_port is not None else b.rng.randint(49152, 65535))),
        ("ImpersonationLevel", "%%1833"),
        ("RestrictedAdminMode", "-"), ("TargetOutboundUserName", "-"),
        ("TargetOutboundDomainName", "-"), ("VirtualAccount", "%%1843"),
        ("TargetLinkedLogonId", "0x0"),
        ("ElevatedToken", "%%1842" if elevated else "%%1843"),
    ]
    return b.add_event("security", 4624, host, dt, data), lid


def sec_4634(b, dt, host, target_sam, logon_type, logon_id):
    dt = b.tj(dt)
    b.close_session(host, target_sam, logon_id, dt)
    data = [("TargetUserSid", _sid(target_sam)), ("TargetUserName", target_sam),
            ("TargetDomainName", "CORP"), ("TargetLogonId", logon_id),
            ("LogonType", str(logon_type))]
    return b.add_event("security", 4634, host, dt, data)


def sec_4625(b, dt, host, target_sam, logon_type, src_ip, src_wks="-",
             user_exists=True, auth="NTLM", substatus=None, ip_port=None):
    """4625. SubStatus: 0xc000006a bad password, 0xc0000064 no such user,
    0xc0000071 password expired, 0xc0000072 account disabled,
    0xc0000234 locked out."""
    dt = b.tj(dt)
    sub = substatus or ("0xc000006a" if user_exists else "0xc0000064")
    status = {"0xc0000234": "0xc0000234"}.get(sub, "0xc000006d")
    reason = {"0xc0000071": "%%2309", "0xc0000072": "%%2310",
              "0xc0000234": "%%2307", "0xc0000064": "%%2313"}.get(sub, "%%2313")
    if logon_type in (2, 7, 11):
        subj = ("S-1-5-18", host.split(".")[0] + "$", "CORP", "0x3e7")
        lpn, pkg = "User32 ", "Negotiate"
        pname, pid = r"C:\Windows\System32\svchost.exe", "0x%x" % b.proc(host, r"C:\Windows\System32\svchost.exe", "logonui")["pid"]
        src_ip, src_wks = "127.0.0.1", host.split(".")[0]
    else:
        subj = ("S-1-0-0", "-", "-", "0x0")
        lpn = "NtLmSsp " if auth == "NTLM" else "Kerberos"
        pkg = auth
        pname, pid = "-", "0x0"
    data = [
        ("SubjectUserSid", subj[0]), ("SubjectUserName", subj[1]),
        ("SubjectDomainName", subj[2]), ("SubjectLogonId", subj[3]),
        ("TargetUserSid", "S-1-0-0"), ("TargetUserName", target_sam),
        ("TargetDomainName", "CORP"), ("Status", status),
        ("FailureReason", reason), ("SubStatus", sub),
        ("LogonType", str(logon_type)),
        ("LogonProcessName", lpn),
        ("AuthenticationPackageName", pkg),
        ("WorkstationName", src_wks), ("TransmittedServices", "-"),
        ("LmPackageName", "-"), ("KeyLength", "0"),
        ("ProcessId", pid), ("ProcessName", pname),
        ("IpAddress", src_ip),
        ("IpPort", str(ip_port if ip_port is not None else b.rng.randint(49152, 65535)) if src_ip not in ("-", "127.0.0.1") else "0"),
    ]
    return b.add_event("security", 4625, host, dt, data)


_INTEG_SID = {"Medium": "S-1-16-8192", "High": "S-1-16-12288",
              "System": "S-1-16-16384", "Low": "S-1-16-4096"}


def sec_4688(b, dt, host, actor_sam, new_proc, cmdline, parent_proc,
             token="%%1936", integrity="Medium", actor_domain="CORP", tag=None,
             parent_tag=None):
    dt = b.tj(dt)
    pp = b.proc(host, parent_proc, parent_tag if parent_tag is not None
                 else "shell-" + actor_sam, user=actor_sam)
    np = b.proc(host, new_proc, _auto_tag(b, tag), user=actor_sam,
                parent=pp["key"], integrity=integrity, cmdline=cmdline)
    lid = (b.sess(host, actor_sam, dt) if actor_domain == "CORP"
           else "0x3e7")
    mand = _INTEG_SID.get(integrity, integrity)
    data = [
        ("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
        ("SubjectDomainName", actor_domain), ("SubjectLogonId", lid),
        ("NewProcessId", "0x%x" % np["pid"]), ("NewProcessName", new_proc),
        ("TokenElevationType", token), ("ProcessId", "0x%x" % pp["pid"]),
        ("CommandLine", cmdline), ("TargetUserSid", "S-1-0-0"),
        ("TargetUserName", "-"), ("TargetDomainName", "-"),
        ("TargetLogonId", "0x0"), ("ParentProcessName", parent_proc),
        ("MandatoryLabel", mand),
    ]
    return b.add_event("security", 4688, host, dt, data)


def sec_4672(b, dt, host, actor_sam):
    dt = b.tj(dt)
    data = [("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
            ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", b.sess(host, actor_sam, dt)),
            ("PrivilegeList", "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeDebugPrivilege")]
    return b.add_event("security", 4672, host, dt, data)


def new_acct_sid(new_sam):
    if new_sam in A.USERS:
        return A.USERS[new_sam]["sid"]
    return A.DOMAIN_SID + "-" + str(1300 + (_stable(new_sam) % 600))


def _stable(x):
    h = 0
    for c in x:
        h = (h * 131 + ord(c)) & 0xffffffff
    return h


def sec_4720(b, dt, host, new_sam, creator_sam, local_host=None):
    dt = b.tj(dt)
    dom = local_host if local_host else "CORP"
    data = [
        ("TargetUserName", new_sam), ("TargetDomainName", dom),
        ("TargetSid", new_acct_sid(new_sam)),
        ("SubjectUserSid", _sid(creator_sam)), ("SubjectUserName", creator_sam),
        ("SubjectDomainName", "CORP"),
        ("SubjectLogonId", b.sess(host, creator_sam, dt)),
        ("SamAccountName", new_sam), ("DisplayName", "%%1793"),
        ("UserPrincipalName", f"{new_sam}@{A.DNS_SUFFIX}" if not local_host else "-"),
    ]
    return b.add_event("security", 4720, host, dt, data)


def sec_4732(b, dt, host, member_sid, group, actor_sam, local_host=None):
    dt = b.tj(dt)
    data = [
        ("MemberName", "-"), ("MemberSid", member_sid),
        ("TargetUserName", group),
        ("TargetDomainName", local_host if local_host else "Builtin"),
        ("TargetSid", "S-1-5-32-544"),
        ("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
        ("SubjectDomainName", "CORP"), ("SubjectLogonId", b.sess(host, actor_sam, dt)),
    ]
    return b.add_event("security", 4732, host, dt, data)


def sec_4728(b, dt, host, member_sid, group_rid, group, actor_sam):
    """Member added to a security-enabled GLOBAL group (e.g. Domain Admins
    -512, Domain Users -513). TargetSid is the domain SID + RID, domain=CORP."""
    dt = b.tj(dt)
    data = [
        ("MemberName", "-"), ("MemberSid", member_sid),
        ("TargetUserName", group), ("TargetDomainName", "CORP"),
        ("TargetSid", A.DOMAIN_SID + "-" + str(group_rid)),
        ("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
        ("SubjectDomainName", "CORP"),
        ("SubjectLogonId", b.sess(host, actor_sam, dt)),
    ]
    return b.add_event("security", 4728, host, dt, data)


def sec_4698(b, dt, host, task_name, actor_sam, command, args=""):
    dt = b.tj(dt)
    xml = (f'<?xml version="1.0" encoding="UTF-16"?>'
           f'<Task><Actions><Exec><Command>{command}</Command>'
           f'<Arguments>{args}</Arguments></Exec></Actions></Task>')
    data = [("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
            ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", b.sess(host, actor_sam, dt)),
            ("TaskName", task_name), ("TaskContent", xml)]
    return b.add_event("security", 4698, host, dt, data)


def sec_4697(b, dt, host, service_name, image_path, actor_sam):
    dt = b.tj(dt)
    data = [("SubjectUserSid", _sid(actor_sam)), ("SubjectUserName", actor_sam),
            ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", b.sess(host, actor_sam, dt)),
            ("ServiceName", service_name), ("ServiceFileName", image_path),
            ("ServiceType", "0x10"), ("ServiceStartType", "3"),
            ("ServiceAccount", "LocalSystem")]
    return b.add_event("security", 4697, host, dt, data)


def sec_4776(b, dt, host, target_sam, src_wks, success=True):
    dt = b.tj(dt)
    data = [("PackageName", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"),
            ("TargetUserName", target_sam), ("Workstation", src_wks),
            ("Status", "0x0" if success else "0xc000006a")]
    return b.add_event("security", 4776, host, dt, data)


def sec_1102(b, dt, host, actor_sam):
    dt = b.tj(dt)
    ud = ('<UserData><LogFileCleared '
          'xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
          f'<SubjectUserSid>{_sid(actor_sam)}</SubjectUserSid>'
          f'<SubjectUserName>{actor_sam}</SubjectUserName>'
          '<SubjectDomainName>CORP</SubjectDomainName>'
          f'<SubjectLogonId>{b.sess(host, actor_sam, dt)}</SubjectLogonId>'
          '</LogFileCleared></UserData>')
    return b.add_event("security", 1102, host, dt, [], userdata_xml=ud)


# ============================ Windows System / App ============================

def sys_7045(b, dt, host, service_name, image_path, start_type="demand start",
             account="LocalSystem", installer="SYSTEM"):
    """7045 System event; <Security UserID> = SID of the installing account."""
    dt = b.tj(dt)
    data = [("ServiceName", service_name), ("ImagePath", image_path),
            ("ServiceType", "user mode service"), ("StartType", start_type),
            ("AccountName", account)]
    return b.add_event("system", 7045, host, dt, data, exec_role="services",
                       security_userid=_sid(installer))


def sys_7036(b, dt, host, service_name, state="running"):
    dt = b.tj(dt)
    data = [("param1", service_name), ("param2", state)]
    return b.add_event("system", 7036, host, dt, data, exec_role="services")


# ============================ PowerShell ============================

def ps_4104(b, dt, host, user_sam, scriptblock, level=5, path=""):
    dt = b.tj(dt)
    data = [("MessageNumber", "1"), ("MessageTotal", "1"),
            ("ScriptBlockText", scriptblock),
            ("ScriptBlockId", "{%08x-%04x-%04x-%04x-%012x}" % (
                b.rng.randrange(0x100000000), b.rng.randrange(0x10000),
                b.rng.randrange(0x10000), b.rng.randrange(0x10000),
                b.rng.randrange(0x1000000000000))),
            ("Path", path)]
    return b.add_event("powershell", 4104, host, dt, data, level=level,
                       exec_role="app")


def ps_4103(b, dt, host, user_sam, payload, command="Invoke-Expression"):
    dt = b.tj(dt)
    data = [("ContextInfo",
             f"        Severity = Informational\n        Host Name = ConsoleHost\n"
             f"        User = CORP\\{user_sam}\n        Command Name = {command}\n"),
            ("UserData", ""), ("Payload", payload)]
    return b.add_event("powershell", 4103, host, dt, data, exec_role="app")


# ============================ WMI-Activity ============================

def wmi_5861(b, dt, host, consumer, filter_name, query,
             namespace="//./root/subscription"):
    dt = b.tj(dt)
    ud = ('<UserData><Operation_ESStoConsumerBinding '
          'xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">'
          f'<Namespace>{namespace}</Namespace>'
          f'<ESS>SELECT * FROM {query}</ESS>'
          f'<CONSUMER>CommandLineEventConsumer="{consumer}"</CONSUMER>'
          f'<PossibleCause>Binding EventFilter: {filter_name}</PossibleCause>'
          '</Operation_ESStoConsumerBinding></UserData>')
    return b.add_event("wmi", 5861, host, dt, [], userdata_xml=ud,
                       exec_role="app")


# ============================ Sysmon ============================

def _ut(dt):
    return __import__("gen.timeutil", fromlist=["x"]).sysmon_utctime(dt)


def _auto_tag(b, tag):
    """Default process instance: inside a scenario group the same image on the
    same host IS the same process (one GUID/PID across EIDs); in noise each
    call is a new short-lived process unless the caller passes a tag."""
    if tag is not None:
        return tag
    if b.in_scen and b._anchor is not None:
        return "g%d" % b._gid
    return "auto%d" % b._new_uid()


def _sm_common(b, dt, proc):
    # v4.1: dt is already jittered by the caller; Sysmon stamps UtcTime when
    # the activity happens and TimeCreated a few ms later when it is logged
    dt = dt - datetime.timedelta(milliseconds=b.trng.randint(1, 12))
    return [("RuleName", "-"), ("UtcTime", _ut(dt)),
            ("ProcessGuid", proc["guid"]), ("ProcessId", str(proc["pid"]))]


def sm1(b, dt, host, image, cmdline, user_sam, parent_image, parent_cmd,
        md5=None, sha256=None, integrity="Medium",
        current_dir=r"C:\Windows\system32" "\\", orig_name=None,
        company="Microsoft Corporation", description="", product="Microsoft Windows",
        tag=None, parent_tag=None):
    dt = b.tj(dt)
    pproc = b.proc(host, parent_image, parent_tag if parent_tag is not None
                   else "shell-" + user_sam, user=user_sam)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam,
                  parent=pproc["key"], integrity=integrity, cmdline=cmdline)
    b._procmeta[proc["key"]]["parent"] = pproc["key"]
    b.touch(pproc, dt)
    b.touch(proc, dt, eid1=True)
    h = b.img_hash(image)
    md5 = md5 or h["md5"]; sha256 = sha256 or h["sha256"]
    orig = orig_name or image.rsplit("\\", 1)[-1]
    lg = ("0x3e7" if user_sam == "SYSTEM" else "0x3e5" if user_sam == "LOCAL SERVICE"
          else b.sess(host, user_sam, dt))
    data = _sm_common(b, dt, proc) + [
        ("Image", image), ("FileVersion", "10.0.19041.1"),
        ("Description", description), ("Product", product),
        ("Company", company), ("OriginalFileName", orig),
        ("CommandLine", cmdline), ("CurrentDirectory", current_dir),
        ("User", _acct(user_sam)),
        ("LogonGuid", b.logon_guid(host, lg)),
        ("LogonId", lg),
        ("TerminalSessionId", "1" if integrity != "System" else "0"),
        ("IntegrityLevel", integrity),
        ("Hashes", f"MD5={md5},SHA256={sha256}"),
        ("ParentProcessGuid", pproc["guid"]),
        ("ParentProcessId", str(pproc["pid"])), ("ParentImage", parent_image),
        ("ParentCommandLine", parent_cmd),
        ("ParentUser", _acct(b._procmeta[pproc["key"]].get("user") or user_sam)),
    ]
    return b.add_event("sysmon", 1, host, dt, data)


def sm3(b, dt, host, image, user_sam, src_ip, src_port, dst_ip, dst_port,
        proto="tcp", dst_host="-", initiated="true", tag=None):
    dt = b.tj(dt)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam)
    b.touch(proc, dt)
    src_host = A.host_by_ip(src_ip) or host
    data = _sm_common(b, dt, proc) + [
        ("Image", image), ("User", _acct(user_sam)), ("Protocol", proto),
        ("Initiated", initiated), ("SourceIsIpv6", "false"),
        ("SourceIp", src_ip),
        ("SourceHostname", (A.fqdn(src_host) if src_host in A.HOSTS else "-")),
        ("SourcePort", str(src_port)), ("SourcePortName", "-"),
        ("DestinationIsIpv6", "false"), ("DestinationIp", dst_ip),
        ("DestinationHostname", dst_host), ("DestinationPort", str(dst_port)),
        ("DestinationPortName", "-")]
    return b.add_event("sysmon", 3, host, dt, data)


def sm7(b, dt, host, image, loaded, signed="true", signature="Microsoft Corporation",
        sha256=None, tag=None, user_sam=None):
    dt = b.tj(dt)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam)
    b.touch(proc, dt)
    data = _sm_common(b, dt, proc) + [
        ("Image", image), ("ImageLoaded", loaded), ("FileVersion", "10.0.19041.1"),
        ("Description", "-"), ("Product", "-"), ("Company", signature),
        ("OriginalFileName", loaded.rsplit("\\", 1)[-1]),
        ("Hashes", f"SHA256={b.img_hash(loaded)['sha256']}"),
        ("Signed", signed), ("Signature", signature),
        ("SignatureStatus", "Valid" if signed == "true" else "Unavailable"),
        ("User", _acct(user_sam or b._procmeta[proc["key"]].get("user") or "SYSTEM"))]
    return b.add_event("sysmon", 7, host, dt, data)


def sm8(b, dt, host, src_image, tgt_image, src_user="SYSTEM", tag=None):
    dt = b.tj(dt)
    sp = b.proc(host, src_image, _auto_tag(b, tag), user=src_user)
    tp = b.proc(host, tgt_image, _auto_tag(b, None))
    b.touch(sp, dt); b.touch(tp, dt)
    data = [("RuleName", "-"), ("UtcTime", _ut(dt)),
            ("SourceProcessGuid", sp["guid"]),
            ("SourceProcessId", str(sp["pid"])), ("SourceImage", src_image),
            ("TargetProcessGuid", tp["guid"]),
            ("TargetProcessId", str(tp["pid"])), ("TargetImage", tgt_image),
            ("NewThreadId", str(b._mult4(1000, 9000))),
            ("StartAddress", "0x" + "".join(b.rng.choice("0123456789ABCDEF") for _ in range(12))),
            ("StartModule", "-"), ("StartFunction", "-")]
    return b.add_event("sysmon", 8, host, dt, data)


def sm10(b, dt, host, src_image, tgt_image, granted, src_user, tgt_user="SYSTEM",
         call_trace=None, tag=None, legit=False):
    dt = b.tj(dt)
    sp = b.proc(host, src_image, _auto_tag(b, tag), user=src_user)
    b.touch(sp, dt)
    is_lsass = tgt_image.lower().endswith("lsass.exe")
    tp = b.lsass(host) if is_lsass else b.proc(host, tgt_image, "")
    if not is_lsass:
        b.touch(tp, dt)
    tpid, tguid = tp["pid"], tp["guid"]
    if call_trace is None:
        if legit:
            call_trace = (r"C:\WINDOWS\SYSTEM32\ntdll.dll+9d2e4|"
                          r"C:\WINDOWS\System32\KERNELBASE.dll+2b3cd|"
                          r"C:\Windows\System32\wbem\wbemcore.dll+1a40")
        else:
            call_trace = (r"C:\WINDOWS\SYSTEM32\ntdll.dll+9d2e4|"
                          r"C:\WINDOWS\System32\KERNELBASE.dll+2b3cd|"
                          f"UNKNOWN({'0x%x' % b.rng.randrange(0x10000000, 0x7fffffff)})")
    data = [("RuleName", "-"), ("UtcTime", _ut(dt)),
            ("SourceProcessGUID", sp["guid"]),
            ("SourceProcessId", str(sp["pid"])),
            ("SourceThreadId", str(b._mult4(1000, 9000))),
            ("SourceImage", src_image),
            ("TargetProcessGUID", tguid),
            ("TargetProcessId", str(tpid)), ("TargetImage", tgt_image),
            ("GrantedAccess", granted), ("CallTrace", call_trace),
            ("SourceUser", _acct(src_user)),
            ("TargetUser", f"NT AUTHORITY\\{tgt_user}")]
    return b.add_event("sysmon", 10, host, dt, data)


def sm11(b, dt, host, image, target_file, user_sam, sha256=None, tag=None):
    dt = b.tj(dt)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam)
    b.touch(proc, dt)
    data = _sm_common(b, dt, proc) + [
        ("Image", image), ("TargetFilename", target_file),
        ("CreationUtcTime", _ut(dt)), ("User", _acct(user_sam))]
    return b.add_event("sysmon", 11, host, dt, data)


def sm13(b, dt, host, image, target_object, details, user_sam, tag=None):
    dt = b.tj(dt)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam)
    b.touch(proc, dt)
    data = _sm_common(b, dt, proc) + [
        ("EventType", "SetValue"), ("Image", image),
        ("TargetObject", target_object), ("Details", details),
        ("User", _acct(user_sam))]
    return b.add_event("sysmon", 13, host, dt, data)


def sm22(b, dt, host, image, query_name, query_results, user_sam, status="0",
         tag=None):
    dt = b.tj(dt)
    proc = b.proc(host, image, _auto_tag(b, tag), user=user_sam)
    b.touch(proc, dt)
    data = _sm_common(b, dt, proc) + [
        ("QueryName", query_name), ("QueryStatus", status),
        ("QueryResults", query_results), ("Image", image),
        ("User", _acct(user_sam))]
    return b.add_event("sysmon", 22, host, dt, data)


# ============================ network-device line builders ============================
from . import emit as _E
import uuid as _uuid


_PAN_ZONE_IF = {"trust": "ethernet1/2", "untrust": "ethernet1/1",
                "dmz": "ethernet1/3", "mgmt": "ethernet1/4"}


def _pan_loc(ip_):
    if ip_.startswith("10."):
        return "10.0.0.0-10.255.255.255"
    return "US"


def pan_traffic(b, dt, device_key, subtype, src_host_or_ip, dst_ip, app, action,
                dport, suser="", end_reason="tcp-fin", bsent=None, brecv=None,
                category="any", szone=None, dzone=None,
                outbound=True, dcountry="US", sport=None, rule=None,
                elapsed=None, fgt_pair=True):
    """PAN-OS TRAFFIC. v4 topology: PA-CORE/PA-DMZ never NAT (internet SNAT
    is done by FGT-EDGE), so natsrc/natdst are 0.0.0.0 and nat ports 0. The
    original sport is shared with the FGT-EDGE record of the same flow."""
    dt = b.tj(dt)
    dev = A.DEVICES[device_key]
    src = A.ip(src_host_or_ip) if src_host_or_ip in A.HOSTS else src_host_or_ip
    sport = sport if sport is not None else b.rng.randint(49152, 65535)
    if szone is None:
        szone = "trust" if src.startswith("10.") else "untrust"
    if dzone is None:
        dzone = ("untrust" if not dst_ip.startswith("10.") else
                 "dmz" if dst_ip.startswith("10.20.40.") else "trust")
    deny = action in ("deny", "drop", "reset-both")
    if deny:
        # denied/incomplete: SYN only, no reply
        bsent = 60 + b.rng.choice([0, 0, 6, 14]); brecv = 0
        ps, pr = 1, 0
        app = "incomplete" if app in ("incomplete", None) else app
    else:
        bsent = bsent if bsent is not None else b.rng.randint(400, 4000)
        brecv = brecv if brecv is not None else b.rng.randint(400, 40000)
        ps = max(3, bsent // 512); pr = max(3, brecv // 512)
    if elapsed is None:
        elapsed = 0 if deny else b.rng.randint(1, 300)
    sess = b.rng.randint(100000, 999999)
    seq = b.rng.randint(7_000_000, 7_999_999)
    rule = rule or ("allow-outbound" if (action == "allow" and dzone == "untrust")
                    else "allow-internal" if action == "allow"
                    else "deny-default")
    line = _E.panos_traffic(
        dt, device_key, dev["serial"],
        subtype, src, dst_ip, "0.0.0.0", "0.0.0.0", 0, 0,
        rule, suser, "", app, dev["vsys"], szone, dzone,
        _PAN_ZONE_IF.get(szone, "ethernet1/2"), _PAN_ZONE_IF.get(dzone, "ethernet1/1"),
        sess, sport, dport, "tcp", action, 0, bsent, brecv,
        ps, pr, category, seq, _pan_loc(src),
        dcountry if not dst_ip.startswith("10.") else _pan_loc(dst_ip), end_reason,
        elapsed=0 if deny else elapsed)
    ref = b.add_line("pan_traffic", line, dt=dt)
    # same flow continues through FGT-EDGE, which does the internet SNAT;
    # emit its record with identical 5-tuple / bytes / duration (NAT fix)
    if (fgt_pair and device_key == "PA-CORE" and not deny
            and src.startswith("10.") and not dst_ip.startswith("10.")):
        svc = {443: "HTTPS", 80: "HTTP", 53: "DNS", 22: "SSH", 25: "SMTP",
               8443: "tcp/8443"}.get(dport, f"tcp/{dport}")
        fapp = {"ssl": "SSL", "web-browsing": "HTTP.BROWSER", "dns": "DNS",
                "ssh": "SSH", "smtp": "SMTP"}.get(app, (app or "unknown").upper())
        fgt(b, dt + datetime.timedelta(milliseconds=b.trng.randint(1, 40)),
            "FGT-EDGE", "traffic", "forward", "notice", src, dst_ip, dport,
            "accept", svc, fapp, "Web.Client" if dport in (80, 443) else "Network.Service",
            sentbyte=bsent, rcvdbyte=brecv, duration=elapsed, sport=sport,
            dstcountry={"US": "United States", "SG": "Singapore", "DE": "Germany",
                        "NL": "Netherlands", "RU": "Russian Federation"}.get(dcountry, "United States"))
    # inbound to the DMZ first passes FGT-EDGE, which DNATs the public VIP to
    # the server address and forwards to PA-DMZ (which enforces policy)
    if (fgt_pair and device_key == "PA-DMZ" and not src.startswith("10.")
            and dst_ip in _VIP_BY_IP):
        fgt(b, dt - datetime.timedelta(milliseconds=b.trng.randint(1, 30)),
            "FGT-EDGE", "traffic", "forward", "notice", src, _VIP_BY_IP[dst_ip],
            dport, "accept", {80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP"}.get(dport, f"tcp/{dport}"),
            "unknown" if deny else {80: "HTTP.BROWSER", 443: "HTTPS", 22: "SSH",
                                    3389: "RDP"}.get(dport, "unknown"),
            "Network.Service",
            sentbyte=bsent, rcvdbyte=brecv, duration=0 if deny else elapsed,
            sport=sport, srccountry="United States", outbound=False,
            dnat_to=dst_ip)
    return ref


_VIP_BY_IP = {A.ip(h): v for h, v in A.VIPS.items()}


# stable PAN ThreatID per threat name (v3 bug: random id per event)
_THREAT_IDS = {}


def threat_id_for(name):
    if name not in _THREAT_IDS:
        _THREAT_IDS[name] = 30000 + (_stable("tid:" + name) % 60000)
    return _THREAT_IDS[name]


def pan_threat(b, dt, device_key, subtype, src_ip, dst_host_or_ip, app, action,
               misc, threat_name, threat_id, category, severity, direction,
               suser="", inbound=True, dport=443, sport=None):
    """PAN-OS THREAT. No NAT on PA (see pan_traffic); ThreatID is stable per
    threat name (threat_id argument kept for call compatibility, ignored)."""
    dt = b.tj(dt)
    dev = A.DEVICES[device_key]
    dst = A.ip(dst_host_or_ip) if dst_host_or_ip in A.HOSTS else dst_host_or_ip
    sport = sport if sport is not None else b.rng.randint(49152, 65535)
    sess = b.rng.randint(100000, 999999)
    seq = b.rng.randint(7_000_000, 7_999_999)
    if inbound:
        szone, dzone = "untrust", ("dmz" if dst.startswith("10.20.40.") else "trust")
    else:
        szone = "trust"
        dzone = "untrust" if not dst.startswith("10.") else (
            "dmz" if dst.startswith("10.20.40.") else "trust")
    rule = ("dmz-inbound" if inbound else
            "allow-outbound" if dzone == "untrust" else "allow-internal")
    line = _E.panos_threat(
        dt, device_key, dev["serial"], subtype, src_ip, dst, "0.0.0.0", "0.0.0.0",
        rule, suser, "", app, dev["vsys"], szone, dzone,
        _PAN_ZONE_IF[szone], _PAN_ZONE_IF[dzone], sess,
        sport, dport, "tcp", action, misc, threat_name, threat_id_for(threat_name),
        category, severity, direction, seq, _pan_loc(src_ip), _pan_loc(dst),
        "text/html" if app in ("web-browsing",) else "-")
    return b.add_line("pan_threat", line, dt=dt)


def fgt(b, dt, device_key, type_, subtype, level, src_host_or_ip, dst_ip, dport,
        action, service, app, appcat, sentbyte=None, rcvdbyte=None, duration=None,
        srccountry="Reserved", dstcountry="United States", outbound=True,
        extra="", sport=None, logid=None, dnat_to=None):
    """FortiGate. Only FGT-EDGE source-NATs internet-bound traffic (to its
    natip); FGT-CORE (east-west) never NATs. sport may be shared with the
    PA-CORE record of the same flow so both devices agree."""
    dt = b.tj(dt)
    dev = A.DEVICES[device_key]
    src = A.ip(src_host_or_ip) if src_host_or_ip in A.HOSTS else src_host_or_ip
    sport = sport if sport is not None else b.rng.randint(49152, 65535)
    deny = action in ("deny", "blocked", "dropped")
    if deny and type_ == "traffic":
        sentbyte, rcvdbyte = 60, 0
    sentbyte = sentbyte if sentbyte is not None else b.rng.randint(400, 4000)
    rcvdbyte = rcvdbyte if rcvdbyte is not None else b.rng.randint(400, 40000)
    if logid is None:
        logid = {"traffic": "0000000013", "utm": "0419016384"}.get(type_, "0000000013")
    sess = b.rng.randint(1_000_000, 9_999_999)
    internet = not str(dst_ip).startswith("10.")
    snat = (device_key == "FGT-EDGE" and internet and type_ == "traffic"
            and not deny and src.startswith("10."))
    trandisp = "snat" if snat else ("dnat" if dnat_to else "noop")
    line = _E.fortigate(
        dt, dev, logid, type_, subtype, level, src, sport,
        "port1" if src.startswith("10.") else "wan1", dst_ip, dport,
        "dmz" if dnat_to else ("wan1" if internet else "port2"), sess, 6, action,
        {"FGT-EDGE": 15, "FGT-CORE": 7}.get(device_key, 1),
        service, srccountry if not src.startswith("10.") else "Reserved",
        dstcountry if (internet and not dnat_to) else "Reserved", app, appcat, sentbyte, rcvdbyte,
        max(3, sentbyte // 512) if not deny else 1,
        max(3, rcvdbyte // 512) if rcvdbyte else 0,
        duration if duration is not None else (0 if deny else b.rng.randint(1, 300)),
        trandisp=trandisp,
        transip=(dev.get("natip", "0.0.0.0") if snat else dnat_to or "0.0.0.0"),
        transport=(b.rng.randint(1024, 65535) if snat else dport if dnat_to else 0),
        extra=extra)
    return b.add_line("fortigate", line, dt=dt)


def cp(b, dt, name_, action, src_ip, dst_ip, dport, rule="Internal-Policy",
       severity="Unknown", extra_pairs=None):
    dt = b.tj(dt)
    pairs = [("act", action), ("src", src_ip), ("dst", dst_ip),
             ("proto", "6"), ("s_port", str(b.rng.randint(49152, 65535))),
             ("service", str(dport)),
             ("ifdir", "inbound"), ("ifname", "eth1"),
             ("cs1Label", "Rule Name"), ("cs1", rule)]
    if extra_pairs:
        pairs += extra_pairs
    return b.add_line("checkpoint", _E.checkpoint_cef(
        dt, "cp-gw01", name_, pairs, origin=A.DEVICES["cp-gw01"]["origin"],
        severity=severity), dt=dt)


# v4.2: F5 virtual servers in front of the two IIS hosts (one ASM policy each)
F5_VS = {"SRV-WEB01": ("/Common/vs_shop_https", "prod_web_asm"),
         "SRV-WEB02": ("/Common/vs_partner_https", "partner_portal_asm")}


def f5(b, dt, pairs, host="SRV-WEB01"):
    """F5 ASM request log. v4.2: carries the virtual server and the pool
    member (dest_ip/dest_port) so a request can be tied to SRV-WEB01/WEB02."""
    dt = b.tj(dt)
    vs, _pol = F5_VS[host]
    out = []
    for k, v in pairs:
        out.append((k, v))
        if k == "policy_name":
            out += [("vs_name", vs), ("dest_ip", A.ip(host)), ("dest_port", "443")]
    pairs = out
    return b.add_line("f5", _E.f5_asm(
        dt, A.DEVICES["bigip-dmz-01"]["unit"], A.DEVICES["bigip-dmz-01"]["mgmt"],
        pairs), dt=dt)


def bind_q(b, dt, client_host_or_ip, qname, qtype="A", flags="+E(0)"):
    dt = b.tj(dt)
    client = A.ip(client_host_or_ip) if client_host_or_ip in A.HOSTS else client_host_or_ip
    return b.add_line("bind", _E.bind_query(
        dt, client, b.rng.randint(1024, 65535), qname, qtype,
        mem="0x%012x" % b.rng.randrange(0x7f0000000000, 0x7fffffffffff),
        flags=flags), dt=dt)


def windns(b, dt, client_host_or_ip, qname, qtype="A", rcode="NOERROR"):
    dt = b.tj(dt)
    client = A.ip(client_host_or_ip) if client_host_or_ip in A.HOSTS else client_host_or_ip
    xid = "%04x" % b.rng.randrange(0x10000)
    return b.add_lines("windns", _E.windns_pair(dt, client, qname, qtype, xid,
                                                rcode=rcode), dt=dt)


def squid(b, dt, client_host_or_ip, method, url, user, bytes_to_client,
          server_ip, content_type="-", result="TCP_MISS/200",
          peer="HIER_DIRECT", elapsed=None):
    dt = b.tj(dt)
    client = A.ip(client_host_or_ip) if client_host_or_ip in A.HOSTS else client_host_or_ip
    if method == "CONNECT":
        if result.startswith("TCP_MISS") or result.startswith("TCP_TUNNEL"):
            result = "TCP_TUNNEL/200"
        content_type = "-"
    if result.startswith("TCP_DENIED"):
        peer, server_ip = "HIER_NONE", "-"
    return b.add_line("squid", _E.squid(
        dt, elapsed if elapsed is not None else b.rng.randint(1, 5000), client,
        result, bytes_to_client, method, url, user, peer, server_ip, content_type), dt=dt)


def docker(b, dt, log_line, stream="stdout"):
    dt = b.tj(dt)
    return b.add_line("docker", _E.docker_json(dt, stream, log_line), dt=dt)


def k8s(b, dt, username, groups, src_ip, verb, resource, subresource, ns, name,
        code, ua, decision="allow", reason="RBAC: allowed", level="Metadata"):
    dt = b.tj(dt)
    aid = str(_uuid.UUID(int=b.rng.getrandbits(128)))
    obj = {"resource": resource, "namespace": ns, "name": name, "apiVersion": "v1"}
    if subresource:
        obj["subresource"] = subresource
    uri = f"/api/v1/namespaces/{ns}/{resource}/{name}"
    if subresource:
        uri += f"/{subresource}"
    return b.add_line("k8s", _E.k8s_audit(
        dt, aid, level, "ResponseComplete", uri, verb, username, groups,
        [src_ip], obj, code, ua, decision=decision, reason=reason), dt=dt)



# ============================ v4: synthesized process creation ============================
_SYS_IMAGES = ("svchost.exe", "msmpeng.exe", "veeamagent.exe", "ccmexec.exe",
               "microsoftedgeupdate.exe", "w3wp.exe", "wmiprvse.exe", "inv.exe",
               "userinit.exe", "sqlservr.exe")
_DEFAULT_CMD = {
    "svchost.exe": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
    "explorer.exe": r"C:\Windows\Explorer.EXE",
    "userinit.exe": r"C:\Windows\system32\userinit.exe",
    "w3wp.exe": 'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "DefaultAppPool"',
    "chrome.exe": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
}


def synth_eid1(b, key, parent_key, dt):
    """Sysmon EID 1 for a process that was observed (EID 3/7/10/11/13/22 or
    as a parent) without an explicit creation record."""
    host, image, tag = key
    m = b._procmeta[key]
    pm = b._procmeta.get(parent_key, {})
    proc = b._procs[key]
    pproc = b._procs[parent_key]
    base = image.rsplit("\\", 1)[-1]
    lb = base.lower()
    user = m.get("user")
    if lb in _SYS_IMAGES or user is None:
        user = "SYSTEM" if lb not in ("explorer.exe",) else (user or "SYSTEM")
    integ = m.get("integrity") or ("System" if user == "SYSTEM" else "Medium")
    cmd = m.get("cmdline") or _DEFAULT_CMD.get(lb, f'"{image}"')
    h = b.img_hash(image)
    puser = pm.get("user") or "SYSTEM"
    if pm.get("root"):
        puser = "SYSTEM"
    pcmd = pm.get("cmdline") or _DEFAULT_CMD.get(
        parent_key[1].rsplit("\\", 1)[-1].lower(), parent_key[1])
    lg = ("0x3e7" if user == "SYSTEM" else b.sess(host, user, dt))
    data = _sm_common(b, dt, proc) + [
        ("Image", image), ("FileVersion", "10.0.19041.1"),
        ("Description", "-"), ("Product", "-"),
        ("Company", "Microsoft Corporation" if image.lower().startswith(
            ("c:\\windows", "c:\\program files\\microsoft", "c:\\program files\\windows"))
            else "-"),
        ("OriginalFileName", base), ("CommandLine", cmd),
        ("CurrentDirectory", "C:\\Windows\\system32\\"),
        ("User", _acct(user)),
        ("LogonGuid", b.logon_guid(host, lg)),
        ("LogonId", lg),
        ("TerminalSessionId", "0" if user == "SYSTEM" else "1"),
        ("IntegrityLevel", integ),
        ("Hashes", f"MD5={h['md5']},SHA256={h['sha256']}"),
        ("ParentProcessGuid", pproc["guid"]),
        ("ParentProcessId", str(pproc["pid"])), ("ParentImage", parent_key[1]),
        ("ParentCommandLine", pcmd), ("ParentUser", _acct(puser)),
    ]
    return b.add_event("sysmon", 1, host, dt, data)


# ---------------- v4.2 DMZ inbound flow helpers ----------------
def rdp_inbound(b, dt_auth, src_ip, host="SRV-RDS01", ok=False, session_s=None):
    """One inbound RDP (NLA) TCP session to a published DMZ host: PA-DMZ
    traffic record (+ FGT-EDGE DNAT twin via pan_traffic). The flow starts
    ~0.3-1.5 s before the Windows authentication event at dt_auth; returns
    the client source port so 4624/4625 IpPort matches the firewall."""
    sport = b.rng.randint(49152, 65535)
    lead = datetime.timedelta(milliseconds=b.rng.randint(300, 1500))
    if ok:
        el = session_s if session_s is not None else b.rng.randint(600, 7200)
        bs, br = b.rng.randint(400_000, 9_000_000), b.rng.randint(2_000_000, 60_000_000)
    else:
        el = b.rng.randint(2, 6)
        bs, br = b.rng.randint(2500, 6000), b.rng.randint(3000, 9000)
    end = dt_auth - lead + datetime.timedelta(seconds=el)
    pan_traffic(b, end, "PA-DMZ", "end", src_ip, A.ip(host), "ms-rdp", "allow",
                3389, outbound=False, rule="dmz-inbound-rdp", sport=sport,
                bsent=bs, brecv=br, elapsed=el, end_reason="tcp-fin")
    return sport


def web_inbound(b, dt_req, src_ip, host="SRV-WEB01", bsent=None, brecv=None):
    """Inbound HTTPS session (client -> F5 VIP -> IIS) recorded by PA-DMZ
    (+ FGT-EDGE DNAT twin); the PAN record is written when the session ends."""
    el = b.rng.randint(1, 45)
    return pan_traffic(b, dt_req + datetime.timedelta(seconds=el), "PA-DMZ", "end",
                       src_ip, A.ip(host), "ssl", "allow", 443, outbound=False,
                       rule="dmz-inbound-web", elapsed=el, bsent=bsent, brecv=brecv)
