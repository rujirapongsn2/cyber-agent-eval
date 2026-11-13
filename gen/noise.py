# -*- coding: utf-8 -*-
"""Multi-day benign background noise (the haystack), v4.

v4 changes (Security Audit round 3):
- Every event TYPE that appears in a case also appears in benign noise:
  4625 (typos / expired / disabled / unknown user), 7045 (driver & agent
  updates), 4720/4728/4732/4698/1102, PAN deny + PAN THREAT low..high,
  F5 blocked/alerted from internet scanners, FortiGate IPS/AV/app-ctrl,
  Check Point IPS/Drop, sshd "Failed password", Squid TCP_DENIED/TCP_TUNNEL,
  Defender detections, PowerShell 4104 warnings, auditd exec records.
- Volumes per type are jittered (no round counts), syslog/auth timestamps are
  independent, Sysmon activity belongs to a per-user-per-day process instance
  (one ProcessGuid), and noise external IPs come from a pool disjoint from
  every case IoC.
- pwadee (onboarded during the window) has activity only AFTER the 4720.
None of these records are referenced by any case. All values are safe.
"""
import datetime
from . import assets as A
from . import evbuilders as EV
from . import timeutil as T

LEGIT_DOMAINS = [
    "www.example.com", "update.example.net", "cdn.example.org",
    "outlook.example.com", "teams.example.net", "portal.example.com",
    "ctldl.windowsupdate.example", "ocsp.example.net", "clients.google.example",
    "api.example.com", "pki.example.org", "ntp.example.net",
    "login.example.net", "files.example.org", "status.example.com",
]
USER_APPS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft\Teams\current\Teams.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
]
SHORT_APPS = [
    (r"C:\Windows\System32\notepad.exe", '"notepad.exe" C:\\Users\\{u}\\Documents\\notes.txt'),
    (r"C:\Windows\System32\cmd.exe", 'cmd.exe /c ipconfig /flushdns'),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     'powershell.exe -NoProfile -Command "Get-Date"'),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
     '"EXCEL.EXE" /e C:\\Users\\{u}\\Documents\\report.xlsx'),
    (r"C:\Windows\System32\mstsc.exe", 'mstsc.exe /v:JUMP01'),
    (r"C:\Program Files\7-Zip\7zFM.exe", '"7zFM.exe"'),
    (r"C:\Windows\System32\rundll32.exe",
     'rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl'),
]
ADMIN_PROCS = [
    (r"C:\Windows\System32\mmc.exe", '"mmc.exe" C:\\Windows\\system32\\dsa.msc'),
    (r"C:\Windows\System32\Taskmgr.exe", '"Taskmgr.exe"'),
    (r"C:\Windows\System32\wbem\WMIC.exe", 'wmic os get lastbootuptime'),
    (r"C:\Program Files\CorpIT\inv.exe", '"inv.exe" /collect'),
    (r"C:\Windows\System32\net.exe", 'net group "Domain Admins" /domain'),
    (r"C:\Windows\System32\sc.exe", 'sc query Spooler'),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     'powershell.exe -ExecutionPolicy Bypass -File C:\\CorpIT\\Scripts\\health.ps1'),
]
WKS = [f"WKS-GEN-{i:03d}" for i in range(1, 41)] + \
      ["WKS-FIN-07", "WKS-HR-03", "WKS-DEV-11", "WKS-SALES-22"]
SRVS = ["SRV-FILE01", "SRV-APP01", "SRV-SQL01", "SRV-DC01", "SRV-MAIL01"]
DMZ_WEB = ["SRV-WEB01", "SRV-WEB02"]
ALL_WIN_SERVERS = sorted(h for h, m in A.HOSTS.items()
                         if m.get("os") == "windows" and m.get("role") != "wks")
# v4.1: every workstation's primary user generates background activity, so
# telemetry (Security + Sysmon) covers all 44 workstations at a similar level
NOISE_USERS = [u for u in sorted(A.HOME) if u != "pwadee"]
ADMINS = ["adm_kitti", "helpdesk"]
SVC = ["svc_sql", "svc_backup", "svc_sccm", "svc_report", "svc_deploy",
       "svc_etl", "svc_monitor"]
DEVS = ["ddeep", "cdao", "kchai"]
# v4.2: service accounts log on (type 5) only where their service runs
SVC_BY_HOST = {
    "JUMP01": ["svc_monitor", "svc_sccm"],
    "SRV-APP01": ["svc_deploy", "svc_monitor", "svc_backup", "svc_etl"],
    "SRV-BACKUP01": ["svc_backup", "svc_monitor"],
    "SRV-DC01": ["svc_backup", "svc_monitor"],
    "SRV-FILE01": ["svc_backup", "svc_sccm", "svc_monitor"],
    "SRV-MAIL01": ["svc_backup", "svc_monitor"],
    "SRV-MON01": ["svc_monitor"],
    "SRV-RDS01": ["svc_monitor", "svc_sccm"],
    "SRV-SCCM01": ["svc_sccm", "svc_deploy", "svc_sql"],
    "SRV-SQL01": ["svc_sql", "svc_backup", "svc_report", "svc_etl", "svc_monitor"],
    "SRV-WEB01": ["svc_deploy", "svc_monitor"],
    "SRV-WEB02": ["svc_deploy", "svc_monitor"],
    "VULNSCAN01": ["svc_monitor"],
}
# v4.2: published DMZ hosts and the ports their internet-facing deny noise hits
DMZ_PUBLISHED = ["SRV-WEB01", "SRV-WEB01", "SRV-WEB02", "SRV-RDS01"]
PARTNERS = ["partner_logistics", "partner_bank", "partner_supplier1",
            "partner_supplier2", "partner_insure", "partner_edi_hub"]
PARTNER_URIS = ["/partner/api/v2/orders", "/partner/api/v2/orders/status",
                "/partner/api/v2/invoices", "/partner/login", "/partner/edi/upload",
                "/partner/api/v2/shipments", "/partner/static/portal.js",
                "/partner/api/v2/catalog?page=%d"]


_WIN_END = datetime.datetime(2026, 11, 12, 23, 59, 0, tzinfo=T.ORG_TZ).astimezone(T.UTC)


def _dmz_target(rng):
    return rng.choice(DMZ_PUBLISHED)


def _home(u):
    return A.HOME[u]


def NX(name):
    return A.alloc_ext(name, noise=True)


def _rand_dom(rng):
    if rng.random() < 0.45:
        w1 = rng.choice(["cdn", "assets", "edge", "static", "img", "pkg", "api",
                         "mail", "share", "up", "bak", "mirror"])
        w2 = rng.choice(["edge-net", "cdn-assets", "akamai-edge", "fastly-net",
                         "pkg-mirror", "corp-cdn", "cloud-share", "static-cdn",
                         "update-check", "telemetry-node", "login-portal"])
        return f"{w1}-{rng.randint(0, 0xffff):04x}.{w2}.example"
    return rng.choice(LEGIT_DOMAINS)


def _jit(day, rng, start_h=7, end_h=20):
    h = rng.randint(start_h, end_h)
    m = rng.randint(0, 59); s = rng.randint(0, 59); us = rng.randint(0, 999) * 1000
    local = datetime.datetime(day.year, day.month, day.day, h, m, s, us,
                              tzinfo=T.ORG_TZ)
    return local.astimezone(T.UTC)


def _n(rng, base):
    """Jittered count (avoid round per-type volumes)."""
    return max(1, int(round(base * rng.uniform(0.82, 1.18))))


def generate(b, days=(datetime.date(2026, 11, 9), datetime.date(2026, 11, 10),
                      datetime.date(2026, 11, 11), datetime.date(2026, 11, 12)),
             scale=1):
    rng = b.rng
    b.in_scen = False
    n = 0
    pw_created = b.created_accounts.get("pwadee")

    def users_at(dtv):
        us = list(NOISE_USERS)
        if pw_created is not None and dtv > pw_created + datetime.timedelta(minutes=120):
            us.append("pwadee")
        return us

    def pick_user(dtv):
        return rng.choice(users_at(dtv))

    for day in days:
        dtag = day.strftime("%m%d")
        for (sh, eh, w) in [(7, 19, 6), (19, 23, 1), (0, 6, 1)]:
            k = w * scale
            # --- Windows logon / logoff (interactive, unlock, cached) ---
            for _ in range(_n(rng, 55 * k)):
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                lt = rng.choice([2, 2, 2, 7, 11])
                if b.find_session(wk, u, dtv) is not None:
                    continue          # already logged on: no second session
                _r, lid = EV.sec_4624(b, dtv, wk, u, lt)
                EV.sec_4634(b, dtv + datetime.timedelta(minutes=rng.randint(20, 400)),
                            wk, u, lt, lid)
                n += 2
            # network logons to servers, Kerberos AND NTLM
            for _ in range(_n(rng, 38 * k)):
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                srv = rng.choice(SRVS)
                auth = "NTLM" if rng.random() < 0.3 else "Kerberos"
                _r, nlid = EV.sec_4624(b, dtv, srv, u, 3, A.ip(wk), wk, auth=auth)
                if rng.random() < 0.65:   # network sessions close quickly
                    EV.sec_4634(b, dtv + datetime.timedelta(seconds=rng.randint(2, 90)),
                                srv, u, 3, nlid)
                    n += 1
                if auth == "NTLM":
                    EV.sec_4776(b, dtv, "SRV-DC01", u, wk)
                    n += 1
                n += 1
            # failed logons: typos / expired / disabled / unknown user
            for _ in range(_n(rng, 9 * k)):
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                kind = rng.random()
                if kind < 0.55:      # typo at the console, then success
                    EV.sec_4625(b, dtv, wk, u, 2, "127.0.0.1", wk,
                                substatus="0xc000006a", auth="Negotiate")
                    EV.sec_4624(b, dtv + datetime.timedelta(seconds=rng.randint(6, 50)),
                                wk, u, 2)
                    n += 2
                elif kind < 0.75:    # stale mapped drive after pw change
                    EV.sec_4625(b, dtv, rng.choice(SRVS), u, 3, A.ip(wk), wk,
                                substatus=rng.choice(["0xc000006a", "0xc0000071"]),
                                auth="NTLM")
                    n += 1
                elif kind < 0.9:     # disabled / leaver account on a shared PC
                    EV.sec_4625(b, dtv, wk, rng.choice(["tmp_vendor01", "old_intern3"]),
                                2, "127.0.0.1", wk, substatus="0xc0000072",
                                auth="Negotiate")
                    n += 1
                else:                # mistyped user name
                    EV.sec_4625(b, dtv, rng.choice(SRVS), u[:-1] + "x", 3,
                                A.ip(wk), wk, user_exists=False, auth="NTLM")
                    n += 1
            # service logons (type 5)
            for _ in range(_n(rng, 10 * k)):
                sa = rng.choice(SVC); srv = rng.choice(SRVS)
                EV.sec_4624(b, _jit(day, rng, sh, eh), srv, sa, 5)
                n += 1
            # admin RDP (type 10) + 4672 via JUMP01; FGT-CORE sees the session
            for _ in range(_n(rng, 7 * k)):
                adm = rng.choice(ADMINS); srv = rng.choice(SRVS)
                dtv = _jit(day, rng, sh, eh)
                _r, rlid = EV.sec_4624(b, dtv, srv, adm, 10, A.ip("JUMP01"), "JUMP01",
                                       auth="Negotiate")
                EV.sec_4672(b, dtv, srv, adm)
                EV.sec_4634(b, dtv + datetime.timedelta(minutes=rng.randint(8, 150)),
                            srv, adm, 10, rlid)
                EV.fgt(b, dtv, "FGT-CORE", "traffic", "forward", "notice", "JUMP01",
                       A.ip(srv), 3389, "accept", "RDP", "RDP", "Remote.Access",
                       outbound=False)
                n += 3

            # --- 4688 process creation ---
            for _ in range(_n(rng, 34 * k)):
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                img, cmd = rng.choice(SHORT_APPS)
                EV.sec_4688(b, dtv, wk, u, img, cmd.replace("{u}", u), EXPL_,
                            integrity="Medium")
                n += 1
            for _ in range(_n(rng, 8 * k)):
                adm = rng.choice(ADMINS); srv = rng.choice(SRVS)
                img, cmd = rng.choice(ADMIN_PROCS)
                EV.sec_4688(b, _jit(day, rng, sh, eh), srv, adm, img, cmd, EXPL_,
                            integrity="High")
                n += 1

            # --- Sysmon (one process instance per user/app/day) ---
            for _ in range(_n(rng, 26 * k)):          # EID 1 short-lived
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                img, cmd = rng.choice(SHORT_APPS)
                EV.sm1(b, dtv, wk, img, cmd.replace("{u}", u), u, EXPL_,
                       r"C:\Windows\Explorer.EXE", integrity="Medium")
                n += 1
            for _ in range(_n(rng, 30 * k)):          # EID 3
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                app = rng.choice(USER_APPS[:3] + USER_APPS[5:])
                dom = _rand_dom(rng)
                EV.sm3(b, dtv, wk, app, u, A.ip(wk), rng.randint(49152, 65535),
                       NX("legit_" + dom), 443, dst_host=dom, tag=f"{u}-{dtag}")
                n += 1
            for _ in range(_n(rng, 5 * k)):           # EID 3 SMB by System
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                srv = rng.choice(["SRV-FILE01", "SRV-APP01"])
                EV.sm3(b, dtv, wk, "System", "SYSTEM", A.ip(wk),
                       rng.randint(49152, 65535), A.ip(srv), 445,
                       dst_host=A.fqdn(srv), tag="")
                n += 1
            for _ in range(_n(rng, 18 * k)):          # EID 7
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                EV.sm7(b, dtv, wk, rng.choice(USER_APPS),
                       rng.choice([r"C:\Windows\System32\msvcp140.dll",
                                   r"C:\Windows\System32\kernel32.dll",
                                   r"C:\Windows\System32\user32.dll",
                                   r"C:\Windows\System32\comsvcs.dll",
                                   r"C:\Windows\System32\wininet.dll"]),
                       tag=f"{u}-{dtag}", user_sam=u)
                n += 1
            for _ in range(_n(rng, 11 * k)):          # EID 10 lsass by AV/backup
                hh = rng.choice(SRVS + WKS)
                if rng.random() < 0.6:
                    EV.sm10(b, _jit(day, rng, sh, eh), hh,
                            r"C:\Program Files\Windows Defender\MsMpEng.exe",
                            r"C:\Windows\System32\lsass.exe",
                            rng.choice(["0x1000", "0x1400", "0x1410"]), "SYSTEM",
                            legit=True, tag="boot")
                else:
                    EV.sm10(b, _jit(day, rng, sh, eh), hh,
                            r"C:\Program Files\Veeam\Backup\VeeamAgent.exe",
                            r"C:\Windows\System32\lsass.exe",
                            rng.choice(["0x1000", "0x1010"]), "svc_backup",
                            legit=True, tag="boot")
                n += 1
            for _ in range(_n(rng, 19 * k)):          # EID 11
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                if rng.random() < 0.7:
                    EV.sm11(b, dtv, wk, USER_APPS[3],
                            rf"C:\Users\{u}\Documents\doc{rng.randint(1, 999)}.docx", u,
                            tag=f"{u}-{dtag}")
                else:
                    EV.sm11(b, dtv, wk, USER_APPS[0],
                            rf"C:\Users\{u}\Downloads\file{rng.randint(1, 999)}.pdf", u,
                            tag=f"{u}-{dtag}")
                n += 1
            for _ in range(_n(rng, 14 * k)):          # EID 13 (user Run keys)
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                key, val = rng.choice([
                    ("OneDrive", r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'),
                    ("com.squirrel.Teams.Teams", r'"C:\Program Files\Microsoft\Teams\current\Teams.exe" --process-start-args "--system-initiated"')])
                EV.sm13(b, dtv, wk, USER_APPS[5] if key == "OneDrive" else USER_APPS[2],
                        "HKU\\" + A.USERS[u]["sid"] +
                        r"\Software\Microsoft\Windows\CurrentVersion\Run" + "\\" + key,
                        val, u, tag=f"{u}-{dtag}")
                n += 1
            for _ in range(_n(rng, 22 * k)):          # EID 22
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                dom = _rand_dom(rng)
                EV.sm22(b, dtv, wk, rng.choice(USER_APPS[:3]), dom,
                        f"type: 5 {dom};::ffff:{NX('legit_' + dom)}", u,
                        tag=f"{u}-{dtag}")
                n += 1

            # --- firewalls / proxy / dns ---
            for _ in range(_n(rng, 29 * k)):  # outbound web: PA-CORE + FGT-EDGE same flow
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                dom = _rand_dom(rng); ext = NX("legit_" + dom)
                sp = rng.randint(49152, 65535)
                bs = rng.randint(400, 4000); br = rng.randint(400, 40000)
                el = rng.randint(1, 300)
                EV.bind_q(b, dtv, wk, dom, "A")
                EV.pan_traffic(b, dtv, "PA-CORE", "end", wk, ext, "ssl", "allow",
                               443, suser=f"corp\\{u}", sport=sp, bsent=bs,
                               brecv=br, elapsed=el)   # + FGT-EDGE SNAT twin

                n += 3
            for _ in range(_n(rng, 6 * k)):   # internal allow / deny on PA-CORE
                dtv = _jit(day, rng, sh, eh)
                wk = rng.choice(WKS)
                if rng.random() < 0.55:
                    EV.pan_traffic(b, dtv, "PA-CORE", "deny", wk,
                                   A.ip(rng.choice(["SRV-SQL01", "SRV-DC01", "JUMP01"])),
                                   "incomplete", "deny", rng.choice([1433, 3389, 22, 5985]),
                                   outbound=False, end_reason="policy-deny")
                else:
                    EV.pan_traffic(b, dtv, "PA-CORE", "end", wk,
                                   A.ip(rng.choice(["SRV-FILE01", "SRV-APP01"])),
                                   rng.choice(["ms-ds-smb", "web-browsing"]), "allow",
                                   rng.choice([445, 443]), outbound=False)
                n += 1
            for _ in range(_n(rng, 11 * k)):  # proxy GET/POST/CONNECT
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                dom = _rand_dom(rng); ext = NX("legit_" + dom)
                meth = rng.choice(["GET", "GET", "POST", "CONNECT", "CONNECT"])
                if meth == "CONNECT":
                    EV.squid(b, dtv, wk, meth, f"{dom}:443", u,
                             rng.randint(500, 400000), ext)
                else:
                    EV.squid(b, dtv, wk, meth,
                             f"https://{dom}/api/v1/{rng.choice(['submit', 'upload', 'sync', 'telemetry', 'u', 'items'])}",
                             u, rng.randint(200, 400000), ext,
                             content_type=rng.choice(["application/json", "text/html",
                                                      "image/png", "application/octet-stream"]),
                             result=rng.choice(["TCP_MISS/200", "TCP_MISS/200",
                                                "TCP_HIT/200", "TCP_MISS/304"]))
                n += 1
            for _ in range(_n(rng, 3 * k)):   # proxy category denies (benign policy)
                dtv = _jit(day, rng, sh, eh); u = pick_user(dtv); wk = _home(u)
                dom = rng.choice(["video-stream.example", "games.example",
                                  "torrent-index.example", _rand_dom(rng)])
                EV.squid(b, dtv, wk, rng.choice(["CONNECT", "GET"]),
                         f"{dom}:443" if rng.random() < 0.6 else f"http://{dom}/",
                         u, 0, NX("legit_" + dom), result="TCP_DENIED/403")
                n += 1
            for _ in range(_n(rng, 9 * k)):   # FGT-EDGE webfilter deny (ads)
                wk = rng.choice(WKS)
                EV.fgt(b, _jit(day, rng, sh, eh), "FGT-EDGE", "utm", "webfilter",
                       "warning", wk, NX("adblock" + str(rng.randint(1, 9))),
                       80, "blocked", "HTTP", "HTTP.BROWSER", "Web.Client",
                       extra='cat=17 catdesc="Advertising" crlevel="low"')
                n += 1
            for _ in range(_n(rng, 2 * k)):   # FGT app-ctrl / NOD notice
                wk = rng.choice(WKS); dom = _rand_dom(rng)
                EV.fgt(b, _jit(day, rng, sh, eh), "FGT-EDGE", "utm",
                       rng.choice(["app-ctrl", "webfilter"]), "notice", wk,
                       NX("legit_" + dom), rng.choice([443, 8443, 80]), "pass",
                       "HTTPS", "Unknown.TCP" if rng.random() < 0.4 else "HTTPS.BROWSER",
                       "unknown", logid="1059028704",
                       extra=f'hostname="{dom}" crlevel="low"')
                n += 1
            for _ in range(_n(rng, 8 * k)):   # check point internal rules
                rule, port = rng.choice([("Internal-FileShare", 445), ("Internal-DNS", 53),
                                         ("Internal-SMB", 445), ("Internal-SQL", 1433),
                                         ("Corp-Web-Out", 443), ("Mgmt-RDP", 3389)])
                act = "Drop" if rng.random() < 0.12 else "Accept"
                EV.cp(b, _jit(day, rng, sh, eh), act, act,
                      A.ip(rng.choice(WKS)),
                      A.ip(rng.choice(["SRV-FILE01", "SRV-APP01", "SRV-SQL01"])),
                      port, rule=rule if act == "Accept" else "Cleanup-Drop")
                n += 1

            # --- k8s: service accounts + devs ---
            for _ in range(_n(rng, 19 * k)):
                if rng.random() < 0.55:
                    user = ("system:serviceaccount:kube-system:" +
                            rng.choice(["replicaset-controller", "deployment-controller",
                                        "endpoint-controller", "cronjob-controller"]))
                    groups = ["system:serviceaccounts", "system:authenticated"]
                    src = A.ip("k8s-cp01"); ua = "kube-controller-manager/v1.29.0"
                elif rng.random() < 0.5:
                    user = "system:serviceaccount:ci:deployer"
                    groups = ["system:serviceaccounts", "system:authenticated"]
                    src = A.ip("lnx-app01"); ua = "helm/v3.14.2"
                else:
                    user = rng.choice(DEVS); groups = ["dev-team", "system:authenticated"]
                    src = A.ip(_home(user)); ua = "kubectl/v1.29.0"
                verb = rng.choice(["get", "list", "watch", "create", "patch"])
                sub = ""
                code = 200
                if user in DEVS and rng.random() < 0.15:
                    verb, sub, code = "create", "exec", 101
                EV.k8s(b, _jit(day, rng, sh, eh), user, groups, src, verb,
                       rng.choice(["pods", "endpoints", "configmaps", "deployments"]),
                       sub, rng.choice(["prod", "dev", "kube-system"]) if user not in DEVS else "dev",
                       f"obj-{rng.randint(1, 99)}", code, ua, level="Request")
                n += 1

            # --- linux sshd (auth.log) ---
            for _ in range(_n(rng, 12 * k)):
                lh = rng.choice(["lnx-web01", "lnx-app01", "lnx-db01"])
                dtv = _jit(day, rng, sh, eh)
                who = rng.choice(["deploy", "opsadmin"])
                pid = rng.randint(1000, 30000)
                port = rng.randint(40000, 65000)
                if rng.random() < 0.12:   # ops typo then success
                    b.add_line("auth", EV._E.syslog_rfc3164(
                        dtv, lh, "sshd", pid,
                        f"Failed password for {who} from {A.ip('lnx-bastion01')} port {port} ssh2"),
                        dt=dtv)
                    dtv = dtv + datetime.timedelta(seconds=rng.randint(4, 30))
                    n += 1
                method = "publickey" if rng.random() < 0.85 else "password"
                b.add_line("auth", EV._E.syslog_rfc3164(
                    dtv, lh, "sshd", pid,
                    f"Accepted {method} for {who} from {A.ip('lnx-bastion01')} port {port} ssh2"),
                    dt=dtv)
                d2 = dtv + datetime.timedelta(milliseconds=rng.randint(20, 400))
                b.add_line("auth", EV._E.syslog_rfc3164(
                    d2, lh, "sshd", pid,
                    f"pam_unix(sshd:session): session opened for user {who}(uid={1001 if who == 'deploy' else 1002}) by (uid=0)"),
                    dt=d2)
                if rng.random() < 0.4:
                    d3 = dtv + datetime.timedelta(seconds=rng.randint(30, 900))
                    b.add_line("auth", EV._E.syslog_rfc3164(
                        d3, lh, "sudo", None,
                        f"  {who} : TTY=pts/0 ; PWD=/home/{who} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"),
                        dt=d3)
                    n += 1
                n += 2
            for _ in range(_n(rng, 2 * k)):   # internal scanner: invalid user
                lh = rng.choice(["lnx-web01", "lnx-app01", "lnx-db01"])
                dtv = _jit(day, rng, sh, eh)
                b.add_line("auth", EV._E.syslog_rfc3164(
                    dtv, lh, "sshd", rng.randint(1000, 30000),
                    f"Invalid user {rng.choice(['test', 'oracle', 'admin'])} from {A.ip('VULNSCAN01')} port {rng.randint(40000, 65000)}"),
                    dt=dtv)
                n += 1

            # --- syslog (varied programs, independent timestamps) ---
            for _ in range(_n(rng, 14 * k)):
                lh = rng.choice(["lnx-web01", "lnx-app01", "lnx-db01", "lnx-bastion01"])
                dtv = _jit(day, rng, sh, eh)
                prog, pid, msg = rng.choice([
                    ("CRON", rng.randint(1000, 30000), "(root) CMD (   cd / && run-parts --report /etc/cron.hourly)"),
                    ("CRON", rng.randint(1000, 30000), "(root) CMD (/usr/lib/sysstat/debian-sa1 1 1)"),
                    ("CRON", rng.randint(1000, 30000), "(deploy) CMD (/opt/app/bin/rotate-cache.sh)"),
                    ("crontab", rng.randint(1000, 30000), "(deploy) REPLACE (deploy)"),
                    ("crontab", rng.randint(1000, 30000), "(root) LIST (root)"),
                    ("crontab", rng.randint(1000, 30000), "(root) BEGIN EDIT (root)"),
                    ("crontab", rng.randint(1000, 30000), "(root) REPLACE (root) new crontab"),
                    ("systemd", 1, "Started Daily apt download activities."),
                    ("systemd", 1, "logrotate.service: Succeeded."),
                    ("chronyd", rng.randint(500, 900), "Selected source 10.20.50.5 (ntp1.corp.example)"),
                    ("kernel", None, f"[UFW BLOCK] IN=eth0 OUT= SRC=10.20.10.{rng.randint(100, 140)} DST=10.20.35.21 PROTO=TCP DPT=8080"),
                    ("nginx", rng.randint(1000, 30000), "worker process exited on signal 0"),
                    ("rsyslogd", rng.randint(500, 900), "imjournal: journal files changed, reloading..."),
                ])
                if rng.random() < 0.2:
                    b.add_line("syslog", EV._E.syslog_rfc5424(
                        dtv, lh, prog, pid if pid is not None else "-", "-", msg), dt=dtv)
                else:
                    b.add_line("syslog", EV._E.syslog_rfc3164(dtv, lh, prog, pid, msg), dt=dtv)
                n += 1

            # --- auditd benign exec ---
            for _ in range(_n(rng, 3 * k)):
                lh_pid = rng.randint(2000, 30000)
                dtv = _jit(day, rng, sh, eh)
                cmd = rng.choice([["/usr/sbin/logrotate", "/etc/logrotate.conf"],
                                  ["/usr/bin/apt-get", "update"],
                                  ["/usr/bin/systemctl", "restart", "nginx"],
                                  ["/usr/bin/curl", "-s", "http://repo.corp.example/health"],
                                  ["/usr/bin/tar", "-czf", "/backup/etc.tar.gz", "/etc"]])
                auid = rng.choice([0, 1001, 1002])
                b.add_lines("auditd", EV._E.auditd(
                    dtv, rng.randint(80000, 89999), syscall=59, success="yes", exit_=0,
                    a0='"%s"' % cmd[0], ppid=rng.randint(1, 2000), pid=lh_pid,
                    auid=auid, uid=0, euid=0, ses=rng.randint(1, 40),
                    tty="(none)" if auid == 0 else "pts/0",
                    comm=cmd[0].rsplit("/", 1)[-1], exe=cmd[0],
                    key=rng.choice(["exec", "pkg-mgmt", "priv"]), execve_argv=cmd,
                    cwd="/root" if auid == 0 else "/home/ops",
                    proctitle=" ".join(cmd)), dt=dtv)
                n += 1

            # --- docker app noise (incl warn/error) ---
            for _ in range(_n(rng, 13 * k)):
                dtv = _jit(day, rng, sh, eh)
                lvl, msg = rng.choice([
                    ("info", "GET /healthz 200"), ("info", "POST /api/v1/payments 201"),
                    ("info", "GET /metrics 200"), ("info", "GET /api/v1/payments/{id} 200"),
                    ("warn", "slow query on payments_ledger"), ("info", "cache refresh complete"),
                    ("error", "upstream timeout calling fraud-score"),
                    ("info", "POST /api/v1/refunds 202"), ("warn", "retrying kafka produce")])
                EV.docker(b, dtv,
                          f'{{"level":"{lvl}","ts":"{T.k8s_time(dtv)}","msg":"{msg}",'
                          f'"latency_ms":{rng.randint(1, 900 if lvl != "info" else 60)}}}',
                          stream="stderr" if lvl == "error" else "stdout")
                n += 1

        # ---------- thin sources: dedicated daily volume ----------
        for _ in range(_n(rng, 14 * scale)):   # F5 passed traffic (shop, WEB01)
            dtv = _jit(day, rng, 0, 23); cli = NX("f5c" + str(rng.randint(1, 80)))
            EV.web_inbound(b, dtv - datetime.timedelta(milliseconds=rng.randint(80, 600)),
                           cli, "SRV-WEB01")          # v4.2: same client seen by PA-DMZ/FGT
            EV.f5(b, dtv, [
                ("policy_name", "prod_web_asm"),
                ("violations", "N/A"), ("request_status", "passed"),
                ("ip_client", cli),
                ("method", rng.choice(["GET", "GET", "POST"])),
                ("uri", rng.choice(["/health", "/api/v1/login", "/static/app.js",
                                    "/api/v1/orders", "/product?id=%d" % rng.randint(1, 900),
                                    "/search?q=shoes", "/cart", "/static/logo.svg",
                                    "/upload.aspx", "/api/v1/profile"])),
                ("response_code", rng.choice(["200", "200", "302", "204", "404"])),
                ("severity", "Informational")])
            n += 2
        for _ in range(_n(rng, 7 * scale)):    # v4.2 partner portal (WEB02), mostly office hours
            dtv = _jit(day, rng, 6, 21) if rng.random() < 0.85 else _jit(day, rng, 0, 23)
            cli = NX(rng.choice(PARTNERS))
            uri = rng.choice(PARTNER_URIS)
            if "%d" in uri:
                uri = uri % rng.randint(1, 40)
            meth = "POST" if uri.endswith(("upload", "orders", "login")) and rng.random() < 0.7 else "GET"
            EV.web_inbound(b, dtv - datetime.timedelta(milliseconds=rng.randint(80, 600)),
                           cli, "SRV-WEB02")
            EV.f5(b, dtv, [
                ("policy_name", "partner_portal_asm"),
                ("violations", "N/A"), ("request_status", "passed"),
                ("ip_client", cli), ("method", meth), ("uri", uri),
                ("response_code", rng.choice(["200", "200", "200", "201", "401", "304"])),
                ("severity", "Informational")], host="SRV-WEB02")
            n += 2
        for fi in range(max(1, _n(rng, 4 * scale))):    # F5 internet scanner blocked/alerted
            sig, uri, sev = rng.choice([
                ("Directory Indexing", "/backup/", "Warning"),
                ("Path Traversal", "/static?f=..%2f..%2fwin.ini", "Error"),
                ("SQL-Injection (parameter)", "/product?id=1%27--", "Critical"),
                ("Automated client access \"curl\"", "/", "Warning"),
                ("Server Side Code Injection", "/index.php?cmd=id", "Error")])
            st = "alerted" if (fi == 0 or rng.random() < 0.25) else "blocked"
            fh = "SRV-WEB02" if rng.random() < 0.3 else "SRV-WEB01"
            dtv = _jit(day, rng, 0, 23); cli = NX("inet_scan" + str(rng.randint(1, 30)))
            EV.web_inbound(b, dtv - datetime.timedelta(milliseconds=rng.randint(80, 600)),
                           cli, fh)
            EV.f5(b, dtv, [
                ("policy_name", EV.F5_VS[fh][1]),
                ("violations", "Attack signature detected"), ("sig_names", sig),
                ("request_status", st),
                ("ip_client", cli),
                ("method", "GET"), ("uri", uri),
                ("response_code", "403" if st == "blocked" else "404"),
                ("severity", sev)], host=fh)
            n += 2
        for _ in range(_n(rng, 5 * scale)):    # PA-DMZ internet background deny
            src = NX("inet_scan" + str(rng.randint(1, 30)))
            th = _dmz_target(rng)
            EV.pan_traffic(b, _jit(day, rng, 0, 23), "PA-DMZ", "deny", src,
                           A.ip(th), "incomplete", "deny",
                           rng.choice([22, 23, 445, 8080, 5900] +
                                      ([] if th == "SRV-RDS01" else [3389])),
                           outbound=False, end_reason="policy-deny")
            n += 1
        for _ in range(_n(rng, 11 * scale)):   # PAN THREAT benign, informational..high
            r = rng.random()
            if r < 0.5:
                wk = rng.choice(WKS)
                tn, sev, cat = rng.choice([("Suspicious HTTP Evasion", "low", "any"),
                                           ("Expired Certificate", "informational", "any"),
                                           ("Newly Registered Domain Access", "informational", "any"),
                                           ("Unknown TLS SNI", "informational", "any")])
                EV.pan_threat(b, _jit(day, rng), "PA-CORE", "vulnerability",
                              A.ip(wk), NX("pt" + str(rng.randint(1, 40))),
                              "web-browsing", "alert", "", tn, 0, cat, sev, 0,
                              suser=f"corp\\{rng.choice(NOISE_USERS)}", inbound=False)
            else:
                tn, sev, cat, act = rng.choice([
                    ("HTTP /etc/passwd Access Attempt", "high", "info-leak", "reset-both"),
                    ("HTTP Directory Traversal Vulnerability", "medium", "info-leak", "reset-both"),
                    ("SSH Brute Force Attempt", "high", "brute-force", "drop"),
                    ("Generic Bot Scanner", "low", "scan", "drop"),
                    ("Apache Log4j Remote Code Execution Attempt", "critical", "code-execution", "reset-both")])
                EV.pan_threat(b, _jit(day, rng, 0, 23), "PA-DMZ", "vulnerability",
                              NX("inet_scan" + str(rng.randint(1, 30))), _dmz_target(rng),
                              "web-browsing", act, "", tn, 0, cat, sev, 0, inbound=True)
            n += 1
        # v4: background for vendor alert types that v3 only had inside cases
        for _ in range(_n(rng, 3 * scale)):    # PAN spyware (benign trackers/adware)
            wk = rng.choice(WKS)
            dom = rng.choice(["metrics-cdn.example", "adsrv-track.example",
                              "toolbar-update.example", _rand_dom(rng)])
            EV.pan_threat(b, _jit(day, rng, 7, 21), "PA-CORE", "spyware",
                          A.ip(wk), NX("legit_" + dom), rng.choice(["ssl", "web-browsing"]),
                          rng.choice(["alert", "alert", "reset-both"]), dom,
                          rng.choice(["Adware Tracking Beacon", "Suspicious DNS Query (generic)",
                                      "Browser Toolbar Phone-Home", "Suspicious TLS Beacon Interval"]),
                          0, rng.choice(["adware", "spyware", "command-and-control"]),
                          rng.choice(["informational", "low", "low", "medium"]), 0,
                          suser=f"corp\\{rng.choice(NOISE_USERS)}", inbound=False)
            n += 1
        for _ in range(_n(rng, 2 * scale)):    # PAN virus at mail relay (blocked spam)
            EV.pan_threat(b, _jit(day, rng, 0, 23), "PA-CORE", "virus",
                          NX("inet_mail" + str(rng.randint(1, 25))), "SRV-MAIL01", "smtp",
                          rng.choice(["reset-both", "alert"]),
                          rng.choice(["invoice.zip", "scan_0042.pdf", "order.docm", "doc.xlsm"]),
                          rng.choice(["Generic Malicious Attachment", "Office Macro Downloader Variant",
                                      "Phishing PDF Generic", "Archive Containing Executable"]),
                          0, "virus", rng.choice(["medium", "high", "high"]), 0,
                          inbound=True, dport=25)
            n += 1
        for _ in range(_n(rng, 2 * scale)):    # PAN scan (internet background)
            EV.pan_threat(b, _jit(day, rng, 0, 23), "PA-DMZ", "scan",
                          NX("inet_scan" + str(rng.randint(1, 30))), _dmz_target(rng),
                          "not-applicable", "drop", "",
                          rng.choice(["TCP Port Scan", "Host Sweep", "UDP Port Scan"]), 0,
                          "scan", rng.choice(["informational", "low"]), 0,
                          inbound=True, dport=0)
            n += 1
        for _ in range(_n(rng, 2 * scale)):    # FGT AV (PUA / test files blocked)
            wk = rng.choice(WKS); dom = _rand_dom(rng)
            vname = rng.choice(["Riskware/Bundler", "Adware/OpenCandy", "PUA/Toolbar",
                                "W32/Agent.GEN!tr", "EICAR_TEST_FILE"])
            EV.fgt(b, _jit(day, rng, 8, 20), "FGT-EDGE", "utm", "virus", "warning",
                   wk, NX("legit_" + dom), 443, "blocked", "HTTPS", "HTTPS.BROWSER",
                   "Web.Client", logid="0211008192",
                   extra=f'virus="{vname}" dtype="Virus" virusid={rng.randint(1000, 9999)} '
                         f'url="https://{dom}/dl/setup{rng.randint(1, 99)}.exe" '
                         f'crlevel="{rng.choice(["medium", "high", "critical"])}" profile="default"')
            n += 1
        for _ in range(_n(rng, 3 * scale)):    # FGT DLP monitor (legit uploads)
            dom = rng.choice(["backup-vendor.example", "files-share.example",
                              "crm-cloud.example", _rand_dom(rng)])
            EV.fgt(b, _jit(day, rng, 0, 23), "FGT-EDGE", "utm", "dlp", "information",
                   A.PROXY_IP, NX("legit_" + dom), 443, "log-only", "HTTPS",
                   "HTTPS.BROWSER", rng.choice(["Storage.Backup", "Collaboration"]),
                   logid="0954024576",
                   extra=f'filtertype="file-size" filteridx=1 dlpextra="upload>1MB" '
                         f'hostname="{dom}" crlevel="low" profile="dlp-monitor"')
            n += 1
        for _ in range(_n(rng, 3 * scale)):    # FGT-EDGE IPS internet background
            th = _dmz_target(rng)              # v4.2: hits the VIP, DNAT to the server
            EV.fgt(b, _jit(day, rng, 0, 23), "FGT-EDGE", "utm", "ips", "alert",
                   NX("inet_scan" + str(rng.randint(1, 30))), A.VIPS[th],
                   rng.choice([80, 443, 22]), "dropped", "HTTPS", "HTTPS",
                   "Network.Service", srccountry="United States", outbound=False,
                   dnat_to=A.ip(th),
                   extra=rng.choice(['attack="HTTP.URI.SQL.Injection" severity="high" crlevel="high" direction="incoming"',
                                     'attack="SSH.Connection.Brute.Force" severity="high" crlevel="high" direction="incoming"',
                                     'attack="Web.Server.Password.Files.Access" severity="medium" crlevel="medium" direction="incoming"']))
            n += 1
        for _ in range(_n(rng, 2 * scale)):    # Check Point IPS detect (internal tools)
            EV.cp(b, _jit(day, rng), "IPS", "Detect", A.ip(rng.choice(WKS)),
                  A.ip(rng.choice(SRVS)), rng.choice([445, 1433, 389]),
                  rule="Internal-SMB", severity=rng.choice(["Low", "Medium", "Medium", "High"]),
                  extra_pairs=[("cs2Label", "Protection Name"),
                               ("cs2", rng.choice(["SMB Protocol Violation",
                                                   "LDAP Anonymous Bind",
                                                   "Microsoft SQL Server Protocol Anomaly"])),
                               ("cs3Label", "Protection Type"), ("cs3", "IPS")])
            n += 1
        for _ in range(_n(rng, 17 * scale)):   # windns
            u = rng.choice(NOISE_USERS)
            EV.windns(b, _jit(day, rng), _home(u), _rand_dom(rng),
                      rng.choice(["A", "AAAA", "CNAME"]),
                      rcode="NXDOMAIN" if rng.random() < 0.08 else "NOERROR")
            n += 1
        for _ in range(_n(rng, 14 * scale)):   # PowerShell 4104 benign (incl warnings)
            u = rng.choice(NOISE_USERS + ADMINS)
            wk = _home(u) if u in A.HOME else rng.choice(SRVS)
            script, lvl = rng.choice([
                ("Get-ChildItem C:\\Users -Recurse -Include *.log | Measure-Object", 5),
                ("Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties LastLogonDate", 5),
                ("Get-Service | Where-Object {$_.Status -eq 'Running'}", 5),
                ("$d=[Convert]::FromBase64String('SGVsbG8gV29ybGQ='); [Text.Encoding]::UTF8.GetString($d)", 5),
                ("Get-WinEvent -LogName System -MaxEvents 50 | Format-Table", 5),
                ("Test-NetConnection -ComputerName SRV-FILE01 -Port 445", 5),
                ("Invoke-WebRequest -Uri https://repo.corp.example/tools/agent.msi -OutFile $env:TEMP\\agent.msi", 3),
                ("(New-Object Net.WebClient).DownloadString('https://portal.example.com/status.json') | ConvertFrom-Json", 3),
                ("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", 5),
                ("Set-ExecutionPolicy -Scope Process Bypass; .\\health.ps1", 3),
            ])
            EV.ps_4104(b, _jit(day, rng), wk, u, script, level=lvl)
            n += 1
        for _ in range(_n(rng, 15 * scale)):   # WMI 5861 benign consumers
            EV.wmi_5861(b, _jit(day, rng), rng.choice(WKS + SRVS),
                        rng.choice(["SCM Event Log Consumer",
                                    "BVTConsumer", "CcmEventConsumer"]),
                        rng.choice(["SCM Event Log Filter", "CcmFilter", "BVTFilter"]),
                        "SELECT * FROM __InstanceModificationEvent WITHIN 60")
            n += 1
        for _ in range(_n(rng, 21 * scale)):   # Application / System
            r = rng.random()
            hh = rng.choice(WKS)
            if r < 0.32:
                b.add_app_event(hh, 11707, _jit(day, rng), "MsiInstaller",
                                f"Product: {rng.choice(['7-Zip 24.08', 'Notepad++ 8.6', 'VLC 3.0', 'Zoom 6.1', 'Adobe Acrobat Reader 24'])}"
                                " (x64) -- Installation completed successfully.")
            elif r < 0.55:
                b.add_app_event(hh, 2000, _jit(day, rng),
                                "Microsoft-Windows-Windows Defender",
                                "Defender signatures updated to version 1.419."
                                + str(rng.randint(100, 999)))
            elif r < 0.62:
                b.add_app_event(hh, 1116, _jit(day, rng),
                                "Microsoft-Windows-Windows Defender",
                                "Microsoft Defender Antivirus has detected potentially unwanted software. "
                                f"Name: {rng.choice(['PUA:Win32/Adware.Bundler', 'PUA:Win32/Toolbar.Search'])} "
                                f"Severity: {rng.choice(['Low', 'Moderate'])} Category: Potentially Unwanted Software "
                                f"Path: file:_C:\\Users\\Public\\Downloads\\setup{rng.randint(1, 99)}.exe "
                                "Action: Quarantined", level=3)
            elif r < 0.78:
                EV.sys_7036(b, _jit(day, rng),
                            rng.choice(SRVS + WKS),
                            rng.choice(["Windows Update", "BITS",
                                        "Windows Defender", "Print Spooler",
                                        "Windows Modules Installer"]),
                            rng.choice(["running", "stopped"]))
            else:                              # 7045 driver / agent updates
                svc, img, acct, st = rng.choice([
                    ("GoogleUpdaterService128.0", r'"C:\Program Files (x86)\Google\GoogleUpdater\128.0.6537.0\updater.exe" --system --windows-service', "LocalSystem", "auto start"),
                    ("MicrosoftEdgeElevationService", r'"C:\Program Files (x86)\Microsoft\Edge\Application\130.0.2849.68\elevation_service.exe"', "LocalSystem", "demand start"),
                    ("CorpITInventoryAgent", r'"C:\Program Files\CorpIT\inv.exe" --service', "LocalSystem", "auto start"),
                    ("RtkAudioUniversalService", r"C:\Windows\System32\DriverStore\FileRepository\realtekservice.inf_amd64_3c1f\RtkAudUService64.exe", "LocalSystem", "auto start"),
                    ("ZoomCptService", r'"C:\Program Files\Common Files\Zoom\Support\CptService.exe" -user_path "C:\Users\Public\AppData\Roaming\Zoom"', "LocalSystem", "demand start"),
                ])
                EV.sys_7045(b, _jit(day, rng), hh, svc, img, start_type=st,
                            account=acct, installer="SYSTEM")
            n += 1
        # ---- v4.1 per-server baseline telemetry (every Windows server) ----
        for hh in ALL_WIN_SERVERS:
            for bi in range(_n(rng, 14)):       # Sysmon: OS / agent processes
                dtv = _jit(day, rng, 0, 23)
                img, cmd, par = rng.choice([
                    (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", r"C:\Windows\System32\svchost.exe"),
                    (r"C:\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding", r"C:\Windows\System32\svchost.exe"),
                    (r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", r"C:\Windows\System32\svchost.exe"),
                    (r"C:\Program Files\CorpIT\inv.exe", '"inv.exe" /collect', r"C:\Windows\System32\services.exe"),
                    (r"C:\Windows\System32\MpSigStub.exe", "MpSigStub.exe /stub 1.1.24080.9 /payload 1.419.0.0", r"C:\Windows\System32\svchost.exe")])
                EV.sm1(b, dtv, hh, img, cmd, "SYSTEM", par, par, integrity="System",
                       tag=f"bl-{dtag}-{bi}")
                n += 1
            for _ in range(_n(rng, 8)):         # Sysmon EID 3: DC / update traffic
                dtv = _jit(day, rng, 0, 23)
                if hh == "SRV-DC01":
                    dst, port = A.ip("SRV-FILE01"), 445
                else:
                    dst, port = A.ip("SRV-DC01"), rng.choice([88, 389, 445, 135])
                EV.sm3(b, dtv, hh, r"C:\Windows\System32\svchost.exe", "NETWORK SERVICE",
                       A.ip(hh), rng.randint(49152, 65535), dst, port,
                       dst_host=A.fqdn("SRV-DC01") if port != 445 or hh != "SRV-DC01" else A.fqdn("SRV-FILE01"),
                       tag="netsvcs")
                n += 1
            for _ in range(_n(rng, 4)):         # service logons + SCM
                dtv = _jit(day, rng, 0, 23)
                sa = rng.choice(SVC_BY_HOST.get(hh, ["svc_monitor"]))
                EV.sec_4624(b, dtv, hh, sa, 5)
                EV.sys_7036(b, dtv + datetime.timedelta(seconds=rng.randint(1, 5)), hh,
                            rng.choice(["Windows Update", "BITS", "Windows Defender",
                                        "Windows Modules Installer", "WinHTTP Web Proxy Auto-Discovery Service"]),
                            rng.choice(["running", "stopped"]))
                n += 2
            for _ in range(_n(rng, 5)):         # admin / helpdesk 4688 via session
                adm = rng.choice(ADMINS)
                img, cmd = rng.choice(ADMIN_PROCS)
                EV.sec_4688(b, _jit(day, rng, 8, 19), hh, adm, img, cmd, EXPL_,
                            integrity="High")
                n += 1
        # ---- v4.1 IIS (SRV-WEB01/02) normal application activity ----
        for hh in DMZ_WEB:
            w3 = r"C:\Windows\System32\inetsrv\w3wp.exe"
            pool = "ShopAppPool" if hh == "SRV-WEB01" else "PartnerAppPool"
            # v4.2: role-specific volumes (shop = busy storefront on SQL01;
            # partner portal = quieter, EDI uploads + API backend on APP01)
            shop = hh == "SRV-WEB01"
            v_rec, v_tmp, v_csc, v_sql, v_mod = (4, 12, 3, 16, 5) if shop else (2, 3, 1, 3, 2)
            for ri in range(_n(rng, v_rec)):        # app-pool recycle: WAS starts w3wp
                dtv = _jit(day, rng, 0, 23)
                EV.sec_4624(b, dtv, hh, "svc_web", 5)
                EV.sm1(b, dtv, hh, w3, f'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "{pool}" -v "v4.0" -l "webengine4.dll" -a \\\\.\\pipe\\iisipm{rng.randint(1000, 9999)}',
                       "svc_web", r"C:\Windows\System32\svchost.exe",
                       r"C:\Windows\system32\svchost.exe -k iissvcs", integrity="System",
                       tag=f"iis-r{dtag}-{ri}")
                n += 2
            for _ in range(_n(rng, v_tmp)):     # ASP.NET compile temp files
                dtv = _jit(day, rng, 0, 23)
                EV.sm11(b, dtv, hh, w3,
                        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\root\\"
                        f"{rng.randint(0, 0xffffffff):08x}\\{rng.randint(0, 0xffffffff):08x}\\App_Web_{rng.randint(0, 0xffffff):06x}.dll",
                        "svc_web", tag="iis")
                n += 1
            for _ in range(_n(rng, v_csc)):     # dynamic compilation: w3wp -> csc.exe
                dtv = _jit(day, rng, 0, 23)
                EV.sm1(b, dtv, hh, r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                       '"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe" /t:library /utf8output /nostdlib+ '
                       f'@"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\root\\{rng.randint(0, 0xffffffff):08x}.cmdline"',
                       "svc_web", w3, f'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "{pool}"',
                       integrity="System", company="Microsoft Corporation", parent_tag="iis")
                n += 1
            for _ in range(_n(rng, v_sql)):     # w3wp -> SQL backend / API
                dtv = _jit(day, rng, 0, 23)
                EV.sm3(b, dtv, hh, w3, "svc_web", A.ip(hh), rng.randint(49152, 65535),
                       A.ip("SRV-SQL01"), 1433, dst_host=A.fqdn("SRV-SQL01"), tag="iis")
                n += 1
            for _ in range(_n(rng, v_mod)):     # module loads
                EV.sm7(b, _jit(day, rng, 0, 23), hh, w3,
                       rng.choice([r"C:\Windows\System32\inetsrv\iiscore.dll",
                                   r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\webengine4.dll",
                                   r"C:\Windows\System32\inetsrv\aspnetcore.dll"]),
                       tag="iis", user_sam="svc_web")
                n += 1
            if not shop:
                for _ in range(_n(rng, 5)):     # partner EDI files received by the portal
                    dtv = _jit(day, rng, 6, 21)
                    EV.sm11(b, dtv, hh, w3,
                            f"C:\\inetpub\\wwwroot\\App_Data\\edi\\inbound\\{rng.choice(['PO', 'ASN', 'INV'])}_"
                            f"{rng.randint(100000, 999999)}.xml", "svc_web", tag="iis")
                    n += 1
                for _ in range(_n(rng, 5)):     # portal -> internal order API on APP01
                    dtv = _jit(day, rng, 6, 21)
                    EV.sm3(b, dtv, hh, w3, "svc_web", A.ip(hh), rng.randint(49152, 65535),
                           A.ip("SRV-APP01"), 8443, dst_host=A.fqdn("SRV-APP01"), tag="iis")
                    n += 1
        # ---- v4.1 RD gateway SRV-RDS01: staff working from home + scanners ----
        # v4.2: every RDP attempt is a TCP session VIP 203.0.113.5 -> FGT-EDGE
        # (DNAT) -> PA-DMZ -> SRV-RDS01:3389; IpPort = the firewall sport
        for _ in range(_n(rng, 9)):
            u = rng.choice(NOISE_USERS)
            dtv = _jit(day, rng, 7, 22)
            home_ip = NX("homeisp_" + u)
            if b.find_session("SRV-RDS01", u, dtv) is not None:
                continue
            if rng.random() < 0.15:              # typo first
                sp = EV.rdp_inbound(b, dtv, home_ip, "SRV-RDS01", ok=False)
                EV.sec_4625(b, dtv, "SRV-RDS01", u, 3, home_ip, "-",
                            auth="NTLM", ip_port=sp)
                dtv = dtv + datetime.timedelta(seconds=rng.randint(8, 40))
                n += 2
            dur = rng.randint(15, 240)
            # sessions end inside the export window (PAN logs at session end)
            left = int((_WIN_END - dtv).total_seconds() // 60) - 2
            dur = max(5, min(dur, left))
            sp = EV.rdp_inbound(b, dtv, home_ip, "SRV-RDS01", ok=True,
                                session_s=dur * 60 + rng.randint(2, 50))
            _r, slid = EV.sec_4624(b, dtv, "SRV-RDS01", u, 10, home_ip, "-",
                                   auth="Negotiate", ip_port=sp)
            EV.sec_4688(b, dtv + datetime.timedelta(seconds=rng.randint(4, 15)),
                        "SRV-RDS01", u, r"C:\Windows\System32\rdpclip.exe", "rdpclip",
                        r"C:\Windows\System32\svchost.exe")
            EV.sec_4634(b, dtv + datetime.timedelta(minutes=dur),
                        "SRV-RDS01", u, 10, slid)
            n += 4
        for _ in range(_n(rng, 6)):              # internet password spraying (all fail)
            dtv = _jit(day, rng, 0, 23); sip = NX("inet_scan" + str(rng.randint(1, 30)))
            sp = EV.rdp_inbound(b, dtv, sip, "SRV-RDS01", ok=False)
            EV.sec_4625(b, dtv, "SRV-RDS01",
                        rng.choice(["administrator", "admin", "test", "user", "scanner", "guest"]),
                        3, sip, "-",
                        user_exists=rng.random() < 0.4, auth="NTLM", ip_port=sp)
            n += 2
        # ---- FGT utm detected / passthrough background ----
        for _ in range(_n(rng, 2)):
            th = rng.choice(["SRV-WEB01", "SRV-WEB02"])
            EV.fgt(b, _jit(day, rng, 0, 23), "FGT-EDGE", "utm", "ips", "notice",
                   NX("inet_scan" + str(rng.randint(1, 30))), A.VIPS[th],
                   443, "detected", "HTTPS", "HTTPS", "Network.Service",
                   srccountry="United States", outbound=False, logid="0419016384",
                   dnat_to=A.ip(th),
                   extra='attack="HTTP.Request.Smuggling" severity="low" crlevel="low" direction="incoming"')
            wk = _home(rng.choice(NOISE_USERS)); dom = _rand_dom(rng)
            EV.fgt(b, _jit(day, rng, 8, 19), "FGT-EDGE", "utm", "webfilter", "notice",
                   wk, NX("legit_" + dom), 80, "passthrough", "HTTP", "HTTP.BROWSER",
                   "Web.Client", extra=f'hostname="{dom}" url="/" cat=90 '
                                        f'catdesc="Newly Observed Domain" crlevel="low"')
            n += 2
        # occasional directory changes by helpdesk / admins
        if rng.random() < 0.8:
            tmpu = f"tmp_vendor{rng.randint(10, 99)}"
            dtv = _jit(day, rng, 9, 17)
            EV.sec_4720(b, dtv, "SRV-DC01", tmpu, "helpdesk")
            EV.sec_4728(b, dtv + datetime.timedelta(seconds=rng.randint(3, 40)),
                        "SRV-DC01", EV.new_acct_sid(tmpu), 513, "Domain Users", "helpdesk")
            n += 2
        for _ in range(_n(rng, 2)):            # local admin adds by admins on servers
            srv = rng.choice(SRVS[:3])
            EV.sec_4732(b, _jit(day, rng, 9, 18), srv,
                        A.USERS["svc_deploy"]["sid"], "Administrators", "adm_kitti",
                        local_host=srv.split("-")[0] if False else None)
            n += 1
        for _ in range(_n(rng, 5)):            # software scheduled tasks
            hh = rng.choice(WKS); u = rng.choice(NOISE_USERS)
            tn, cmd, actor = rng.choice([
                ("\\GoogleUpdaterTaskSystem128.0", r"C:\Program Files (x86)\Google\GoogleUpdater\128.0.6537.0\updater.exe", "SYSTEM"),
                ("\\OneDrive Standalone Update Task-" + A.USERS[u]["sid"], r"C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe", u),
                ("\\Microsoft\\Office\\Office Automatic Updates 2.0", r"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe", "SYSTEM")])
            EV.sec_4698(b, _jit(day, rng), hh, tn, actor, cmd, "/ua /installsource scheduler")
            n += 1

    # one benign log clear during a documented lab re-image (1102 noise)
    dtv = _jit(datetime.date(2026, 11, 10), rng, 16, 17)
    EV.sec_1102(b, dtv, "WKS-GEN-029", "adm_kitti")
    b.add_change("CHG-2611-1310", dtv - datetime.timedelta(minutes=40),
                 dtv + datetime.timedelta(hours=2), ["WKS-GEN-029"],
                 "re-image เครื่องทดสอบ WKS-GEN-029 (ล้าง event log ก่อนส่งคืน) โดย adm_kitti")
    n += 1
    # unrelated change-calendar entries (context noise)
    for cid, dday, h0, hosts, txt in [
            ("CHG-2611-0701", datetime.date(2026, 11, 9), 22, ["SRV-APP01"], "อัปเดต .NET runtime บน SRV-APP01"),
            ("CHG-2611-1120", datetime.date(2026, 11, 11), 20, ["FGT-EDGE-01"], "ปรับ firewall policy ขาออก (เพิ่ม allow สำหรับ partner API)"),
            ("CHG-2611-0905", datetime.date(2026, 11, 12), 13, ["SRV-SQL01"], "เพิ่มดิสก์ log ให้ SRV-SQL01"),
            ("CHG-2611-0230", datetime.date(2026, 11, 10), 2, ["k8s-cp01", "k8s-node01", "k8s-node02"], "อัปเกรด node pool คลัสเตอร์ dev")]:
        st = datetime.datetime(dday.year, dday.month, dday.day, h0, 0, tzinfo=T.ORG_TZ).astimezone(T.UTC)
        b.add_change(cid, st, st + datetime.timedelta(hours=2), hosts, txt)

    # pwadee: first-day activity strictly after the account was created
    if pw_created is not None:
        t0 = pw_created + datetime.timedelta(minutes=rng.randint(45, 120))
        wk = _home("pwadee")
        _r, lid = EV.sec_4624(b, t0, wk, "pwadee", 2)
        EV.sec_4688(b, t0 + datetime.timedelta(minutes=3), wk, "pwadee",
                    USER_APPS[1], f'"{USER_APPS[1]}"', EXPL_)
        n += 2
    return n


EXPL_ = r"C:\Windows\explorer.exe"
