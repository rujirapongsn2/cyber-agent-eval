# cyber-agent-eval (v4.2.1)

ชุดข้อมูลประเมิน (evaluation dataset) สำหรับ **AI agent ที่ทำงานด้าน SOC / threat hunting**
สร้างแบบ deterministic ด้วย Python 3 (standard library ล้วน) ไม่เรียกโมเดลใด ๆ ทั้งสิ้น
ทั้งตอนสร้าง ตรวจสอบ และให้คะแนน ประวัติการเปลี่ยนแปลงอยู่ใน `CHANGELOG.md`

## สิ่งที่ส่งให้ agent

- ส่งให้ agent ได้เฉพาะ `inputs/` (และ README นี้ถ้าต้องการ)
- **ห้ามส่ง** `answers/`, `gen/`, `generator.py`, `dataset_meta.json` และ log ผลของ
  validator/leakcheck/scorer ให้ agent เพราะคำเฉลยคำนวณหรืออ่านได้จากไฟล์เหล่านี้

## โครงสร้างไฟล์ (จริงตามที่ generator สร้าง)

```
inputs/                         # สิ่งที่ส่งให้ agent เท่านั้น (ไม่มีคำเฉลย)
  logs/
    windows/Security.xml        # Windows Security (4624/4625/4634/4672/4688/4698/4720/4728/4732/4776/1102)
    windows/System.xml          # System (7045/7036)
    windows/Application.xml     # Application (MsiInstaller ฯลฯ)
    windows/PowerShell-Operational.xml   # 4104
    windows/WMI-Activity-Operational.xml # 5861
    sysmon/Sysmon-Operational.xml        # EID 1,3,7,10,11,13,22
    linux/auth.log              # RFC3164 (sshd ฯลฯ)
    linux/syslog                # RFC3164/5424
    linux/audit.log             # auditd (SYSCALL/EXECVE/CWD/PATH/PROCTITLE)
    paloalto/traffic.log        # PAN-OS TRAFFIC (CSV)
    paloalto/threat.log         # PAN-OS THREAT (CSV)
    fortigate/fortigate.log     # FortiGate key=value
    checkpoint/checkpoint-cef.log # Check Point Log Exporter CEF
    f5/asm.log                  # F5 BIG-IP ASM
    bind/named-query.log        # BIND query log
    windows_dns/dns-debug.log   # Windows DNS debug (Rcv/Snd)
    squid/access.log            # Squid proxy
    docker/payments-api.json    # Docker JSON file log
    k8s/kube-apiserver-audit.jsonl # Kubernetes audit (audit.k8s.io/v1)
  cases_input.jsonl             # 1 บรรทัด/เคส: case_id, task_type, prompt_th, input_log_refs
  campaigns_input.json          # รายการ campaign_id ที่ต้อง reconstruct
  environment.json              # เขตเวลา, asset inventory (hosts/users/devices), topology,
                                #   change_calendar (change/scan/pentest/SR), approved pentest IP
  tz_conventions.json           # รูปแบบการ render เวลา ต่อแหล่ง log

answers/                        # คำเฉลย (อย่าส่งให้ agent)
  ground_truth.jsonl            # severity, is_malicious, is_fp_trap, techniques, iocs, ...
  campaigns.json                # ลำดับ stage + เทคนิคของแต่ละแคมเปญ
  predictions_oracle.jsonl      # คำตอบสมบูรณ์ (ใช้ self-test ให้ได้ 1.0)
  predictions_dumb.jsonl        # baseline โง่ (ตอบ high + malicious ทุกเคส)

schema/                         # JSON Schema (subset) + attack_whitelist.json
  case_input.schema.json
  ground_truth.schema.json
  campaign.schema.json
  attack_whitelist.json         # 706 เทคนิค/ซับเทคนิค ปัจจุบันของ MITRE ATT&CK (v19)

gen/                            # โมดูลสร้างข้อมูล
generator.py validator.py scorer.py leakcheck.py
dataset_meta.json tz_conventions.json   # dataset_meta.json มีสถิติจากคำเฉลย (อย่าส่งให้ agent)
CHANGELOG.md                    # ประวัติเวอร์ชัน (ไม่มี case_id / คำเฉลย)
```

## Timezone (สำคัญ)

ทุกเหตุการณ์มี **หนึ่ง instant มาตรฐานเป็น UTC** และถูก render ตามรูปแบบ native ของแต่ละแหล่ง
ทั้งองค์กร (โฮสต์และอุปกรณ์เครือข่าย) ใช้เขต **Asia/Bangkok (ICT, UTC+07, ไม่มี DST)**
รายละเอียดการ render ต่อแหล่งอยู่ใน `tz_conventions.json` เช่น

- Windows Event XML / Sysmon UtcTime / Squid / Docker / K8s → **UTC**
- Linux syslog RFC3164 / PAN-OS / F5 / BIND / Windows DNS → **เวลา local ของอุปกรณ์ (ICT)**
- FortiGate → date/time เป็น local, `tz=+0700`, `eventtime` เป็น UTC epoch นาโนวินาที
- Check Point CEF → `rt=` เป็น UTC epoch มิลลิวินาที, header syslog เป็น ISO8601 พร้อม offset

## ความปลอดภัยของค่า (safe fake values)

- IP ภายนอกใช้ RFC5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) เท่านั้น,
  ภายในใช้ RFC1918; มี loopback/link-local ได้ตามจริง
- โดเมนอยู่ใต้ .example/.test/.invalid (RFC2606/6761)
- แฮชเป็น hex สุ่ม, ไม่มีชื่อมัลแวร์/เครื่องมือจริง, payload ถูก defang
- validator สแกนทุกไฟล์เพื่อยืนยันว่าไม่มี IP ที่ routable จริงและไม่มีชื่อต้องห้าม


## นิยาม label
- **malicious** = กิจกรรมของผู้โจมตี/ผู้ไม่ได้รับอนุญาต แม้จะ "พยายามแต่ไม่สำเร็จ"
- **benign** = กิจกรรมของผู้มีสิทธิ์โดยชอบ แม้จะ**ผิด policy** หรือ**ไม่มี change ticket**
  ; ความผิด policy สะท้อนใน severity ไม่ใช่ label
- **fp_trap** = benign ที่หน้าตาคล้ายการโจมตี ; **decoy** = benign ที่คล้าย IoC หรือรูปแบบของเคสอื่น
- change_calendar ใน environment.json เป็นข้อมูลบริบท ไม่ใช่คำเฉลย

## งาน (task types) และรูปแบบคำตอบ

ทุก prompt เป็นภาษาไทยและเป็น **กลาง** (คำสั่งเดียวกันทุกเคสในประเภทงานเดียวกัน)
ประเภทงาน: `triage_severity`, `ioc_extraction`, `attack_mapping`, `correlation`,
`campaign_reconstruction`

รูปแบบ prediction (1 JSON/บรรทัด, ค่าด้านล่างเป็นตัวอย่างรูปแบบเท่านั้น):
```json
{"case_id":"CAE-XXXX","severity":"<critical|high|medium|low|info>","is_malicious":<true|false>,
 "is_fp_trap":<true|false>,"techniques":["Txxxx.xxx"],"iocs":[{"type":"<ip|domain|file|...>","value":"..."}],
 "correlation_keys":[],"campaign_id":null,"campaign_stage":null}
```

## วิธีใช้งาน (บนเครื่อง ไม่มีการเรียกโมเดล)

```bash
python3 generator.py --seed 20261113 --out .     # สร้าง inputs/ + answers/ (deterministic)
python3 validator.py                             # schema/format/refs/IoC/safety/ATT&CK
                                                 #  + LOO leak-checks + realism guards
python3 leakcheck.py                             # ตาราง leak-check อย่างเดียว
python3 scorer.py --pred answers/predictions_oracle.jsonl   # self-test: overall_score = 1.0
python3 scorer.py --pred answers/predictions_dumb.jsonl     # baseline ต่ำ
python3 scorer.py --pred <ไฟล์ prediction ของ agent>
```

- generator ให้ผลลัพธ์ **byte-identical** ไม่ขึ้นกับ PYTHONHASHSEED ; ชุดที่เผยแพร่ใช้ seed 20261113
- scorer รองรับ ATT&CK id ที่ถูก revoke/เปลี่ยนชื่อ โดย canonicalize ก่อนเทียบ
- การให้คะแนน: severity (exact + ordinal partial), malicious accuracy, fp-trap accuracy,
  technique/IoC/correlation P/R/F1 (เทคนิคให้เครดิตบางส่วน 0.5 เมื่อตรงระดับ parent),
  campaign id/stage/ลำดับ (Kendall-tau)

> ชุดข้อมูลนี้สำหรับ "ประเมิน" เท่านั้น การ self-test ของ scorer ด้วย oracle/dumb baseline ไม่ใช้โมเดล

## License

This dataset is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). See LICENSE.
