# CHANGELOG – cyber-agent-eval

ไฟล์นี้บันทึกเฉพาะการเปลี่ยนแปลงของ generator / รูปแบบ log / validator ตามรอบ Security Audit
**ไม่มี case_id ไม่มี label และไม่มีคำเฉลยของเคสใด ๆ** (คำเฉลยอยู่ใน `answers/` เท่านั้น)

## v4.2.1 (2026-11-13)
- เอกสารเท่านั้น: ย้าย changelog/ประวัติ audit ออกจาก README มาไว้ไฟล์นี้ และตัดทุกส่วนที่อ้าง case_id,
  label หรือสถิติจากคำเฉลยออกจาก README ; ตัวอย่างรูปแบบ prediction ใช้ค่า placeholder
- README ระบุชัดว่าส่งให้ agent ได้เฉพาะ `inputs/` (ห้ามส่ง `answers/`, `gen/`, `generator.py`,
  `dataset_meta.json`)
- ข้อมูล log และเคสไม่เปลี่ยนจาก v4.2 (`inputs/`, `answers/` byte-identical) ; `generator_version` = v4.2.1

## v4.2 (แก้ตาม audit รอบ 5 ; ผล audit รอบ 6 ของรุ่นนี้ = 8.5/10)
- ทราฟฟิกขาเข้า DMZ ครบทุกชั้นสำหรับทุก host ที่เผยแพร่ (FGT-EDGE DNAT → PA-DMZ → F5 สำหรับเว็บ) ;
  ค่า IpPort ของ Windows 4624/4625 จากอินเทอร์เน็ตตรงกับ source port ของ firewall
- FortiGate `srcintfrole`/`dstintfrole` ผูกกับ interface จริง (wan1=wan, dmz=dmz, portN=lan) ;
  DNAT ขาเข้าใช้ dstcountry=Reserved ; app ของ DNAT ตามพอร์ต
- F5 ASM ทุกบรรทัดมี `vs_name`, `dest_ip`, `dest_port` (virtual server ต่อเว็บเซิร์ฟเวอร์ 2 ตัว)
- noise ตามบทบาทของ host DMZ (ปริมาณและชนิด event ต่างกันต่อ host, ทราฟฟิก partner/EDI,
  ผู้ใช้ remote desktop) ; scanner/IPS/deny กระจายทุก host ที่เผยแพร่
- logon type 5 ของบัญชีบริการเกิดเฉพาะบน host ที่บริการนั้นรัน ; Check Point IPS noise มีหลายระดับความรุนแรง
- เพิ่มเคส 2 เคส (75 → 77) ; case_id ถูกสุ่มใหม่ทั้งชุดเพราะจำนวนเคสเปลี่ยน
- validator เพิ่ม realism guard: FortiGate intfrole ผิด = 0, logon จากอินเทอร์เน็ตบน host DMZ ต้องมี
  flow ที่ IP+port ตรงกัน, ทุก F5 request ต้องมี client ใน PA-DMZ

## v4.1 (แก้ตาม audit รอบ 4 ; ผล audit รอบ 5 = 8/10)
- host ของเคสมาจาก pool เดียวกับ noise ; ผู้ใช้ทั่วไป map ลงเครื่อง WKS-GEN แบบคงที่ ; telemetry ครบทุก workstation
- baseline ต่อวันของทุก Windows server (process ระบบ, การคุยกับ DC, service logon, งานแอดมิน, IIS/RDS)
- LogonId ใหม่ทุก session (4624 → 4634), SubjectLogonId ทุกตัวอ้าง session ที่เปิดอยู่จริง
- ทราฟฟิกขาเข้า DMZ ผ่าน FGT-EDGE (DNAT twin กับ PA-DMZ) ; DNS debug ใช้ worker thread หลายตัว ;
  FGT utm noise เพิ่ม
- validator เพิ่ม leak-check ระดับ host (ชุด host, เลขเครื่อง, ปริมาณ log, สัดส่วนเคส)

## v4 (แก้ตาม audit รอบ 3 ; ผล audit รอบ 4 = 7.5/10)
- เวลาเริ่มเคสมาจากตารางที่ไม่ดู label (กระจาย 4 วัน) ; offset ภายในกลุ่มถูก scale จึงไม่อยู่บนนาทีหาร 5
- leak-check แบบ leave-one-out ใน validator (ตำแหน่ง, เวลา, ชั่วโมง, วัน, ชุด source, ชุด EID, ความแรง alert, task_type)
- Sysmon process tree ตามย้อนได้ (GUID/PID คงที่, สังเคราะห์ EID 1 ที่ขาด) ; lsass PID คงที่ต่อโฮสต์
- NAT: PA ไม่ทำ NAT, FGT-EDGE ทำ SNAT และมี record คู่กับ PA-CORE ทุก flow
- เพิ่ม noise ให้ทุกชนิด event ที่เคยมีเฉพาะในเคส ; RecordID มีช่องว่าง ; prompt เป็นกลาง ;
  ค่าทั้งหมดเป็นค่าปลอมที่ปลอดภัย (RFC5737, .example, serial ปลอม)

## v3 และก่อนหน้า
- โครงสร้างชุดข้อมูล 19 แหล่ง log, schema, scorer, validator และ ATT&CK whitelist (v19)

## ผลตรวจคุณภาพ (v4.2.1, seed 20261113)
- validator PASSED, warnings 0 ; scorer oracle = 1.0
- leak-check LOO (input feature เดี่ยว → label) ทุก feature ต่ำกว่าเกณฑ์ (gap ≤ +0.10)
- generator byte-identical ข้าม PYTHONHASHSEED ; seed 1, 7, 42 ผ่าน validator
