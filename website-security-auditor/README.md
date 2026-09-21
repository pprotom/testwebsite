# Website Security Auditor (ระบบตรวจสอบความปลอดภัยเว็บไซต์อัตโนมัติ)

ระบบตรวจสอบความปลอดภัยเว็บไซต์อัตโนมัติสำหรับสภาพแวดล้อม Linux พัฒนาด้วย **Python 3.10+** และสคริปต์ **Bash wrapper** โดยยึดหลักการประเมินเชิงประจักษ์:

> **"Look like closed ≠ proven closed" (ดูเหมือนปิด ≠ พิสูจน์แล้วว่าปิดจริง)**  
> ทุกข้อสรุปต้องมีไฟล์หลักฐานดิบ (Raw Evidence) รองรับพร้อมบันทึก SHA-256 Checksum ตรวจสอบย้อนกลับได้เสมอ

---

## 1. สถาปัตยกรรมระบบ (System Architecture)

ระบบประกอบด้วย 5 โมดูลหลัก ทำงานอย่างเป็นอิสระและเชื่อมโยงกันอย่างเป็นระบบ:

```
website-security-auditor/
├── main.py                  # CLI Entrypoint (Rich terminal, argparse)
├── config.yaml              # ค่าคอนฟิกเป้าหมาย, Scope, Safe Mode, Proxy
├── config.example.yaml      # ไฟล์ตัวอย่างคอนฟิก
├── requirements.txt         # รายการ Python dependencies
├── auditor/
│   ├── config.py            # ตรวจสอบ Scope, CIDR, Domain, Limiter
│   ├── evidence.py          # EvidenceManager บันทึกไฟล์พร้อมคำนวณ SHA-256
│   ├── scanner.py           # Subprocess wrapper, Timeout <= 60s, Retry, Safety guard
│   ├── scoring.py           # Scoring Engine (0/1/2), 10 P0 Gates, Delta engine
│   ├── runner.py            # Orchestrator คุม 5 โมดูล, Rerun cache, Report-only
│   ├── report.py            # Markdown, JSON Schema & Delta Report Generator
│   └── modules/
│       ├── recon.py         # D1: IP, Port 1000, Subdomain, Tech stack, WAF
│       ├── files.py         # D2: Sensitive files (.git, .env, backups), Dir listing
│       ├── weblayer.py      # D3: 5 Security Headers, HTTPS redirect, TLS, Cookies, SQLi
│       ├── infra.py         # D4: DB Ports (3306..), TruffleHog secrets, robots/sitemap
│       └── supply.py        # D5: Dependency audit, CVE matching (CVSS >= 7, 9)
├── scripts/
│   ├── install-tools.sh     # ตรวจสอบและติดตั้งเครื่องมือภายนอก (ขอการยืนยันทีละตัว)
│   └── run-audit.sh         # Bash wrapper เปิด venv แล้วรันการตรวจสอบ
└── tests/
    ├── test_scoring.py      # Unit tests ระบบคะแนน, P0 gates และ Delta report
    ├── test_scanner.py      # Unit tests Subprocess, Timeout, Safety patterns, Safe mode
    └── fixtures/            # ไฟล์ตัวอย่างผลการสแกนและรายงาน
```

---

## 2. กฎเหล็กความปลอดภัย (Safety System & Limiters)

1. **Safe Mode (Default ON):**
   - ไม่อนุญาตให้รันคำสั่งเชิงรุก (เช่น `sqlmap`, `nikto`, `hydra`) เว้นแต่ผู้ใช้จะระบุอย่างชัดเจนผ่าน `--allow-risky <tool_name>` หรือเปิดใน `config.yaml`
2. **ห้ามคำสั่งและแฟล็กทำลายล้างเด็ดขาด:**
   - ระบบจะสกัดกั้นและปฏิเสธคำสั่งที่มี `--drop`, `rm -rf`, `--os-shell`, `--os-cmd`, `--purge`, `mkfs`, `dd if=`, SQL DDL (`DROP TABLE`, `DELETE FROM`) ทันที
3. **การจำกัดขอบเขต (Scope Enforcement):**
   - ตรวจสอบ Domain และ IP ที่ Resolve ได้เทียบกับ `allowed_domains` ในคอนฟิก ปฏิเสธการสแกนเป้าหมายนอกขอบเขต
4. **Safety Limiters:**
   - เวลาจำกัดคำสั่ง (Timeout) สูงสุดไม่เกิน 60 วินาที
   - การสแกนพอร์ตจำกัดที่ 1,000 พอร์ต เว้นแต่จะระบุ `--confirm-large-scan`
   - Concurrency จำกัดที่ 3 เพื่อไม่รบกวนประสิทธิภาพเซิร์ฟเวอร์เป้าหมาย

---

## 3. เกณฑ์ 10 ประตูความปลอดภัยระดับวิกฤต (10 Hardcoded P0 Gates)

หากพบข้อใดข้อหนึ่งล้มเหลว (FAIL) ผลการตรวจสอบโดยรวมจะถูกตัดสินเป็น **NOT PASS** ทันที:

| Gate ID | หัวข้อการตรวจสอบ | ผลกระทบวิกฤต (P0 Severity) |
| :---: | :--- | :--- |
| **1** | Database Service Ports Exposed | พอร์ตฐานข้อมูล (3306, 5432, 27017, 6379, ฯลฯ) เปิดสู่อินเทอร์เน็ต |
| **2** | Sensitive Files Leaked (.git, .env, *.sql) | ไฟล์คอนฟิก, ประวัติ Git, หรือไฟล์สำรองข้อมูลเปิดสาธารณะ (HTTP 200) |
| **3** | SQL Injection Lead Detected | ตัวแปรตอบสนองต่อ SQL Syntax Error หรือ Boolean Differential ชัดเจน |
| **4** | Unauthenticated Admin Access | หน้าจัดการผู้ดูแลระบบ (Admin) เข้าถึงได้โดยไม่ต้องยืนยันตัวตน |
| **5** | Verified Secrets in Repository | พบ API Key, Token, หรือรหัสผ่านจริงในซอร์สโค้ด (TruffleHog) |
| **6** | Insecure Session Cookie Flags | คุกกี้เซสชันขาดแฟล็ก Secure, HttpOnly, หรือ SameSite |
| **7** | Remote Code Execution Lead | สัญญาณช่องโหว่รันคำสั่งบนเซิร์ฟเวอร์ (RCE / Command Injection) |
| **8** | Arbitrary File Upload Execution | อัปโหลดไฟล์เข้าสู่ไดเรกทอรีที่สามารถรันสคริปต์ได้ |
| **9** | Known Critical CVE (CVSS >= 9.0) | ส่วนประกอบซอฟต์แวร์ที่ใช้งานมีช่องโหว่วิกฤตที่ยืนยันแล้ว |
| **10** | Deprecated Insecure TLS (TLS 1.0/1.1) | เซิร์ฟเวอร์ยังคงเปิดใช้งานโปรโตคอลการเข้ารหัสที่เลิกใช้งาน |

---

## 4. ระบบการให้คะแนนและระดับความครอบคลุม (Scoring & Coverage)

- **0 คะแนน:** ไม่ผ่าน (FAIL) — ตรวจพบช่องโหว่หรือการตั้งค่าที่ไม่ปลอดภัย
- **1 คะแนน:** ไม่ทราบสถานะ (UNKNOWN) หรือตรวจผ่านแต่ไม่มีไฟล์หลักฐานดิบ (PASS without evidence)
- **2 คะแนน:** ผ่านอย่างสมบูรณ์ (PASS with raw evidence) — ตรวจสอบแล้วและมีไฟล์หลักฐานรองรับ
- **ระดับความครอบคลุม (Coverage %):**
  $$\text{Coverage \%} = \frac{\sum \text{คะแนนที่ได้}}{\text{จำนวนข้อ} \times 2} \times 100$$
- **คำตัดสิน (Verdict):**
  - `PASS`: ทุกข้อที่ประเมินผ่านเกณฑ์ความปลอดภัย และ **ไม่มี P0 ข้อใด FAIL**
  - `NOT PASS`: พบ **P0 อย่างน้อย 1 ข้อ FAIL** หรือมีข้อบกพร่องวิกฤต

---

## 5. วิธีการติดตั้งและใช้งาน (Installation & Usage)

### การติดตั้ง

```bash
# 1. ติดตั้ง System dependencies และ Python libraries
sudo apt-get update && sudo apt-get install -y nmap python3-requests python3-yaml python3-rich python3-click

# 2. ตรวจสอบเครื่องมือภายนอก (ระบบจะถามยืนยันทีละตัว)
./scripts/install-tools.sh
```

### คำสั่งการรันตรวจสอบ (CLI Usage)

```bash
# รันการตรวจสอบแบบเต็มรูปแบบ (ทุกโมดูล)
./scripts/run-audit.sh --config config.yaml

# รันเฉพาะโมดูลที่ต้องการ (เช่น files, recon, weblayer, infra, supply)
./scripts/run-audit.sh --config config.yaml --only files

# โหมด Rerun (ข้าม recon หากมีผลการสแกนเดิมที่ใหม่กว่า 24 ชั่วโมง)
./scripts/run-audit.sh --config config.yaml --rerun

# โหมด Report-Only (สร้างรายงานผลใหม่จากหลักฐานที่มีอยู่เดิมโดยไม่ต้องสแกนซ้ำ)
./scripts/run-audit.sh --config config.yaml --report-only

# เปรียบเทียบผลกับรอบก่อนหน้า (สร้าง Delta Report อัตโนมัติ)
./scripts/run-audit.sh --config config.yaml --compare reports/report-20260918_100000.json

# อนุญาตให้ใช้งานเครื่องมือเชิงรุกเฉพาะตัว
./scripts/run-audit.sh --config config.yaml --allow-risky sqlmap

# ยืนยันการสแกนมากกว่า 1000 พอร์ต
./scripts/run-audit.sh --config config.yaml --confirm-large-scan
```

### การรันชุดทดสอบ (Automated Unit Tests)

```bash
PYTHONPATH=website-security-auditor pytest -v website-security-auditor/tests/
```

---

## 6. ผลลัพธ์รายงาน (Report Outputs)

- `report-<date>.json`: รายงานข้อมูลตามมาตรฐาน JSON Schema พร้อมรายการข้อค้นพบและคำสั่งที่รัน
- `report-<date>.md`: รายงานภาษา Markdown ครบถ้วนตามโครงสร้างผู้บริหารและวิศวกรความปลอดภัย
- `report-delta-<date>.md`: รายงานเปรียบเทียบความแตกต่าง (Delta Report) สรุปทิศทางการปรับปรุง (IMPROVED / REGRESSED / NEUTRAL)
