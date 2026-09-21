"""
Auditor Report Generator
สร้างรายงานตรวจสอบความปลอดภัยตาม JSON schema และรายงาน Markdown (รวม Delta Report)
"""

from datetime import datetime
import json
import os
from typing import Any, Dict, List, Optional


class ReportGenerator:
    def __init__(self, data: Dict[str, Any], output_dir: str = "."):
        self.data = data
        self.output_dir = output_dir

    def get_json_filename(self, date_str: str) -> str:
        safe_date = date_str.replace(":", "-").replace(" ", "_")
        return os.path.join(self.output_dir, f"report-{safe_date}.json")

    def get_md_filename(self, date_str: str) -> str:
        safe_date = date_str.replace(":", "-").replace(" ", "_")
        return os.path.join(self.output_dir, f"report-{safe_date}.md")

    def save_json(self, date_str: str) -> str:
        filepath = self.get_json_filename(date_str)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        return filepath

    def save_markdown(self, date_str: str) -> str:
        filepath = self.get_md_filename(date_str)
        md_content = self.generate_markdown()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        return filepath

    def generate_markdown(self) -> str:
        domain = self.data.get("domain", "Unknown")
        date = self.data.get("date", "Unknown")
        verdict = self.data.get("verdict", "UNKNOWN")
        coverage = self.data.get("coverage_pct", 0.0)
        summary = self.data.get("summary", {})
        findings = self.data.get("findings", [])
        items = self.data.get("items", [])
        limitations = self.data.get("limitations", [])
        commands_run = self.data.get("commands_run", [])

        status_badge = "🔴 NOT PASS" if verdict == "NOT PASS" else "🟢 PASS"

        lines = [
            f"# รายงานผลการตรวจสอบความปลอดภัยเว็บไซต์: {domain}",
            "",
            f"- **วันที่ตรวจสอบ:** {date}",
            f"- **ผลการประเมิน (Verdict):** {status_badge}",
            f"- **ระดับความครอบคลุม (Coverage):** {coverage:.1f}%",
            f"- **สถิติผลการตรวจ:** ผ่าน {summary.get('pass', 0)} | ไม่ผ่าน {summary.get('fail', 0)} | ไม่ทราบสถานะ {summary.get('unknown', 0)} (รวม {summary.get('total', 0)} รายการ)",
            "",
            "---",
            "",
            "## 1. ข้อค้นพบความปลอดภัย (Security Findings)",
            "",
        ]

        if not findings:
            lines.append("✅ ไม่พบช่องโหว่ความเสี่ยงระดับวิกฤต (P0-P2)")
            lines.append("")
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "P2")
                sev_icon = "🚨 P0 (Critical)" if sev == "P0" else ("⚠️ P1 (High)" if sev == "P1" else "ℹ️ P2 (Medium)")
                lines.extend([
                    f"### {idx}. [{sev_icon}] {f.get('title')}",
                    f"- **เป้าหมายที่ได้รับผลกระทบ (Affected):** `{f.get('affected')}`",
                    f"- **ผลกระทบ (Impact):** {f.get('impact')}",
                    f"- **วิธีจำลอง (Reproduce):** `{f.get('reproduce')}`",
                    f"- **คำแนะนำแก้ไข (Remediation):** {f.get('remediation')}",
                    "- **หลักฐาน (Evidence):**",
                ])
                for ev in f.get("evidence", []):
                    lines.append(f"  - `{ev}`")
                lines.append("")

        lines.extend([
            "---",
            "",
            "## 2. รายละเอียดการตรวจรายข้อ (Checklist Items)",
            "",
            "| ID | โมดูล | การตรวจสอบ | สถานะ | คะแนน | หลักฐาน / หมายเหตุ |",
            "| :--- | :--- | :--- | :---: | :---: | :--- |",
        ])

        for it in items:
            st = it.get("status", "UNKNOWN")
            st_icon = "🟢 PASS" if st == "PASS" else ("🔴 FAIL" if st == "FAIL" else "⚪ UNKNOWN")
            ev_str = "<br>".join([f"`{os.path.basename(e)}`" for e in it.get("evidence", [])])
            note_str = it.get("note", "")
            full_note = f"{ev_str}<br>{note_str}" if ev_str and note_str else (ev_str or note_str or "-")
            lines.append(
                f"| {it.get('id')} | {it.get('module')} | {it.get('check')} | {st_icon} | {it.get('score')} | {full_note} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. ข้อจำกัดและเงื่อนไขความปลอดภัย (Limitations & Safety)",
            "",
        ])
        for lim in limitations:
            lines.append(f"- {lim}")

        lines.extend([
            "",
            "## 4. บันทึกคำสั่งที่รัน (Executed Commands Audit Trail)",
            "",
            "```bash",
        ])
        for cmd in commands_run:
            lines.append(cmd)
        lines.extend([
            "```",
            "",
            "---",
            "*สร้างโดยระบบ website-security-auditor — ข้อมูลในรายงานนี้สร้างขึ้นจากการพิสูจน์เชิงประจักษ์*",
        ])

        return "\n".join(lines)

    @classmethod
    def generate_delta_markdown(cls, delta: Dict[str, Any], output_dir: str = ".") -> str:
        date_str = delta.get("new_date", datetime.now().strftime("%Y%m%d_%H%M%S"))
        safe_date = date_str.replace(":", "-").replace(" ", "_")
        filepath = os.path.join(output_dir, f"report-delta-{safe_date}.md")

        direction = delta.get("overall_direction", "NEUTRAL")
        direction_icon = "📈 ปรับปรุงดีขึ้น (IMPROVED)" if direction == "IMPROVED" else (
            "📉 มีความเสี่ยงเพิ่มขึ้น (REGRESSED)" if direction == "REGRESSED" else "⚖️ เท่าเดิม (NEUTRAL)"
        )

        lines = [
            f"# รายงานเปรียบเทียบผลการตรวจความปลอดภัย (Delta Report)",
            "",
            f"- **รอบเดิม:** {delta.get('old_date')} (ผล: {delta.get('old_verdict')}, ครอบคลุม: {delta.get('old_coverage')}%)",
            f"- **รอบใหม่:** {delta.get('new_date')} (ผล: {delta.get('new_verdict')}, ครอบคลุม: {delta.get('new_coverage')}%)",
            f"- **ทิศทางความปลอดภัยโดยรวม:** {direction_icon}",
            f"- **การเปลี่ยนแปลงความครอบคลุม:** {delta.get('coverage_delta'):+0.2f}%",
            f"- **จำนวนข้อค้นพบระดับวิกฤต (P0):** เดิม {delta.get('old_p0_count')} รายการ ➡️ ใหม่ {delta.get('new_p0_count')} รายการ",
            "",
            "---",
            "",
            "## 1. รายการที่มีการเปลี่ยนสถานะ (Status Transitions)",
            "",
        ]

        status_changes = delta.get("status_changes", [])
        if not status_changes:
            lines.append("ไม่มีรายการตรวจที่เปลี่ยนสถานะ")
            lines.append("")
        else:
            lines.extend([
                "| รหัส | หัวข้อตรวจ | สถานะเดิม | สถานะใหม่ | ผลกระทบ |",
                "| :--- | :--- | :---: | :---: | :--- |",
            ])
            for ch in status_changes:
                old_s = ch.get("old_status")
                new_s = ch.get("new_status")
                impact = "🟢 ดีขึ้น (Resolved)" if (old_s == "FAIL" and new_s == "PASS") else (
                    "🔴 แย่ลง (New Failure)" if new_s == "FAIL" else "⚪ เปลี่ยนแปลง"
                )
                lines.append(f"| {ch.get('id')} | {ch.get('check')} | {old_s} | {new_s} | {impact} |")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 2. รายการที่มีการเปลี่ยนคะแนน (Score Changes)",
            "",
        ])
        score_changes = delta.get("score_changes", [])
        if not score_changes:
            lines.append("ไม่มีรายการตรวจที่เปลี่ยนคะแนน")
        else:
            lines.extend([
                "| รหัส | หัวข้อตรวจ | คะแนนเดิม | คะแนนใหม่ | ผลต่าง |",
                "| :--- | :--- | :---: | :---: | :---: |",
            ])
            for sc in score_changes:
                old_sc = sc.get("old_score", 0)
                new_sc = sc.get("new_score", 0)
                lines.append(f"| {sc.get('id')} | {sc.get('check')} | {old_sc} | {new_sc} | {new_sc - old_sc:+d} |")

        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
