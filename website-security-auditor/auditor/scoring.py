"""
Auditor Scoring & Compliance Engine
คำนวณคะแนน 0/1/2, ตรวจสอบ P0 Gate 10 ข้อ, และเปรียบเทียบผลลัพธ์รอบก่อน (Delta)
"""

from typing import Any, Dict, List, Optional, Tuple


class ChecklistItem:
    def __init__(
        self,
        item_id: str,
        module: str,
        check: str,
        status: str = "UNKNOWN",
        score: int = 1,
        evidence: Optional[List[str]] = None,
        note: str = "",
        p0_gate_id: Optional[int] = None,
    ):
        self.item_id = item_id
        self.module = module
        self.check = check
        self.status = status  # PASS, FAIL, UNKNOWN
        self.score = score    # 0, 1, 2
        self.evidence = evidence or []
        self.note = note
        self.p0_gate_id = p0_gate_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.item_id,
            "module": self.module,
            "check": self.check,
            "status": self.status,
            "score": self.score,
            "evidence": self.evidence,
            "note": self.note,
        }


# ==============================================================================
# รายการ 10 P0 Security Gates (Hardcoded)
# หากข้อใดข้อหนึ่งไม่ผ่าน (FAIL) ผลสรุปต้องเป็น "NOT PASS" ทันที
# ==============================================================================
P0_GATES: Dict[int, str] = {
    1: "db/service เปิดสู่ internet (Database port exposed)",
    2: ".git/.env/*.sql/backup เปิด (200) (Sensitive files / backups exposed)",
    3: "SQLi ที่พิสูจน์ได้ (Proven SQL Injection lead)",
    4: "IDOR/auth bypass (Unauthenticated administrative access)",
    5: "password plaintext/hash อ่อน (Exposed secrets or plaintext credentials)",
    6: "cookie session ขาด Secure/HttpOnly/SameSite (Insecure session cookies)",
    7: "upload ไม่ตรวจ content (Unrestricted file upload)",
    8: "LFI/SSRF (Path traversal or SSRF exposure)",
    9: "CVE CVSS>=9 ที่ใช้งาน (Critical active CVE vulnerability)",
    10: "ไม่มี HTTPS/TLS1.0-1.1 (Missing HTTPS or deprecated TLS 1.0/1.1 enabled)",
}


def calculate_item_score(status: str, has_evidence: bool) -> int:
    """
    คำนวณคะแนนตามข้อกำหนด:
    0 = ยังไม่ได้ทำ / พบปัญหา (FAIL)
    1 = ทำแล้วแต่หลักฐานไม่สมบูรณ์ หรือ UNKNOWN
    2 = ทำแล้ว + หลักฐานยืนยัน (PASS และต้องมีไฟล์หลักฐาน)
    """
    st = status.upper()
    if st == "FAIL":
        return 0
    elif st == "PASS":
        return 2 if has_evidence else 1
    else:  # UNKNOWN หรืออื่นๆ
        return 1


class ScoringEngine:
    @staticmethod
    def evaluate(
        items: List[ChecklistItem],
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        findings = findings or []
        pass_count = 0
        fail_count = 0
        unknown_count = 0
        total_score = 0
        p0_failures: List[Dict[str, Any]] = []

        total_items = len(items)
        max_possible_score = total_items * 2 if total_items > 0 else 1

        for item in items:
            has_ev = bool(item.evidence and len(item.evidence) > 0)
            item.score = calculate_item_score(item.status, has_ev)
            total_score += item.score

            st = item.status.upper()
            if st == "PASS":
                pass_count += 1
            elif st == "FAIL":
                fail_count += 1
                if item.p0_gate_id and item.p0_gate_id in P0_GATES:
                    p0_failures.append({
                        "gate_id": item.p0_gate_id,
                        "description": P0_GATES[item.p0_gate_id],
                        "check_id": item.item_id,
                        "check": item.check,
                        "note": item.note,
                    })
            else:
                unknown_count += 1

        # ตรวจสอบว่ามี findings ที่เป็นระดับ P0 หรือไม่
        for f in findings:
            if f.get("severity") == "P0":
                # เพิ่มลงใน p0_failures ถ้ายังไม่มี
                p0_failures.append({
                    "gate_id": 0,
                    "description": f.get("title", "Critical Finding"),
                    "check_id": f.get("affected", "N/A"),
                    "check": f.get("title", ""),
                    "note": f.get("impact", ""),
                })

        coverage_pct = round((total_score / max_possible_score) * 100.0, 2)

        # เงื่อนไข Verdict: หากมี P0 FAIL ข้อใดข้อหนึ่ง -> "NOT PASS" เสมอ แม้ coverage 99%
        if p0_failures or fail_count > 0:
            verdict = "NOT PASS"
        else:
            verdict = "PASS"

        return {
            "verdict": verdict,
            "coverage_pct": coverage_pct,
            "summary": {
                "pass": pass_count,
                "fail": fail_count,
                "unknown": unknown_count,
                "total": total_items,
            },
            "p0_failures": p0_failures,
            "items": [item.to_dict() for item in items],
        }

    @staticmethod
    def compare_runs(
        old_report: Dict[str, Any],
        new_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        เปรียบเทียบผลการตรวจสอบ 2 รอบ (Delta Comparison)
        """
        old_summary = old_report.get("summary", {})
        new_summary = new_report.get("summary", {})

        old_cov = old_report.get("coverage_pct", 0.0)
        new_cov = new_report.get("coverage_pct", 0.0)

        old_items = {it["id"]: it for it in old_report.get("items", [])}
        new_items = {it["id"]: it for it in new_report.get("items", [])}

        status_changes = []
        score_changes = []

        for item_id, new_it in new_items.items():
            if item_id in old_items:
                old_it = old_items[item_id]
                if old_it.get("status") != new_it.get("status"):
                    status_changes.append({
                        "id": item_id,
                        "check": new_it.get("check", ""),
                        "old_status": old_it.get("status"),
                        "new_status": new_it.get("status"),
                    })
                if old_it.get("score") != new_it.get("score"):
                    score_changes.append({
                        "id": item_id,
                        "check": new_it.get("check", ""),
                        "old_score": old_it.get("score"),
                        "new_score": new_it.get("score"),
                    })

        old_p0_count = sum(
            1 for f in old_report.get("findings", []) if f.get("severity") == "P0"
        )
        new_p0_count = sum(
            1 for f in new_report.get("findings", []) if f.get("severity") == "P0"
        )

        improved = (new_cov > old_cov) or (new_summary.get("fail", 0) < old_summary.get("fail", 0))
        regressed = (new_cov < old_cov) or (new_summary.get("fail", 0) > old_summary.get("fail", 0))

        if improved and not regressed:
            overall_direction = "IMPROVED"
        elif regressed and not improved:
            overall_direction = "REGRESSED"
        else:
            overall_direction = "NEUTRAL"

        return {
            "old_date": old_report.get("date", "unknown"),
            "new_date": new_report.get("date", "unknown"),
            "old_verdict": old_report.get("verdict", "UNKNOWN"),
            "new_verdict": new_report.get("verdict", "UNKNOWN"),
            "old_coverage": old_cov,
            "new_coverage": new_cov,
            "coverage_delta": round(new_cov - old_cov, 2),
            "status_changes": status_changes,
            "score_changes": score_changes,
            "old_p0_count": old_p0_count,
            "new_p0_count": new_p0_count,
            "overall_direction": overall_direction,
        }
