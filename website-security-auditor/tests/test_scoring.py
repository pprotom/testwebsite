"""
Unit Tests for Auditor Scoring Engine (test_scoring.py)
ทดสอบระบบคะแนน 0/1/2, การบังคับใช้ P0 Gate และการเปรียบเทียบผล Delta
"""

import json
import os
import unittest
from auditor.scoring import (
    ChecklistItem,
    P0_GATES,
    ScoringEngine,
    calculate_item_score,
)


class TestScoringEngine(unittest.TestCase):
    def test_calculate_item_score(self):
        """ทดสอบกฎการให้คะแนน 0 / 1 / 2"""
        # FAIL ต้องได้ 0 เสมอ แม้มี evidence
        self.assertEqual(calculate_item_score("FAIL", True), 0)
        self.assertEqual(calculate_item_score("FAIL", False), 0)

        # UNKNOWN ต้องได้ 1
        self.assertEqual(calculate_item_score("UNKNOWN", False), 1)
        self.assertEqual(calculate_item_score("UNKNOWN", True), 1)

        # PASS แต่ไม่มีไฟล์ evidence ได้ 1
        self.assertEqual(calculate_item_score("PASS", False), 1)

        # PASS และมีหลักฐาน ได้คะแนนเต็ม 2
        self.assertEqual(calculate_item_score("PASS", True), 2)

    def test_coverage_calculation(self):
        """ทดสอบการคำนวณร้อยละความครอบคลุม (Coverage %)"""
        items = [
            ChecklistItem("1.1", "recon", "DNS Scope", status="PASS", evidence=["ev1.txt"]),  # score 2
            ChecklistItem("1.2", "recon", "Port Scan", status="PASS", evidence=["ev2.txt"]),  # score 2
            ChecklistItem("1.3", "recon", "WAF Detect", status="UNKNOWN", evidence=[]),        # score 1
            ChecklistItem("1.4", "recon", "DB Exposed", status="PASS", evidence=[]),           # score 1 (no ev)
        ]
        # Total items = 4, max score = 8
        # Scores: 2 + 2 + 1 + 1 = 6. 6 / 8 * 100 = 75.0%
        result = ScoringEngine.evaluate(items)
        self.assertEqual(result["coverage_pct"], 75.0)
        self.assertEqual(result["summary"]["pass"], 3)
        self.assertEqual(result["summary"]["unknown"], 1)
        self.assertEqual(result["summary"]["fail"], 0)
        self.assertEqual(result["verdict"], "PASS")

    def test_p0_gate_enforcement(self):
        """
        ทดสอบเงื่อนไข P0 Gate:
        หากมีข้อ P0 ข้อใดล้มเหลว (FAIL) ผล verdict ต้องเป็น 'NOT PASS' เสมอ แม้ coverage จะสูง
        """
        items = [
            ChecklistItem("1.1", "recon", "Check 1", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.2", "recon", "Check 2", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.3", "recon", "Check 3", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.4", "recon", "Check 4", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.5", "recon", "Check 5", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.6", "recon", "Check 6", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.7", "recon", "Check 7", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.8", "recon", "Check 8", status="PASS", evidence=["ev.txt"]),
            ChecklistItem("1.9", "recon", "Check 9", status="PASS", evidence=["ev.txt"]),
            # ข้อ P0 Gate #1 (DB exposed) ล้มเหลว
            ChecklistItem(
                "2.0",
                "recon",
                "Database Port Exposed",
                status="FAIL",
                evidence=["db.txt"],
                p0_gate_id=1,
            ),
        ]
        # 9 PASS (18 pts) + 1 FAIL (0 pts) = 18 / 20 = 90.0% coverage
        result = ScoringEngine.evaluate(items)
        self.assertEqual(result["coverage_pct"], 90.0)
        self.assertEqual(result["verdict"], "NOT PASS")
        self.assertTrue(len(result["p0_failures"]) > 0)
        self.assertEqual(result["p0_failures"][0]["gate_id"], 1)

    def test_all_10_p0_gates_defined(self):
        """ตรวจสอบว่ารายการ 10 P0 Hardcoded Gates ครบถ้วนตามโจทย์"""
        self.assertEqual(len(P0_GATES), 10)
        for i in range(1, 11):
            self.assertIn(i, P0_GATES)

    def test_delta_comparison(self):
        """ทดสอบการเปรียบเทียบผลรอบก่อน (Delta Compare) จากไฟล์ fixture"""
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        base_path = os.path.join(fixtures_dir, "sample_report_baseline.json")
        imp_path = os.path.join(fixtures_dir, "sample_report_improved.json")

        with open(base_path, "r", encoding="utf-8") as f:
            old_data = json.load(f)
        with open(imp_path, "r", encoding="utf-8") as f:
            new_data = json.load(f)

        delta = ScoringEngine.compare_runs(old_data, new_data)

        self.assertEqual(delta["old_verdict"], "NOT PASS")
        self.assertEqual(delta["new_verdict"], "PASS")
        self.assertEqual(delta["coverage_delta"], 20.0)
        self.assertEqual(delta["overall_direction"], "IMPROVED")
        self.assertEqual(delta["old_p0_count"], 1)
        self.assertEqual(delta["new_p0_count"], 0)
        self.assertTrue(len(delta["status_changes"]) >= 2)


if __name__ == "__main__":
    unittest.main()
