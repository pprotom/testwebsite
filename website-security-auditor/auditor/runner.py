"""
Auditor Orchestration Runner
ควบคุมลำดับการรันทั้ง 5 โมดูล, จัดการ rerun (แคช recon < 24 ชม.), report-only, การเก็บหลักฐาน และคำนวณคะแนน
"""

from datetime import datetime
import json
import os
import time
from typing import Any, Dict, List, Optional

from .config import AuditorConfig
from .evidence import EvidenceManager
from .modules.files import run_files
from .modules.infra import run_infra
from .modules.recon import run_recon
from .modules.supply import run_supply
from .modules.weblayer import run_weblayer
from .report import ReportGenerator
from .scanner import CommandScanner
from .scoring import ChecklistItem, ScoringEngine


class AuditRunner:
    def __init__(
        self,
        config: AuditorConfig,
        only_module: Optional[str] = None,
        rerun_mode: bool = False,
        report_only: bool = False,
        compare_path: Optional[str] = None,
    ):
        self.config = config
        self.only_module = only_module.lower() if only_module else None
        self.rerun_mode = rerun_mode
        self.report_only = report_only
        self.compare_path = compare_path

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.evidence_mgr = EvidenceManager(
            base_dir=self.config.evidence_dir,
            timestamp=self.timestamp,
        )
        self.scanner = CommandScanner(
            safe_mode=self.config.safe_mode,
            allow_risky=self.config.allow_risky,
            timeout=self.config.command_timeout,
        )

    def execute(self) -> Dict[str, Any]:
        """
        รันการตรวจความปลอดภัยตามเงื่อนไขที่กำหนด
        """
        all_items: List[ChecklistItem] = []
        all_findings: List[Dict[str, Any]] = []
        limitations: List[str] = [
            f"Authorized Scope restricted to: {', '.join(self.config.allowed_domains)}",
            f"Command Timeout enforced at <= {self.config.command_timeout}s",
            f"Safe Mode is {'ACTIVE (non-destructive)' if self.config.safe_mode else 'DISABLED'}",
            f"Port scan capped at {self.config.port_scan_limit} ports without interactive confirmation",
        ]

        recon_data: Dict[str, Any] = {}

        # ==============================================================================
        # โหมด Report-Only: โหลดผลการประเมินที่มีอยู่เดิม
        # ==============================================================================
        if self.report_only:
            latest_recon = EvidenceManager.get_latest_module_evidence(self.config.evidence_dir, "recon")
            if latest_recon:
                recon_summary_path = os.path.join(latest_recon, "recon_summary.json")
                if os.path.exists(recon_summary_path):
                    try:
                        with open(recon_summary_path, "r", encoding="utf-8") as f:
                            recon_data = json.load(f)
                    except Exception:
                        pass

            limitations.append("Generated from cached evidence in --report-only mode.")

        # ==============================================================================
        # โมดูล 1: RECON
        # ==============================================================================
        if not self.report_only and (not self.only_module or self.only_module == "recon"):
            # ตรวจสอบ rerun: ถ้ามีผล recon < 24 ชม. สามารถข้ามเพื่อลด traffic
            cached_recon_dir = EvidenceManager.get_latest_module_evidence(self.config.evidence_dir, "recon")
            skip_recon = False
            if self.rerun_mode and cached_recon_dir and EvidenceManager.is_within_hours(cached_recon_dir, 24.0):
                recon_summary = os.path.join(cached_recon_dir, "recon_summary.json")
                if os.path.exists(recon_summary):
                    try:
                        with open(recon_summary, "r", encoding="utf-8") as f:
                            recon_data = json.load(f)
                            skip_recon = True
                            limitations.append(f"Recon skipped via --rerun (using fresh cache from {os.path.basename(cached_recon_dir)} < 24h)")
                    except Exception:
                        pass

            if not skip_recon:
                recon_res = run_recon(self.config, self.scanner, self.evidence_mgr)
                all_items.extend(recon_res.get("items", []))
                all_findings.extend(recon_res.get("findings", []))
                recon_data = recon_res

        # ==============================================================================
        # โมดูล 2: FILES
        # ==============================================================================
        if not self.report_only and (not self.only_module or self.only_module == "files"):
            files_res = run_files(self.config, self.scanner, self.evidence_mgr)
            all_items.extend(files_res.get("items", []))
            all_findings.extend(files_res.get("findings", []))

        # ==============================================================================
        # โมดูล 3: WEBLAYER
        # ==============================================================================
        if not self.report_only and (not self.only_module or self.only_module == "weblayer"):
            weblayer_res = run_weblayer(self.config, self.scanner, self.evidence_mgr)
            all_items.extend(weblayer_res.get("items", []))
            all_findings.extend(weblayer_res.get("findings", []))

        # ==============================================================================
        # โมดูล 4: INFRA
        # ==============================================================================
        if not self.report_only and (not self.only_module or self.only_module == "infra"):
            infra_res = run_infra(self.config, self.scanner, self.evidence_mgr)
            all_items.extend(infra_res.get("items", []))
            all_findings.extend(infra_res.get("findings", []))

        # ==============================================================================
        # โมดูล 5: SUPPLY
        # ==============================================================================
        if not self.report_only and (not self.only_module or self.only_module == "supply"):
            supply_res = run_supply(self.config, self.scanner, self.evidence_mgr, recon_data=recon_data)
            all_items.extend(supply_res.get("items", []))
            all_findings.extend(supply_res.get("findings", []))

        # ==============================================================================
        # คำนวณคะแนน (Scoring & P0 Gate)
        # ==============================================================================
        eval_result = ScoringEngine.evaluate(all_items, all_findings)

        report_payload: Dict[str, Any] = {
            "domain": self.config.domain,
            "date": self.date_str,
            "verdict": eval_result["verdict"],
            "coverage_pct": eval_result["coverage_pct"],
            "summary": eval_result["summary"],
            "items": eval_result["items"],
            "findings": all_findings,
            "limitations": limitations,
            "commands_run": self.scanner.history,
        }

        # บันทึกรายงาน Markdown และ JSON
        report_gen = ReportGenerator(report_payload, output_dir=self.config.report_dir)
        json_path = report_gen.save_json(self.timestamp)
        md_path = report_gen.save_markdown(self.timestamp)

        delta_info = None
        delta_md_path = None

        # ==============================================================================
        # Delta Comparison (ถ้ามีการระบุ --compare <path>)
        # ==============================================================================
        if self.compare_path and os.path.exists(self.compare_path):
            try:
                with open(self.compare_path, "r", encoding="utf-8") as f:
                    old_report_data = json.load(f)
                delta_info = ScoringEngine.compare_runs(old_report_data, report_payload)
                delta_md_path = ReportGenerator.generate_delta_markdown(
                    delta_info, output_dir=self.config.report_dir
                )
            except Exception as e:
                limitations.append(f"Delta comparison failed: {e}")

        return {
            "report": report_payload,
            "json_path": json_path,
            "md_path": md_path,
            "delta_info": delta_info,
            "delta_md_path": delta_md_path,
            "timestamp": self.timestamp,
        }
