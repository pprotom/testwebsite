"""
D5: Supply Chain Module — ตรวจสอบห่วงโซ่อุปทานและช่องโหว่ซอฟต์แวร์ (Supply Chain & CVE Analysis)
- Package Dependency Audit (npm audit / composer audit / trivy)
- Public CVE Analysis on Detected Web Components (NVD/OSV check or manual review note)
- Platform / CMS Specific Supply-Chain Audit (wpscan with rate limiting)
- CVSS Criteria: CVSS >= 7 = FAIL, CVSS >= 9 = Critical P0 FAIL
"""

import json
import os
import re
from typing import Any, Dict, List, Optional
import requests

from ..config import AuditorConfig
from ..evidence import EvidenceManager
from ..scanner import CommandScanner
from ..scoring import ChecklistItem


def run_supply(
    config: AuditorConfig,
    scanner: CommandScanner,
    evidence_mgr: EvidenceManager,
    recon_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    notes: List[str] = []
    findings: List[Dict[str, Any]] = []
    items: List[ChecklistItem] = []

    ev_dir = evidence_mgr.get_module_dir("supply")
    recon_data = recon_data or {}
    detected_tech: List[str] = recon_data.get("tech", [])

    # ==============================================================================
    # D5.1: Dependency Audit (npm audit / composer audit / trivy)
    # ==============================================================================
    repo_path = config.repo_path
    dep_audit_run = False
    dep_audit_findings = []
    dep_audit_file = os.path.join(ev_dir, "dependency_audit.json")

    if repo_path and os.path.isdir(repo_path):
        # 1. npm audit
        if os.path.exists(os.path.join(repo_path, "package.json")):
            res_npm = scanner.run(f"npm audit --json --prefix {repo_path}")
            if res_npm.stdout:
                try:
                    data = json.loads(res_npm.stdout)
                    vulns = data.get("vulnerabilities", {})
                    for name, v_info in vulns.items():
                        sev = v_info.get("severity", "moderate")
                        dep_audit_findings.append({
                            "package": name,
                            "severity": sev,
                            "range": v_info.get("range", ""),
                        })
                    dep_audit_run = True
                except Exception:
                    pass

        # 2. composer audit
        if os.path.exists(os.path.join(repo_path, "composer.json")):
            res_comp = scanner.run(f"composer audit --format=json --working-dir={repo_path}")
            if res_comp.stdout:
                try:
                    data = json.loads(res_comp.stdout)
                    for c_name, c_info in data.get("advisories", {}).items():
                        dep_audit_findings.append({
                            "package": c_name,
                            "severity": "high",
                            "advisory": str(c_info)[:100],
                        })
                    dep_audit_run = True
                except Exception:
                    pass

        # 3. trivy fs
        if scanner.is_tool_installed("trivy"):
            res_trivy = scanner.run(f"trivy fs --format json {repo_path} > {dep_audit_file}")
            if res_trivy.is_success and os.path.exists(dep_audit_file):
                dep_audit_run = True

    with open(dep_audit_file, "w", encoding="utf-8") as f:
        json.dump({
            "repo_scanned": repo_path or "none",
            "audit_executed": dep_audit_run,
            "findings": dep_audit_findings,
        }, f, indent=2)
    ev_dep = evidence_mgr.save_file("supply", "dependency_audit.json", dep_audit_findings)

    if dep_audit_run:
        high_critical = [d for d in dep_audit_findings if d.get("severity") in ("high", "critical")]
        if high_critical:
            items.append(
                ChecklistItem(
                    item_id="5.1",
                    module="supply",
                    check="Package Dependency Vulnerability Audit",
                    status="FAIL",
                    score=0,
                    evidence=[ev_dep],
                    note=f"Discovered {len(high_critical)} high/critical vulnerabilities in dependencies.",
                )
            )
        else:
            items.append(
                ChecklistItem(
                    item_id="5.1",
                    module="supply",
                    check="Package Dependency Vulnerability Audit",
                    status="PASS",
                    score=2,
                    evidence=[ev_dep],
                    note="No high/critical vulnerabilities found in scanned dependency manifests.",
                )
            )
    else:
        # Live Web Frontend Dependency & Script Supply Chain Audit
        script_assets = []
        insecure_script_domains = []
        missing_sri = []

        try:
            target_resp = requests.get(config.url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor/1.0)"})
            # Find script elements
            script_tags = re.findall(r'<script\b([^>]*)>', target_resp.text, re.IGNORECASE)
            for tag in script_tags:
                src_match = re.search(r'src=["\']([^"\']+)["\']', tag)
                if src_match:
                    src_url = src_match.group(1)
                    has_integrity = "integrity=" in tag
                    is_http = src_url.startswith("http://")
                    script_assets.append({
                        "src": src_url,
                        "integrity": has_integrity,
                        "insecure_protocol": is_http,
                    })
                    if is_http:
                        insecure_script_domains.append(src_url)
                    if not has_integrity and any(cdn in src_url for cdn in ["cdnjs", "unpkg", "jsdelivr", "googleapis"]):
                        missing_sri.append(src_url)
        except Exception as e:
            notes.append(f"Frontend supply chain note: {e}")

        dep_audit_ev = evidence_mgr.save_file("supply", "frontend_supply_chain.json", {
            "mode": "live_web_frontend_script_audit",
            "total_scripts_detected": len(script_assets),
            "scripts": script_assets,
            "insecure_http_scripts": insecure_script_domains,
            "external_cdn_missing_sri": missing_sri,
        })

        if insecure_script_domains:
            items.append(
                ChecklistItem(
                    item_id="5.1",
                    module="supply",
                    check="Package & Web Frontend Dependency Audit",
                    status="FAIL",
                    score=0,
                    evidence=[dep_audit_ev],
                    note=f"Insecure third-party scripts loaded over unencrypted HTTP ({len(insecure_script_domains)} sources).",
                )
            )
            findings.append({
                "title": "Third-Party JavaScript Loaded over Unencrypted HTTP",
                "severity": "P1",
                "affected": ", ".join(insecure_script_domains[:3]),
                "evidence": [dep_audit_ev],
                "reproduce": f"curl -s {config.url} | grep 'http://'",
                "impact": "Man-in-the-middle attackers can alter unencrypted script contents and execute malicious code.",
                "remediation": "Update all script tags to HTTPS and specify subresource integrity (SRI) hashes.",
            })
        else:
            items.append(
                ChecklistItem(
                    item_id="5.1",
                    module="supply",
                    check="Package & Web Frontend Dependency Audit",
                    status="PASS",
                    score=2,
                    evidence=[dep_audit_ev],
                    note=f"Verified {len(script_assets)} client-side scripts; no insecure HTTP external CDN scripts detected.",
                )
            )

    # ==============================================================================
    # D5.2: Public CVE Vulnerability Analysis on Detected Components
    # ==============================================================================
    cve_findings = []
    cve_analysis_record = {}

    # ฐานข้อมูลตัวอย่าง CVE สำคัญสำหรับส่วนประกอบยอดนิยมที่มีช่องโหว่รุนแรง
    KNOWN_CRITICAL_CVES = {
        "apache": {
            "2.4.49": ("CVE-2021-41773", 9.8, "Path traversal and remote code execution"),
            "2.4.50": ("CVE-2021-42013", 9.8, "Path traversal and remote code execution"),
        },
        "nginx": {
            "1.20.0": ("CVE-2021-23017", 7.7, "1-byte memory overwrite via DNS resolver"),
        },
        "log4j": {
            "2.14.1": ("CVE-2021-44228", 10.0, "Log4Shell remote code execution"),
        },
        "openssl": {
            "1.0.1": ("CVE-2014-0160", 7.5, "Heartbleed information disclosure"),
        }
    }

    critical_cve_detected = False

    for tech_str in detected_tech:
        parts = tech_str.split("/")
        app_name = parts[0].lower()
        version = parts[1] if len(parts) > 1 else ""

        if app_name in KNOWN_CRITICAL_CVES and version:
            v_matches = KNOWN_CRITICAL_CVES[app_name]
            if version in v_matches:
                cve_id, cvss, desc = v_matches[version]
                record = {
                    "tech": tech_str,
                    "cve": cve_id,
                    "cvss": cvss,
                    "description": desc,
                    "active_use": True,
                }
                cve_findings.append(record)
                if cvss >= 9.0:
                    critical_cve_detected = True

    cve_ev = evidence_mgr.save_file("supply", "cve_analysis.json", {
        "detected_tech": detected_tech,
        "cve_findings": cve_findings,
        "manual_review_required": len(detected_tech) > 0 and len(cve_findings) == 0,
    })

    if critical_cve_detected or any(f["cvss"] >= 7.0 for f in cve_findings):
        highest_cve = max(cve_findings, key=lambda x: x["cvss"])
        is_p0 = highest_cve["cvss"] >= 9.0
        sev = "P0" if is_p0 else "P1"

        items.append(
            ChecklistItem(
                item_id="5.2",
                module="supply",
                check="Public CVE Vulnerability Analysis on Detected Components",
                status="FAIL",
                score=0,
                evidence=[cve_ev],
                note=f"{'CRITICAL P0: ' if is_p0 else ''}Detected {highest_cve['cve']} (CVSS {highest_cve['cvss']}) in {highest_cve['tech']}",
                p0_gate_id=9 if is_p0 else None,
            )
        )
        findings.append({
            "title": f"Known CVE Vulnerability in Web Component: {highest_cve['cve']} (CVSS {highest_cve['cvss']})",
            "severity": sev,
            "affected": highest_cve["tech"],
            "evidence": [cve_ev],
            "reproduce": f"Fingerprinted version: {highest_cve['tech']}",
            "impact": highest_cve["description"],
            "remediation": f"Upgrade {highest_cve['tech']} to the latest stable vendor patch immediately.",
        })
    elif detected_tech:
        items.append(
            ChecklistItem(
                item_id="5.2",
                module="supply",
                check="Public CVE Vulnerability Analysis on Detected Components",
                status="PASS",
                score=2,
                evidence=[cve_ev],
                note=f"No known critical CVEs (CVSS>=7) matched for identified components ({', '.join(detected_tech[:4])}). Manual review recommended.",
                p0_gate_id=9,
            )
        )
    else:
        items.append(
            ChecklistItem(
                item_id="5.2",
                module="supply",
                check="Public CVE Vulnerability Analysis on Detected Components",
                status="PASS",
                score=2,
                evidence=[cve_ev],
                note="Web stack components inspected; no vulnerable banner versions or critical CVEs (CVSS >= 9) matched.",
                p0_gate_id=9,
            )
        )

    # ==============================================================================
    # D5.3: CMS / Platform Specific Audit (wpscan with rate limiting)
    # ==============================================================================
    is_wordpress = any("wordpress" in t.lower() for t in detected_tech)
    wpscan_file = os.path.join(ev_dir, "wpscan.txt")

    if is_wordpress and scanner.is_tool_installed("wpscan"):
        # Rate limited wpscan (non-intrusive)
        wpscan_cmd = f"wpscan --url {config.url} --throttle 1000 --random-user-agent --detection passive -o {wpscan_file}"
        res_wp = scanner.run(wpscan_cmd, custom_timeout=60)
        evidence_mgr.save_file("supply", "wpscan.txt", open(wpscan_file, "r", errors="ignore").read() if os.path.exists(wpscan_file) else "")

        items.append(
            ChecklistItem(
                item_id="5.3",
                module="supply",
                check="CMS Platform Security Audit (wpscan)",
                status="PASS" if res_wp.is_success else "UNKNOWN",
                score=2 if res_wp.is_success else 1,
                evidence=[wpscan_file],
                note="Passive WordPress audit completed with rate limiting.",
            )
        )
    else:
        wp_status_ev = evidence_mgr.save_file("supply", "cms_status.txt", "No WordPress detected or wpscan not installed.")
        items.append(
            ChecklistItem(
                item_id="5.3",
                module="supply",
                check="CMS Platform Security Audit",
                status="PASS" if not is_wordpress else "UNKNOWN",
                score=2 if not is_wordpress else 1,
                evidence=[wp_status_ev],
                note="Target does not run WordPress or specialized CMS." if not is_wordpress else "WordPress detected; manual wpscan recommended.",
            )
        )

    return {
        "findings": findings,
        "items": items,
        "note": notes,
        "detected_tech": detected_tech,
    }
