"""
D2: Files Module — ตรวจสอบไฟล์และโฟลเดอร์รั่วไหล (Sensitive File & Directory Exposure)
- dirsearch enumeration
- Probe 19 sensitive paths (timeout 15s)
- P0 gate check for .git, .env, *.sql, backup archives returning 200 OK
- Directory listing inspection on /uploads/ and /
- Recommendation for gitdumper + trufflehog if /.git/config is exposed
"""

import os
import re
import socket
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests

from ..config import AuditorConfig
from ..evidence import EvidenceManager
from ..scanner import CommandScanner
from ..scoring import ChecklistItem


SENSITIVE_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.backup",
    "/.env.production",
    "/db.sql",
    "/backup.zip",
    "/dump.rar",
    "/site.tar.gz",
    "/composer.json",
    "/package.json",
    "/config.php",
    "/wp-config.php.bak",
    "/admin",
    "/phpmyadmin",
    "/uploads/",
    "/storage/",
    "/logs/",
    "/api/docs",
]

P0_FILE_PATTERNS = [r"\.git/", r"\.env", r"\.sql$", r"backup\.", r"dump\.", r"site\.tar\.gz"]


def is_p0_path(path: str) -> bool:
    for pattern in P0_FILE_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False


def run_files(
    config: AuditorConfig,
    scanner: CommandScanner,
    evidence_mgr: EvidenceManager,
) -> Dict[str, Any]:
    notes: List[str] = []
    findings: List[Dict[str, Any]] = []
    items: List[ChecklistItem] = []

    # ==============================================================================
    # D0: Resolve IP และตรวจสอบ Scope
    # ==============================================================================
    try:
        resolved_ip = socket.gethostbyname(config.domain)
        if not (config.is_in_scope(resolved_ip) or config.is_in_scope(config.domain)):
            items.append(
                ChecklistItem(
                    item_id="2.1",
                    module="files",
                    check="Sensitive Files Scope Check",
                    status="FAIL",
                    score=0,
                    note=f"Target {config.domain} is OUT OF SCOPE.",
                )
            )
            return {"findings": findings, "items": items, "note": ["Out of scope"]}
    except Exception as e:
        notes.append(f"DNS check: {e}")

    ev_dir = evidence_mgr.get_module_dir("files")
    base_url = config.url.rstrip("/")

    # ==============================================================================
    # D2.1: dirsearch enumeration
    # ==============================================================================
    dirsearch_file = os.path.join(ev_dir, "dirsearch.txt")
    dirsearch_cmd = (
        f"dirsearch -u {base_url} -e php,txt,bak,sql,env -t 10 "
        f"--format plain -o {dirsearch_file}"
    )
    res_dirsearch = scanner.run(dirsearch_cmd, custom_timeout=60)

    if res_dirsearch.is_success and os.path.exists(dirsearch_file):
        evidence_mgr.save_file("files", "dirsearch.txt", open(dirsearch_file, "r", errors="ignore").read())
    else:
        notes.append(res_dirsearch.tool_missing_message or "dirsearch skipped or finished without output")
        with open(dirsearch_file, "w", encoding="utf-8") as f:
            f.write(f"# dirsearch run note: {res_dirsearch.tool_missing_message or 'direct requests probing used'}\n")
        evidence_mgr.save_file("files", "dirsearch.txt", f"# dirsearch probe note: {res_dirsearch.tool_missing_message}\n")

    # ==============================================================================
    # D2.2: ตรวจสอบ 19 Path อ่อนไหวด้วย HTTP requests (timeout 15s)
    # ==============================================================================
    session = requests.Session()
    if config.get_proxies_dict():
        session.proxies.update(config.get_proxies_dict())
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SecurityAuditor/1.0)"})

    path_results: Dict[str, Any] = {}
    exposed_p0_paths: List[str] = []
    exposed_other_paths: List[str] = []

    git_config_exposed = False

    for path in SENSITIVE_PATHS:
        target_url = base_url + path
        try:
            resp = session.get(target_url, timeout=15, allow_redirects=False)
            status = resp.status_code
            content_snippet = resp.text[:150].replace("\n", " ").strip()
            path_results[path] = {
                "status_code": status,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
                "snippet": content_snippet,
            }

            # พิจารณาว่า 200 จริงหรือไม่ (ไม่รวม custom 404 ที่ตอบ 200 แต่เป็นหน้า error ทั่วไป)
            if status == 200:
                # ตรวจ false positive เล็กน้อย
                is_false_404 = any(
                    err in resp.text.lower() for err in ["404 not found", "page not found", "cannot find"]
                ) and len(resp.text) < 1000

                if not is_false_404:
                    if is_p0_path(path):
                        exposed_p0_paths.append(path)
                    else:
                        exposed_other_paths.append(path)

                    if path == "/.git/config" and "[core]" in resp.text:
                        git_config_exposed = True
        except Exception as e:
            path_results[path] = {"error": str(e)}

    # บันทึกผลการตรวจ HTTP probes ลงหลักฐาน
    paths_ev = evidence_mgr.save_file("files", "sensitive_paths_probe.json", path_results)

    # 2.1: Directory Brute-Force & Sensitive File Enumeration
    items.append(
        ChecklistItem(
            item_id="2.1",
            module="files",
            check="Directory Brute-Force & Sensitive File Enumeration",
            status="PASS" if (res_dirsearch.is_success or paths_ev) else "UNKNOWN",
            score=2 if (res_dirsearch.is_success or paths_ev) else 1,
            evidence=[paths_ev] if paths_ev else [dirsearch_file],
            note=f"Probed sensitive paths ({len(path_results)} targets verified)",
        )
    )

    # 2.2: Git / VCS Exposure (P0 Gate #2)
    git_paths = [p for p in exposed_p0_paths if ".git" in p]
    if git_paths:
        note_git = "CRITICAL P0: Git repository structure exposed publicly."
        if git_config_exposed:
            note_git += " Recommendation: Use gitdumper and trufflehog to extract and audit exposed repository secrets (Manual review recommended; not run automatically)."
        items.append(
            ChecklistItem(
                item_id="2.2",
                module="files",
                check="Version Control (.git) Exposure",
                status="FAIL",
                score=0,
                evidence=[paths_ev],
                note=note_git,
                p0_gate_id=2,
            )
        )
        findings.append({
            "title": "Publicly Accessible Git Repository (.git)",
            "severity": "P0",
            "affected": ", ".join(git_paths),
            "evidence": [paths_ev],
            "reproduce": f"curl -sI {base_url}/.git/config",
            "impact": "Attackers can download the entire source code, commit history, and embedded API keys.",
            "remediation": "Block access to .git directory in web server configuration (e.g., return 403/404).",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="2.2",
                module="files",
                check="Version Control (.git) Exposure",
                status="PASS",
                score=2,
                evidence=[paths_ev],
                note="No .git configuration or HEAD files exposed (Properly blocked)",
                p0_gate_id=2,
            )
        )

    # 2.3: Environment Secrets (.env) Exposure (P0 Gate #2)
    env_paths = [p for p in exposed_p0_paths if ".env" in p]
    if env_paths:
        items.append(
            ChecklistItem(
                item_id="2.3",
                module="files",
                check="Environment Configuration (.env) Exposure",
                status="FAIL",
                score=0,
                evidence=[paths_ev],
                note=f"CRITICAL P0: Environment files accessible: {', '.join(env_paths)}",
                p0_gate_id=2,
            )
        )
        findings.append({
            "title": "Publicly Accessible Environment File (.env)",
            "severity": "P0",
            "affected": ", ".join(env_paths),
            "evidence": [paths_ev],
            "reproduce": f"curl -sI {base_url}/.env",
            "impact": "Severe data leak: Database credentials, secret keys, and tokens are directly exposed.",
            "remediation": "Configure web server to deny all requests to files starting with .env immediately.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="2.3",
                module="files",
                check="Environment Configuration (.env) Exposure",
                status="PASS",
                score=2,
                evidence=[paths_ev],
                note="No .env files exposed",
                p0_gate_id=2,
            )
        )

    # 2.4: Database Backups & Archive Dumps (P0 Gate #2)
    dump_paths = [p for p in exposed_p0_paths if any(ext in p for ext in [".sql", ".zip", ".rar", ".tar.gz"])]
    if dump_paths:
        items.append(
            ChecklistItem(
                item_id="2.4",
                module="files",
                check="Database Backups & Archive Dump Exposure",
                status="FAIL",
                score=0,
                evidence=[paths_ev],
                note=f"CRITICAL P0: Database or backup archive exposed: {', '.join(dump_paths)}",
                p0_gate_id=2,
            )
        )
        findings.append({
            "title": "Publicly Accessible Database Dump or Archive Backup",
            "severity": "P0",
            "affected": ", ".join(dump_paths),
            "evidence": [paths_ev],
            "reproduce": f"curl -sI {base_url}/{dump_paths[0].lstrip('/')}",
            "impact": "Complete database compromise and disclosure of private system data.",
            "remediation": "Remove backup files from public web root and store securely in off-site storage.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="2.4",
                module="files",
                check="Database Backups & Archive Dump Exposure",
                status="PASS",
                score=2,
                evidence=[paths_ev],
                note="No database backups or archive files exposed",
                p0_gate_id=2,
            )
        )

    # ==============================================================================
    # D2.3: Directory Listing Inspection (/uploads/ และ /)
    # ==============================================================================
    dir_listing_found = False
    dir_listing_evidence = []
    dir_listing_patterns = [
        r"<title>Index of\s+/[^<]*</title>",
        r"<h1>Index of\s+/[^<]*</h1>",
        r"Parent Directory</a>",
        r"<a href=\"[^\"]+\">\s*\[(?:DIR|TXT|PARENT)\]",
    ]

    for check_dir in ["/uploads/", "/"]:
        try:
            r = session.get(base_url + check_dir, timeout=10)
            if r.status_code == 200:
                for pat in dir_listing_patterns:
                    if re.search(pat, r.text, re.IGNORECASE):
                        dir_listing_found = True
                        ev_dl = evidence_mgr.save_file(
                            "files",
                            f"dir_listing_{check_dir.replace('/', '_')}.html",
                            r.text[:2000],
                        )
                        dir_listing_evidence.append(ev_dl)
                        break
        except Exception:
            pass

    items.append(
        ChecklistItem(
            item_id="2.5",
            module="files",
            check="Directory Listing Inspection (/uploads/, /)",
            status="FAIL" if dir_listing_found else "PASS",
            score=0 if dir_listing_found else 2,
            evidence=dir_listing_evidence if dir_listing_found else [paths_ev],
            note="Directory indexing is enabled" if dir_listing_found else "Directory indexing is disabled",
        )
    )
    if dir_listing_found:
        findings.append({
            "title": "Directory Listing Enabled",
            "severity": "P2",
            "affected": f"{base_url}/uploads/",
            "evidence": dir_listing_evidence,
            "reproduce": f"curl -s {base_url}/uploads/",
            "impact": "Allows attackers to browse folder contents and discover sensitive files.",
            "remediation": "Disable directory browsing (Options -Indexes in Apache, autoindex off in Nginx).",
        })

    # 2.6: Administrative interfaces (/admin, /phpmyadmin, /logs/, /api/docs)
    admin_exposed = [p for p in exposed_other_paths if any(a in p for a in ["/admin", "/phpmyadmin", "/logs/"])]
    items.append(
        ChecklistItem(
            item_id="2.6",
            module="files",
            check="Sensitive Administrative & Diagnostic Path Exposure",
            status="FAIL" if admin_exposed else "PASS",
            score=0 if admin_exposed else 2,
            evidence=[paths_ev],
            note=f"Accessible paths: {', '.join(admin_exposed)}" if admin_exposed else "No unprotected admin endpoints exposed",
        )
    )

    return {
        "findings": findings,
        "items": items,
        "note": notes,
        "exposed_p0": exposed_p0_paths,
        "exposed_other": exposed_other_paths,
    }
