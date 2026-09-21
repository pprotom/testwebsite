"""
D4: Infrastructure Module — ตรวจสอบโครงสร้างพื้นฐานและ Secret Leaks
- Targeted direct Database Port Scan on IP (3306, 5432, 27017, 6379, 9200, 11211, 1433, 5984)
- TruffleHog Filesystem Secret Scan (if repo_path configured) with REDACTED outputs
- Crawler Directives (robots.txt) & Sitemap Discovery (sitemap.xml)
"""

import json
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


TARGET_DB_PORTS = [3306, 5432, 27017, 6379, 9200, 11211, 1433, 5984]
DB_PORT_NAMES = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    1433: "Microsoft SQL Server",
    5984: "Apache CouchDB",
}


def run_infra(
    config: AuditorConfig,
    scanner: CommandScanner,
    evidence_mgr: EvidenceManager,
) -> Dict[str, Any]:
    notes: List[str] = []
    findings: List[Dict[str, Any]] = []
    items: List[ChecklistItem] = []

    # D0: Resolve IP
    resolved_ip = ""
    try:
        resolved_ip = socket.gethostbyname(config.domain)
        if not (config.is_in_scope(resolved_ip) or config.is_in_scope(config.domain)):
            items.append(
                ChecklistItem(
                    item_id="4.1",
                    module="infra",
                    check="Infrastructure Scope Verification",
                    status="FAIL",
                    score=0,
                    note=f"IP {resolved_ip} is out of authorized scope.",
                )
            )
            return {"findings": findings, "items": items, "note": ["Out of scope"]}
    except Exception as e:
        notes.append(f"DNS Resolution: {e}")
        resolved_ip = config.domain

    ev_dir = evidence_mgr.get_module_dir("infra")

    # ==============================================================================
    # D4.1: Direct database ports scan on IP
    # nmap -Pn -sV -p 3306,5432,27017,6379,9200,11211,1433,5984 <ip> -oN <ev>/dbports.txt
    # ==============================================================================
    dbports_file = os.path.join(ev_dir, "dbports.txt")
    port_list_str = ",".join(str(p) for p in TARGET_DB_PORTS)
    nmap_db_cmd = f"nmap -Pn -sV -p {port_list_str} {resolved_ip} -oN {dbports_file}"
    res_db = scanner.run(nmap_db_cmd, custom_timeout=60)

    open_db_ports = []
    if res_db.is_success and os.path.exists(dbports_file):
        evidence_mgr.save_file("infra", "dbports.txt", open(dbports_file, "r", errors="ignore").read())
        with open(dbports_file, "r", errors="ignore") as f:
            for line in f:
                m = re.search(r"^(\d+)/tcp\s+(\w+)", line.strip())
                if m:
                    p_num = int(m.group(1))
                    state = m.group(2)
                    if state == "open" and p_num in TARGET_DB_PORTS:
                        open_db_ports.append({"port": p_num, "name": DB_PORT_NAMES.get(p_num, "Database")})
    else:
        # Socket fallback check
        notes.append(res_db.tool_missing_message or "Socket fallback verification for DB ports")
        for p in TARGET_DB_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((resolved_ip, p)) == 0:
                    open_db_ports.append({"port": p, "name": DB_PORT_NAMES.get(p, "Database")})
                s.close()
            except Exception:
                pass
        evidence_mgr.save_file("infra", "dbports_socket.json", open_db_ports)

    ev_db = [dbports_file if os.path.exists(dbports_file) else os.path.join(ev_dir, "dbports_socket.json")]

    if open_db_ports:
        exposed_summary = ", ".join([f"{p['port']}:{p['name']}" for p in open_db_ports])
        items.append(
            ChecklistItem(
                item_id="4.1",
                module="infra",
                check="Direct Database Port Exposure (IP Level)",
                status="FAIL",
                score=0,
                evidence=ev_db,
                note=f"CRITICAL P0: Database ports open to internet on {resolved_ip}: {exposed_summary}",
                p0_gate_id=1,
            )
        )
        findings.append({
            "title": f"Database Port Open to Public Internet: {exposed_summary}",
            "severity": "P0",
            "affected": f"{resolved_ip} ({exposed_summary})",
            "evidence": ev_db,
            "reproduce": f"nmap -Pn -p {port_list_str} {resolved_ip}",
            "impact": "Exposing production database instances directly on the internet allows credential stuffing and zero-day exploits.",
            "remediation": "Bind database listeners to 127.0.0.1 or configure cloud firewall / security groups to drop inbound internet traffic.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="4.1",
                module="infra",
                check="Direct Database Port Exposure (IP Level)",
                status="PASS",
                score=2,
                evidence=ev_db,
                note="All examined database ports are closed or properly firewalled.",
                p0_gate_id=1,
            )
        )

    # ==============================================================================
    # D4.2: Secret Scan (TruffleHog)
    # ถ้า repo_path ใน config -> trufflehog filesystem --only-verified <repo>
    # บันทึกเฉพาะ path + ประเภท secret, REDACT ค่าจริง
    # ==============================================================================
    secrets_found = []
    repo_to_scan = config.repo_path

    if repo_to_scan and os.path.exists(repo_to_scan):
        truffle_file = os.path.join(ev_dir, "trufflehog.json")
        truffle_cmd = f"trufflehog filesystem --only-verified --json {repo_to_scan} > {truffle_file}"
        res_truffle = scanner.run(truffle_cmd, custom_timeout=60)

        if os.path.exists(truffle_file):
            with open(truffle_file, "r", errors="ignore") as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        # REDACT ค่าจริงเด็ดขาด
                        detector = record.get("DetectorName", "Secret")
                        file_src = record.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown")
                        secrets_found.append({
                            "type": detector,
                            "file": file_src,
                            "value": "[REDACTED_SECRET]",
                        })
                    except Exception:
                        pass
        truffle_ev = evidence_mgr.save_file("infra", "trufflehog_redacted.json", secrets_found)

        if secrets_found:
            items.append(
                ChecklistItem(
                    item_id="4.2",
                    module="infra",
                    check="Repository Secret & Credential Leak Scan",
                    status="FAIL",
                    score=0,
                    evidence=[truffle_ev],
                    note=f"CRITICAL P0: Found {len(secrets_found)} verified secrets in source repository.",
                    p0_gate_id=5,
                )
            )
            findings.append({
                "title": f"Verified Hardcoded Secrets in Repository ({len(secrets_found)} items)",
                "severity": "P0",
                "affected": f"Repository: {repo_to_scan}",
                "evidence": [truffle_ev],
                "reproduce": f"trufflehog filesystem --only-verified {repo_to_scan}",
                "impact": "Exposed API keys and credentials lead to complete identity compromise.",
                "remediation": "Revoke and rotate exposed credentials immediately and purge from git history.",
            })
        else:
            items.append(
                ChecklistItem(
                    item_id="4.2",
                    module="infra",
                    check="Repository Secret & Credential Leak Scan",
                    status="PASS",
                    score=2,
                    evidence=[truffle_ev],
                    note="No verified secrets detected in scanned repository.",
                    p0_gate_id=5,
                )
            )
    else:
        # Remote Live Web Asset & Script Secret Inspection
        web_secrets_found = []
        try:
            target_resp = requests.get(config.url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor/1.0)"})
            page_text = target_resp.text
            # Extract inline scripts and external JS URLs
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page_text, re.IGNORECASE)
            combined_texts = [("index_html", page_text)]

            for js_rel in js_urls[:5]:
                js_full = urljoin(config.url, js_rel)
                try:
                    js_resp = requests.get(js_full, timeout=8, verify=False)
                    combined_texts.append((js_rel, js_resp.text))
                except Exception:
                    pass

            secret_patterns = [
                ("AWS Key", r"\b(AKIA[0-9A-Z]{16})\b"),
                ("Google API Key", r"\b(AIzaSy[0-9A-Za-z\-_]{33})\b"),
                ("GitHub Token", r"\b(ghp_[0-9a-zA-Z]{36})\b"),
                ("Stripe Secret Key", r"\b(sk_live_[0-9a-zA-Z]{24})\b"),
                ("Private Key", r"-----BEGIN (?:RSA|EC|OPENSSH)? PRIVATE KEY-----"),
                ("Database URL with Auth", r"\b(?:postgres|mysql|mongodb):\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\.\-]+"),
            ]

            for src_name, text in combined_texts:
                for sec_type, pat in secret_patterns:
                    if re.search(pat, text):
                        web_secrets_found.append({
                            "type": sec_type,
                            "source": src_name,
                            "value": "[REDACTED_SECRET]",
                        })
        except Exception as e:
            notes.append(f"Web secret scan note: {e}")

        web_sec_ev = evidence_mgr.save_file("infra", "web_secrets_probe.json", {
            "mode": "live_web_asset_secret_scan",
            "secrets_found": web_secrets_found,
        })

        if web_secrets_found:
            items.append(
                ChecklistItem(
                    item_id="4.2",
                    module="infra",
                    check="Repository & Web Asset Secret Leak Scan",
                    status="FAIL",
                    score=0,
                    evidence=[web_sec_ev],
                    note=f"CRITICAL P0: Found {len(web_secrets_found)} sensitive secrets in public web client scripts.",
                    p0_gate_id=5,
                )
            )
            findings.append({
                "title": f"Exposed API Secrets in Client-Side Web Assets ({len(web_secrets_found)} found)",
                "severity": "P0",
                "affected": f"{config.url} web client assets",
                "evidence": [web_sec_ev],
                "reproduce": f"curl -s {config.url} | grep -E 'AKIA|AIzaSy|sk_live'",
                "impact": "Exposing private credentials and API keys allows attackers to access cloud infrastructure.",
                "remediation": "Move all secret keys to server-side environment variables and proxy requests.",
            })
        else:
            items.append(
                ChecklistItem(
                    item_id="4.2",
                    module="infra",
                    check="Repository & Web Asset Secret Leak Scan",
                    status="PASS",
                    score=2,
                    evidence=[web_sec_ev],
                    note="No hardcoded secrets or credentials detected in web assets and scripts.",
                    p0_gate_id=5,
                )
            )

    # ==============================================================================
    # D4.3: Crawler Directives (robots.txt) & Sitemap.xml
    # ==============================================================================
    session = requests.Session()
    if config.get_proxies_dict():
        session.proxies.update(config.get_proxies_dict())

    robots_url = urljoin(config.url, "/robots.txt")
    sitemap_url = urljoin(config.url, "/sitemap.xml")
    crawlers_info: Dict[str, Any] = {"robots_txt": "", "disallowed_paths": [], "sitemap_urls": []}

    try:
        r_rob = session.get(robots_url, timeout=10)
        if r_rob.status_code == 200:
            crawlers_info["robots_txt"] = r_rob.text
            for line in r_rob.text.splitlines():
                if line.lower().startswith("disallow:"):
                    dis_path = line.split(":", 1)[1].strip()
                    if dis_path and dis_path not in crawlers_info["disallowed_paths"]:
                        crawlers_info["disallowed_paths"].append(dis_path)
    except Exception as e:
        notes.append(f"robots.txt check: {e}")

    try:
        r_site = session.get(sitemap_url, timeout=10)
        if r_site.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", r_site.text)
            crawlers_info["sitemap_urls"] = urls[:50]
    except Exception as e:
        notes.append(f"sitemap.xml check: {e}")

    crawlers_ev = evidence_mgr.save_file("infra", "crawler_directives.json", crawlers_info)

    items.append(
        ChecklistItem(
            item_id="4.3",
            module="infra",
            check="Search Engine Crawler Directives & Information Disclosure",
            status="PASS",
            score=2,
            evidence=[crawlers_ev],
            note=f"Indexed {len(crawlers_info['disallowed_paths'])} disallowed paths and {len(crawlers_info['sitemap_urls'])} sitemap entries.",
        )
    )

    return {
        "findings": findings,
        "items": items,
        "note": notes,
        "open_db_ports": open_db_ports,
    }
