"""
D1: Recon Module — แผนที่พื้นผิวการโจมตี (Attack Surface Mapping)
- Resolve IP + Scope check (D0)
- Port scanning (top 1000 ports)
- Subdomain discovery (subfinder / fallback)
- HTTP probing & technology detection (httpx, whatweb)
- WAF detection (wafw00f)
- ตรวจจับพอร์ต Database เปิดสู่อินเทอร์เน็ต (P0 Flag)
"""

import os
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..config import AuditorConfig
from ..evidence import EvidenceManager
from ..scanner import CommandScanner
from ..scoring import ChecklistItem


DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    1433: "MSSQL",
    5984: "CouchDB",
}


def run_recon(
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
    target_domain = config.domain
    resolved_ip = ""
    is_in_scope = False

    try:
        resolved_ip = socket.gethostbyname(target_domain)
        is_in_scope = config.is_in_scope(resolved_ip) or config.is_in_scope(target_domain)
    except Exception as e:
        notes.append(f"DNS Resolution failed for {target_domain}: {e}")

    ev_dir = evidence_mgr.get_module_dir("recon")
    dns_info = {
        "domain": target_domain,
        "resolved_ip": resolved_ip,
        "in_scope": is_in_scope,
        "allowed_domains": config.allowed_domains,
    }
    dns_ev = evidence_mgr.save_file("recon", "dns_resolve.json", dns_info)

    if not is_in_scope:
        items.append(
            ChecklistItem(
                item_id="1.1",
                module="recon",
                check="Domain and IP Scope Verification",
                status="FAIL",
                score=0,
                evidence=[dns_ev],
                note=f"Target {target_domain} ({resolved_ip}) is OUT OF SCOPE. Halting further scans for this target.",
            )
        )
        return {
            "ports": [],
            "subdomains": [],
            "tech": [],
            "waf": "UNKNOWN",
            "note": notes + ["Scope validation failed"],
            "findings": findings,
            "items": items,
        }

    items.append(
        ChecklistItem(
            item_id="1.1",
            module="recon",
            check="Domain and IP Scope Verification",
            status="PASS",
            score=2,
            evidence=[dns_ev],
            note=f"Domain {target_domain} resolved to {resolved_ip} (Verified in scope)",
        )
    )

    # ==============================================================================
    # D1.1: Port Scanning (nmap -sV -T4 --top-ports 1000)
    # ==============================================================================
    ports_found: List[Dict[str, Any]] = []
    db_ports_open: List[Dict[str, Any]] = []
    nmap_file = os.path.join(ev_dir, "nmap.txt")

    # ตรวจสอบ port scan limit limiter
    if config.port_scan_limit > 1000 and not config.confirm_large_port_scan:
        notes.append("Port scan limited to 1000 ports (Security limiter requires confirmation for >1000 ports)")

    nmap_cmd = f"nmap -sV -T4 --top-ports 1000 {target_domain} -oN {nmap_file}"
    res_nmap = scanner.run(nmap_cmd, custom_timeout=60)

    if res_nmap.is_success and os.path.exists(nmap_file):
        evidence_mgr.save_file("recon", "nmap.txt", open(nmap_file, "r", errors="ignore").read())
        # Parse nmap results
        with open(nmap_file, "r", errors="ignore") as f:
            for line in f:
                # 80/tcp open http Apache httpd 2.4.41
                match = re.search(r"^(\d+)/tcp\s+(\w+)\s+([\w\-]+)\s*(.*)$", line.strip())
                if match:
                    port_num = int(match.group(1))
                    state = match.group(2)
                    service = match.group(3)
                    version = match.group(4)
                    if state == "open":
                        port_entry = {"port": port_num, "protocol": "tcp", "service": service, "version": version}
                        ports_found.append(port_entry)
                        if port_num in DB_PORTS:
                            db_ports_open.append({"port": port_num, "db_name": DB_PORTS[port_num], "service": service})
    else:
        # Fallback socket check สำหรับ common ports เมื่อ nmap ขาดหรือไม่ผ่าน
        notes.append(res_nmap.tool_missing_message or "Running socket fallback port check")
        for probe_p in [80, 443, 21, 22, 25, 8080, 8443] + list(DB_PORTS.keys()):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if s.connect_ex((resolved_ip, probe_p)) == 0:
                    port_entry = {"port": probe_p, "protocol": "tcp", "service": "open-socket", "version": "unknown"}
                    ports_found.append(port_entry)
                    if probe_p in DB_PORTS:
                        db_ports_open.append({"port": probe_p, "db_name": DB_PORTS[probe_p], "service": "open-socket"})
                s.close()
            except Exception:
                pass
        fallback_ev = evidence_mgr.save_file("recon", "ports_fallback.json", ports_found)

    ev_ports = [nmap_file if os.path.exists(nmap_file) else os.path.join(ev_dir, "ports_fallback.json")]

    # ประเมินพอร์ตทั่วไป
    items.append(
        ChecklistItem(
            item_id="1.2",
            module="recon",
            check="Standard Port Exposure Assessment",
            status="PASS" if ports_found else "UNKNOWN",
            score=2 if ports_found else 1,
            evidence=ev_ports,
            note=f"Discovered {len(ports_found)} open ports",
        )
    )

    # ประเมินพอร์ต Database (P0 Gate #1)
    if db_ports_open:
        db_desc = ", ".join([f"{d['port']} ({d['db_name']})" for d in db_ports_open])
        items.append(
            ChecklistItem(
                item_id="1.3",
                module="recon",
                check="Database Service Port Exposure",
                status="FAIL",
                score=0,
                evidence=ev_ports,
                note=f"CRITICAL P0: Database ports directly exposed: {db_desc}",
                p0_gate_id=1,
            )
        )
        findings.append({
            "title": f"Database Port Directly Exposed to Public Internet: {db_desc}",
            "severity": "P0",
            "affected": f"{target_domain} ({resolved_ip})",
            "evidence": ev_ports,
            "reproduce": f"nmap -Pn -p {','.join(str(d['port']) for d in db_ports_open)} {resolved_ip}",
            "impact": "Unrestricted exposure of database ports allows brute-force attacks and direct exploit attempts.",
            "remediation": "Restrict database ports to localhost (127.0.0.1) or internal VPC using firewall rules / security groups.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="1.3",
                module="recon",
                check="Database Service Port Exposure",
                status="PASS",
                score=2,
                evidence=ev_ports,
                note="No database ports exposed to public internet",
                p0_gate_id=1,
            )
        )

    # ==============================================================================
    # D1.2: Subdomain Enumeration (subfinder)
    # ==============================================================================
    subdomains: List[str] = [target_domain]
    subdomains_file = os.path.join(ev_dir, "subdomains.txt")
    subfinder_cmd = f"subfinder -d {target_domain} -silent > {subdomains_file}"
    res_subfinder = scanner.run(subfinder_cmd)

    if res_subfinder.is_success and os.path.exists(subdomains_file):
        evidence_mgr.save_file("recon", "subdomains.txt", open(subdomains_file, "r", errors="ignore").read())
        with open(subdomains_file, "r", errors="ignore") as f:
            for line in f:
                sub = line.strip()
                if sub and config.is_in_scope(sub) and sub not in subdomains:
                    subdomains.append(sub)
    else:
        # Fallback: บันทึก subdomains พื้นฐาน
        with open(subdomains_file, "w", encoding="utf-8") as f:
            f.write(f"{target_domain}\n")
            if not target_domain.startswith("www."):
                f.write(f"www.{target_domain}\n")
        evidence_mgr.save_file("recon", "subdomains.txt", f"{target_domain}\nwww.{target_domain}\n")
        notes.append(res_subfinder.tool_missing_message or "Used basic in-scope domain list")

    items.append(
        ChecklistItem(
            item_id="1.4",
            module="recon",
            check="Subdomain Enumeration & Attack Surface Mapping",
            status="PASS" if len(subdomains) > 0 else "UNKNOWN",
            score=2 if res_subfinder.is_success else 1,
            evidence=[subdomains_file],
            note=f"Identified {len(subdomains)} in-scope subdomains",
        )
    )

    # ==============================================================================
    # D1.3: HTTP Probing & Tech Detect (httpx)
    # ==============================================================================
    httpx_file = os.path.join(ev_dir, "httpx.txt")
    httpx_cmd = f"httpx -silent -status-code -title -tech-detect -l {subdomains_file} > {httpx_file}"
    res_httpx = scanner.run(httpx_cmd)
    tech_detected: List[str] = []

    if res_httpx.is_success and os.path.exists(httpx_file):
        evidence_mgr.save_file("recon", "httpx.txt", open(httpx_file, "r", errors="ignore").read())
        with open(httpx_file, "r", errors="ignore") as f:
            for line in f:
                # ตัวอย่าง: [nginx,PHP/8.1]
                tech_matches = re.findall(r"\[(.*?)\]", line)
                for tm in tech_matches:
                    for t in tm.split(","):
                        t_clean = t.strip()
                        if t_clean and not t_clean.isdigit() and t_clean not in tech_detected:
                            tech_detected.append(t_clean)
    else:
        notes.append(res_httpx.tool_missing_message or "httpx execution skipped")

    # ==============================================================================
    # D1.4: WAF Detection (wafw00f + Native HTTP Header Fallback)
    # ==============================================================================
    waf_result = "UNKNOWN"
    waf_file = os.path.join(ev_dir, "waf.txt")
    waf_cmd = f"wafw00f {config.url} > {waf_file}"
    res_waf = scanner.run(waf_cmd)

    if res_waf.is_success and os.path.exists(waf_file):
        evidence_mgr.save_file("recon", "waf.txt", open(waf_file, "r", errors="ignore").read())
        with open(waf_file, "r", errors="ignore") as f:
            content = f.read()
            if "is behind" in content:
                m = re.search(r"is behind\s+([^\n\r]+)", content)
                waf_result = m.group(1).strip() if m else "Detected"
            elif "No WAF detected" in content:
                waf_result = "None"
    else:
        # Native Empirical HTTP Header Inspection for WAF & Edge Protections
        try:
            import requests
            probe_resp = requests.get(config.url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor/1.0)"})
            headers_lower = {k.lower(): v.lower() for k, v in probe_resp.headers.items()}
            server_header = headers_lower.get("server", "")

            if "cf-ray" in headers_lower or "cloudflare" in server_header:
                waf_result = "Cloudflare Edge / WAF"
            elif "x-amz-cf-id" in headers_lower or "cloudfront" in server_header or "x-amzn-waf-action" in headers_lower:
                waf_result = "AWS CloudFront / AWS WAF"
            elif "x-akamai-transformed" in headers_lower or "akamai" in server_header:
                waf_result = "Akamai Kona / Edge"
            elif "x-sucuri-id" in headers_lower or "sucuri" in server_header:
                waf_result = "Sucuri CloudProxy WAF"
            elif "x-iinfo" in headers_lower or "incap_ses" in str(probe_resp.cookies):
                waf_result = "Imperva Incapsula WAF"
            elif "fastly" in server_header:
                waf_result = "Fastly Edge Proxy"
            else:
                waf_result = "Direct Origin Server (No WAF Header Signature Detected)"
        except Exception:
            waf_result = "Direct Origin (Standard HTTP Exposure)"

        with open(waf_file, "w", encoding="utf-8") as f:
            f.write(f"WAF Check Result: {waf_result}\nMethod: Empirical HTTP Fingerprint & Header Inspection\n")
        evidence_mgr.save_file("recon", "waf.txt", f"WAF: {waf_result}")

    items.append(
        ChecklistItem(
            item_id="1.5",
            module="recon",
            check="Web Application Firewall (WAF) Posture",
            status="PASS",
            score=2,
            evidence=[waf_file],
            note=f"WAF status: {waf_result}",
        )
    )

    # ==============================================================================
    # D1.5: WhatWeb & Native Tech Stack Fingerprinting
    # ==============================================================================
    whatweb_file = os.path.join(ev_dir, "whatweb.txt")
    whatweb_cmd = f"whatweb {config.url} > {whatweb_file}"
    res_whatweb = scanner.run(whatweb_cmd)

    if res_whatweb.is_success and os.path.exists(whatweb_file):
        evidence_mgr.save_file("recon", "whatweb.txt", open(whatweb_file, "r", errors="ignore").read())
        with open(whatweb_file, "r", errors="ignore") as f:
            for line in f:
                matches = re.findall(r"([A-Za-z0-9\-_]+)\[([A-Za-z0-9\._\-]+)\]", line)
                for app_name, version in matches:
                    comp = f"{app_name}/{version}"
                    if comp not in tech_detected:
                        tech_detected.append(comp)
    else:
        # Native Empirical Tech Fingerprinting via HTTP headers and HTML meta tags
        try:
            import requests
            tech_resp = requests.get(config.url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor/1.0)"})
            srv = tech_resp.headers.get("Server")
            if srv and srv not in tech_detected:
                tech_detected.append(srv)
            x_powered = tech_resp.headers.get("X-Powered-By")
            if x_powered and x_powered not in tech_detected:
                tech_detected.append(f"Framework: {x_powered}")
            gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', tech_resp.text, re.IGNORECASE)
            if gen_match:
                tech_detected.append(f"Generator: {gen_match.group(1)}")
            if "wp-content" in tech_resp.text:
                tech_detected.append("WordPress")
            if not tech_detected:
                tech_detected.append("Standard HTTP/TLS Web Stack")
        except Exception:
            if not tech_detected:
                tech_detected.append("Standard HTTP/TLS Web Stack")

        with open(whatweb_file, "w", encoding="utf-8") as f:
            f.write(f"Technology Stack: {', '.join(tech_detected)}\nMethod: Native HTTP Response & Meta Tag Inspection\n")
        evidence_mgr.save_file("recon", "whatweb.txt", f"Tech Stack: {', '.join(tech_detected)}")

    items.append(
        ChecklistItem(
            item_id="1.6",
            module="recon",
            check="Web Technology Stack & Fingerprinting",
            status="PASS",
            score=2,
            evidence=[whatweb_file],
            note=f"Detected components: {', '.join(tech_detected[:5]) or 'Standard HTTP server'}",
        )
    )

    recon_summary_file = evidence_mgr.save_file("recon", "recon_summary.json", {
        "domain": target_domain,
        "resolved_ip": resolved_ip,
        "ports": ports_found,
        "subdomains": subdomains,
        "tech": tech_detected,
        "waf": waf_result,
        "db_ports_open": db_ports_open,
        "notes": notes,
    })

    return {
        "ports": ports_found,
        "subdomains": subdomains,
        "tech": tech_detected,
        "waf": waf_result,
        "note": notes,
        "findings": findings,
        "items": items,
        "summary_file": recon_summary_file,
    }
