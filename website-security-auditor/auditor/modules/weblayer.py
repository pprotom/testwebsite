"""
D3: Web Layer Module — ตรวจสอบความปลอดภัยระดับ Web Application
- 5 Mandatory Security Headers
- HTTP -> HTTPS Redirection check
- TLS Configuration & Deprecated Protocol Audit (TLS 1.0/1.1 check)
- Cookie Security Flags (Secure, HttpOnly, SameSite)
- Non-destructive SQLi Pilot Injection Test
- Unauthenticated Administrative Path Access
- Capture Request/Response Snippets (Headers + first 100 bytes)
"""

import json
import os
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..config import AuditorConfig
from ..evidence import EvidenceManager
from ..scanner import CommandScanner
from ..scoring import ChecklistItem


MANDATORY_HEADERS = [
    ("Content-Security-Policy", "CSP defines approved sources of content preventing XSS."),
    ("Strict-Transport-Security", "HSTS enforces secure HTTPS connections."),
    ("X-Frame-Options", "Prevents clickjacking attacks by controlling framing."),
    ("X-Content-Type-Options", "Prevents MIME-sniffing vulnerabilities (must be 'nosniff')."),
    ("Referrer-Policy", "Controls information sent in Referer header on navigation."),
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"postgresql.*?error",
    r"sqlite3::sqlexception",
    r"syntax error at or near",
    r"ora-01756",
    r"microsoft ole db provider for odbc drivers",
]


def run_weblayer(
    config: AuditorConfig,
    scanner: CommandScanner,
    evidence_mgr: EvidenceManager,
) -> Dict[str, Any]:
    notes: List[str] = []
    findings: List[Dict[str, Any]] = []
    items: List[ChecklistItem] = []

    # Scope verification
    try:
        ip = socket.gethostbyname(config.domain)
        if not (config.is_in_scope(ip) or config.is_in_scope(config.domain)):
            items.append(
                ChecklistItem(
                    item_id="3.1",
                    module="weblayer",
                    check="Web Layer Scope Verification",
                    status="FAIL",
                    score=0,
                    note="Target domain is out of scope",
                )
            )
            return {"findings": findings, "items": items, "note": ["Out of scope"]}
    except Exception as e:
        notes.append(f"DNS resolution: {e}")

    ev_dir = evidence_mgr.get_module_dir("weblayer")
    session = requests.Session()
    if config.get_proxies_dict():
        session.proxies.update(config.get_proxies_dict())
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; WebSecurityAuditor/1.0)"})

    # ==============================================================================
    # D3.1: ตรวจสอบ 5 Mandatory Security Headers
    # ==============================================================================
    headers_detected = {}
    missing_headers = []
    snippet_main = {}

    try:
        r_main = session.get(config.url, timeout=15, allow_redirects=True)
        headers_detected = dict(r_main.headers)
        snippet_main = {
            "url": config.url,
            "status_code": r_main.status_code,
            "request_headers": dict(r_main.request.headers),
            "response_headers": dict(r_main.headers),
            "body_first_100_bytes": r_main.text[:100],
        }
        for hdr_name, hdr_desc in MANDATORY_HEADERS:
            val = r_main.headers.get(hdr_name)
            if not val:
                missing_headers.append(hdr_name)
            elif hdr_name == "X-Content-Type-Options" and "nosniff" not in val.lower():
                missing_headers.append(f"{hdr_name} (must be nosniff, got '{val}')")
    except Exception as e:
        notes.append(f"Header probe failed: {e}")
        missing_headers = [h[0] for h in MANDATORY_HEADERS]

    headers_ev = evidence_mgr.save_file("weblayer", "security_headers_probe.json", {
        "headers": headers_detected,
        "missing": missing_headers,
        "sample_snippet": snippet_main,
    })

    if missing_headers:
        items.append(
            ChecklistItem(
                item_id="3.1",
                module="weblayer",
                check="Mandatory Security Headers (CSP, HSTS, XFO, XCTO, Referrer)",
                status="FAIL",
                score=0,
                evidence=[headers_ev],
                note=f"Missing or misconfigured security headers: {', '.join(missing_headers)}",
            )
        )
        findings.append({
            "title": "Missing Essential HTTP Security Headers",
            "severity": "P2",
            "affected": config.url,
            "evidence": [headers_ev],
            "reproduce": f"curl -sI {config.url}",
            "impact": "Exposes users to clickjacking, cross-site scripting (XSS), and protocol downgrade attacks.",
            "remediation": f"Implement missing security headers on web server or CDN: {', '.join(missing_headers)}.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="3.1",
                module="weblayer",
                check="Mandatory Security Headers (CSP, HSTS, XFO, XCTO, Referrer)",
                status="PASS",
                score=2,
                evidence=[headers_ev],
                note="All 5 mandatory security headers are present and properly configured.",
            )
        )

    # ==============================================================================
    # D3.2: HTTP to HTTPS Redirection Check
    # ==============================================================================
    parsed_url = urlparse(config.url)
    http_test_url = urlunparse(("http", parsed_url.netloc, parsed_url.path or "/", "", "", ""))
    https_redirect_pass = False
    https_redirect_status = 0
    https_location = ""
    snippet_http = {}

    try:
        r_http = session.get(http_test_url, timeout=10, allow_redirects=False)
        https_redirect_status = r_http.status_code
        https_location = r_http.headers.get("Location", "")
        snippet_http = {
            "url": http_test_url,
            "status_code": https_redirect_status,
            "location": https_location,
            "headers": dict(r_http.headers),
            "body_first_100_bytes": r_http.text[:100],
        }
        if https_redirect_status in (301, 302, 307, 308) and https_location.startswith("https://"):
            https_redirect_pass = True
    except Exception as e:
        notes.append(f"HTTP redirection check error: {e}")

    http_ev = evidence_mgr.save_file("weblayer", "http_redirect.json", snippet_http)

    if https_redirect_pass:
        items.append(
            ChecklistItem(
                item_id="3.2",
                module="weblayer",
                check="HTTP to HTTPS Enforced Redirection",
                status="PASS",
                score=2,
                evidence=[http_ev],
                note=f"HTTP correctly redirects to HTTPS ({https_redirect_status} -> {https_location})",
                p0_gate_id=10,
            )
        )
    else:
        items.append(
            ChecklistItem(
                item_id="3.2",
                module="weblayer",
                check="HTTP to HTTPS Enforced Redirection",
                status="FAIL",
                score=0,
                evidence=[http_ev],
                note=f"Insecure connection: HTTP does not redirect to HTTPS (Status {https_redirect_status})",
                p0_gate_id=10,
            )
        )
        findings.append({
            "title": "Unenforced HTTPS Encryption (No Automatic Redirect)",
            "severity": "P0",
            "affected": http_test_url,
            "evidence": [http_ev],
            "reproduce": f"curl -sI {http_test_url}",
            "impact": "Unencrypted HTTP traffic allows man-in-the-middle (MITM) eavesdropping and session hijacking.",
            "remediation": "Configure 301 redirect from HTTP to HTTPS in server configuration.",
        })

    # ==============================================================================
    # D3.3: TLS Cipher & Deprecated Protocols (TLS 1.0 / 1.1)
    # ==============================================================================
    tls_file = os.path.join(ev_dir, "tls_ciphers.txt")
    nmap_tls_cmd = f"nmap --script ssl-enum-ciphers -p 443 {config.domain} -oN {tls_file}"
    res_tls = scanner.run(nmap_tls_cmd, custom_timeout=60)
    weak_tls_found = False
    tls_details = ""

    if res_tls.is_success and os.path.exists(tls_file):
        evidence_mgr.save_file("weblayer", "tls_ciphers.txt", open(tls_file, "r", errors="ignore").read())
        with open(tls_file, "r", errors="ignore") as f:
            tls_content = f.read()
            if re.search(r"TLSv1\.[01]", tls_content):
                weak_tls_found = True
                tls_details = "Deprecated TLS 1.0 or TLS 1.1 detected in cipher scan"
    else:
        # Fallback python SSL socket probe สำหรับ TLS 1.0 / 1.1
        notes.append(res_tls.tool_missing_message or "Running socket TLS probe fallback")
        try:
            # ทดสอบว่า server ยอมรับ TLSv1 หรือ TLSv1_1 หรือไม่
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # เปิด deprecated versions เพื่อทดสอบ
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            s = socket.create_connection((config.domain, 443), timeout=5)
            with ctx.wrap_socket(s, server_hostname=config.domain) as ss:
                ver = ss.version()
                if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                    weak_tls_found = True
                    tls_details = f"Handshake succeeded with obsolete protocol {ver}"
        except Exception:
            # ถ้า handshake ล้มเหลว แปลว่า server ปิด TLS 1.0/1.1 ถูกต้องแล้ว
            tls_details = "Server rejected TLS <= 1.1 handshake (Secure)"

        with open(tls_file, "w", encoding="utf-8") as f:
            f.write(f"TLS Probe Result: {tls_details}\n")
        evidence_mgr.save_file("weblayer", "tls_ciphers.txt", tls_details)

    if weak_tls_found:
        items.append(
            ChecklistItem(
                item_id="3.3",
                module="weblayer",
                check="Modern TLS Encryption (No TLS 1.0/1.1)",
                status="FAIL",
                score=0,
                evidence=[tls_file],
                note=f"CRITICAL P0: Obsolete TLS protocols enabled: {tls_details}",
                p0_gate_id=10,
            )
        )
        findings.append({
            "title": "Deprecated and Vulnerable TLS Protocols Enabled (TLS 1.0 / 1.1)",
            "severity": "P0",
            "affected": f"{config.domain}:443",
            "evidence": [tls_file],
            "reproduce": f"nmap --script ssl-enum-ciphers -p 443 {config.domain}",
            "impact": "Exposes traffic to cryptographic downgrades and protocol attacks (POODLE, BEAST).",
            "remediation": "Disable TLS 1.0 and TLS 1.1 in web server and TLS termination configurations (require TLS 1.2+).",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="3.3",
                module="weblayer",
                check="Modern TLS Encryption (No TLS 1.0/1.1)",
                status="PASS",
                score=2,
                evidence=[tls_file],
                note="Modern TLS enforced (No obsolete TLS 1.0/1.1 detected)",
                p0_gate_id=10,
            )
        )

    # ==============================================================================
    # D3.4: Cookie Security Flags (Secure, HttpOnly, SameSite)
    # ==============================================================================
    target_cookie_url = config.login_url if config.login_url else config.url
    insecure_cookies = []
    cookies_tested = []

    try:
        r_cookie = session.get(target_cookie_url, timeout=10, allow_redirects=True)
        # ตรวจสอบ Set-Cookie headers
        raw_set_cookie = r_cookie.raw.headers.getlist("Set-Cookie") if hasattr(r_cookie.raw, "headers") else []
        if not raw_set_cookie and "Set-Cookie" in r_cookie.headers:
            raw_set_cookie = [r_cookie.headers["Set-Cookie"]]

        for cookie_str in raw_set_cookie:
            c_name = cookie_str.split("=")[0].strip()
            c_lower = cookie_str.lower()
            missing_flags = []
            if "secure" not in c_lower:
                missing_flags.append("Secure")
            if "httponly" not in c_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in c_lower:
                missing_flags.append("SameSite")

            entry = {"cookie": c_name, "raw": cookie_str[:80], "missing": missing_flags}
            cookies_tested.append(entry)
            if missing_flags:
                insecure_cookies.append(entry)
    except Exception as e:
        notes.append(f"Cookie check error: {e}")

    cookie_ev = evidence_mgr.save_file("weblayer", "cookies_audit.json", {
        "url_tested": target_cookie_url,
        "cookies": cookies_tested,
        "insecure": insecure_cookies,
    })

    if insecure_cookies:
        items.append(
            ChecklistItem(
                item_id="3.4",
                module="weblayer",
                check="Session Cookie Security Attributes (Secure, HttpOnly, SameSite)",
                status="FAIL",
                score=0,
                evidence=[cookie_ev],
                note=f"Insecure cookie flags found: {', '.join([c['cookie'] + ' missing ' + '/'.join(c['missing']) for c in insecure_cookies])}",
                p0_gate_id=6,
            )
        )
        findings.append({
            "title": "Session Cookies Missing Security Flags (Secure, HttpOnly, SameSite)",
            "severity": "P0",
            "affected": target_cookie_url,
            "evidence": [cookie_ev],
            "reproduce": f"curl -sI {target_cookie_url}",
            "impact": "Allows XSS to steal cookies (no HttpOnly), transmission over plain HTTP (no Secure), and CSRF (no SameSite).",
            "remediation": "Configure session cookies with Secure; HttpOnly; SameSite=Lax (or Strict).",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="3.4",
                module="weblayer",
                check="Session Cookie Security Attributes (Secure, HttpOnly, SameSite)",
                status="PASS",
                score=2,
                evidence=[cookie_ev],
                note="All examined cookies have appropriate security flags or no session cookies set.",
                p0_gate_id=6,
            )
        )

    # ==============================================================================
    # D3.5: Non-destructive SQLi Pilot Injection
    # 4 Requests: baseline, ', 1 AND 1=1, 1 AND 1=2
    # ==============================================================================
    sqli_leads = []
    sqli_evidence_records = []
    params_to_test = config.test_params or ["id", "cat"]

    for param in params_to_test:
        test_cases = [
            ("baseline", "1"),
            ("quote", "1'"),
            ("true_cond", "1 AND 1=1"),
            ("false_cond", "1 AND 1=2"),
        ]
        responses = {}
        for case_name, payload in test_cases:
            target_sqli_url = f"{config.url}?{urlencode({param: payload})}"
            try:
                r_sqli = session.get(target_sqli_url, timeout=10)
                # บันทึก request/response snippet
                responses[case_name] = {
                    "url": target_sqli_url,
                    "status_code": r_sqli.status_code,
                    "content_length": len(r_sqli.content),
                    "header_snippet": dict(list(r_sqli.headers.items())[:6]),
                    "body_first_100": r_sqli.text[:100],
                    "has_sql_error": any(re.search(pat, r_sqli.text, re.IGNORECASE) for pat in SQLI_ERROR_PATTERNS),
                }
            except Exception as e:
                responses[case_name] = {"error": str(e)}

        sqli_evidence_records.append({"param": param, "results": responses})

        # วิเคราะห์ผลต่างชัดเจน
        if "baseline" in responses and "quote" in responses:
            b_res = responses["baseline"]
            q_res = responses["quote"]
            t_res = responses.get("true_cond", {})
            f_res = responses.get("false_cond", {})

            # 1. เช็ค error SQL syntax
            if q_res.get("has_sql_error"):
                sqli_leads.append(f"SQL error pattern triggered on param '{param}'")

            # 2. เช็คความต่างของ boolean conditions
            if (
                t_res.get("status_code") == b_res.get("status_code")
                and f_res.get("status_code") != b_res.get("status_code")
            ) or (
                abs(t_res.get("content_length", 0) - b_res.get("content_length", 0)) < 50
                and abs(f_res.get("content_length", 0) - b_res.get("content_length", 0)) > 500
            ):
                sqli_leads.append(f"Boolean SQL injection differential response on param '{param}'")

    sqli_ev = evidence_mgr.save_file("weblayer", "sqli_pilot_probe.json", sqli_evidence_records)

    if sqli_leads:
        items.append(
            ChecklistItem(
                item_id="3.5",
                module="weblayer",
                check="SQL Injection Pilot Non-Destructive Probe",
                status="FAIL",
                score=0,
                evidence=[sqli_ev],
                note=f"CRITICAL P0: Potential SQLi leads detected: {'; '.join(sqli_leads)}",
                p0_gate_id=3,
            )
        )
        findings.append({
            "title": "SQL Injection Lead Detected (Pilot Probe)",
            "severity": "P0",
            "affected": f"{config.url} ({', '.join(params_to_test)})",
            "evidence": [sqli_ev],
            "reproduce": f"curl -s '{config.url}?{params_to_test[0]}=1%27'",
            "impact": "Critical database compromise, arbitrary data modification or extraction.",
            "remediation": "Use parameterized queries (Prepared Statements) and validate all input types strictly.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="3.5",
                module="weblayer",
                check="SQL Injection Pilot Non-Destructive Probe",
                status="PASS",
                score=2,
                evidence=[sqli_ev],
                note="No SQL injection leads or error differentials detected on test parameters.",
                p0_gate_id=3,
            )
        )

    # ==============================================================================
    # D3.6: Unauthenticated Administrative Path Access
    # ==============================================================================
    admin_paths = ["/admin", "/admin/", "/administrator", "/dashboard"]
    unauthenticated_admin_exposed = []
    admin_ev_records = {}

    for ap in admin_paths:
        adm_url = config.url.rstrip("/") + ap
        try:
            r_adm = session.get(adm_url, timeout=10, allow_redirects=False)
            admin_ev_records[ap] = {
                "url": adm_url,
                "status_code": r_adm.status_code,
                "headers": dict(list(r_adm.headers.items())[:6]),
                "body_first_100": r_adm.text[:100],
            }
            if r_adm.status_code == 200:
                # ตรวจสอบว่าเป็น login form หรือ dashboard จริง
                text_lower = r_adm.text.lower()
                is_login_page = any(kw in text_lower for kw in ["login", "sign in", "password", "username"])
                if not is_login_page and len(r_adm.text) > 200:
                    unauthenticated_admin_exposed.append(adm_url)
        except Exception as e:
            admin_ev_records[ap] = {"error": str(e)}

    admin_ev = evidence_mgr.save_file("weblayer", "admin_access_probe.json", admin_ev_records)

    if unauthenticated_admin_exposed:
        items.append(
            ChecklistItem(
                item_id="3.6",
                module="weblayer",
                check="Unauthenticated Administrative Interface Access",
                status="FAIL",
                score=0,
                evidence=[admin_ev],
                note=f"CRITICAL P0: Unauthenticated admin access: {', '.join(unauthenticated_admin_exposed)}",
                p0_gate_id=4,
            )
        )
        findings.append({
            "title": "Administrative Interface Accessible Without Authentication",
            "severity": "P0",
            "affected": ", ".join(unauthenticated_admin_exposed),
            "evidence": [admin_ev],
            "reproduce": f"curl -s {unauthenticated_admin_exposed[0]}",
            "impact": "Allows attackers direct administrative privileges without credentials.",
            "remediation": "Enforce strong authentication and IP whitelist restrictions on admin routes.",
        })
    else:
        items.append(
            ChecklistItem(
                item_id="3.6",
                module="weblayer",
                check="Unauthenticated Administrative Interface Access",
                status="PASS",
                score=2,
                evidence=[admin_ev],
                note="No unauthenticated admin interface exposure detected.",
                p0_gate_id=4,
            )
        )

    return {
        "findings": findings,
        "items": items,
        "note": notes,
        "headers": headers_detected,
    }
