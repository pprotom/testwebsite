"""
Auditor Configuration Loader & Validator
ตรวจสอบและจัดการตั้งค่าความปลอดภัยของระบบสแกน
"""

import os
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import yaml


class ConfigError(Exception):
    """ข้อผิดพลาดจากการตรวจสอบ config ไม่ผ่าน"""
    pass


class AuditorConfig:
    def __init__(self, data: Dict[str, Any], config_path: str = ""):
        self.raw_data = data
        self.config_path = config_path
        self._validate_and_init()

    def _validate_and_init(self) -> None:
        target = self.raw_data.get("target", {})
        if not target:
            raise ConfigError("Missing 'target' section in config.yaml")

        self.url: str = target.get("url", "").strip()
        if not self.url:
            raise ConfigError("target.url is required")

        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            raise ConfigError(f"Invalid target.url: '{self.url}' (must include http:// or https://)")

        self.domain: str = target.get("domain", "").strip()
        if not self.domain:
            self.domain = parsed.hostname or ""

        self.allowed_domains: List[str] = [
            d.strip().lower() for d in target.get("allowed_domains", []) if d.strip()
        ]
        if not self.allowed_domains:
            # กำหนด domain เริ่มต้นเข้า scope
            self.allowed_domains = [self.domain.lower()]

        self.login_url: str = target.get("login_url", "").strip()
        self.test_params: List[str] = target.get("test_params", ["id", "query", "cat"])
        self.repo_path: str = target.get("repo_path", "").strip()

        # ส่วน execution และความปลอดภัย
        execution = self.raw_data.get("execution", {})
        self.safe_mode: bool = bool(execution.get("safe_mode", True))
        self.allow_risky: List[str] = [
            str(x).strip().lower() for x in execution.get("allow_risky", [])
        ]

        # Limiter บังคับ: timeout <= 60s
        self.command_timeout: int = int(execution.get("command_timeout", 60))
        if self.command_timeout > 60:
            raise ConfigError(
                f"Security limitation: command_timeout ({self.command_timeout}s) must be <= 60s"
            )

        # Concurrency limiter: <= 3
        self.max_concurrency: int = int(execution.get("max_concurrency", 3))
        if self.max_concurrency > 3:
            raise ConfigError(
                f"Security limitation: max_concurrency ({self.max_concurrency}) must be <= 3"
            )

        # Port scan limit: default 1000
        self.port_scan_limit: int = int(execution.get("port_scan_limit", 1000))
        self.confirm_large_port_scan: bool = bool(
            execution.get("confirm_large_port_scan", False)
        )

        # Proxy
        proxy_cfg = self.raw_data.get("proxy", {})
        self.http_proxy: str = proxy_cfg.get("http_proxy", "") or os.environ.get("HTTP_PROXY", "")
        self.https_proxy: str = proxy_cfg.get("https_proxy", "") or os.environ.get("HTTPS_PROXY", "")

        # Evidence & Report
        evidence_cfg = self.raw_data.get("evidence", {})
        self.evidence_dir: str = evidence_cfg.get("base_dir", "evidence")

        report_cfg = self.raw_data.get("report", {})
        self.report_dir: str = report_cfg.get("output_dir", ".")

    def is_in_scope(self, host_or_url: str) -> bool:
        """
        ตรวจสอบว่า host, URL หรือ IP อยู่ในขอบเขต allowed_domains หรือไม่
        """
        if not host_or_url:
            return False

        clean_host = host_or_url.strip().lower()
        if "://" in clean_host:
            parsed = urlparse(clean_host)
            clean_host = (parsed.hostname or "").lower()

        # ตัด port ออกถ้ามี เช่น example.com:8080
        if ":" in clean_host and not clean_host.startswith("["):
            clean_host = clean_host.split(":")[0]

        for allowed in self.allowed_domains:
            allowed = allowed.lower()
            if clean_host == allowed:
                return True
            # รองรับ wildcard subdomains เช่น *.example.com หรือ match domain หลัก
            if clean_host.endswith("." + allowed):
                return True

        # ตรวจสอบ resolution IP ว่าตรงกับ domain ใน scope หรือไม่
        try:
            ip = socket.gethostbyname(clean_host)
            for allowed in self.allowed_domains:
                try:
                    allowed_ip = socket.gethostbyname(allowed)
                    if ip == allowed_ip:
                        return True
                except Exception:
                    pass
        except Exception:
            pass

        return False

    def get_proxies_dict(self) -> Optional[Dict[str, str]]:
        """คืนค่า dictionary proxy สำหรับ requests library"""
        proxies = {}
        if self.http_proxy:
            proxies["http"] = self.http_proxy
        if self.https_proxy:
            proxies["https"] = self.https_proxy
        return proxies if proxies else None


def load_config(path: str) -> AuditorConfig:
    """โหลดและแปลงไฟล์ config.yaml เข้าเป็น AuditorConfig"""
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found at: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ConfigError(f"Failed to parse YAML config: {e}")

    if not isinstance(data, dict):
        raise ConfigError("Invalid YAML format: root must be a mapping dictionary")

    return AuditorConfig(data, config_path=path)
