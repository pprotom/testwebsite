"""
Command Execution & Scanner Wrapper
ควบคุมการรัน subprocess อย่างปลอดภัย มี timeout, capture output, retry 1 ครั้ง และ safety guard
"""

import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Set


class SafetyViolation(Exception):
    """ข้อผิดพลาดเมื่อพบคำสั่งหรือพารามิเตอร์ที่เป็นอันตราย"""
    pass


class ScanResult:
    def __init__(
        self,
        command: str,
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        duration: float = 0.0,
        tool_found: bool = True,
        tool_missing_message: str = "",
        timed_out: bool = False,
        safety_blocked: bool = False,
        safety_reason: str = "",
        retried: bool = False,
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr or (f"BLOCKED by safety validator: {safety_reason}" if safety_blocked else "")
        self.duration = duration
        self.tool_found = tool_found
        self.tool_missing_message = tool_missing_message
        self.timed_out = timed_out
        self.safety_blocked = safety_blocked
        self.safety_reason = safety_reason
        self.retried = retried

    @property
    def returncode(self) -> int:
        return self.exit_code

    @property
    def is_timeout(self) -> bool:
        return self.timed_out

    @property
    def is_success(self) -> bool:
        return self.tool_found and not self.safety_blocked and not self.timed_out and self.exit_code == 0

    def get_output(self) -> str:
        return self.stdout if self.stdout else self.stderr


class CommandScanner:
    # คำสั่งและแฟล็กอันตรายที่ห้ามมีในระบบเด็ดขาด
    BANNED_PATTERNS = [
        r"--drop",
        r"rm\s+-rf",
        r"--os-shell",
        r"--os-cmd",
        r"--os-pwn",
        r"--sql-shell",
        r"--purge",
        r"--alter",
        r"--truncate",
        r"\bDELETE\s+FROM\b",
        r"\bDROP\s+TABLE\b",
        r"\bDROP\s+DATABASE\b",
        r"mkfs",
        r"dd\s+if=",
        r":\(\)\s*\{",
        r"unsafe=1",
    ]

    # รายชื่อโปรแกรมเชิงรุก (Aggressive / Risky tools)
    RISKY_TOOLS = {"sqlmap", "nikto", "hydra", "medusa", "ncrack"}

    TOOL_INSTALL_HINTS: Dict[str, str] = {
        "nmap": "sudo apt-get install -y nmap",
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "wafw00f": "pip install wafw00f หรือ sudo apt-get install -y wafw00f",
        "whatweb": "sudo apt-get install -y whatweb",
        "dirsearch": "pip install dirsearch หรือ sudo apt-get install -y dirsearch",
        "trufflehog": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
        "sqlmap": "sudo apt-get install -y sqlmap หรือ pip install sqlmap",
        "trivy": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
        "wpscan": "sudo apt-get install -y wpscan หรือ gem install wpscan",
    }

    def __init__(
        self,
        safe_mode: bool = True,
        allow_risky: Optional[List[str]] = None,
        timeout: int = 60,
        max_retries: int = 1,
    ):
        self.safe_mode = safe_mode
        self.allow_risky: Set[str] = {r.lower() for r in (allow_risky or [])}
        self.timeout = min(timeout, 60)  # บังคับ limiter <= 60s
        self.max_retries = max(0, max_retries)
        self.history: List[str] = []

    def check_safety(self, cmd_str: str) -> None:
        """
        ตรวจสอบเงื่อนไขความปลอดภัย:
        1. ห้ามมี flag อันตราย
        2. เช็ค safe_mode กับเครื่องมือที่มีความเสี่ยง
        """
        for pattern in self.BANNED_PATTERNS:
            if re.search(pattern, cmd_str, re.IGNORECASE):
                raise SafetyViolation(
                    f"Blocked dangerous command pattern '{pattern}' in: {cmd_str}"
                )

        # แยก binary หลักออกมาเช็ค
        tokens = shlex.split(cmd_str)
        if tokens:
            binary = os.path.basename(tokens[0]).lower()
            if binary in self.RISKY_TOOLS:
                if self.safe_mode and binary not in self.allow_risky:
                    raise SafetyViolation(
                        f"BLOCKED in Safe Mode: Aggressive tool '{binary}' is disabled. "
                        f"Use --allow-risky {binary} or add to config.yaml to enable."
                    )

    def is_tool_installed(self, tool_name: str) -> bool:
        """ตรวจสอบว่าโปรแกรมมีอยู่ใน PATH หรือไม่"""
        return shutil.which(tool_name) is not None

    def run(self, cmd_str: str, custom_timeout: Optional[int] = None) -> ScanResult:
        """
        รันคำสั่ง subprocess พร้อม timeout, capture output และ retry กรณีข้อผิดพลาด
        """
        self.history.append(cmd_str)
        effective_timeout = min(custom_timeout or self.timeout, 60)

        # 1. ตรวจสอบความปลอดภัย
        try:
            self.check_safety(cmd_str)
        except SafetyViolation as sv:
            return ScanResult(
                command=cmd_str,
                exit_code=-1,
                safety_blocked=True,
                safety_reason=str(sv),
            )

        # 2. ตรวจสอบว่ามี executable ในระบบหรือไม่
        tokens = shlex.split(cmd_str)
        if not tokens:
            return ScanResult(command=cmd_str, exit_code=-1, stderr="Empty command")

        binary_name = os.path.basename(tokens[0])
        if not self.is_tool_installed(binary_name):
            hint = self.TOOL_INSTALL_HINTS.get(
                binary_name, f"Please install '{binary_name}' manually."
            )
            return ScanResult(
                command=cmd_str,
                exit_code=-1,
                tool_found=False,
                tool_missing_message=f"Tool '{binary_name}' is not installed in system. Install command: {hint}",
            )

        # 3. รัน subprocess พร้อม retry
        attempts = 1 + self.max_retries
        for attempt in range(attempts):
            start_time = time.time()
            try:
                proc = subprocess.run(
                    cmd_str,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=effective_timeout,
                )
                duration = time.time() - start_time
                res = ScanResult(
                    command=cmd_str,
                    exit_code=proc.returncode,
                    stdout=proc.stdout or "",
                    stderr=proc.stderr or "",
                    duration=duration,
                    retried=(attempt > 0),
                )
                if proc.returncode == 0 or attempt == (attempts - 1):
                    return res
                time.sleep(1)
            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                return ScanResult(
                    command=cmd_str,
                    exit_code=-2,
                    duration=duration,
                    timed_out=True,
                    stderr=f"TIMEOUT: Command timed out after {effective_timeout}s",
                    retried=(attempt > 0),
                )
            except Exception as e:
                duration = time.time() - start_time
                if attempt == (attempts - 1):
                    return ScanResult(
                        command=cmd_str,
                        exit_code=-3,
                        duration=duration,
                        stderr=f"Execution error: {str(e)}",
                        retried=(attempt > 0),
                    )
                time.sleep(1)

        return ScanResult(command=cmd_str, exit_code=-1, stderr="Execution failed after retry")
