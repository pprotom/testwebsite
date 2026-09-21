"""
Unit Tests for Command Scanner (test_scanner.py)
ทดสอบ Subprocess execution, Timeout, Safety patterns, Safe mode, และ Allow-risky overrides
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from auditor.scanner import CommandScanner, ScanResult


class TestCommandScanner(unittest.TestCase):
    def setUp(self):
        self.scanner_safe = CommandScanner(safe_mode=True, allow_risky=[], timeout=10)
        self.scanner_risky = CommandScanner(safe_mode=True, allow_risky=["sqlmap"], timeout=10)

    def test_banned_command_blocked(self):
        """คำสั่งอันตราย (rm -rf, mkfs, dd) ต้องถูกบล็อกทันทีโดยไม่รันจริง"""
        banned_commands = [
            "rm -rf /var/www",
            "sudo mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",
        ]
        for cmd in banned_commands:
            res = self.scanner_safe.run(cmd)
            self.assertFalse(res.is_success)
            self.assertEqual(res.returncode, -1)
            self.assertIn("BLOCKED by safety validator", res.stderr)

    def test_destructive_flags_blocked(self):
        """แฟล็กอันตราย (--drop, --os-shell, --purge) ต้องถูกบล็อก"""
        dangerous_flag_cmds = [
            "sqlmap -u 'http://example.com' --drop",
            "sqlmap -u 'http://example.com' --os-shell",
            "nmap -sS --script-args unsafe=1 example.com",
            "dirsearch -u http://example.com --purge",
        ]
        for cmd in dangerous_flag_cmds:
            res = self.scanner_safe.run(cmd)
            self.assertFalse(res.is_success)
            self.assertEqual(res.returncode, -1)
            self.assertIn("BLOCKED", res.stderr)

    def test_safe_mode_blocks_aggressive_tools(self):
        """Safe Mode ต้องไม่อนุญาตให้รัน sqlmap เว้นแต่จะระบุใน allow_risky"""
        cmd = "sqlmap -u http://example.com/item?id=1 --batch"
        res_blocked = self.scanner_safe.run(cmd)
        self.assertFalse(res_blocked.is_success)
        self.assertIn("BLOCKED in Safe Mode", res_blocked.stderr)

    @patch("shutil.which", return_value="/usr/bin/sqlmap")
    @patch("subprocess.run")
    def test_allow_risky_permits_aggressive_tool(self, mock_subproc, mock_which):
        """เมื่อระบุ --allow-risky sqlmap ต้องอนุญาตให้รันได้"""
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout="sqlmap scan finished",
            stderr="",
        )
        cmd = "sqlmap -u http://example.com/item?id=1 --batch"
        res = self.scanner_risky.run(cmd)
        self.assertTrue(res.is_success)
        self.assertEqual(res.stdout, "sqlmap scan finished")

    @patch("shutil.which", return_value="/usr/bin/nmap")
    @patch("subprocess.run")
    def test_timeout_handling(self, mock_subproc, mock_which):
        """การติด Timeout ต้องบันทึกว่า Timeout อย่างชัดเจน"""
        mock_subproc.side_effect = subprocess.TimeoutExpired(cmd="nmap target", timeout=5)
        res = self.scanner_safe.run("nmap target", custom_timeout=5)
        self.assertTrue(res.is_timeout)
        self.assertFalse(res.is_success)
        self.assertIn("TIMEOUT", res.stderr)

    @patch("shutil.which", return_value="/usr/bin/curl")
    @patch("subprocess.run")
    def test_retry_on_transient_failure(self, mock_subproc, mock_which):
        """การ retry คำสั่งที่ล้มเหลวแบบ transient"""
        # ครั้งแรก error, ครั้งที่สองผ่าน
        mock_subproc.side_effect = [
            subprocess.CalledProcessError(returncode=2, cmd="curl", stderr="Connection reset"),
            MagicMock(returncode=0, stdout="Success response", stderr=""),
        ]
        scanner_retry = CommandScanner(safe_mode=True, timeout=5, max_retries=2)
        res = scanner_retry.run("curl -sI https://example.com")
        self.assertTrue(res.is_success)
        self.assertEqual(res.stdout, "Success response")
        self.assertEqual(mock_subproc.call_count, 2)


if __name__ == "__main__":
    unittest.main()
