"""
Evidence Management Engine
จัดเก็บไฟล์หลักฐานดิบ (Raw Evidence) แยกตามโมดูลและ timestamp พร้อมบันทึก SHA-256 hash
"""

from datetime import datetime
import hashlib
import json
import os
from typing import Any, Dict, List, Optional


class EvidenceManager:
    def __init__(self, base_dir: str = "evidence", timestamp: Optional[str] = None):
        self.base_dir = base_dir
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.manifest_data: Dict[str, Any] = {
            "session_timestamp": self.timestamp,
            "created_at": datetime.now().isoformat(),
            "files": []
        }

    def get_module_dir(self, module: str) -> str:
        """คืนค่า path โฟลเดอร์หลักฐานสำหรับโมดูลในรอบนี้"""
        path = os.path.join(self.base_dir, module, self.timestamp)
        os.makedirs(path, exist_ok=True)
        return path

    def save_file(self, module: str, filename: str, content: Any) -> str:
        """
        บันทึกเนื้อหาลงไฟล์หลักฐาน คำนวณ SHA-256 และอัปเดต manifest
        คืนค่า path ของไฟล์หลักฐาน
        """
        module_dir = self.get_module_dir(module)
        file_path = os.path.join(module_dir, filename)

        if isinstance(content, str):
            raw_bytes = content.encode("utf-8", errors="replace")
        elif isinstance(content, (dict, list)):
            raw_bytes = json.dumps(content, indent=2, ensure_ascii=False).encode("utf-8")
        elif isinstance(content, bytes):
            raw_bytes = content
        else:
            raw_bytes = str(content).encode("utf-8", errors="replace")

        with open(file_path, "wb") as f:
            f.write(raw_bytes)

        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        file_size = len(raw_bytes)

        entry = {
            "module": module,
            "filename": filename,
            "relative_path": file_path,
            "sha256": file_hash,
            "size_bytes": file_size,
            "saved_at": datetime.now().isoformat()
        }
        self.manifest_data["files"].append(entry)
        self._write_manifest(module_dir)

        return file_path

    def _write_manifest(self, module_dir: str) -> None:
        """บันทึก manifest ในโฟลเดอร์โมดูล"""
        manifest_path = os.path.join(module_dir, "manifest.json")
        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(self.manifest_data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    @classmethod
    def get_latest_module_evidence(cls, base_dir: str, module: str) -> Optional[str]:
        """ค้นหาโฟลเดอร์ timestamp ล่าสุดของโมดูลที่เคยรันไว้"""
        module_base = os.path.join(base_dir, module)
        if not os.path.exists(module_base):
            return None

        subdirs = [
            d for d in os.listdir(module_base)
            if os.path.isdir(os.path.join(module_base, d))
        ]
        if not subdirs:
            return None

        # เรียงตามชื่อ timestamp (รูปแบบ YYYYMMDD_HHMMSS)
        subdirs.sort(reverse=True)
        return os.path.join(module_base, subdirs[0])

    @classmethod
    def is_within_hours(cls, timestamp_str: str, max_hours: float = 24.0) -> bool:
        """ตรวจสอบว่า timestamp ไม่เก่าเกิน max_hours หรือไม่ (สำหรับ --rerun)"""
        try:
            # รูปแบบ YYYYMMDD_HHMMSS
            ts_clean = os.path.basename(timestamp_str)
            dt = datetime.strptime(ts_clean, "%Y%m%d_%H%M%S")
            diff_hours = (datetime.now() - dt).total_seconds() / 3600.0
            return diff_hours <= max_hours
        except Exception:
            return False
