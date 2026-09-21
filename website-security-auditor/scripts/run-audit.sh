#!/usr/bin/env bash
# ==============================================================================
# website-security-auditor: Execution Wrapper Script
# เปิด venv (ถ้ามี) แล้วรัน python main.py
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

# ตรวจสอบและ activate virtual environment ถ้ามี
if [ -d "venv" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "[*] Activating virtual environment (.venv)..."
    source .venv/bin/activate
fi

# รัน main.py พร้อมส่งต่อ arguments ทั้งหมด
python3 main.py "$@"
