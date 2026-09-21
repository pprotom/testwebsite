#!/usr/bin/env bash
# ==============================================================================
# website-security-auditor: Tool Installation Script
# ตรวจสอบและติดตั้งเครื่องมือที่ขาด (apt/pip/go) โดยขอการยืนยันทีละตัว
# ==============================================================================

set -e

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}         website-security-auditor: Tool Environment Checker           ${NC}"
echo -e "${BLUE}======================================================================${NC}"

confirm_and_install() {
    local tool_name="$1"
    local install_cmd="$2"
    local check_bin="$3"

    if command -v "$check_bin" >/dev/null 2>&1; then
        echo -e "${GREEN}[✔ FOUND]${NC} $tool_name is already installed at: $(which "$check_bin")"
        return 0
    fi

    echo -e "${YELLOW}[✖ MISSING]${NC} $tool_name is not installed."
    echo -e "   Recommended command: ${BLUE}$install_cmd${NC}"
    
    # ถ้ามี flag -y ใน arguments ให้ติดตั้งทันที
    if [[ "$AUTO_YES" == "1" ]]; then
        echo "Auto-confirming installation..."
        eval "$install_cmd"
        return 0
    fi

    read -p "   Do you want to install $tool_name now? [y/N]: " choice
    case "$choice" in
        y|Y|yes|YES)
            echo -e "${GREEN}Installing $tool_name...${NC}"
            eval "$install_cmd"
            ;;
        *)
            echo -e "${YELLOW}Skipping $tool_name installation.${NC}"
            ;;
    esac
    echo ""
}

AUTO_YES=0
if [[ "$1" == "-y" || "$1" == "--yes" ]]; then
    AUTO_YES=1
fi

echo -e "Checking system tools...\n"

# 1. nmap
confirm_and_install "nmap" "sudo apt-get update && sudo apt-get install -y nmap" "nmap"

# 2. wafw00f
confirm_and_install "wafw00f" "sudo apt-get install -y wafw00f || pip3 install wafw00f" "wafw00f"

# 3. whatweb
confirm_and_install "whatweb" "sudo apt-get install -y whatweb" "whatweb"

# 4. dirsearch
confirm_and_install "dirsearch" "sudo apt-get install -y dirsearch || pip3 install dirsearch" "dirsearch"

# 5. subfinder
confirm_and_install "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || sudo apt-get install -y subfinder" "subfinder"

# 6. httpx
confirm_and_install "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || sudo apt-get install -y httpx" "httpx"

# 7. trufflehog
confirm_and_install "trufflehog" "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin" "trufflehog"

# 8. sqlmap (Optional - Aggressive tool)
confirm_and_install "sqlmap" "sudo apt-get install -y sqlmap || pip3 install sqlmap" "sqlmap"

echo -e "\n${GREEN}Tool check completed!${NC}"
