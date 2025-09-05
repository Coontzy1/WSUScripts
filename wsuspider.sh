#!/bin/bash

# =============================
# WSUS Registry Policy Extractor via manspider
# Author : Austin Coontz + DennisTheMenace
# Date   : July 2025
# =============================

# Colors
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
NC='\033[0m'

print_banner() {
    echo -e "${RED}"
    cat << "EOF"
                              (_)   | |             | |    
 __      _____ _   _ ___ _ __  _  __| | ___ _ __ ___| |__  
 \ \ /\ / / __| | | / __| '_ \| |/ _` |/ _ \ '__/ __| '_ \ 
  \ V  V /\__ \ |_| \__ \ |_) | | (_| |  __/ |_ \__ \ | | |
   \_/\_/ |___/\__,_|___/ .__/|_|\__,_|\___|_(_)|___/_| |_|
                        | |                                
                        |_|                                

EOF
    echo -e "Austin Coontz + DennisTheMenace${NC}"
}

# Default banner behavior
hacking_the_matrix=1
PARSE_ONLY=0

# Dependency checks
check_regpol() {
    if ! command -v regpol >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] regpol not found. Would you like to install it? (y/N)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Installing regpol...${NC}"
            proxychains -q pipx install regpol
        else
            echo -e "${RED}[-] regpol is required. Install with: pipx install regpol${NC}"
            exit 1
        fi
    fi
}

check_manspider() {
    if ! command -v manspider >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] manspider not found. Would you like to install it? (y/N)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Installing manspider...${NC}"
            proxychains -q pipx install manspider
        else
            echo -e "${RED}[-] manspider is required. Install with: pipx install manspider${NC}"
            exit 1
        fi
    fi
}

check_manspider
check_regpol

# Usage/help
usage() {
    echo -e "${YELLOW}Usage:${NC} ${0##*/} -dc-ip <IP> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> --no-banner"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -dc-ip           or --dc-ip <IP>              Domain Controller IP"
    echo -e "  -d               or --domain|--Domain         Domain name"
    echo -e "  -u               or --user|--username         Username"
    echo -e "  -p               or --password|--Password     Password"
    echo -e "  -n               or --no-banner|-no-banner    Don't show the banner"
    echo -e "  -e               or --parse-only              Only parse existing loot"
    echo -e "  -h               or --help                    Show this help menu"
    exit 1
}

# Arg parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -dc-ip|--dc-ip|-DC-IP|--DC-IP)
            DCIP="$2"; shift 2;;
        -d|--domain|--Domain|--DOMAIN)
            DOMAIN="$2"; shift 2;;
        -u|--user|--username|--User|--Username|--USERNAME)
            USERNAME="$2"; shift 2;;
        -p|--password|--Password|--PASSWORD)
            PASSWORD="$2"; shift 2;;
        -n|--no-banner|--No-Banner|--NO-BANNER)
            hacking_the_matrix=2; shift;;
        -e|--parse-only|--Parse-Only|--PARSE-ONLY)
            PARSE_ONLY=1; shift;;
        -H|--hash|--Hash|--HASH)
            HASH="$2"; shift 2;;
        -h|--help|--Help|--HELP)
            usage;;
        *)
            echo -e "${RED}[-] Unknown option:${NC} $1"
            usage;;
    esac
done

if [[ "$PARSE_ONLY" -eq 0 ]]; then
    if [[ -z "$DCIP" || -z "$DOMAIN" || -z "$USERNAME" ]]; then
        usage
    fi

    if [[ -n "$PASSWORD" && -n "$HASH" ]]; then
        echo -e "${RED}[-] You cannot specify both a password and a hash.${NC}"
        exit 1
    elif [[ -z "$PASSWORD" && -z "$HASH" ]]; then
        echo -e "${RED}[-] You must specify either a password (-p) or a hash (-H).${NC}"
        exit 1
    fi
fi

# Show banner
for ((i=1; i<=hacking_the_matrix; i++)); do
    print_banner
done

# Directory setup
MAIN_DIR="$(pwd)"
LOOT_DIR="${MAIN_DIR}/manspider"
OUT_DIR="${MAIN_DIR}/parsed_reg_files"
SUMMARY="${MAIN_DIR}/wsus_summary.txt"

mkdir -p "$LOOT_DIR"
mkdir -p "$OUT_DIR"
echo "WSUS Summary - Generated on $(date)" >> "$SUMMARY"

# =============================
# Step 0: Run manspider
# =============================
if [[ "$PARSE_ONLY" -eq 0 ]]; then
    echo -e "${BLUE}[*] Step 0:${NC} Running manspider against ${CYAN}$DCIP${NC}..."

    if [[ -n "$PASSWORD" ]]; then
        manspider "$DCIP" -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" \
            --sharenames SYSVOL -f Registry -e pol -l "$LOOT_DIR"
    elif [[ -n "$HASH" ]]; then
        manspider "$DCIP" -d "$DOMAIN" -u "$USERNAME" -H "$HASH" \
            --sharenames SYSVOL -f Registry -e pol -l "$LOOT_DIR"
    fi
else
    echo -e "${YELLOW}[!] Parse-only mode enabled. Skipping manspider...${NC}"
fi

# =============================
# Step 1: Decode Machine_Registry.pol files
# =============================
echo -e "${BLUE}[*] Step 1:${NC} Decoding Machine registry policy files..."
find "$LOOT_DIR" -type f -iname '*_Machine_Registry.pol' | while read -r polfile; do
    outfile="${OUT_DIR}/$(basename "$polfile" .pol).txt"
    regpol "$polfile" > "$outfile"
    echo -e "${GREEN}[+] Decoded:${NC} $polfile -> $outfile"
done

# =============================
# Step 2: Parse for WSUS values
# =============================
echo -e "${BLUE}[*] Step 2:${NC} Parsing registry text files for WSUS policy values..."

# REG_SZ keys
string_keys=(
  WUServer
  WUStatusServer
  TargetGroup
  AccountDomainSid
  SusClientId
)

# REG_DWORD keys
dword_keys=(
  UseWUServer
  NoAutoUpdate
  AUOptions
  ScheduledInstallDay
  ScheduledInstallTime
  RescheduleWaitTime
  DetectionFrequencyEnabled
  DetectionFrequency
  RebootWarningTimeout
  RebootRelaunchTimeout
  RebootRelaunchTimeoutEnabled
  IncludeRecommendedUpdates
  AutoInstallMinorUpdates
  TargetGroupEnabled
  ElevateNonAdmins
  DisableWindowsUpdateAccess
  DoNotConnectToWindowsUpdateInternetLocations
  SetAutoRestartDeadline
  SetUpdateNotificationLevel
)

# Process all decoded files
for file in "$OUT_DIR"/*.txt; do
    domain=$(basename "$file" | cut -d'_' -f1)
    gpoid=$(echo "$file" | rev | cut -d '_' -f 3 | rev)
    label="$domain-$gpoid"

    for key in "${string_keys[@]}"; do
        val_string=""
        raw=$(grep -aiA4 "value: $key" "$file" | grep -ai 'data:' | head -n1 | grep -ao "b'.*'" | cut -d"'" -f2)
        if [[ -n "$raw" ]]; then
            val_string=$(echo -e "$raw" | tr -d '\0')
            echo "$label - $key - $val_string" | tee -a "$SUMMARY"
        fi
    done

    for key in "${dword_keys[@]}"; do
        val_int=""
        raw=$(grep -aiA4 -P "value:\s*${key}\\b" "$file" | grep -aPo "data:\s+b'\K(.*)(?=')" | head -1)
        if [[ -n "$raw" ]]; then
            val_int=$(printf "$raw" | od -An -t u4 | xargs)
            echo "$label - $key - $val_int" | tee -a "$SUMMARY"
        fi
    done
done

echo -e "${GREEN}[+] Complete.${NC} Parsed output saved to ${CYAN}${SUMMARY}${NC}"
