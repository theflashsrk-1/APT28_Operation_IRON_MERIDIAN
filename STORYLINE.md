# APT28 Operation IRON MERIDIAN — Full Storyline

## Intelligence Brief

**Operation:** IRON MERIDIAN
**Classification:** CONFIDENTIAL // EXERCISE ONLY
**Issuing Authority:** Corporate Incident Response Division (CIRD)
**Target Organization:** CybeRange Healthcare Systems
**Threat Actor:** APT28 / Forest Blizzard / STRONTIUM (GRU Unit 26165)
**Date:** [EXERCISE DATE]

---

## Situation

MERIDIAN ACTUAL — Threat intelligence indicates APT28 has expanded targeting to healthcare organizations with Active Directory Certificate Services (ADCS) infrastructure. The shift is strategic — compromising an organization's PKI allows the attacker to forge authentication certificates for any identity in the domain, providing persistent access that survives password resets and account lockouts.

CybeRange Healthcare Systems operates a standard five-server Windows AD environment. The IT team deployed a PKI infrastructure for internal application authentication but never hardened the certificate templates. A web file server was set up with dozens of SMB shares for department-level file sharing — over time, configuration files with embedded credentials accumulated across these shares. A SQL database cluster uses linked servers for cross-application data access. These are textbook enterprise misconfigurations that exist in thousands of organizations.

---

## Red Team Brief (IRON MERIDIAN Operators)

You are operators for IRON MERIDIAN. Your mission is to achieve full domain compromise of CybeRange Healthcare's Active Directory environment through certificate abuse. The operation has five phases, each building on credentials or access obtained in the previous phase. Your final objective is a complete dump of NTDS.dit.

**Entry Point:** Network access to the corporate LAN segment. No credentials.
**Final Objective:** DCSync or NTDS.dit extraction from the Domain Controller.
**ROE:** No destructive actions. No ransomware. Collection only.

### Phase 1 — The Needle in the Haystack

CybeRange Healthcare's web file server hosts 15 SMB shares containing hundreds of files. Eleven shares allow anonymous access. The shares are full of configuration files, scripts, templates, and documents — most containing credentials. Nearly all of these credentials are decoys that lead nowhere. The real credentials are buried in exactly two locations, deep in the directory structure. One is a backup web.config file four directories deep. The other is a PowerShell maintenance script that hardcodes a SQL password. Both contain the same credential: `svc_db:Db@ccess2025!`. Finding them requires systematic enumeration and patience.

### Phase 2 — The Database Bridge

The svc_db credential grants sysadmin access to SRV02-DB's MSSQL instance. Enumerate the SQL Server's configuration and discover a linked server pointing to SRV03-APP. The linked server has RPC OUT enabled and runs in the security context of svc_app. This means you can execute operating system commands on SRV03-APP by routing xp_cmdshell calls through the linked server.

### Phase 3 — The Impersonation

The svc_app account on SRV03-APP has SeImpersonatePrivilege — standard for SQL service accounts. Upload PrintSpoofer to SRV03-APP through an SMB server hosted on your machine (Windows blocks anonymous SMB connections). Use PrintSpoofer to escalate from svc_app to NT AUTHORITY\SYSTEM. As SYSTEM, create a local admin account and dump LSASS to extract svc_app's NT hash. This hash is the key to the next phase.

### Phase 4 — The Shadow

svc_app has WriteProperty on svc_adm's msDS-KeyCredentialLink attribute. This was configured during an automation project that needed svc_app to manage svc_adm's authentication properties — a delegation that was never revoked. Use certipy-ad's shadow auto command to write a new key credential to svc_adm and authenticate via PKINIT. This gives you svc_adm's TGT and NT hash without ever knowing or changing svc_adm's password.

### Phase 5 — The Crown Jewels

svc_adm is a member of CertManagers and has WriteProperty, WriteDACL, and WriteOwner on the CorpAuth certificate template. This is ADCS ESC4 — the ability to modify template configuration. Enable the "Enrollee Supplies Subject" flag, converting the template to ESC1. Request a certificate with Administrator's UPN in the Subject Alternative Name. Authenticate as Administrator via PKINIT. Run DCSync. Every credential in the domain is yours.

---

## Blue Team Brief (CybeRange SOC)

You are the Security Operations Center at CybeRange Healthcare. Anomalous SMB enumeration activity was detected against the file server. Your mission is to trace the full attack chain.

**For each phase you must:**

- Identify the specific log evidence
- Name the technique (MITRE ATT&CK ID)
- Identify the affected account/service
- Provide remediation steps

**Key Log Sources:**

- DC01: Security log — Events 4768/4769 (Kerberos), 5136 (DS modification of KeyCredentialLink), 4662 (DCSync)
- SRV01-WEB: Security log — Events 5140/5145 (share access patterns)
- SRV02-DB: SQL Server audit log — linked server EXEC AT statements
- SRV03-APP: Security log — Events 4688 (PrintSpoofer, net.exe), 4720/4732 (user creation)
- SRV04-CA: Security log — Events 4899/4900 (template modification), 4887 (cert request with SAN)

**Critical Detection Opportunities:**
1. **Step 1:** Anonymous SMB access from single IP iterating through 15+ shares in rapid succession
2. **Step 3:** PrintSpoofer process creation (Event 4688) with parent process sqlservr.exe
3. **Step 4:** msDS-KeyCredentialLink modification (Event 5136) — should almost never change
4. **Step 5:** Certificate template attribute modification (4899) followed immediately by certificate request with SAN (4887) — the ESC4→ESC1 chain

---

## Chain of Compromise — Summary

```
[Attacker — Corporate LAN]
         │
         │ Anonymous SMB
         ▼
┌─────────────────────────────────┐
│  M2: SRV01-WEB                  │  PHASE 1
│  IIS File Server                │  15 SMB shares, 40+ config files
│  Port 445 — Anonymous shares    │  Real creds buried deep:
│                                 │  svc_db : Db@ccess2025!
└──────────────┬──────────────────┘
               │  svc_db : Db@ccess2025!
               │  MSSQL auth
               ▼
┌─────────────────────────────────┐
│  M3: SRV02-DB                   │  PHASE 2
│  MSSQL Primary (default inst.)  │  Linked Server → SRV03-APP
│  Port 1433                      │  EXEC xp_cmdshell AT [SRV03-APP]
│  svc_db = sysadmin              │  → runs as svc_app
└──────────────┬──────────────────┘
               │  Linked Server pivot
               │  xp_cmdshell as svc_app
               ▼
┌─────────────────────────────────┐
│  M4: SRV03-APP                  │  PHASE 3
│  MSSQL Application Server       │  SeImpersonatePrivilege
│  svc_app runs SQL service       │  PrintSpoofer → SYSTEM
│                                 │  → LSASS dump → svc_app hash
└──────────────┬──────────────────┘
               │  svc_app NT hash
               │  WriteProperty on svc_adm
               ▼
┌─────────────────────────────────┐
│  M1: DC01                       │  PHASE 4
│  Domain Controller              │  Shadow Credentials
│  svc_app → svc_adm              │  certipy-ad shadow auto
│  msDS-KeyCredentialLink         │  → svc_adm PKINIT auth
└──────────────┬──────────────────┘
               │  svc_adm hash + TGT
               │  CertManagers group
               ▼
┌─────────────────────────────────┐
│  M5: SRV04-CA                   │  PHASE 5
│  Enterprise CA (cyberange-CA)   │  ESC4: Modify CorpAuth template
│  CorpAuth template              │  ESC1: Request cert as Admin
│  svc_adm has WriteDACL          │  PKINIT → Administrator
│                                 │  DCSync → NTDS.dit
└─────────────────────────────────┘
```
