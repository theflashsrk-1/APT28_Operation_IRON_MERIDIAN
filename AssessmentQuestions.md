# APT28 — Operation IRON MERIDIAN — Participant Assessment

## Challenge Verification Questions

> **Instructions:**
>
> - Each Range has **3 MCQs** (choose the single best answer) and **2 Static Answer** questions
> - Questions are based on information gathered **during exploitation** — you must have solved the challenge to answer correctly
> - Answers are provided at the end of this document for facilitator use only

---

# Range 1 — The Haystack (M2: SRV01-WEB)

### *SMB Share Enumeration + Credential Discovery*

---

### MCQ 1.1

**SRV01-WEB hosts 15 SMB shares. How many of these shares allow anonymous (null session) access?**

- A) 5
- B) 8
- C) 11
- D) 15
- E) 3

---

### MCQ 1.2

**The real svc_db credentials are found in a web.config file buried deep in the WebApps share. What is the exact directory path within the share where this file is located?**

- A) `configs/production/web.config`
- B) `archive/2024-Q3/corpapp.bak/web.config`
- C) `backup/latest/web.config`
- D) `deployment/staging/corpapp/web.config`
- E) `archive/2024-Q4/web.config`

---

### MCQ 1.3

**Many of the configuration files across the shares contain credentials. Most of these are decoys. What distinguishes the real credentials from the decoys?**

- A) Real credentials use stronger passwords
- B) Real credentials reference actual hostnames (SRV02-DB) that exist in the environment
- C) Real credentials are in XML format while decoys are in JSON
- D) Decoy credentials use the same username as real ones
- E) Real credentials are always in the first file found

---

### Static Question 1.4 — Credential Submission

**Submit the password discovered for svc_db:**

**Answer:** `Db@ccess2025!`

---

### Static Question 1.5

**Name the second location (besides WebApps) where the real svc_db credentials appear. Provide the share name and filename.**

**Answer:** `Ops-Scripts` share — `Database/Weekly_DB_Maintenance.ps1`

---



---

# Range 2 — The Bridge (M3: SRV02-DB → M4: SRV03-APP)

### *SQL Linked Server Pivot via xp_cmdshell*

---

### MCQ 2.1

**After authenticating to SRV02-DB as svc_db, you discover a linked server. What SQL query reveals linked servers on the instance?**

- A) `SELECT * FROM sys.linked_servers`
- B) `SELECT name, data_source FROM sys.servers WHERE is_linked = 1`
- C) `EXEC sp_linkedservers`
- D) `SELECT * FROM sys.remote_logins`
- E) `EXEC xp_enum_linked_servers`

---

### MCQ 2.2

**The linked server to SRV03-APP has a specific configuration that allows remote OS command execution. What must be enabled on the linked server for `EXEC AT` with xp_cmdshell to work?**

- A) xp_cmdshell on the local server only
- B) Remote Admin Connections
- C) RPC and RPC OUT on the linked server definition
- D) SQL Agent on both servers
- E) Windows Authentication delegation

---

### MCQ 2.3

**When you execute `EXEC ('xp_cmdshell ''whoami''') AT [SRV03-APP]`, the command runs as which account on SRV03-APP?**

- A) CYBERANGE\svc_db
- B) NT AUTHORITY\SYSTEM
- C) CYBERANGE\svc_app
- D) CYBERANGE\Administrator
- E) NT SERVICE\MSSQLSERVER

---

### Static Question 2.4 — Evidence Submission

**What is the exact SQL syntax to execute whoami on SRV03-APP through the linked server from SRV02-DB?**

**Answer:** `EXEC ('xp_cmdshell ''whoami''') AT [SRV03-APP];`

---

### Static Question 2.5

**What database exists on SRV03-APP that confirms it is the application tier?**

**Answer:** `AppData`

---



---

# Range 3 — The Escalation (M4: SRV03-APP)

### *PrintSpoofer Privilege Escalation + LSASS Dump*

---

### MCQ 3.1

**svc_app can escalate to SYSTEM using PrintSpoofer because of a specific Windows privilege. Which privilege is required?**

- A) SeDebugPrivilege
- B) SeBackupPrivilege
- C) SeImpersonatePrivilege
- D) SeTcbPrivilege
- E) SeAssignPrimaryTokenPrivilege

---

### MCQ 3.2

**You upload PrintSpoofer64.exe to SRV03-APP via an SMB server on your attacker machine. Why must the SMB server use authentication (username/password) instead of anonymous access?**

- A) Impacket's smbserver requires credentials by default
- B) Windows Server 2019 blocks anonymous (guest) SMB connections to remote shares by default
- C) PrintSpoofer requires authenticated SMB to function
- D) The domain GPO enforces SMB signing
- E) Anonymous SMB is disabled on the attacker's OS

---

### MCQ 3.3

**After escalating to SYSTEM on SRV03-APP and dumping LSASS, which account's NT hash do you extract that enables the next phase (Shadow Credentials)?**

- A) CYBERANGE\Administrator
- B) CYBERANGE\svc_db
- C) SRV03-APP$ machine hash
- D) CYBERANGE\svc_app
- E) CYBERANGE\svc_adm

---

### Static Question 3.4 — Hash Submission

**Submit the svc_app NT hash extracted from LSASS on SRV03-APP:**

**Answer:** `[HASH — extracted during exploitation]`

---

### Static Question 3.5

**What is the exact PrintSpoofer command used to create a local admin account named tempadmin on SRV03-APP? (Provide the full command as executed via xp_cmdshell through the linked server.)**

**Answer:** `C:\Windows\Temp\PrintSpoofer64.exe -i -c "net user tempadmin P@ss123! /add"`

---



---

# Range 4 — The Shadow (M1: DC01)

### *Shadow Credentials Attack via msDS-KeyCredentialLink*

---

### MCQ 4.1

**The Shadow Credentials attack works because svc_app has WriteProperty on svc_adm's msDS-KeyCredentialLink attribute. What does writing to this attribute allow the attacker to do?**

- A) Change svc_adm's password without knowing the current password
- B) Add svc_app to the Domain Admins group
- C) Register a new public key for svc_adm, enabling certificate-based Kerberos (PKINIT) authentication as svc_adm
- D) Disable svc_adm's account lockout
- E) Grant svc_app delegation rights to svc_adm

---

### MCQ 4.2

**After running `certipy-ad shadow auto`, the tool authenticates as svc_adm using which Kerberos pre-authentication method?**

- A) Standard password-based pre-authentication (PA-ENC-TIMESTAMP)
- B) NTLM pass-through authentication
- C) PKINIT — certificate-based pre-authentication (PA-PK-AS-REQ)
- D) Kerberos constrained delegation (S4U2Self)
- E) Anonymous authentication with TGT forwarding

---

### MCQ 4.3

**The Shadow Credentials attack requires the Domain Controller to have a specific certificate for PKINIT to work. What scheduled task ensures DC01 obtains this certificate?**

- A) CertAutoEnroll — retries certutil -pulse every 2 minutes until KDC cert is obtained
- B) LabBootstrap-DC — configures DNS and network settings
- C) KerberosKeyDistribution — pre-installed Windows task
- D) CertSvc-Renew — renews expired certificates
- E) PKINITSetup — one-time certificate enrollment

---

### Static Question 4.4 — Hash Submission

**Submit the svc_adm NT hash obtained via Shadow Credentials PKINIT:**

**Answer:** `[HASH — extracted during exploitation]`

---

### Static Question 4.5

**What certipy-ad command did you use to perform the Shadow Credentials attack? (Use placeholders for hashes and IPs.)**

**Answer:** `certipy-ad shadow auto -u 'svc_app@cyberange.local' -hashes ':<SVC_APP_HASH>' -account svc_adm -dc-ip <DC_IP>`

---



---

# Range 5 — The Forge (M5: SRV04-CA)

### *ADCS ESC4 → ESC1: Certificate Template Abuse*

---

### MCQ 5.1

**ESC4 refers to the ability to modify a certificate template's configuration. Which specific permission on the CorpAuth template enables the ESC4 attack for svc_adm?**

- A) Enroll
- B) Full Control
- C) WriteProperty and WriteDACL
- D) Read
- E) AutoEnroll

---

### MCQ 5.2

**To convert ESC4 to ESC1, you modify the CorpAuth template to enable "Enrollee Supplies Subject." What is the technical name of the flag that gets set on the template?**

- A) EDITF_ATTRIBUTESUBJECTALTNAME2
- B) CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
- C) msPKI-Enrollment-Flag
- D) CERT_TEMPLATE_ALLOW_SAN
- E) pKIExtendedKeyUsage

---

### MCQ 5.3

**After requesting a certificate as Administrator and authenticating via PKINIT, you run secretsdump against DC01. What MS-DRSR operation does secretsdump perform to extract all domain hashes?**

- A) LDAP search for userPassword attributes
- B) Remote SAM registry dump
- C) DCSync — DRS_REPLICAINFO_NEIGHBORS replication request
- D) Direct NTDS.dit file copy via SMB
- E) LSASS process memory dump

---

### Static Question 5.4 — Evidence Submission

**What is the name of the Enterprise CA on SRV04-CA?**

**Answer:** `cyberange-CA`

---

### Static Question 5.5

**Provide the exact certipy-ad command to request a certificate as Administrator using the modified CorpAuth template (use placeholders):**

**Answer:** `certipy-ad req -u 'svc_adm@cyberange.local' -hashes ':<SVC_ADM_HASH>' -ca 'cyberange-CA' -template 'CorpAuth' -upn 'Administrator@cyberange.local' -dc-ip <DC_IP>`

---



---

# FACILITATOR ANSWER KEY

### (Do not distribute to participants)

| Q# | Question | Answer |
|----|----------|--------|
| 1.1 | Anonymous share count | **C** — 11 |
| 1.2 | Path to real web.config | **B** |
| 1.3 | Real vs decoy distinction | **B** — references real hostnames |
| 1.4 | svc_db password | `Db@ccess2025!` |
| 1.5 | Second credential location | `Ops-Scripts / Weekly_DB_Maintenance.ps1` |
| 2.1 | Query for linked servers | **B** |
| 2.2 | Config for remote xp_cmdshell | **C** — RPC and RPC OUT |
| 2.3 | Linked server execution context | **C** — svc_app |
| 2.4 | EXEC AT syntax | See answer above |
| 2.5 | Database on SRV03-APP | `AppData` |
| 3.1 | Required privilege for PrintSpoofer | **C** — SeImpersonatePrivilege |
| 3.2 | Why authenticated SMB | **B** — Win2019 blocks guest SMB |
| 3.3 | Hash needed for next phase | **D** — svc_app |
| 3.4 | svc_app hash | *Extracted during exploitation* |
| 3.5 | PrintSpoofer command | See answer above |
| 4.1 | What KeyCredentialLink write enables | **C** — PKINIT auth |
| 4.2 | PKINIT pre-auth method | **C** — PA-PK-AS-REQ |
| 4.3 | Task ensuring DC KDC cert | **A** — CertAutoEnroll |
| 4.4 | svc_adm hash | *Extracted during exploitation* |
| 4.5 | certipy shadow command | See answer above |
| 5.1 | ESC4 permission | **C** — WriteProperty + WriteDACL |
| 5.2 | SAN flag name | **B** — CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT |
| 5.3 | secretsdump operation | **C** — DCSync |
| 5.4 | CA name | `cyberange-CA` |
| 5.5 | certipy req command | See answer above |

---

## Scoring Guide

| Score | Percentage | Assessment |
|-------|------------|------------|
| 25/25 | 100% | Full Chain Compromised — DOMAIN BREACH |
| 20–24 | 80–96% | Deep Penetration — Minor gaps |
| 15–19 | 60–76% | Partial Compromise — Training recommended |
| 10–14 | 40–56% | Limited Access — Significant gaps |
| < 10 | < 40% | Insufficient — Remedial training required |
