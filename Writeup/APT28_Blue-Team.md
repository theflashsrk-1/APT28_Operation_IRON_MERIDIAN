# Operation IRON MERIDIAN — Blue Team Writeup
## Range 1 (APT28) · Domain: cyberange.local

This writeup is the defender's view of Range 1. It follows the same five-stage chain the red side walks (anonymous SMB foothold, SQL linked-server pivot, SYSTEM on the app server, Shadow Credentials, ADCS ESC4/ESC1, DCSync) and maps each action to the telemetry it leaves, what an analyst actually sees in that telemetry, how to detect it, and how to shut it down. No malware or exploits are involved, so detection lives almost entirely in authentication, directory, and process logs.

Severity scale used throughout: Informational, Low, Medium, High, Critical.

SIEM examples are written in Splunk SPL against Windows event logs ingested via the Splunk Add-on for Windows. Field names (`Account_Name`, `Logon_Type`, `Relative_Target_Name`, and so on) depend on your add-on and sourcetype; adjust to match your environment, or translate the same logic to KQL/Elastic.

## Detection prerequisites

The events below only exist if the matching auditing is on. Confirm these first, because a "clean" log is usually an unmonitored one:

- Advanced audit policy on all servers: Logon/Logoff, Detailed Tracking (process creation, with command line), Object Access (File Share, File System), DS Access (Directory Service Changes), Account Management.
- Process creation auditing (4688) with command-line capture enabled, plus Sysmon on member servers for process and LSASS-access visibility.
- SACL on the `svc_adm` object and on certificate-template objects so directory modifications raise 5136.
- AD CS auditing enabled on the issuing CA (audit filter set to log issuance), so 4886/4887 are generated.
- DCSync detection depends on a SACL on the domain head auditing replication extended rights.

## Stage 1 — Anonymous SMB share enumeration (SRV01-WEB)

Attacker action: null-session listing of 15 shares, then spidering for config files, ending with the buried `svc_db` credential.

Telemetry and what you see:
- Security 5140 (network share accessed) and 5145 (detailed file share access) on SRV01-WEB. 5145 logs the relative path of each file touched, so the attacker's spidering shows up as a dense burst of 5145 events from one source address running through share after share within seconds.
- Security 4624 Logon Type 3 with the account `ANONYMOUS LOGON` confirms the null session.
- Host/network sensors will also show the preceding nmap sweep as a fan-out of short-lived connections, but that alone is low signal.

Severity: Low for the scan, Medium once 5145 shows systematic enumeration of credential-bearing file types (.config, .ps1, .xml, .bak).

Detection: alert on anonymous (Type 3) logons to file servers, and on a single source generating an abnormal volume of 5145 across multiple shares in a short window.

```spl
index=wineventlog host=SRV01-WEB EventCode=5145
| stats dc(Relative_Target_Name) AS files values(Share_Name) AS shares BY Source_Address, Account_Name
| where files > 50
```
```spl
index=wineventlog host=SRV01-WEB EventCode=4624 Logon_Type=3 Account_Name="ANONYMOUS LOGON"
```

Response: pull the source off the network, rotate `svc_db`, and audit all 15 shares for embedded secrets. Disable anonymous/guest share access.

## Stage 2 — SQL linked-server pivot (SRV02-DB to SRV03-APP)

Attacker action: as `svc_db` (sysadmin on SRV02-DB), runs `EXEC ... AT [SRV03-APP]` across a linked server with RPC OUT enabled, executing `xp_cmdshell` on SRV03-APP in the `svc_app` context.

Telemetry and what you see:
- SQL Server itself logs little to Windows by default. The reliable signal is process creation on SRV03-APP: Security 4688 / Sysmon EID 1 showing a parent of `sqlservr.exe` spawning `cmd.exe` or `powershell.exe`. The process owner is the SQL service account `svc_app`.
- With SQL Server audit enabled, you also capture the `xp_cmdshell` invocation and the `sp_configure` change that turned it on.

Severity: High. A database engine spawning a shell is rarely legitimate.

Detection: any child process of `sqlservr.exe` that is a command interpreter or LOLBin. Correlate with `sp_configure 'xp_cmdshell',1` if SQL auditing is present.

```spl
index=wineventlog host=SRV03-APP EventCode=4688 ParentProcessName="*\\sqlservr.exe"
NewProcessName IN ("*\\cmd.exe","*\\powershell.exe")
```

Response: disable `xp_cmdshell`, remove RPC OUT on the linked server (or scope its login), and restrict the SQL service account.

## Stage 3 — PrintSpoofer to SYSTEM, local admin, LSASS dump (SRV03-APP)

Attacker action: abuses `SeImpersonatePrivilege` to get SYSTEM, creates a temporary local admin (`svc_maint`), dumps LSASS for the `svc_app` NT hash, then deletes the account and binary.

Telemetry and what you see:
- 4688 for the escalation binary (named `PrintSpoofer64.exe` here; a renamed copy defeats name matching, so rely on the behavior, not the filename).
- A tight create-then-delete sequence: 4720 (local account created) and 4732 (added to local Administrators), followed minutes later by 4733 (removed from group) and 4726 (account deleted). That short-lived privileged account is the strongest single signal in this stage.
- LSASS access: Sysmon EID 10 (ProcessAccess) with TargetImage `lsass.exe` and a credential-theft access mask (commonly 0x1010 or 0x1410). If a SACL is on the LSASS process, Security 4656/4663 appear instead.

Severity: High, rising to Critical at the LSASS read.

Detection: alert on local admin accounts that are created and deleted within a short window, and on any non-system process opening a handle to LSASS with read access.

```spl
index=wineventlog host=SRV03-APP EventCode IN (4720,4732,4726,4733)
| stats values(EventCode) AS events min(_time) AS first max(_time) AS last BY Target_Account_Name
| where mvcount(events)>=3 AND (last-first)<600
```
```spl
index=sysmon host=SRV03-APP EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1410")
```

Response: enable RunAsPPL and Credential Guard on SRV03-APP, set `WDigest UseLogonCredential=0`, and reduce the privileges held by `svc_app`.

## Stage 4 — Shadow Credentials (svc_app writes svc_adm) on DC01

Attacker action: writes a rogue key credential to `svc_adm`'s `msDS-KeyCredentialLink`, then authenticates as `svc_adm` via Kerberos PKINIT. No password is changed and no failed-logon event is produced.

Telemetry and what you see:
- Security 5136 (directory service object modified) on DC01, target object `svc_adm`, attribute `msDS-KeyCredentialLink`, with the modifying account shown as `svc_app`. A write to this attribute on an account that is not enrolled in Windows Hello for Business is the tell.
- The follow-on authentication is 4768 (Kerberos TGT issued) for `svc_adm` with Pre-Authentication Type 16 and a populated Certificate Issuer/Serial Number, indicating certificate-based (PKINIT) auth rather than a password.

Severity: High. The write itself is the actionable event; PKINIT by a service account is corroborating.

Detection: alert on any 5136 touching `msDS-KeyCredentialLink`, and on 4768 with PreAuthType 16 for accounts that should never use certificate logon.

```spl
index=wineventlog host=DC01 EventCode=5136 LDAP_Display_Name="msDS-KeyCredentialLink"
| table _time Account_Name Object_DN Operation_Type
```
```spl
index=wineventlog host=DC01 EventCode=4768 Pre_Authentication_Type=16
| search Account_Name IN (svc_adm,svc_*)
```

Response: remove `svc_app`'s write access to `svc_adm`, reset `svc_adm`, and strip any rogue key credentials from the attribute.

## Stage 5 — ADCS ESC4 to ESC1 to DCSync (SRV04-CA, DC01)

Attacker action: edits the `CorpAuth` template to re-enable Enrollee-Supplies-Subject (ESC4), requests a certificate with SAN `Administrator@cyberange.local` (ESC1), PKINIT-authenticates as Administrator, and performs DCSync.

Telemetry and what you see:
- Security 5136 / 4662 on the `CorpAuth` certificate-template object on the DC, showing the template attributes being modified (the name-flag change that enables arbitrary subjects).
- On the CA: 4886 (certificate requested) and 4887 (certificate issued). The high-fidelity indicator is a mismatch — the Requester is the attacker's account while the issued SAN/UPN is `Administrator`. Confirmed industry detection logic flags 4886/4887 where the SAN does not match the requester.
- 4768 with PreAuthType 16 for `Administrator`.
- DCSync: Security 4662 on the domain object from a principal that is not a domain controller, with the replication extended rights present — `DS-Replication-Get-Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) and `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`).

Severity: High for the template edit and cert issuance; Critical for DCSync.

Detection: alert on certificate-template attribute changes, on 4886/4887 where requester and subject differ, and on replication requests originating from any host that is not a DC.

```spl
index=wineventlog EventCode IN (4886,4887) Attributes="*SAN:*upn*"
| rex field=Attributes "(?i)upn=(?<san_upn>[^\r\n&]+)"
| rex field=Requester "(.+\\\\)?(?<req_user>[^\r\n]+)"
| where lower(san_upn) != lower(req_user)
```
```spl
index=wineventlog host=DC01 EventCode=4662
Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name IN ("DC01$","DC02$")
```

Response: treat as full domain compromise. Lock down template ACLs, revoke the rogue certificate, rotate all privileged credentials, and reset `krbtgt` twice.

## Root-cause remediation

1. Secrets buried in SMB shares: remove the embedded `svc_db` credentials, rotate the account, and disable anonymous share access.
2. Linked server running as `svc_app` with RPC OUT: disable `xp_cmdshell`, remove RPC OUT, and scope the linked-server login to least privilege.
3. WriteProperty on `svc_adm`'s key-credential attribute: remove the over-broad ACL, which was placed on the wrong object during provisioning.
4. ESC4 on `CorpAuth`: restrict template WriteProperty to PKI administrators, keep Enrollee-Supplies-Subject disabled, and enable strong CA SAN policy.

## Detection coverage summary

| Stage | ATT&CK | Primary log source | Event ID(s) | Severity |
|---|---|---|---|---|
| 1 SMB enumeration | T1083 / T1552.001 | SRV01-WEB Security | 5140, 5145, 4624 (anon) | Low–Medium |
| 2 SQL pivot | T1021 / T1059.003 | SRV03-APP Security / Sysmon | 4688, Sysmon 1 | High |
| 3 SYSTEM + LSASS | T1134 / T1003.001 | SRV03-APP Security / Sysmon | 4688, 4720, 4732, 4726, 4733, Sysmon 10 | High–Critical |
| 4 Shadow Credentials | T1556 / T1558 | DC01 Security | 5136, 4768 (PreAuth 16) | High |
| 5 ESC4/ESC1 + DCSync | T1649 / T1003.006 | CA + DC Security | 5136/4662, 4886, 4887, 4768, 4662 (repl GUID) | High–Critical |
