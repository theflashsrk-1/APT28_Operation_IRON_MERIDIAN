# Network Diagram — APT28 — Operation IRON MERIDIAN

```
                    [Attacker — Kali Linux]
                             │
                    [lab-net  DHCP]
                             │
     ┌───────────────────────┼───────────────────────────────────┐
     │                       │         cyberange.local           │
     │          Single Flat Network (lab-net)                    │
     │          DC01 provides DNS for name resolution            │
     │                       │                                   │
     │  ┌────────────────────┴────────────────────────┐          │
     │  │  M1: DC01                                   │          │
     │  │  Windows Server 2019                        │          │
     │  │  AD DS + DNS                                │          │
     │  │  Ports: 53, 88, 135, 389, 445, 636, 5985   │          │
     │  │  Shadow Creds ACL: svc_app → svc_adm        │          │
     │  │  CertEnroll task (auto-enrolls KDC cert)    │          │
     │  └─────────────────────────────────────────────┘          │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │  M2: SRV01-WEB                           │             │
     │  │  IIS File Server                         │             │
     │  │  15 SMB Shares (11 anonymous, 4 auth)    │             │
     │  │  40+ config files (38 decoy, 2 real)     │             │
     │  │  Port 445 — SMB                          │             │
     │  │  Port 80 — IIS                           │             │
     │  │  CREDENTIAL DISCOVERY                    │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │  M3: SRV02-DB                            │             │
     │  │  MSSQL Default Instance (MSSQLSERVER)    │             │
     │  │  Service: CYBERANGE\svc_db (sysadmin)     │             │
     │  │  Linked Server → SRV03-APP (RPC OUT on)  │             │
     │  │  xp_cmdshell enabled                     │             │
     │  │  Port 1433 — SQL                         │             │
     │  │  SQL PIVOT                               │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │  M4: SRV03-APP                           │             │
     │  │  MSSQL Default Instance (MSSQLSERVER)    │             │
     │  │  Service: CYBERANGE\svc_app               │             │
     │  │  SeImpersonatePrivilege on svc_app       │             │
     │  │  LocalAccountTokenFilterPolicy = 1       │             │
     │  │  Port 1433, 445, 5985                    │             │
     │  │  PRIVILEGE ESCALATION                    │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │  M5: SRV04-CA                            │             │
     │  │  AD Certificate Services                 │             │
     │  │  CA Name: cyberange-CA                   │             │
     │  │  CorpAuth template (ESC4 → ESC1)         │             │
     │  │  svc_adm: WriteDACL + WriteProperty      │             │
     │  │  CertManagers: Enroll                    │             │
     │  │  Port 80, 135, 445                       │             │
     │  │  CERTIFICATE ABUSE                       │             │
     │  └──────────────────────────────────────────┘             │
     └───────────────────────────────────────────────────────────┘
```

## Attack Path Overlay

```
     ┌─────────────┐
     │  ATTACKER    │
     │  (Kali)      │
     └──────┬───────┘
            │
            │ 1. Anonymous SMB enumeration
            │    → svc_db:Db@ccess2025!
            ▼
     ┌─────────────┐         ┌─────────────┐
     │  SRV01-WEB  │         │  SRV02-DB   │
     │  (M2)       │────────→│  (M3)       │
     │  SMB shares │ 2. SQL  │  Linked Srv │
     └─────────────┘  Login  └──────┬──────┘
                                    │
                                    │ 3. Linked Server xp_cmdshell
                                    ▼
                             ┌─────────────┐
                             │  SRV03-APP  │
                             │  (M4)       │
                             │  PrintSpoofer│
                             │  → svc_app  │
                             └──────┬──────┘
                                    │
                                    │ 4. Shadow Credentials (svc_app → svc_adm)
                                    ▼
                             ┌─────────────┐
                             │    DC01     │
                             │   (M1)      │
                             │  PKINIT    │
                             └──────┬──────┘
                                    │
                                    │ 5. ESC4→ESC1 (cert as Admin → DCSync)
                                    ▼
                             ┌─────────────┐
                             │  SRV04-CA   │
                             │   (M5)      │
                             │  GAME OVER  │
                             └─────────────┘
```

## Port Matrix

| Source | Target | Port | Protocol | Purpose |
|--------|--------|------|----------|---------|
| Attacker | SRV01-WEB | 445 | SMB | Share enumeration + file download |
| Attacker | SRV02-DB | 1433 | MSSQL | SQL login as svc_db |
| SRV02-DB | SRV03-APP | 1433 | MSSQL | Linked server xp_cmdshell |
| SRV03-APP | Attacker | 445 | SMB | PrintSpoofer upload (impacket-smbserver) |
| Attacker | SRV03-APP | 445 | SMB | LSASS dump via nxc |
| Attacker | DC01 | 88 | Kerberos | Shadow Credentials PKINIT |
| Attacker | SRV04-CA | 445 | SMB | certipy-ad template + req |
| Attacker | DC01 | 88 | Kerberos | Administrator PKINIT |
| Attacker | DC01 | 445 | SMB | DCSync (secretsdump) |

## Discovery (No Static IPs)

```bash
# Find DC (port 88)
nmap -p 88 --open <SUBNET>.0/24

# Set DNS to DC
echo "nameserver <DC_IP>" > /etc/resolv.conf

# Resolve all machines
dig SRV01-WEB.cyberange.local
dig SRV02-DB.cyberange.local
dig SRV03-APP.cyberange.local
dig SRV04-CA.cyberange.local
```
