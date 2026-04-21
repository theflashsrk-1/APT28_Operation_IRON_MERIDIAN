# GitHub Push — APT28 — Operation IRON MERIDIAN

## Initial Setup

```bash
git init APT28
cd APT28
cp -r /path/to/extracted/* .
git add .
git commit -m "APT28 - Operation IRON MERIDIAN - Initial Release"
git remote add origin https://github.com/hacktifytechnologies/APT28.git
git branch -M main
git push -u origin main
```

## File Structure

```
APT28/
├── README.md
├── STORYLINE.md
├── NETWORK_DIAGRAM.md
├── AssessmentQuestions.md
├── GITHUB_PUSH.md
├── machines/
│   ├── M1-DC01/
│   │   ├── setup.ps1            # Domain promotion
│   │   └── setup-post.ps1       # AD structure + Shadow Creds ACL + CertEnroll
│   ├── M2-SRV01-WEB/
│   │   └── setup.ps1            # IIS + 15 SMB shares + decoy/real creds
│   ├── M3-SRV02-DB/
│   │   └── setup.ps1            # MSSQL default instance + linked server
│   ├── M4-SRV03-APP/
│   │   └── setup.ps1            # MSSQL as svc_app + xp_cmdshell
│   └── M5-SRV04-CA/
│       └── setup.ps1            # ADCS Enterprise CA + CorpAuth template
└── ttps/
    ├── TTP1-smb-share-maze.sh
    ├── TTP2-sql-linked-server.sh
    ├── TTP3-printspoofer-privesc.sh
    ├── TTP4-shadow-credentials.sh
    └── TTP5-adcs-esc4-esc1.sh
```
