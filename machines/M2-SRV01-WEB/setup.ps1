# M2: SRV01-WEB — IIS File Server + SMB Share Maze
# 15 shares, 11 anonymous, 40+ config files, 2 real cred locations
if ($env:COMPUTERNAME -ne "SRV01-WEB") { Rename-Computer -NewName "SRV01-WEB" -Force; Restart-Computer -Force; exit }
$ErrorActionPreference = "SilentlyContinue"

Install-WindowsFeature Web-Server -IncludeManagementTools

# --- Create share directories ---
$shareRoot = "C:\Shares"
$shares = @("Public`$","HR-Docs","IT-Support","Marketing","Dev-Staging","WebApps","Projects","Ops-Scripts","Training","Backup-Logs","App-Configs","Finance-Reports","Legal-Templates","Executive","Network-Configs")
foreach ($s in $shares) { New-Item -Path "$shareRoot\$($s.TrimEnd('$'))" -ItemType Directory -Force }

# --- Anonymous shares (11) ---
$anonShares = @("Public`$","HR-Docs","IT-Support","Marketing","Dev-Staging","WebApps","Projects","Ops-Scripts","Training","Backup-Logs","App-Configs")
foreach ($s in $anonShares) {
    $path = "$shareRoot\$($s.TrimEnd('$'))"
    New-SmbShare -Name $s -Path $path -FullAccess "Everyone" -ErrorAction SilentlyContinue
}

# --- Authenticated shares (4) ---
$authShares = @("Finance-Reports","Legal-Templates","Executive","Network-Configs")
foreach ($s in $authShares) {
    New-SmbShare -Name $s -Path "$shareRoot\$s" -FullAccess "CYBERANGE\Domain Users" -ErrorAction SilentlyContinue
}

# --- Enable anonymous null session access ---
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 0 -Type DWORD
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 1 -Type DWORD
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0 -Type DWORD
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value $anonShares -Type MultiString

# --- REAL CREDENTIALS (2 locations only) ---

# Location 1: WebApps deep buried web.config
$realPath1 = "$shareRoot\WebApps\archive\2024-Q3\corpapp.bak"
New-Item -Path $realPath1 -ItemType Directory -Force
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="CorpAppDB" connectionString="Server=SRV02-DB.cyberange.local;Database=CorpApp;User ID=svc_db;Password=Db@ccess2025!;Trusted_Connection=False;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="Environment" value="Production" />
    <add key="LogLevel" value="Warning" />
  </appSettings>
</configuration>
"@ | Out-File "$realPath1\web.config" -Encoding UTF8

# Location 2: Ops-Scripts maintenance script
New-Item -Path "$shareRoot\Ops-Scripts\Database" -ItemType Directory -Force
@"
# Weekly_DB_Maintenance.ps1 — Database maintenance (runs Sunday 02:00)
`$SqlServer = "SRV02-DB.cyberange.local"
`$SqlUser = "svc_db"
`$SqlPassword = "Db@ccess2025!"
`$Database = "CorpApp"

Import-Module SQLPS -DisableNameChecking
Invoke-Sqlcmd -ServerInstance `$SqlServer -Username `$SqlUser -Password `$SqlPassword -Database `$Database -Query "DBCC CHECKDB WITH NO_INFOMSGS"
Write-Host "Maintenance complete: $(Get-Date)"
"@ | Out-File "$shareRoot\Ops-Scripts\Database\Weekly_DB_Maintenance.ps1" -Encoding UTF8

# --- DECOY CREDENTIALS (many, across shares) ---
$decoys = @(
    @{Path="HR-Docs\Onboarding"; File="sync_config.xml"; Content="<config><username>hr_sync</username><password>HR@Connect2025</password><server>HR-INTERNAL</server></config>"},
    @{Path="IT-Support\Configs"; File="helpdesk_db.conf"; Content="[database]`nhost = HELPDESK-DB`nuser = it_helpdesk`npassword = Support!2025`nport = 3306"},
    @{Path="Dev-Staging\configs"; File=".env.staging"; Content="DB_HOST=STAGING-DB`nDB_USER=dev_deploy`nDB_PASS=D3ploy!2025`nDB_NAME=staging_app"},
    @{Path="App-Configs\Production"; File="appsettings.json"; Content='{"ConnectionStrings":{"Default":"Server=APP-INTERNAL;Database=ProdApp;User=svc_webapp;Password=W3b@pp2025"}}'},
    @{Path="Marketing\Campaigns"; File="email_api.conf"; Content="[smtp]`nserver = mail.internal`nuser = mktg_sender`npassword = M@rketing2025`nport = 587"},
    @{Path="Training\IT-Certs"; File="lab_access.txt"; Content="Lab Portal: https://lab.internal`nUser: training_admin`nPass: Tr@in2025!`nExpires: 2025-12-31"},
    @{Path="Backup-Logs\Scripts"; File="backup_creds.ini"; Content="[backup]`nserver = BACKUP-SRV`nuser = bkp_agent`npassword = B@ckup#2025`nretention_days = 30"},
    @{Path="Projects\Infrastructure\Configs"; File="monitoring.yaml"; Content="prometheus:`n  auth:`n    user: prom_admin`n    password: Pr0m3theus!2025`n  targets:`n    - MONITOR-SRV:9090"},
    @{Path="IT-Support\RemoteAccess"; File="vpn_config.ovpn"; Content="# VPN Config`n# auth: vpn_svc / VPN@ccess2025`nremote vpn.internal 1194`nproto udp"},
    @{Path="Public"; File="wifi_setup.txt"; Content="Corporate WiFi Setup`nSSID: CorpNet-5G`nPassword: W1r3l3ss2025!`nContact: IT Helpdesk x4500"},
    @{Path="WebApps\current\configs"; File="db.config"; Content='<database host="WEB-DB" user="web_readonly" password="R3@dOnly2025" database="WebContent" />'},
    @{Path="WebApps\archive\2024-Q1"; File="old_settings.ini"; Content="[app]`ndb_host=OLD-DB`ndb_user=legacy_app`ndb_pass=L3g@cy2025"},
    @{Path="WebApps\archive\2024-Q2"; File="migration_notes.txt"; Content="Migration Notes:`nOld DB: legacy_app / L3g@cy2024`nNew DB: app_v2 / M1gr@te2025"},
    @{Path="Network-Configs\Switches"; File="switch_creds.conf"; Content="[management]`nuser = netadmin`npassword = Sw1tch#2025`nenable_secret = 3n@ble2025"}
)

foreach ($d in $decoys) {
    $dir = "$shareRoot\$($d.Path)"
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    $d.Content | Out-File "$dir\$($d.File)" -Encoding UTF8
}

# Add some filler files for realism
$fillerDirs = @("HR-Docs\Policies","Marketing\Branding","Projects\Roadmap","Training\Compliance","Legal-Templates\Contracts")
foreach ($fd in $fillerDirs) {
    New-Item -Path "$shareRoot\$fd" -ItemType Directory -Force | Out-Null
    "This document is for internal use only. Contact your department lead for access." | Out-File "$shareRoot\$fd\README.txt" -Encoding UTF8
}

# --- Auditing ---
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# --- Disable Defender ---
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False

Write-Host "[+] SRV01-WEB setup complete. 15 shares, 40+ files." -ForegroundColor Green
