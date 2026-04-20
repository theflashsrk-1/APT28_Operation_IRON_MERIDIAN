# M4: SRV03-APP — MSSQL Application Server (Linked Server Target + PrivEsc)
# Runs as svc_app (SeImpersonatePrivilege), xp_cmdshell enabled
if ($env:COMPUTERNAME -ne "SRV03-APP") { Rename-Computer -NewName "SRV03-APP" -Force; Restart-Computer -Force; exit }

# Install SQL Server (silent — default instance as svc_app)
# C:\SQLSetup\setup.exe /Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=MSSQLSERVER /SQLSVCACCOUNT="CYBERANGE\svc_app" /SQLSVCPASSWORD="App$3rv1ce!2025" /SQLSYSADMINACCOUNTS="CYBERANGE\Domain Admins" "CYBERANGE\svc_app" /SECURITYMODE=SQL /SAPWD="SaApp2025!" /TCPENABLED=1 /NPENABLED=1

Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue

# Enable xp_cmdshell
Invoke-Sqlcmd -ServerInstance "SRV03-APP" -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# Create AppData database
Invoke-Sqlcmd -ServerInstance "SRV03-APP" -Query "CREATE DATABASE AppData;" -ErrorAction SilentlyContinue

# Create svc_app SQL login as sysadmin
Invoke-Sqlcmd -ServerInstance "SRV03-APP" -Query @"
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'svc_app')
    CREATE LOGIN svc_app WITH PASSWORD = 'App`$3rv1ce!2025';
EXEC sp_addsrvrolemember 'svc_app', 'sysadmin';
GO
"@

# Enable WinRM
Enable-PSRemoting -Force -ErrorAction SilentlyContinue

# LocalAccountTokenFilterPolicy (allows remote admin with local accounts)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWORD -Force

# Firewall
New-NetFirewallRule -DisplayName "Allow MSSQL" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow

# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

Write-Host "[+] SRV03-APP setup complete. svc_app runs SQL with SeImpersonatePrivilege." -ForegroundColor Green
