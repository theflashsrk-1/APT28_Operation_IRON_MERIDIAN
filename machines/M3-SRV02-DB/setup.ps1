# M3: SRV02-DB — MSSQL Primary Database + Linked Server
# Default instance (MSSQLSERVER), svc_db as sysadmin, linked server to SRV03-APP
if ($env:COMPUTERNAME -ne "SRV02-DB") { Rename-Computer -NewName "SRV02-DB" -Force; Restart-Computer -Force; exit }

# Install SQL Server (silent — requires installer at C:\SQLSetup\)
# C:\SQLSetup\setup.exe /Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=MSSQLSERVER /SQLSVCACCOUNT="CYBERANGE\svc_db" /SQLSVCPASSWORD="Db@ccess2025!" /SQLSYSADMINACCOUNTS="CYBERANGE\Domain Admins" "CYBERANGE\svc_db" /SECURITYMODE=SQL /SAPWD="SaP@ss2025!" /TCPENABLED=1 /NPENABLED=1

Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue

# Enable xp_cmdshell
Invoke-Sqlcmd -ServerInstance "SRV02-DB" -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# Create CorpApp database with test data
Invoke-Sqlcmd -ServerInstance "SRV02-DB" -Query @"
CREATE DATABASE CorpApp;
GO
USE CorpApp;
CREATE TABLE Employees (ID INT PRIMARY KEY IDENTITY, FirstName NVARCHAR(50), LastName NVARCHAR(50), SSN NVARCHAR(11), Salary DECIMAL(10,2), Department NVARCHAR(50));
INSERT INTO Employees VALUES ('John','Smith','123-45-6789',85000,'Engineering'),('Mary','Jones','234-56-7890',92000,'Finance'),('Ana','Garcia','345-67-8901',78000,'Marketing'),('Bob','Wilson','456-78-9012',105000,'Engineering'),('Chris','Lee','567-89-0123',88000,'Operations'),('David','Khan','678-90-1234',76000,'HR'),('Emily','Nguyen','789-01-2345',95000,'Legal'),('Fatima','Patel','890-12-3456',82000,'Finance'),('George','Martin','901-23-4567',91000,'Engineering'),('Helen','Brown','012-34-5678',87000,'Operations');
GO
"@

# Create linked server to SRV03-APP
Invoke-Sqlcmd -ServerInstance "SRV02-DB" -Query @"
EXEC sp_addlinkedserver @server='SRV03-APP', @srvproduct='', @provider='SQLNCLI', @datasrc='SRV03-APP.cyberange.local';
EXEC sp_addlinkedsrvlogin @rmtsrvname='SRV03-APP', @useself='FALSE', @rmtuser='svc_app', @rmtpassword='App`$3rv1ce!2025';
EXEC sp_serveroption @server='SRV03-APP', @optname='rpc', @optvalue='TRUE';
EXEC sp_serveroption @server='SRV03-APP', @optname='rpc out', @optvalue='TRUE';
GO
"@

# Firewall
New-NetFirewallRule -DisplayName "Allow MSSQL" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

Write-Host "[+] SRV02-DB setup complete. Linked server to SRV03-APP configured." -ForegroundColor Green
