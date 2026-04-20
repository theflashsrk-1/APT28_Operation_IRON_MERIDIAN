# M1: DC01 — Post-Promotion (run after reboot as CYBERANGE\Administrator)
Import-Module ActiveDirectory
$ErrorActionPreference = "SilentlyContinue"

# --- OUs ---
"CorpServers","CorpUsers","ServiceAccounts" | ForEach-Object {
    New-ADOrganizationalUnit -Name $_ -Path "DC=cyberange,DC=local"
}

# --- Service Accounts ---
New-ADUser -Name "svc_db" -SamAccountName "svc_db" -UserPrincipalName "svc_db@cyberange.local" `
    -Path "OU=ServiceAccounts,DC=cyberange,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Db@ccess2025!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true

New-ADUser -Name "svc_app" -SamAccountName "svc_app" -UserPrincipalName "svc_app@cyberange.local" `
    -Path "OU=ServiceAccounts,DC=cyberange,DC=local" `
    -AccountPassword (ConvertTo-SecureString "App$3rv1ce!2025" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true

New-ADUser -Name "svc_adm" -SamAccountName "svc_adm" -UserPrincipalName "svc_adm@cyberange.local" `
    -Path "OU=ServiceAccounts,DC=cyberange,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Adm!n$vc#2025" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true

# --- CertManagers Group ---
New-ADGroup -Name "CertManagers" -GroupCategory Security -GroupScope Global `
    -Path "OU=ServiceAccounts,DC=cyberange,DC=local"
Add-ADGroupMember -Identity "CertManagers" -Members "svc_adm"

# --- Regular Users ---
@("jparker","slee","mchen","awright","rsingh","lmartinez","dwilliams","kpatel","tnguyen","egarcia") | ForEach-Object {
    New-ADUser -Name $_ -SamAccountName $_ -UserPrincipalName "$_@cyberange.local" `
        -Path "OU=CorpUsers,DC=cyberange,DC=local" `
        -AccountPassword (ConvertTo-SecureString "Welcome#2025!" -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
}

# --- Password Policy (no lockout) ---
Set-ADDefaultDomainPasswordPolicy -Identity "cyberange.local" -LockoutThreshold 0 -MinPasswordLength 8

# --- Shadow Credentials ACL: svc_app WriteProperty on svc_adm msDS-KeyCredentialLink ---
$svcAdmDN = (Get-ADUser -Identity "svc_adm").DistinguishedName
$svcAppSID = (Get-ADUser -Identity "svc_app").SID
$acl = Get-Acl "AD:\$svcAdmDN"
$keyCredGuid = [GUID]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcAppSID, "WriteProperty", "Allow", $keyCredGuid, "None"
)
$acl.AddAccessRule($ace)
Set-Acl "AD:\$svcAdmDN" $acl
Write-Host "[+] svc_app has WriteProperty on svc_adm msDS-KeyCredentialLink" -ForegroundColor Green

# --- SPNs ---
Set-ADUser -Identity "svc_db" -ServicePrincipalNames @{Add="MSSQLSvc/SRV02-DB.cyberange.local:1433"}
Set-ADUser -Identity "svc_app" -ServicePrincipalNames @{Add="MSSQLSvc/SRV03-APP.cyberange.local:1433"}

# --- Audit Policies ---
@("Kerberos Authentication Service","Kerberos Service Ticket Operations","Logon",
  "Directory Service Changes","Directory Service Access","Certification Services",
  "Sensitive Privilege Use","Computer Account Management") | ForEach-Object {
    auditpol /set /subcategory:"$_" /success:enable /failure:enable 2>$null
}

# --- CertEnroll Task (retries until KDC cert obtained from CA) ---
mkdir C:\LabBootstrap -Force | Out-Null
@"
for (`$i = 0; `$i -lt 60; `$i++) {
    certutil -pulse 2>&1 | Out-Null
    `$kdc = Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.2.3.5" }
    if (`$kdc) { "$(Get-Date) KDC cert OK" | Out-File C:\LabBootstrap\certenroll.log -Append; exit 0 }
    Start-Sleep 120
}
"@ | Out-File "C:\LabBootstrap\CertEnroll.ps1" -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\LabBootstrap\CertEnroll.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "CertAutoEnroll" -Action $action -Trigger $trigger -Principal $principal -Force

# --- Disable Defender + Firewall ---
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

Write-Host "[+] DC01 post-promotion setup complete." -ForegroundColor Green
