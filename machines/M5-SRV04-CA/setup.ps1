# M5: SRV04-CA — AD Certificate Services (ESC4 → ESC1 Target)
# Enterprise CA with CorpAuth template, svc_adm has WriteDACL+WriteProperty
if ($env:COMPUTERNAME -ne "SRV04-CA") { Rename-Computer -NewName "SRV04-CA" -Force; Restart-Computer -Force; exit }

# Install ADCS + Web Enrollment
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Server -IncludeManagementTools

# Configure Enterprise CA
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 -HashAlgorithmName SHA256 `
    -CACommonName "cyberange-CA" -Force

Install-AdcsWebEnrollment -Force

# --- Create CorpAuth Certificate Template ---
# Duplicate the User template via AD
Import-Module ActiveDirectory
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get the User template as base
$userTemplate = Get-ADObject -SearchBase $templateContainer -Filter "Name -eq 'User'" -Properties *

# Create CorpAuth template
$newDN = "CN=CorpAuth,$templateContainer"
$templateOID = "1.3.6.1.4.1.311.21.8.$(Get-Random).$(Get-Random).$(Get-Random).$(Get-Random).$(Get-Random).$(Get-Random)"

New-ADObject -Name "CorpAuth" -Type "pKICertificateTemplate" -Path $templateContainer -OtherAttributes @{
    'displayName' = "CorpAuth"
    'pKIExtendedKeyUsage' = @("1.3.6.1.5.5.7.3.2")  # Client Authentication
    'pKIDefaultKeySpec' = 1
    'pKIMaxIssuingDepth' = 0
    'msPKI-Certificate-Name-Flag' = 0  # SAN DISABLED initially (attacker enables via ESC4→ESC1)
    'msPKI-Enrollment-Flag' = 0
    'msPKI-Private-Key-Flag' = 16842752
    'msPKI-Cert-Template-OID' = $templateOID
    'msPKI-Minimal-Key-Size' = 2048
    'msPKI-Template-Schema-Version' = 2
    'msPKI-Template-Minor-Revision' = 0
    'msPKI-RA-Signature' = 0
    'revision' = 100
    'flags' = 131680
} -ErrorAction SilentlyContinue

# --- Set ACLs on CorpAuth template ---
$tmplDN = "CN=CorpAuth,$templateContainer"
$tmplAcl = Get-Acl "AD:\$tmplDN"

# CertManagers: Enroll
$certMgrsSID = (Get-ADGroup -Identity "CertManagers").SID
$enrollGuid = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
$enrollAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $certMgrsSID, "ExtendedRight", "Allow", $enrollGuid, "None"
)
$tmplAcl.AddAccessRule($enrollAce)

# svc_adm: WriteProperty + WriteDACL + WriteOwner (ESC4)
$svcAdmSID = (Get-ADUser -Identity "svc_adm").SID
$writeAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcAdmSID, "WriteProperty", "Allow"
)
$writeDaclAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcAdmSID, "WriteDacl", "Allow"
)
$writeOwnerAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcAdmSID, "WriteOwner", "Allow"
)
$tmplAcl.AddAccessRule($writeAce)
$tmplAcl.AddAccessRule($writeDaclAce)
$tmplAcl.AddAccessRule($writeOwnerAce)

Set-Acl "AD:\$tmplDN" $tmplAcl

# Publish template on CA
certutil -setcatemplates +CorpAuth

# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA policy
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc

# --- Auditing ---
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# --- Disable Defender ---
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False

Write-Host "[+] SRV04-CA setup complete. cyberange-CA with CorpAuth template (ESC4)." -ForegroundColor Green
Write-Host "[+] svc_adm has WriteProperty+WriteDACL on CorpAuth template." -ForegroundColor Green
