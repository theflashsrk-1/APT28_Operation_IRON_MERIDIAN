# M1: DC01 — Domain Controller Initial Setup
# Run as LOCAL Administrator BEFORE domain promotion
# After reboot, run setup-post.ps1 as CYBERANGE\Administrator
$ErrorActionPreference = "Stop"
if ($env:COMPUTERNAME -ne "DC01") {
    Rename-Computer -NewName "DC01" -Force; Restart-Computer -Force; exit
}
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
$sp = ConvertTo-SecureString "LabSafeMode123!" -AsPlainText -Force
Install-ADDSForest -DomainName "cyberange.local" -DomainNetbiosName "CYBERANGE" `
    -ForestMode "WinThreshold" -DomainMode "WinThreshold" -InstallDns:$true `
    -SafeModeAdministratorPassword $sp -NoRebootOnCompletion:$false -Force:$true
