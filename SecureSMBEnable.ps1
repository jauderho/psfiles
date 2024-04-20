
<#
.SYNOPSIS
   Enable secure SMB configuration

.DESCRIPTION
   WARNING: Test before deployment

   Disable SMBv1
   Set and require SMB signing
   Require SMB server encryption
   Disallow guest logons

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://www.carumba.com
#>

# Elevate as needed
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
param([switch]$Elevated)

function Test-Admin {
   $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
   $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false) {
   if ($elevated) {
      # tried to elevate, did not work, aborting
   }
   else {
      Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
   }

   exit
}

Write-Output 'Running with full privileges...'

function Enable-SecureSMBClient {
   Set-SmbServerConfiguration -Force -AuditSmb1Access $true
   # Get-WinEvent -LogName Microsoft-Windows-SMBServer/Audit
   # Get-SmbSession | Select Dialect,ClientComputerName,ClientUserName | Where-Object {$_.Dialect -lt 2.00}

   Disable-WindowsOptionalFeature -Online -FeatureName smb1Protocol -NoRestart

   Set-SmbClientConfiguration -Force -EnableSecuritySignature $true
   Set-SmbClientConfiguration -Force -RequireSecuritySignature $true

   # do not attempt to access insecure file shares
   Set-SmbClientConfiguration -Force -EnableInsecureGuestLogons $false
}

function Enable-SecureSMBServer {
   # Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol
   Set-SmbServerConfiguration -Force -EnableSMB1Protocol $false
   # Set-SmbServerConfiguration -Force -EnableSMB2Protocol $false
   # on Server products only
   # Remove-WindowsFeature FS-SMB1

   Set-SmbServerConfiguration -Force -EnableSecuritySignature $true
   Set-SmbServerConfiguration -Force -RequireSecuritySignature $true
   Set-SmbServerConfiguration -Force -EncryptData $true
}

Enable-SecureSMBClient
Enable-SecureSMBServer

Write-Output 'SMB secured...'