
<#
.SYNOPSIS
   Allow Win11 upgrades on unsupported systems

.DESCRIPTION
   Allow Win11 upgrades on unsupported systems

.NOTES
   Created by Jauder Ho
   Last modified 2/1/2023
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

function Enable-Win11Upgrade {
  If (!(Test-Path 'HKLM:\SYSTEM\Setup\MoSetup')) {
    New-Item 'HKLM:\SYSTEM\Setup\MoSetup' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\Setup\MoSetup' -name 'AllowUpgradesWithUnsupportedTPMOrCPU' -value '1' -PropertyType 'DWord' -Force | Out-Null
}

Enable-Win11Upgrade
