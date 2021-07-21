
<#
.SYNOPSIS
   Disable Firefox Telemetry

.DESCRIPTION
   This disables most/all known telemetry for Firefox.

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

function Disable-FirefoxTelemetry {
   # https://www.bleepingcomputer.com/news/software/firefox-now-tells-mozilla-what-your-default-browser-is-every-day/

   #Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent"

   If (!(Test-Path 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox')) {
      New-Item 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox' -Force | Out-Null
   }
   Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWord 1
}

Disable-FirefoxTelemetry