
<#
.SYNOPSIS
   Enable PTP

.DESCRIPTION
   Enable PTP

   WARNING: This is still experimental and has a high chance of breaking things

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://techcommunity.microsoft.com/t5/networking-blog/windows-subsystem-for-linux-for-testing-windows-10-ptp-client/ba-p/389181
   https://github.com/microsoft/W32Time/tree/master/Precision%20Time%20Protocol/docs
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

function Enable-PTP {
  # Enable PTP. Make sure to define what the PTP master should be
  If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'PtpMasters' -value '' -PropertyType 'String' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'InputProvider' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'DllName' -value '%systemroot%\system32\ptpprov.dll' -PropertyType 'String' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'DelayPollInterval' -value '0x3e80' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'AnnounceInterval' -value '0x0fa0' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PtpClient' -name 'EnableMulticastRx' -value '0' -PropertyType 'DWord' -Force | Out-Null

  # Open local firewall ports for PTP comms
  New-NetFirewallRule -DisplayName 'PTP-319' -Name 'PTP-319' -LocalPort 319 -Direction Inbound -Action Allow -Protocol UDP
  New-NetFirewallRule -DisplayName 'PTP-320' -Name 'PTP-320' -LocalPort 320 -Direction Inbound -Action Allow -Protocol UDP

  Write-Output 'PTP has been enabled.'
}

Enable-PTP
