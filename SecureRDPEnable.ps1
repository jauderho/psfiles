
<#
.SYNOPSIS
   Enable high security for RDP

.DESCRIPTION
   Ensure that RDP is in a high security configuration using TLSv1.2 and NLA

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

# Make sure that WinRM is running
Get-Service -Name winRM | Set-Service -Status Running

function Enable-SecureRDP {
   # Permit RDP to run
   # (Get-CimInstance -class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTSConnections(1,1) | Out-Null
   (Get-WmiObject -class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTSConnections(1,1) | Out-Null

   # Remote Desktop Services: Enable NLA Requirement
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null
   (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null

   # Remote Desktop Services: Require 'High' level of encryption
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").MinEncryptionLevel
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetEncryptionLevel(3) | Out-Null
   (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetEncryptionLevel(3) | Out-Null

   # Remote Desktop Services: Set Security Layer to SSL
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SecurityLayer
   # (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetSecurityLayer(2) | Out-Null
   (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetSecurityLayer(2) | Out-Null

   # Allow RDP connections
   # Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
   Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

   # Workaround for Error Code 0x4. Check Windows TLS config as a possible source of error
   # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxOutstandingConnections"
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxOutstandingConnections" -Type DWord 10000
}

Enable-SecureRDP

Write-Output 'RDP secured...'
