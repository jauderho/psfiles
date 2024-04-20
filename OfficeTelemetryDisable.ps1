
<#
.SYNOPSIS
   Disable Office Telemetry

.DESCRIPTION
   This disables most/all known telemetry for Office 2013, 2016 and 2019.
   2019 has not been tested at this time.

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

function Disable-OfficeTelemetry {
   # Office 2016 Telemetry
   # https://social.technet.microsoft.com/Forums/en-US/f98e0256-2f8f-40f2-8b6c-7463a4187995/performance-issue-caused-by-office-telemetry?forum=Office2016ITPro
   # https://docs.microsoft.com/en-us/DeployOffice/compat/manage-the-privacy-of-data-monitored-by-telemetry-in-office#Disable%20data%20collection%20for%20the%20telemetry%20agent
   # Keep the following directories empty
   # 	%AppData%\..\Local\Microsoft\Office\OTele
   # 	%AppData%\..\Local\Microsoft\Office\16.0\Telemetry
   #
   # May need to set DisableTelemetry DWord to 00027100 instead of 1

   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload"
   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging"
   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableFileObfuscation"

   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload"
   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging"
   Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableFileObfuscation"

   Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry"
   Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging"

   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWord 0
   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type DWord 0
   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableFileObfuscation" -Type DWord 1

   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWord 0
   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type DWord 0
   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableFileObfuscation" -Type DWord 1

   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord 1
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Type DWord 0

   New-Item "HKCU:\Software\Policies\Microsoft\office\common\clienttelemetry" -Force
   Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\office\common\clienttelemetry" -Name "DisableTelemetry" -Type DWord 1
}

Disable-OfficeTelemetry