
<#
.SYNOPSIS
   Set time and adjust timings for certain items

.DESCRIPTION
   Set the following

   NTP to resync every hour
   Windows Defender to resync every hour

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

function Set-NTPTiming {
   # https://support.microsoft.com/en-us/help/816042/how-to-configure-an-authoritative-time-server-in-windows-server

   # Define the list of NTP servers to be used. Adjust as necessary. Try to use at least 4 servers.
   $ntpservers = "aion.carumba.org,0x9 balrog.carumba.org,0x9 etu.carumba.org,0x9 time.cloudflare.com,0x9 0.pool.ntp.org,0x9 1.pool.ntp.org,0x9 2.pool.ntp.org,0x9"
   #$ntpservers = "balrog.carumba.org,0x1 time.cloudflare.com,0x1 0.pool.ntp.org,0x1 1.pool.ntp.org,0x1 2.pool.ntp.org,0x1 3.pool.ntp.org,0x1"

   $IsVirtual=((Get-CimInstance win32_computersystem).model -eq 'VMware Virtual Platform' -or ((Get-CimInstance win32_computersystem).model -eq 'Virtual Machine'))

   # Force clock resync every hour (3600s)
   # VMware recommends a resync every 15 mins for VMs (900s)
   if ($IsVirtual) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Type DWord -Value 900
   } else {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Type DWord -Value 3600
   }
   # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval"

   # If 0x5 does not work, try using 0xA
   #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Config" -Name "AnnounceFlags" -Type DWord -Value 0x5

   # 0x9 is a combination of 0x1 (Use SpecialPollInterval) and 0x8 (act as client)
   # Currently using time.cloudflare.com. Change this as necessary
   #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters" -Name "Type" -Type String -Value NTP
   #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters" -Name "NtpServer" -Type String -Value "time.cloudflare.com,0x9"
   #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name "0" -Type String -Value "time.cloudflare.com"

   # Set NTP parameters
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters" -Name "Type" -Type String -Value NTP
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters" -Name "NtpServer" -Type String -Value $ntpservers
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name "0" -Type String -Value "time.cloudflare.com"

   # Set the following for high accuracy
   # https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/configuring-systems-for-high-accuracy?tabs=MaxPollInterval#registry-settings
   # https://github.com/MicrosoftDocs/windowsserverdocs/issues/2065
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MinPollInterval" -Type DWord -Value 6
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxPollInterval" -Type DWord -Value 6
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "UpdateInterval" -Type DWord -Value 100
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "FrequencyCorrectRate" -Type DWord -Value 2
   #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Type DWord -Value 64

   # w32tm /config /syncfromflags:manual /manualpeerlist:"balrog.carumba.org,0x9 time.cloudflare.com,0x9 0.pool.ntp.org,0x9 1.pool.ntp.org,0x9 2.pool.ntp.org,0x9 3.pool.ntp.org,0x9" /update
   # w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org,0x9 1.pool.ntp.org,0x9 2.pool.ntp.org,0x9 3.pool.ntp.org,0x9" /update
   # w32tm /config /syncfromflags:manual /manualpeerlist:"time.cloudflare.com,0x9" /update

   # Disable SecureTimeSeeding. See https://arstechnica.com/security/2023/08/windows-feature-that-resets-system-clocks-based-on-random-data-is-wreaking-havoc/
   # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits"
   # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "UtilizeSslTimeData"
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "UtilizeSslTimeData" -Type DWord -Value 0

   # Restart time server to take effect
   Stop-Service w32time
   Start-Service w32time

   Write-Output 'NTP server changes complete...'
}

function Set-MPTiming {
   # Get-MpComputerStatus
   # Get-MpPreference

   # Force hourly Windows Definition updates every day.
   # High frequency updates means that each update is usually fairly small. Also, this is what SwiftOnSecurity recommends.
   # "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -validatemapsconnection
   Set-MpPreference -SignatureScheduleDay 0
   Set-MpPreference -SignatureUpdateInterval 1

   Set-MpPreference -PUAProtection 1

   # This is aggressive
   Set-MpPreference -MAPSReporting Advanced
   Set-MpPreference -SubmitSamplesConsent AlwaysPrompt
   Set-MpPreference -CloudBlockLevel High
   Set-MpPreference -DisableBlockAtFirstSeen $False
   Set-MpPreference -CloudExtendedTimeout 50

   # Adjust as necessary
   Set-MpPreference -DisableRemovableDriveScanning $False
   Set-MpPreference -DisableEmailScanning $False

   Set-MpPreference -EnableNetworkProtection Enabled

   # Reduce attack surface rules
   # https://jacksonvd.com/levelling-up-windows-defender/
   Set-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled

   #Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
   #Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
   #Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled

   # new in 1809
   Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
   Set-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled

   # new in 1903
   Set-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled

   # Get-MpPreference | select Signature*
   Update-MpSignature
}

function Disable-LLMNR {
   # Disable NetBIOS over TCP for all interfaces
   $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
   Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name "NetbiosOptions" -Value 2 }

   # Use the following to verify
   #$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
   #Get-ChildItem $key |
   #foreach {
   #Write-Output("Modify $key\$($_.pschildname)")
   #$NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
   #Write-Output("NetbiosOptions updated value is $NetbiosOptions_Value")
   #}

   If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient | Out-Null
   }

   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWORD -Value 0 -Force
}

Set-NTPTiming
Set-MPTiming

Disable-LLMNR

Write-Output 'Adjustments complete...'
