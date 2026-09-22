
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
.PARAMETER Force
   Skip the PTP capability check and enable PTP anyway.
.PARAMETER DryRun
   Check PTP capability and report what would happen without enabling.
   Common -Verbose switch adds per-adapter detail.

#>

# Elevate as needed
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
[CmdletBinding()] param([switch]$Elevated, [switch]$Force, [switch]$DryRun)

function Test-Admin {
   $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
   $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((-not $DryRun) -and ((Test-Admin) -eq $false)) {
   if ($elevated) {
      # tried to elevate, did not work, aborting
   }
   else {
      $argList = '-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition)
      if ($Force) { $argList += ' -Force' }
      if ($VerbosePreference -ne 'SilentlyContinue') { $argList += ' -Verbose' }
      Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
   }

   exit
}

if ($DryRun) { Write-Output 'Running in dry-run mode, no changes will be made...' } else { Write-Output 'Running with full privileges...' }

function Test-PtpCapable {
   # Keyword presence shows the driver exposes the timestamp switch, not that the silicon timestamps correctly; update the driver first on a miss
   $capable = @()
   try {
      $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -ne 'Disabled' }
   }
   catch {
      return $capable
   }
   Write-Verbose ('Probing {0} adapter(s) for *PtpHardwareTimestamp / *SoftwareTimestamp.' -f @($adapters).Count)
   foreach ($adapter in $adapters) {
      Write-Verbose ('Checking {0} ({1}, {2}).' -f $adapter.Name, $adapter.InterfaceDescription, $adapter.Status)
      foreach ($keyword in '*PtpHardwareTimestamp', '*SoftwareTimestamp') {
         if ($null -ne (Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $keyword -ErrorAction SilentlyContinue)) {
            Write-Verbose ('{0} reports {1}.' -f $adapter.Name, $keyword)
            $capable += $adapter
            break
         }
      }
   }
   return $capable
}

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

if ($Force) {
   Write-Output '-Force specified, skipping PTP capability check.'
}
else {
   Write-Verbose ('-Force: {0}, -DryRun: {1}.' -f $Force, $DryRun)
   $capable = @(Test-PtpCapable | Where-Object { $null -ne $_ })
   if ($capable.Count -eq 0) {
      $intelFound = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Intel' }).Count -gt 0
      if ($intelFound) {
         Write-Error 'No PTP-capable interfaces found. Intel NIC detected but it does not report *PtpHardwareTimestamp; update the driver and retry, or rerun with -Force to override.'
      }
      else {
         Write-Error 'No PTP-capable interfaces found. PTP needs a NIC reporting *PtpHardwareTimestamp (typically Intel I210/I211/I350/X550/X710/E810) or *SoftwareTimestamp; rerun with -Force to override.'
      }
      exit 1
   }
   Write-Output ('PTP-capable interface(s): {0}' -f (($capable | ForEach-Object { $_.Name }) -join ', '))
}
if ($DryRun) {
   if ($Force) { Write-Output 'Dry run: PTP would be enabled (capability check skipped).' }
   else { Write-Output 'Dry run: capability check passed, PTP was not enabled.' }
}
else {
   Enable-PTP
}
