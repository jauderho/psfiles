
<#
.SYNOPSIS
   Enable RSS on VMware VMs

.DESCRIPTION
   Enabling RSS will enable multiple CPUs to send/process network traffic

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

function Enable-VMwareRSS {
   # https://virtualnomadblog.com/2018/04/04/vmware-tools-10-2-5/
   # https://kb.vmware.com/s/article/2008925
   Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "vmxnet3*" } | Get-NetAdapterAdvancedProperty | Where-Object { $_.RegistryKeyword -like "*RSS" -or $_.RegistryKeyword -like "RxThrottle" } | Format-Table -AutoSize

   Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "vmxnet3*" } | Set-NetAdapterAdvancedProperty -DisplayName "Receive Side Scaling" -DisplayValue "Enabled" -NoRestart
   Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "vmxnet3*" } | Set-NetAdapterAdvancedProperty -DisplayName "Receive Throttle" -DisplayValue "30" -NoRestart

   Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "vmxnet3*" } | Get-NetAdapterAdvancedProperty | Where-Object { $_.RegistryKeyword -like "*RSS" -or $_.RegistryKeyword -like "RxThrottle" } | Format-Table -AutoSize

   # Get-NetAdapter | Get-NetAdapterAdvancedProperty | Where-Object { $_.RegistryKeyword -like "*RSS" -or $_.RegistryKeyword -like "RxThrottle" } | Format-Table -AutoSize
}

Enable-VMwareRSS