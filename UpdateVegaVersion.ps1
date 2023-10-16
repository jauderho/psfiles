
<#
.SYNOPSIS
   Set the correct AMD driver version for the Hades Canyon NUCs

.DESCRIPTION
   Set the correct AMD driver version manually for the Hades Canyon NUCs.

   AMD stopped providing proper driver updates after 10.4.1 for Hades Canyon systems. This enables the use of the latest AMD software after manually installing the Radeon RX Vega 64 driver.

   Steps to take:
   * Download the latest driver from http://www.amd.com/us-en/drivers/
   * Install the driver (driver install will error out)
   * Start Device Manager
   * Select "Update Driver" for RX Vega 64
   * Navigate to the C:\AMD folder
   * For example: C:\AMD\AMD-Software-Adrenalin-Edition-22.4.1-Win10-Win11-April5\Packages\Drivers\Display\WT6A_INF\
   * Select the desired version (file starting with U or C, ignore the complaint about mismatch)
   * Complete install
   * Run this script
   * Radeon Software dashboard will now work

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2020
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

function Update-VegaVersion {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact="Low"
    )]

    # For tips on how to manually upgrade AMD driver for Hades Canyon
    # See https://community.amd.com/message/2994618

    # Get the current version from the driver. Use Device Manager > Display Adapter > Properties > Driver
    #
    # Get-WmiObject Win32_PnPSignedDriver| select DeviceName, Manufacturer, DriverVersion | where {$_.DeviceName -like "*Vega*"} | select DriverVersion
    # Get-WindowsDriver -Online -All | select ProviderName, Driver, OriginalFileName, Version | where {$_.ProviderName -like "*Advanced Micro Devices*"}
    # Get-WindowsDriver -Online -All | select ProviderName, Driver, OriginalFileName, Version | where {$_.Driver -like "*oem52.inf*"}
    #
    #$vegadriver = Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, Manufacturer, DriverVersion | Where-Object {$_.DeviceName -like "*Vega*"} | Select-Object DriverVersion
    $vegadriver = Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, Manufacturer, DriverVersion | Where-Object {$_.DeviceName -like "*Vega*"} | Select-Object DriverVersion
    $vegaversion = $vegadriver.DriverVersion | Select-Object -First 1
    #$version = "26.20.15029.20013"

    # Set the version
    # Get-ItemProperty -Path "HKLM:\SOFTWARE\AMD\CN" -Name "DriverVersion"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\AMD\CN" -Name "DriverVersion" -Type String -Value $vegaversion -Confirm:$false
    Write-Output "Version set to" $vegaversion
}

Update-VegaVersion -Confirm:$false

Write-Output 'Adjustments complete...'
