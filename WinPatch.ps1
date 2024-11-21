
<#
.SYNOPSIS
   Patch Windows using PowerShell

.DESCRIPTION
   Set the following

   Use this if Windows Update is not working
   Also update Windows Defender

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

function WinPatch {
   # Check the version of Windows currently running
   #$osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
   #$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
   $osVersion = [System.Environment]::OSVersion.VersionString
   Write-Host "Current OS Version: $osVersion"

   # Check if the PSWindowsUpdate module is installed
   $module = Get-Module -ListAvailable -Name PSWindowsUpdate
   if ($module -eq $null) {
      # Install the PSWindowsUpdate module
      Install-Module -Name PSWindowsUpdate -Force
   }
   else {
      Update-Module -Name PSWindowsUpdate -Force
   }

   # Get the list of available updates
   $updates = Get-WindowsUpdate

   # Display the latest KB
   if ($updates.Count -gt 0) {
      $latestKB = $updates[0].KB
      Write-Host "Latest KB: $latestKB"
   }
   else {
      Write-Host "No updates available."
   }

   # Download and install the latest patch
   Get-WindowsUpdate -AcceptAll -Download

   # Get confirmation to proceed with the installation
   $confirmation = Read-Host "Do you want to proceed with the installation? (y/n)"
   if ($confirmation -eq 'y') {
      # Install the updates
      Install-WindowsUpdate -AcceptAll -Install
   }
   else {
      Write-Host "Installation cancelled by user."
   }

   Write-Output 'Patching complete...'
}

WinPatch
Update-MpSignature

Write-Output 'Adjustments complete...'
