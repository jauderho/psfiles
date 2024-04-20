
<#
.SYNOPSIS
   Set the ArchiveIgnoreLastModifiedTime for Outlook

.DESCRIPTION
   Set the ArchiveIgnoreLastModifiedTime for Outlook

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

function Set-IgnoreModifiedDate {
   # Tell Outlook to ignore the modified date for archive purposes
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences" -Name "ArchiveIgnoreLastModifiedTime" -Type DWord 1
}

Set-Ignore-ModifiedDate

Write-Output 'Updated registry...'