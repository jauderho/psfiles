
<#
.SYNOPSIS
   Enable TLSv1.3 including for .NET and browser

.DESCRIPTION
   Enable TLSv1.3 including for .NET and browser

   WARNING: This is still experimental and has a high chance of breaking things

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement
   https://jorgequestforknowledge.wordpress.com/category/windows-azure-active-directory/azure-ad-application-proxy-connector/
   https://support.microsoft.com/en-us/help/3135244/tls-1.3-support-for-microsoft-sql-server
   https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12
   https://msdn.microsoft.com/en-us/library/aa374757(VS.85).aspx
   https://blogs.technet.microsoft.com/askpfeplat/2017/11/13/demystifying-schannel/
   https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi
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

function Enable-TLSv1.3 {
  # Enable TLSv1.3
  If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null

  If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null

  Write-Output 'TLS 1.3 has been enabled.'
}

Enable-TLSv1.3
