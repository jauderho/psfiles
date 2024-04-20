
<#
.SYNOPSIS
   Enable TLSv1.2 including for .NET and browser

.DESCRIPTION
   Enable TLSv1.2 including for .NET and browser

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement
   https://jorgequestforknowledge.wordpress.com/category/windows-azure-active-directory/azure-ad-application-proxy-connector/
   https://support.microsoft.com/en-us/help/3135244/tls-1.2-support-for-microsoft-sql-server
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

function Enable-TLSv1.2 {
  # Enable TLSv1.2
  If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null

  If (!(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null

  Write-Output 'TLS 1.2 has been enabled'
}

function Enable-TLSv1.2-dotNET {
  # Force TLSv1.2 only for .NET
  If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

  If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

  If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

  If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
  }
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

  Write-Output 'TLS 1.2 has been enabled for .NET'
}

function Enable-TLSv1.2-Browser {
  # http://www.keithtwombley.com/set-internet-options-via-the-registry/
  # Set IE to 0x800 to only use TLS 1.2, set to 0xA80 to enable 1.0, 1.1 and 1.2, 0x880 for 1.0 and 1.2 only

  # Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols"
  # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS"
  # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"

  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -Value '0x800'
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'Enabled' -value '1'
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'Enabled' -value '0'

  # Set minimum DH to 2048
  # https://technet.microsoft.com/library/security/3174644
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Type DWord -Value '0x00000800'

  Write-Output 'TLS 1.2 has been enabled for browser'
}

Enable-TLSv1.2
Enable-TLSv1.2-dotNET
Enable-TLSv1.2-Browser