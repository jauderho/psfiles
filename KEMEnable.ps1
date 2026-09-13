
<#
.SYNOPSIS
   Enable KEM 

.DESCRIPTION
   Enable KEM

.NOTES
   Created by Jauder Ho
   Last modified 9/1/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://techcommunity.microsoft.com/blog/microsoft-security-blog/new-windows-features-to-secure-today’s-data-in-a-post-quantum-world/4523370
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

function Enable-KEM {
  # Enable X25519 ML-KEM hybrid at the very top of the priority list
  Enable-TlsEccCurve -Name 'x25519_mlkem768' -Position 0

  # Enable the two NIST-based ML-KEM hybrids right after it
  Enable-TlsEccCurve -Name 'secp256r1_mlkem768' -Position 1
  Enable-TlsEccCurve -Name 'secp384r1_mlkem1024' -Position 2

  # Confirm the resulting priority order
  Get-TlsEccCurve

  Write-Output 'KEM has been enabled'
}

Enable-KEM
