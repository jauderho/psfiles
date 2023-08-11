
<#
.SYNOPSIS
   Import certificate for use with RDP

.DESCRIPTION
   Import certificate for use with RDP

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019

   BSD License

   Pull requests are welcome.

   TODO: Incorporate ACMESharp capability

.LINK
   https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement
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

# Make sure that WinRM is running
Get-Service -Name winRM | Set-Service -Status Running

# https://jrich523.wordpress.com/2011/07/01/powershell-working-with-strings/
#
# USE THIS
#
# POSH script to import PFX cert for use with RDP (in this case a Let's Encrypt cert)
# Once this is done, RDP will no longer complain about the hostname when connecting
# Creation and renewal of cert is left as an exercise for the user. ACMESharp could potentially be used
# as part of an overall solution
#
# define where the certificate is located. Make sure to include trailing \ in path
$srcdir = ""
$nic = ""

# there does not seem to be a good way to get the FQDN. start by figuring out the associated DNS domain
#$nic = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property DNSDomain
#$nic = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property DNSDomain

# FQDN assemble! Also, trim any extraneous space
#$fqdn = $fqdn + "." + $nic.DNSDomain
$fqdn = $env:computername + "." + $nic
$fqdn = $fqdn.trim()

# full path to PFX file. PFX filename should be <FQDN>.pfx
$pfxfile = $fqdn + ".pfx"
$pfxfile = join-path $srcdir $pfxfile

# run if PFX exists
if (Test-Path $pfxfile) {

	# import and obtain the thumbprint from the PFX file
	$thumbprint = (Import-PfxCertificate -CertStoreLocation cert:\LocalMachine\my -FilePath $pfxfile).thumbprint

	# configure RDP to use the right cert
	#$path = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
	#Set-WmiInstance -Path $path -argument @{SSLCertificateSHA1Hash="$thumbprint"}

   # configure RDP to use the right cert
   # https://serverfault.com/questions/1025992/cant-write-to-root-cimv2-terminalservices-via-powershell
   $RDPInstance = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices
   Set-CimInstance -CimInstance $RDPInstance -Property @{SSLCertificateSHA1Hash="$thumbprint"} -PassThru

	# cleanup on aisle 9. PFX file is no longer needed once imported
	Remove-Item $pfxfile

	# remove expired/old certs matching hostname
	Get-ChildItem -Path "cert:\LocalMachine\my" -SSLServerAuthentication -ExpiringInDays 0 -DnsName *$env:computername* | Remove-Item
	Get-ChildItem -Path "cert:\LocalMachine\Remote Desktop" -SSLServerAuthentication -ExpiringInDays 0 -DnsName *$env:computername* | Remove-Item
}

Write-Output 'Certificate has been updated'

# check cert
# Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
