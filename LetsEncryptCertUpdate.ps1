
<#
.SYNOPSIS
   Import certificate for use with RDP

.DESCRIPTION
   Import certificate for use with RDP

.PARAMETER Elevated
   Internal. Set on the self-elevated relaunch so a failed elevation does not loop.

.PARAMETER Verbose
   Emit step-level progress and key variable state. Silent by default.
   Standard PowerShell switch, so -v is accepted as an unambiguous prefix.

.EXAMPLE
   .\LetsEncryptCertUpdate.ps1
   .\LetsEncryptCertUpdate.ps1 -Verbose

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019

   BSD License

   Pull requests are welcome.

   Designed for unattended use: the script never prompts. It exits non-zero on any
   failure and leaves the PFX in place unless the certificate is confirmed installed.

   config.json lives beside this script and defines:
     srcDir               - directory holding <FQDN>.pfx
     domain               - DNS domain appended to the computer name
     pfxPasswordEncrypted - optional, only for a password protected PFX. DPAPI
                            encrypted string, see the import section below.

   TODO: Incorporate ACMESharp capability

.LINK
   https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement
#>

# Elevate as needed
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
[CmdletBinding()]
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false) {
    if ($elevated) {
        # tried to elevate, did not work, aborting
        Write-Error 'Failed to elevate. Administrator rights are required.'
        exit 1
    }

    # carry -verbose across the elevation boundary
    $relaunchArgs = '-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition)
    if ($VerbosePreference -eq 'Continue') {
        $relaunchArgs += ' -verbose'
    }

    Write-Verbose "Relaunching elevated: powershell.exe $relaunchArgs"
    Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunchArgs

    exit
}

Write-Output 'Running with full privileges...'
Write-Verbose "Running as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:computername"

# Make sure that WinRM is running
Get-Service -Name winRM | Set-Service -Status Running

# https://jrich523.wordpress.com/2011/07/01/powershell-working-with-strings/
#
# USE THIS
#
# POSH script to import PFX cert for use with RDP (in this case a Let's Encrypt cert)
# Once this is done, RDP will no longer complain about the hostname when connecting.
# Creation and renewal of cert is left as an exercise for the user. ACMESharp could potentially be used
# as part of an overall solution.
#
# Create a config.json file in the same directory and define values for "srcDir" and "domain"
#

# Get the path of the config file
#$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'

# import the configuration from the JSON file
#$config = Get-Content -Path $configPath | ConvertFrom-Json
#$config = Get-Content -Path '.\config.json' | ConvertFrom-Json

# check if the config.json file exists in the script directory
$configPath = Join-Path -Path $PSScriptRoot -ChildPath "config.json"
if (-not (Test-Path -LiteralPath $configPath)) {
    Write-Error "config.json file not found in the script directory."
    exit 1
}

# read the config.json file
Write-Verbose "Reading configuration from $configPath"
try {
    $config = Get-Content -Path $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "config.json could not be parsed: $($_.Exception.Message)"
    exit 1
}

# define where the certificate is located. Make sure to include trailing \ in path
$srcdir = $config.srcDir
$nic = $config.domain

# without both values the FQDN and the PFX path are meaningless
if ([string]::IsNullOrWhiteSpace($srcdir) -or [string]::IsNullOrWhiteSpace($nic)) {
    Write-Error 'config.json must define non-empty "srcDir" and "domain" values.'
    exit 1
}

Write-Verbose "srcDir: $srcdir, domain: $nic"

# there does not seem to be a good way to get the FQDN. start by figuring out the associated DNS domain
#$nic = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property DNSDomain
#$nic = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property DNSDomain
#
# this works. more testing needed
# [System.Net.Dns]::GetHostByAddress([System.Net.Dns]::GetHostByName($env:computerName).AddressList[0]).HostName

# FQDN assemble! Also, trim any extraneous space
#$fqdn = $fqdn + "." + $nic.DNSDomain
$fqdn = ($env:computername + "." + "$nic".Trim()).Trim()
#$fqdn =  [System.Net.Dns]::GetHostByAddress([System.Net.Dns]::GetHostByName($env:computerName).AddressList[0]).HostName

# full path to PFX file. PFX filename should be <FQDN>.pfx
$pfxfile = Join-Path -Path $srcdir -ChildPath "$fqdn.pfx"

Write-Verbose "FQDN: $fqdn, expecting PFX at $pfxfile"

# nothing to renew if the PFX was never dropped off
if (-not (Test-Path -LiteralPath $pfxfile)) {
    Write-Output "No certificate found at $pfxfile. Nothing to do."
    exit 0
}

# -Password is always supplied so a password protected PFX fails instead of prompting an
# unattended run. An empty secure string is the password of a PFX exported without one.
#
# For a password protected PFX, add "pfxPasswordEncrypted" to config.json. Generate the
# value on THIS machine, signed in as the account that runs the script (a scheduled task
# running as SYSTEM needs a string generated as SYSTEM), then paste the output into
# config.json:
#   (Read-Host -AsSecureString -Prompt 'PFX password') | ConvertFrom-SecureString
# DPAPI ties the string to that account and machine, so it is useless to anyone who reads
# config.json elsewhere. Omit the key for a passwordless PFX.
if ([string]::IsNullOrWhiteSpace($config.pfxPasswordEncrypted)) {
    Write-Verbose 'No pfxPasswordEncrypted in config.json. Importing with an empty password'
    $pfxPassword = New-Object System.Security.SecureString
}
else {
    Write-Verbose 'Decrypting pfxPasswordEncrypted from config.json'
    try {
        $pfxPassword = ConvertTo-SecureString -String $config.pfxPasswordEncrypted -ErrorAction Stop
    }
    catch {
        Write-Error "pfxPasswordEncrypted could not be decrypted. Regenerate it as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) on ${env:computername}: $($_.Exception.Message)"
        exit 1
    }
}

# import and obtain the thumbprint from the PFX file
Write-Verbose "Importing $pfxfile into cert:\LocalMachine\my"
try {
    $thumbprint = (Import-PfxCertificate -CertStoreLocation cert:\LocalMachine\my -FilePath $pfxfile -Password $pfxPassword -ErrorAction Stop).Thumbprint
}
catch {
    Write-Error "Failed to import ${pfxfile}: $($_.Exception.Message)"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($thumbprint)) {
    Write-Error "Import of $pfxfile returned no thumbprint. RDP configuration left unchanged."
    exit 1
}

# configure RDP to use the right cert
#$path = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
#Set-WmiInstance -Path $path -argument @{SSLCertificateSHA1Hash="$thumbprint"}

# configure RDP to use the right cert
# https://serverfault.com/questions/1025992/cant-write-to-root-cimv2-terminalservices-via-powershell
Write-Verbose "Imported $thumbprint. Assigning it to the RDP-tcp listener"
try {
    $RDPInstance = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
    Write-Verbose "RDP-tcp currently uses thumbprint '$($RDPInstance.SSLCertificateSHA1Hash)'"
    Set-CimInstance -CimInstance $RDPInstance -Property @{SSLCertificateSHA1Hash = "$thumbprint" } -ErrorAction Stop
}
catch {
    Write-Error "Failed to assign certificate $thumbprint to RDP: $($_.Exception.Message)"
    exit 1
}

# read back the listener before discarding the only copy of the PFX
$applied = (Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash
if ($applied -ne $thumbprint) {
    Write-Error "RDP reports thumbprint '$applied' instead of '$thumbprint'. Keeping $pfxfile."
    exit 1
}

Write-Verbose "RDP-tcp verified on $applied"

# cleanup on aisle 9. PFX file is no longer needed once imported
Write-Verbose "Removing $pfxfile"
Remove-Item -LiteralPath $pfxfile

# remove expired/old certs matching hostname
foreach ($store in @("cert:\LocalMachine\my", "cert:\LocalMachine\Remote Desktop")) {
    if (-not (Test-Path -LiteralPath $store)) {
        Write-Verbose "Store $store does not exist. Skipping"
        continue
    }

    # keep the cert just installed even if it is already past its notAfter date
    $expired = @(Get-ChildItem -Path $store -SSLServerAuthentication -ExpiringInDays 0 -DnsName "${env:computername}.*" |
            Where-Object { $_.Thumbprint -ne $thumbprint })

    Write-Verbose "$store has $($expired.Count) expired certificate(s) to remove"
    foreach ($cert in $expired) {
        Write-Verbose "Removing $($cert.Thumbprint) (subject $($cert.Subject), expired $($cert.NotAfter))"
        $cert | Remove-Item
    }
}

Write-Output "Certificate $thumbprint has been installed for $fqdn"

# check cert
# Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
