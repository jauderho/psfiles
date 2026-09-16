
<#
.SYNOPSIS
   Enable the post-quantum ML-KEM hybrid key exchange groups

.DESCRIPTION
   Enables the three hybrid ML-KEM supported groups and puts them at the top of
   the Schannel priority list. They are disabled by default on every build that
   has them.

   The groups need a recent build. The script stops rather than write a name
   that Schannel does not know, because an unknown group in the priority list is
   accepted and then ignored, which looks like success and is not.

   These groups work with TLS 1.3 only. Both ends have to offer a common group.
   When the far end has none, the handshake falls back to the classical half of
   the hybrid, so a peer without ML-KEM still connects.

.PARAMETER Elevated
   Internal. Set on the self-elevated relaunch so a failed elevation does not loop.

.PARAMETER DryRun
   Report each change but make none. Use this first.

.PARAMETER Verbose
   Emit step-level progress and the group order before and after. ON by default.
   Turn it off with -Quiet.

.PARAMETER Quiet
   Turn the verbose output off. Use this rather than -Verbose:$false, which
   does not survive the elevation relaunch.

.EXAMPLE
   .\KEMEnable.ps1 -DryRun
   Report every change without making one. Always start here.

.NOTES
   Created by Jauder Ho
   Last modified 9/12/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   MINIMUM BUILDS
   Taken from the Microsoft Learn reference in .LINK, which lists:
     26100.8514  Windows 11 24H2
     26200.8514  Windows 11 25H2
     28000.2173  Windows 11 26H1
   The same page cites build 29550 for Windows Server 2025. That is a vNext
   preview number and does not match Server 2025 shipping as build 26100, so a
   server build is not given its own floor here. The check after the write
   catches a server that took the update later.

   KNOWN ISSUE
   On some builds a WPA2-Enterprise (802.1X) wireless connection fails while
   x25519_mlkem768 is enabled. The fix is:
     Disable-TlsEccCurve -Name x25519_mlkem768

.LINK
   https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-supported-groups-in-windows-11-24h2-and-later
   https://techcommunity.microsoft.com/blog/microsoft-security-blog/new-windows-features-to-secure-today’s-data-in-a-post-quantum-world/4523370
   https://learn.microsoft.com/en-us/powershell/module/tls
   https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls
#>

# Elevate as needed
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
[CmdletBinding()]
param(
  [switch]$Elevated,
  [switch]$DryRun,
  [switch]$Quiet
)

# Verbose is the default here. The group order is the point of the script and
# the per-group detail is worth more than a quiet console. Turn it off with
# -Quiet. An explicit -Verbose:$false still works in a session that is already
# elevated, but only -Quiet survives the relaunch.
if ($Quiet) {
  $VerbosePreference = 'SilentlyContinue'
}
elseif (-not $PSBoundParameters.ContainsKey('Verbose')) {
  $VerbosePreference = 'Continue'
}

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
  else {
    # carry the switches across the elevation boundary
    $relaunchArgs = '-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition)
    if ($DryRun) {
      $relaunchArgs += ' -dryrun'
    }

    # -Quiet rather than -Verbose:$false. powershell -File passes each argument
    # as a literal string, so "$false" never binds to a switch and the elevated
    # copy would fail to start.
    if ($VerbosePreference -ne 'Continue') {
      $relaunchArgs += ' -quiet'
    }

    Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunchArgs
  }

  exit
}

Write-Output 'Running with full privileges...'
if ($DryRun) {
  Write-Output 'Dry run. No change is made.'
}


# ---------------------------------------------------------------------------
# Build requirement
#
# Each major build carries its own revision floor. Below the floor Schannel has
# no ML-KEM group, and Enable-TlsEccCurve will still accept the name and write
# it to the priority list, where it is ignored. That is the failure this gate
# exists to prevent, so it is an error and not a warning.
# ---------------------------------------------------------------------------

$currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osBuild = [int]$currentVersion.CurrentBuildNumber
$osRevision = [int]$currentVersion.UBR
$osName = '{0} {1} (build {2}.{3})' -f $currentVersion.ProductName, $currentVersion.DisplayVersion, $osBuild, $osRevision

Write-Output $osName

# major build -> minimum revision
$script:MinimumRevision = @{
  26100 = 8514   # Windows 11 24H2
  26200 = 8514   # Windows 11 25H2
  28000 = 2173   # Windows 11 26H1
}

# the oldest major build that has ML-KEM at all
$script:OldestSupportedBuild = 26100

if ($osBuild -lt $script:OldestSupportedBuild) {
  Write-Error "The ML-KEM groups need Windows 11 24H2 (build $script:OldestSupportedBuild) or later."
  Write-Error "Found $osName."
  exit 1
}

if ($script:MinimumRevision.ContainsKey($osBuild)) {
  $needed = $script:MinimumRevision[$osBuild]
  if ($osRevision -lt $needed) {
    Write-Error "The ML-KEM groups need build $osBuild.$needed or later. Found $osBuild.$osRevision."
    Write-Error 'Install the latest cumulative update, then run this again.'
    exit 1
  }
  Write-Verbose "Build $osBuild.$osRevision meets the floor of $osBuild.$needed"
}
elseif ($osBuild -gt ($script:MinimumRevision.Keys | Measure-Object -Maximum).Maximum) {
  # newer than every build in the table, so take it on trust and let the check
  # after the write be the real test
  Write-Verbose "Build $osBuild is newer than every entry in the table. No revision floor applied."
}
else {
  Write-Warning "Build $osBuild is not in the table of known builds. Proceeding."
  Write-Warning 'The check after the write will report whether the groups took effect.'
}

foreach ($name in @('Get-TlsEccCurve', 'Enable-TlsEccCurve')) {
  if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
    Write-Error "$name is not available. The TLS module is required."
    exit 1
  }
}


function Enable-KEM {
  # The names are case sensitive to Schannel and are spelled as the Learn
  # reference spells them. x25519_mlkem768 first, which Microsoft recommends for
  # general use. secp384r1_mlkem1024 is the CNSA 2.0 choice.
  $groups = @(
    'x25519_mlkem768'
    'secp256r1_mlkem768'
    'secp384r1_mlkem1024'
  )

  $before = @((Get-TlsEccCurve) -split '\s+' | Where-Object { $_ })
  Write-Verbose "Group order before: $($before -join ', ')"

  # nothing to do when the three already sit at the front in this order
  $actualTop = @($before | Select-Object -First $groups.Count)
  if (-not (Compare-Object -ReferenceObject $groups -DifferenceObject $actualTop -SyncWindow 0)) {
    Write-Output 'The ML-KEM groups are already first. No change needed.'
    return
  }

  for ($i = 0; $i -lt $groups.Count; $i++) {
    $group = $groups[$i]

    if ($DryRun) {
      Write-Output "[dryrun] Placing $group at position $i"
      continue
    }

    try {
      Enable-TlsEccCurve -Name $group -Position $i -ErrorAction Stop
      Write-Verbose "Placed $group at position $i"
    }
    catch {
      Write-Error "Could not enable ${group}: $($_.Exception.Message)"
      return
    }
  }

  if ($DryRun) {
    return
  }

  # Confirm the groups are really in the list. A build without ML-KEM accepts
  # the name and drops it, so the read back is what proves the build gate above
  # was right.
  $after = @((Get-TlsEccCurve) -split '\s+' | Where-Object { $_ })
  Write-Output "Group order now: $($after -join ', ')"

  $missing = @($groups | Where-Object { $_ -notin $after })
  if ($missing.Count -gt 0) {
    Write-Error "These groups did not take effect: $($missing -join ', ')"
    Write-Error 'This build accepted the name and discarded it. Install the latest cumulative update.'
    return
  }

  if (Compare-Object -ReferenceObject $groups -DifferenceObject @($after | Select-Object -First $groups.Count) -SyncWindow 0) {
    Write-Warning 'The ML-KEM groups are present but not first. Check for a Group Policy ECC Curve Order.'
    return
  }

  Write-Output 'KEM has been enabled'
}

Enable-KEM

if ($DryRun) {
  Write-Output 'Dry run finished. Nothing was changed.'
}
else {
  Write-Output 'Restart to apply the Schannel changes.'
}
