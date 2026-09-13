
<#
.SYNOPSIS
   Enable TLSv1.3 including for .NET and browser

.DESCRIPTION
   Enable TLSv1.3 including for .NET and browser, then move the TLS 1.3 cipher
   suites to the top of the Schannel priority list so they are offered first.

   WARNING: This is still experimental and has a high chance of breaking things

.PARAMETER Elevated
   Internal. Set on the self-elevated relaunch so a failed elevation does not loop.

.PARAMETER DryRun
   Report each change but make none. Use this first.

.PARAMETER Verbose
   Emit step-level progress and the cipher order before and after. ON by
   default. Turn it off with -Verbose:$false.

.EXAMPLE
   .\TLSv1.3Enable.ps1 -DryRun
   Report every change without making one. Always start here.

.EXAMPLE
   .\TLSv1.3Enable.ps1 -Verbose:$false
   Apply the changes quietly.

.NOTES
   Created by Jauder Ho
   Last modified 9/12/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   The protocol version is negotiated before the cipher suite, so a peer that
   supports TLS 1.3 gets TLS 1.3 whatever the order says. The order decides
   which suite is chosen inside a version, and it sets the order of the list in
   the ClientHello, which a server that honours client preference reads.

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
[CmdletBinding()]
param(
  [switch]$Elevated,
  [switch]$DryRun
)

# Verbose is the default here. The cipher order is the point of the script and
# the per-suite detail is worth more than a quiet console. Turn it off with
# -Verbose:$false, which the test below leaves alone because the caller named it.
if (-not $PSBoundParameters.ContainsKey('Verbose')) {
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
    # state it either way. The relaunched copy would otherwise apply its own
    # default and undo an explicit -Verbose:$false.
    if ($VerbosePreference -eq 'Continue') {
      $relaunchArgs += ' -verbose'
    }
    else {
      $relaunchArgs += ' -verbose:$false'
    }

    Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunchArgs
  }

  exit
}

Write-Output 'Running with full privileges...'
if ($DryRun) {
  Write-Output 'Dry run. No change is made.'
}

# Schannel gained TLS 1.3 in build 20348, which is Server 2022 and Windows 11.
# Below that the registry values below are accepted and then ignored.
$osBuild = [int](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$script:Tls13MinimumBuild = 20348

Write-Verbose "Build $osBuild"
if ($osBuild -lt $script:Tls13MinimumBuild) {
  Write-Warning "Schannel has no TLS 1.3 before build $script:Tls13MinimumBuild. Found $osBuild."
  Write-Warning 'The protocol keys will be written and ignored, and no cipher suite can be ordered.'
}

# the Group Policy cipher suite order. A value here replaces the local list.
$script:GpoSslPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'

# every TLS 1.3 suite name, used to strip old entries before they are re-added
$script:AllTls13Names = @(
  'TLS_AES_256_GCM_SHA384'
  'TLS_AES_128_GCM_SHA256'
  'TLS_CHACHA20_POLY1305_SHA256'
)

# the documented maximum for the SSL Cipher Suite Order policy field
$script:GpoFunctionsMaxLength = 1023

function Set-Tls13GpoOrder {
  <#
  .SYNOPSIS
     Put the TLS 1.3 suites first in the Group Policy cipher suite order.

  .DESCRIPTION
     The policy value is a single REG_SZ of comma separated names, and it
     replaces the operating system list rather than adding to it. A policy list
     without a TLS 1.3 suite therefore turns TLS 1.3 off, whatever the protocol
     keys say.

     The existing list is read, edited and written back. It is never rebuilt
     from scratch, because that would drop whatever else the policy carries.
  #>
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Existing,
    [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Suites
  )

  Write-Output 'A cipher suite order is set by Group Policy. Editing that list.'
  Write-Verbose "Policy key: $script:GpoSslPath"

  $list = @($Existing -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  Write-Verbose "Policy list holds $($list.Count) suite(s), $($Existing.Length) chars"

  # only the suites this build can actually use, in the preferred order
  $wanted = @($Suites.Keys | Where-Object { $osBuild -ge $Suites[$_] })
  $tooOld = @($Suites.Keys | Where-Object { $osBuild -lt $Suites[$_] })
  if ($tooOld.Count -gt 0) {
    Write-Output "Not available on build ${osBuild}: $($tooOld -join ', ')"
  }
  if ($wanted.Count -eq 0) {
    Write-Warning 'No TLS 1.3 cipher suite is available on this build. Leaving the policy alone.'
    return
  }

  $already = @($list | Where-Object { $_ -in $script:AllTls13Names })
  if ($already.Count -eq 0) {
    Write-Warning 'The policy list has no TLS 1.3 suite in it, so TLS 1.3 cannot be negotiated'
    Write-Warning 'at present, whatever the protocol keys say. Adding the suites now.'
  }

  # strip every TLS 1.3 name wherever it sits, then put them back on the front
  $others = @($list | Where-Object { $_ -notin $script:AllTls13Names })
  $new = @($wanted) + $others

  # a sanity check on the edit itself. Losing a non TLS 1.3 suite here would
  # silently weaken or break what the policy was set up to allow.
  if ($others.Count -ne ($list.Count - $already.Count)) {
    Write-Error 'The edit would change the non TLS 1.3 entries. Leaving the policy alone.'
    return
  }

  $newValue = $new -join ','

  if ($newValue -eq $Existing) {
    Write-Output 'The policy already lists the TLS 1.3 suites first. No change needed.'
    return
  }

  if ($newValue.Length -gt $script:GpoFunctionsMaxLength) {
    Write-Warning "The new list is $($newValue.Length) chars. The documented limit is $script:GpoFunctionsMaxLength."
    Write-Warning 'The Group Policy editor will not accept a value this long, and Schannel may'
    Write-Warning 'drop the tail. The TLS 1.3 suites are at the front, so they survive a trim.'
  }

  Write-Verbose "New policy list: $newValue"

  if ($DryRun) {
    Write-Output "[dryrun] Would set the policy list to $($new.Count) suites, TLS 1.3 first:"
    Write-Output "[dryrun]   $($wanted -join ', ') then $($others.Count) existing suite(s)"
    return
  }

  # keep a copy of the key before it is edited
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $backupDir = Join-Path -Path $env:ProgramData -ChildPath 'TLSv13Enable\Backup'
  $backupFile = Join-Path -Path $backupDir -ChildPath "SSL-00010002-$stamp.reg"
  try {
    New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    & reg.exe export 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' $backupFile /y 2>&1 | Out-Null
    Write-Output "Policy key backed up to $backupFile"
  }
  catch {
    Write-Error "Could not back up the policy key: $($_.Exception.Message)"
    Write-Error 'Leaving the policy alone.'
    return
  }

  try {
    New-ItemProperty -Path $script:GpoSslPath -Name 'Functions' -Value $newValue -PropertyType 'String' -Force -ErrorAction Stop | Out-Null
  }
  catch {
    Write-Error "Could not write the policy value: $($_.Exception.Message)"
    return
  }

  $readBack = (Get-ItemProperty -Path $script:GpoSslPath -Name 'Functions' -ErrorAction SilentlyContinue).Functions
  if ($readBack -ne $newValue) {
    Write-Warning 'The policy value did not read back as written.'
    return
  }

  Write-Output "Policy list updated. TLS 1.3 first: $($wanted -join ', ')"

  # A local policy owns this value through Registry.pol and puts it back at the
  # next refresh, so the registry edit above is temporary on its own.
  $machinePol = Join-Path -Path $env:SystemRoot -ChildPath 'System32\GroupPolicy\Machine\Registry.pol'
  if (Test-Path -LiteralPath $machinePol) {
    Write-Warning 'Local Group Policy is in use on this machine:'
    Write-Warning "  $machinePol"
    Write-Warning 'It will restore the old list at the next policy refresh or restart.'
    Write-Warning 'To make this permanent, open gpedit.msc and set:'
    Write-Warning '  Computer Configuration > Administrative Templates > Network >'
    Write-Warning '  SSL Configuration Settings > SSL Cipher Suite Order'
    Write-Warning 'Paste the list printed below into that field.'
    Write-Output ''
    Write-Output $newValue
    Write-Output ''
  }

  if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    Write-Warning 'This machine is domain joined. A domain policy that sets the same value'
    Write-Warning 'will overwrite this edit at the next refresh. Change it in the domain GPO.'
  }
}

function Set-TLSv13CipherPriority {
  <#
  .SYNOPSIS
     Move the TLS 1.3 cipher suites to the top of the Schannel priority list.
  #>

  # The order Windows itself prefers, with the build each suite arrived in.
  # Each suite is inserted at position 0, so the list is walked backwards and
  # the first entry here ends up on top.
  #
  # CHACHA20 is present on Windows 11 and on Server 2022, but Server 2022
  # leaves it off by default.
  $tls13Suites = [ordered]@{
    'TLS_AES_256_GCM_SHA384'       = 20348
    'TLS_AES_128_GCM_SHA256'       = 20348
    'TLS_CHACHA20_POLY1305_SHA256' = 22000
  }

  foreach ($name in @('Get-TlsCipherSuite', 'Enable-TlsCipherSuite')) {
    if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
      Write-Warning "$name is not available, so the cipher order cannot be changed."
      return
    }
  }

  if ($osBuild -lt $script:Tls13MinimumBuild) {
    Write-Warning 'This build has no TLS 1.3 cipher suite to order.'
    return
  }

  # A cipher suite order set by policy replaces the local list outright, so the
  # policy list is the one that has to change. Enable-TlsCipherSuite writes the
  # local list, which nothing would read while the policy is in place.
  $gpoFunctions = (Get-ItemProperty -Path $script:GpoSslPath -Name 'Functions' -ErrorAction SilentlyContinue).Functions
  if ($gpoFunctions) {
    Set-Tls13GpoOrder -Existing $gpoFunctions -Suites $tls13Suites
    return
  }

  $current = @(Get-TlsCipherSuite | Select-Object -ExpandProperty Name)
  if ($current.Count -eq 0) {
    Write-Warning 'Get-TlsCipherSuite returned nothing. Not ordering a list that cannot be read.'
    return
  }
  Write-Verbose "Cipher order before: $(($current | Select-Object -First 6) -join ', ')"

  # Sort the three into what is already usable, what the build should have but
  # does not currently offer, and what this build cannot have at all. Only the
  # first two groups are touched. Enable-TlsCipherSuite is never called for a
  # suite the build does not know, which would otherwise write a name Schannel
  # ignores and report a change that did not happen.
  $usable = @()
  $missing = @()
  $tooOld = @()

  foreach ($suite in $tls13Suites.Keys) {
    if ($current -contains $suite) {
      Write-Verbose "$suite is present and can be ordered"
      $usable += $suite
    }
    elseif ($osBuild -ge $tls13Suites[$suite]) {
      Write-Verbose "$suite is supported by build $osBuild but is not in the list"
      $missing += $suite
    }
    else {
      Write-Verbose "$suite needs build $($tls13Suites[$suite]). This is $osBuild."
      $tooOld += $suite
    }
  }

  if ($tooOld.Count -gt 0) {
    Write-Output "Not available on build ${osBuild}: $($tooOld -join ', ')"
  }
  if ($missing.Count -gt 0) {
    Write-Output "Supported but currently switched off: $($missing -join ', ')"
  }

  # the suites to place, in the preferred order, that this build can actually use
  $wanted = @($tls13Suites.Keys | Where-Object { $_ -in $usable -or $_ -in $missing })
  if ($wanted.Count -eq 0) {
    Write-Warning 'No TLS 1.3 cipher suite is available on this build. Nothing to order.'
    return
  }

  $actualTop = @($current | Select-Object -First $wanted.Count)
  if ($missing.Count -eq 0 -and
    -not (Compare-Object -ReferenceObject $wanted -DifferenceObject $actualTop -SyncWindow 0)) {
    Write-Output 'The TLS 1.3 cipher suites are already first. No change needed.'
    return
  }

  # walk backwards, because each insert goes to position 0
  for ($i = $wanted.Count - 1; $i -ge 0; $i--) {
    $suite = $wanted[$i]

    if ($DryRun) {
      $verb = if ($suite -in $missing) { 'Switching on and placing' } else { 'Placing' }
      Write-Output "[dryrun] $verb $suite at the top of the list"
      continue
    }

    try {
      Enable-TlsCipherSuite -Name $suite -Position 0 -ErrorAction Stop
    }
    catch {
      Write-Warning "Could not place ${suite}: $($_.Exception.Message)"
      continue
    }

    # confirm it landed rather than trust the call
    $check = @(Get-TlsCipherSuite | Select-Object -ExpandProperty Name)
    if ($check[0] -ne $suite) {
      Write-Warning "$suite did not move to the top. The list starts with $($check[0])."
    }
    else {
      Write-Verbose "Placed $suite at the top"
    }
  }

  if ($DryRun) {
    return
  }

  $after = @(Get-TlsCipherSuite | Select-Object -ExpandProperty Name)
  Write-Output "Cipher order now: $(($after | Select-Object -First 6) -join ', ')"

  # a reinsert of an existing suite should move it, not copy it
  $duplicates = @($after | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name)
  if ($duplicates.Count -gt 0) {
    Write-Warning "The list has duplicate entries: $($duplicates -join ', ')"
  }

  $afterTop = @($after | Select-Object -First $wanted.Count)
  if (Compare-Object -ReferenceObject $wanted -DifferenceObject $afterTop -SyncWindow 0) {
    Write-Warning 'The TLS 1.3 suites are still not first. Check for a policy or a third party agent.'
  }
  else {
    Write-Output 'TLS 1.3 cipher suites are now negotiated first.'
  }
}

function Enable-TLSv1.3 {
  $protocols = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3'

  foreach ($role in @('Server', 'Client')) {
    $path = Join-Path -Path $protocols -ChildPath $role

    if ($DryRun) {
      Write-Output "[dryrun] Enabling TLS 1.3 for the $role role at $path"
      continue
    }

    If (!(Test-Path $path)) {
      New-Item $path -Force | Out-Null
    }
    New-ItemProperty -path $path -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path $path -name 'DisabledByDefault' -value '0' -PropertyType 'DWord' -Force | Out-Null
    Write-Verbose "Enabled TLS 1.3 for the $role role"
  }

  if ($DryRun) {
    return
  }

  # do not claim an effect this build cannot have. The keys are written either
  # way, so an upgrade later finds them already correct.
  if ($osBuild -lt $script:Tls13MinimumBuild) {
    Write-Warning "TLS 1.3 keys written, but build $osBuild ignores them."
    return
  }

  Write-Output 'TLS 1.3 has been enabled.'
}

# order matters: turn the protocol on, then put its suites first
Enable-TLSv1.3
Set-TLSv13CipherPriority

if ($DryRun) {
  Write-Output 'Dry run finished. Nothing was changed.'
}
else {
  Write-Output 'Restart to apply the Schannel changes.'
}
