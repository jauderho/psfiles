
<#
.SYNOPSIS
   Reclaim space from %SystemRoot%\SoftwareDistribution.

.DESCRIPTION
   SoftwareDistribution is the Windows Update working area. The Download subfolder holds
   update payloads. A payload that has already been installed is never reused, so it is
   safe to clear once servicing is quiescent and nothing is downloaded and waiting to
   install. The DataStore subfolder holds the update database.

   This script clears Download by default. -Full additionally clears DataStore.

   HOW IT WORKS

   The default path is the rename-then-delete sequence Microsoft documents:

     stop services -> rename Download to Download.<timestamp>.bak -> restart services
     -> delete the .bak afterwards

   Rename-Item is a metadata operation, so service downtime is milliseconds rather than
   the minutes a recursive delete takes. It is also recoverable: the renamed folder sits
   on disk until the delete finishes, and a .bak left behind by an interrupted run is
   found, reported and deleted by the next run.

   -OlderThanDays cannot use that sequence, because half a folder cannot be renamed. With
   -OlderThanDays the script falls back to a selective in-place delete, which holds the
   services down for the length of the delete.

   SAFETY

   - Dry run is the default. -Execute is required to change anything.
   - Hard stops cannot be overridden by any switch:
       * an update that is already downloaded and waiting to install, because its payload
         is exactly what Download holds (asked of the Windows Update Agent, local cache
         only, no network call)
       * the servicing worker TiWorker.exe running, which means CBS is mid-transaction
       * CBS RebootPending or RebootInProgress, WindowsUpdate RebootRequired, or
         WinSxS\pending.xml
       * an active BITS transfer
       * a reparse point (junction or directory symlink) anywhere in the tree, because
         both Remove-Item -Recurse and robocopy /MIR delete through one
   - Advisory warnings block the run unless -IgnoreAdvisories is passed. CBS
     PackagesPending is advisory, not a hard stop, because it is a documented sticky key
     that can survive reboots and would otherwise lock a stuck machine out forever.
   - Services are recorded in a script-scope collection BEFORE each stop is attempted, and
     a finally block restarts everything that had been running, in reverse order. This
     covers a normal exit, an early return, an exception and a declined confirmation.
     It is best effort for Ctrl+C: PowerShell normally runs finally blocks on a stop
     request, but a hard kill of the host cannot be caught. A .bak left on disk and a
     stopped service are both visible and recoverable, which is why the rename path exists.
   - A service that will not stop aborts the run before anything is renamed or deleted.
   - A service that will not start again makes the exit code non-zero.

.PARAMETER Elevated
   Internal. Set automatically when the script relaunches itself elevated. Do not pass it
   by hand.

.PARAMETER Execute
   Perform the work. Without this the script reports what it would delete and changes
   nothing.

.PARAMETER DryRun
   Explicitly request a dry run. This is the default. Cannot be combined with -Execute.

.PARAMETER Full
   Also clear DataStore. This resets the Windows Update database. You lose update history,
   the hidden and declined update list, the cached WSUS or Intune deployment metadata and
   the last scan cookie, and the per-update retry and backoff state. Requires an
   interactive confirmation that no switch suppresses, so it cannot be combined with
   -NonInteractive. Cannot be combined with -OlderThanDays.

.PARAMETER OlderThanDays
   Only delete a top level item whose subtree has not been written to for this many days.
   The filter uses the MAXIMUM LastWriteTime found anywhere under the item, not the
   timestamp on the folder itself, because a folder's own timestamp does not change when a
   file inside it is written. 0 (default) selects the whole folder and enables the
   rename-then-delete path.

.PARAMETER NonInteractive
   Suppress confirmation prompts. Does not override a hard stop and does not override an
   advisory warning; use -IgnoreAdvisories for that. Cannot be combined with -Full.

.PARAMETER IgnoreAdvisories
   Continue past advisory warnings, for example a check that could not run. Never
   overrides a hard stop.

.PARAMETER NoUI
   Never show the option dialog. The dialog already suppresses itself when the session is
   not interactive, when -NonInteractive is given, or when a mode was named on the command
   line, so this is only needed to force the command line path in an interactive session.

.PARAMETER ServiceTimeoutSeconds
   How long to wait for each service to stop or start. Default 60.

.PARAMETER LogDirectory
   Where to write the transcript. Default %SystemRoot%\Logs\SoftwareDistributionCleanup.
   An interactive relaunch keeps its console open, but the transcript is the durable
   record and is the only output an automated run leaves behind.

.EXAMPLE
   .\SoftwareDistributionCleanup.ps1
   Dry run. Reports what would be deleted and how much space it would free.

.EXAMPLE
   .\SoftwareDistributionCleanup.ps1 -Execute
   Renames Download out of the way, restarts Windows Update within milliseconds, then
   deletes the renamed folder. Prompts once before starting.

.EXAMPLE
   .\SoftwareDistributionCleanup.ps1 -Execute -NonInteractive -OlderThanDays 30
   Unattended. Deletes only payloads whose subtree has been untouched for 30 days, in
   place, and leaves recent ones alone.

.EXAMPLE
   .\SoftwareDistributionCleanup.ps1 -Execute -Full
   Full reset of the Windows Update working area, including the update database. Asks for
   a typed confirmation first.

.NOTES
   Created by Jauder Ho
   Last modified 9/11/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   Requires PowerShell 5.1 or later and an elevated session.

   Service set. UsoSvc (Update Orchestrator) is stopped first, because it will restart
   wuauserv underneath a run that ignores it. DoSvc (Delivery Optimization) is the default
   download transport on current Windows 10 and 11, so BITS alone is not enough. msiserver
   and cryptsvc are deliberately NOT stopped: msiserver is demand-start, so it running
   means an MSI transaction is in flight right now, and cryptsvc only belongs in the
   documented reset because that procedure renames catroot2, which this script never
   touches.

   The BITS check is defence in depth only. A Delivery Optimization download produces no
   BITS job at all, and -AllUsers does not reliably surface a SYSTEM session 0 job. The
   Windows Update Agent query is the check that actually answers the question. If
   Get-BitsTransfer reports an error it is shown and treated as an advisory, so a run that
   could not perform the check is never reported as one that passed it.

   SusClientId, deferral and pause policy, and active hours live in the registry and are
   not touched by anything here.

   Structure and the robocopy long-path idea follow Tom de Leeuw's Clear-SoftwareDistribution
   from the ComputerCleanup module.

.LINK
   https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/additional-resources-for-windows-update

.LINK
   https://www.powershellgallery.com/packages/ComputerCleanup
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Elevated,
    [switch]$Execute,
    [switch]$DryRun,
    [switch]$Full,
    [ValidateRange(0, 3650)]
    [int]$OlderThanDays = 0,
    [switch]$NonInteractive,
    [switch]$IgnoreAdvisories,
    [switch]$NoUI,
    [ValidateRange(5, 600)]
    [int]$ServiceTimeoutSeconds = 60,
    [string]$LogDirectory = (Join-Path $env:SystemRoot 'Logs\SoftwareDistributionCleanup')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SoftwareDistribution = Join-Path $env:SystemRoot 'SoftwareDistribution'
$script:DownloadPath = Join-Path $script:SoftwareDistribution 'Download'
$script:DataStorePath = Join-Path $script:SoftwareDistribution 'DataStore'

# Absolute path. An elevated session must not resolve a tool through $env:PATH.
$script:Robocopy = Join-Path $env:SystemRoot 'System32\robocopy.exe'

# Stop order. The orchestrator goes first so it cannot restart the ones below it, and the
# transports go last. Restart order is the reverse of the order things were recorded in.
$script:StopOrder = @('UsoSvc', 'wuauserv', 'DoSvc', 'bits')

# Names a backup folder from this script can have, so an interrupted run is recognisable.
$script:BackupPattern = '^(Download|DataStore)\.\d{8}-\d{6}(-\d+)?\.bak$'

# A run of failures this long is a systemic problem, not a long-path problem.
$script:MaxConsecutiveFailures = 10

# How many items a dry run prints before it summarises. The rest go to the verbose stream.
$script:PreviewCount = 20

# Caller owned service state. Every entry is appended BEFORE the matching stop is
# attempted, so an interruption between the append and the stop still leaves the finally
# block something to restore. Safety state is never round-tripped through a return value.
$script:ServiceState = New-Object System.Collections.ArrayList
$script:RestoreFailures = 0

# One empty directory per run for the robocopy mirror-from-empty fallback.
$script:EmptyMirrorSource = $null

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

$script:UseColor = [string]::IsNullOrEmpty($env:NO_COLOR)

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Good', 'Warn', 'Bad', 'Step')][string]$Level = 'Info'
    )

    $prefix = @{ Info = '   '; Good = '[+]'; Warn = '[!]'; Bad = '[x]'; Step = '==>' }[$Level]
    $color = @{ Info = 'Gray'; Good = 'Green'; Warn = 'Yellow'; Bad = 'Red'; Step = 'Cyan' }[$Level]

    if ($script:UseColor) {
        Write-Host ('{0} {1}' -f $prefix, $Message) -ForegroundColor $color
    }
    else {
        Write-Host ('{0} {1}' -f $prefix, $Message)
    }
}

function Format-Bytes {
    param([AllowNull()][Nullable[long]]$Bytes)

    if ($null -eq $Bytes) { return 'n/a' }

    $sign = ''
    $value = [double]$Bytes
    if ($value -lt 0) {
        $sign = '-'
        $value = -$value
    }

    foreach ($unit in @('B', 'KB', 'MB', 'GB', 'TB')) {
        if ($value -lt 1024 -or $unit -eq 'TB') {
            return ('{0}{1:N2} {2}' -f $sign, $value, $unit)
        }
        $value = $value / 1024
    }
}

function Get-SystemDriveFree {
    $drive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($drive -and $null -ne $drive.Free) { return [long]$drive.Free }
    return $null
}

# ---------------------------------------------------------------------------
# Argument validation. Deliberately ahead of the elevation block: an invalid invocation
# must fail in the caller's console, not behind a UAC prompt in a window that closes.
# ---------------------------------------------------------------------------

function Test-ParameterCombination {
    <#
        Returns a message describing the first invalid combination, or $null when the
        current settings are coherent. Called before elevation, and again after the option
        dialog, because the dialog can change what was chosen.
    #>
    if ($Execute -and $DryRun) {
        return '-Execute and -DryRun are mutually exclusive.'
    }
    if ($Full -and $OlderThanDays -gt 0) {
        return '-Full and -OlderThanDays are mutually exclusive. The update database is not cleared selectively.'
    }
    if ($Full -and $NonInteractive) {
        return '-Full and -NonInteractive are mutually exclusive. Clearing DataStore requires a typed confirmation that no switch suppresses.'
    }
    if ($LogDirectory -match '"') {
        return '-LogDirectory must not contain a double quote character.'
    }
    return $null
}

$invalid = Test-ParameterCombination
if ($invalid) {
    Write-Error $invalid
    exit 1
}

# ---------------------------------------------------------------------------
# Elevation. Matches the pattern used by the other scripts in this repo.
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
# ---------------------------------------------------------------------------

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function ConvertTo-QuotedArgument {
    <#
        CommandLineToArgvW treats a run of backslashes immediately before a closing quote
        as escapes, so "D:\WU Logs\" would swallow the quote and corrupt the rest of the
        child command line. Doubling that trailing run is the documented fix.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $escaped = $Value
    if ($escaped -match '(\\+)$') {
        $escaped = $escaped + $Matches[1]
    }

    return ('"{0}"' -f $escaped)
}

if ((Test-Admin) -eq $false) {
    if ($Elevated) {
        Write-Error 'Elevation was attempted and failed. Rerun from an elevated PowerShell session.'
        exit 1
    }

    # Matches the elevation idiom used by the rest of this repo: -NoProfile -NoExit, fired
    # and forgotten so UAC comes up immediately and no non-elevated console is left behind.
    # -NoExit keeps the elevated window up so the operator can read the result.
    $interactive = [Environment]::UserInteractive

    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($interactive) { $relaunch += '-NoExit' }
    $relaunch += @('-File', (ConvertTo-QuotedArgument $PSCommandPath), '-Elevated')

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'Elevated') { continue }
        if ($entry.Value -is [switch]) {
            # Emit the explicit boolean so -Confirm:$false and -Verbose:$false survive.
            $relaunch += ('-{0}:${1}' -f $entry.Key, $entry.Value.IsPresent)
        }
        else {
            $relaunch += ('-{0}' -f $entry.Key)
            $relaunch += (ConvertTo-QuotedArgument ([string]$entry.Value))
        }
    }

    try {
        if ($interactive) {
            Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunch | Out-Null
            exit 0
        }

        # No console to read in an automated context, so wait and report the real result.
        $childExit = 1
        $child = Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunch -PassThru -Wait

        if ($null -ne $child) {
            try {
                if ($null -ne $child.ExitCode) { $childExit = [int]$child.ExitCode }
            }
            catch {
                Write-Warning ('Could not read the exit code of the elevated run: {0}' -f $_.Exception.Message)
            }
        }

        exit $childExit
    }
    catch {
        Write-Error 'Elevation was declined or failed.'
        exit 1
    }
}

Write-Output 'Running with full privileges...'

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

function Test-ShouldShowDialog {
    <#
        The dialog appears only for an operator who launched the script without saying what
        they wanted. An explicit mode on the command line, -NonInteractive, -NoUI, or a
        non-interactive session all suppress it, so a scheduled task never blocks on a
        window nobody is there to close.
    #>
    if ($NoUI) { return $false }
    if ($NonInteractive) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }

    foreach ($explicit in @('Execute', 'DryRun', 'Full')) {
        if ($PSBoundParameters.ContainsKey($explicit)) { return $false }
    }

    return $true
}

function Show-OptionDialog {
    <#
        Presents the run options and writes the operator's choices back into the script
        scope parameter variables. Returns $false if the operator cancelled.

        Invalid combinations are made unreachable by enabling and disabling controls rather
        than by rejecting the form afterwards, and Test-ParameterCombination still runs as
        a backstop.
    #>
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    }
    catch {
        Write-Log ('Windows Forms is unavailable, so the option dialog is skipped: {0}' -f $_.Exception.Message) -Level Warn
        Write-Log 'Continuing with command line settings (dry run unless -Execute was passed).' -Level Warn
        return $true
    }

    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'SoftwareDistribution Cleanup'
    $form.ClientSize = New-Object Drawing.Size(520, 545)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    # The UAC transition can leave a new window behind the console otherwise.
    $form.Topmost = $true

    $intro = New-Object Windows.Forms.Label
    $intro.Location = New-Object Drawing.Point(12, 12)
    $intro.Size = New-Object Drawing.Size(496, 46)
    $intro.Text = "Clears the Windows Update download cache.`r`nWindows Update is stopped only for the moment it takes to rename the folder; the delete happens with it running again."
    $form.Controls.Add($intro)

    $modeBox = New-Object Windows.Forms.GroupBox
    $modeBox.Text = 'Mode'
    $modeBox.Location = New-Object Drawing.Point(12, 62)
    $modeBox.Size = New-Object Drawing.Size(496, 80)
    $form.Controls.Add($modeBox)

    $radioDry = New-Object Windows.Forms.RadioButton
    $radioDry.Text = 'Dry run - report only, change nothing (recommended first)'
    $radioDry.Location = New-Object Drawing.Point(15, 22)
    $radioDry.Size = New-Object Drawing.Size(465, 22)
    $radioDry.Checked = -not $Execute
    $modeBox.Controls.Add($radioDry)

    $radioExecute = New-Object Windows.Forms.RadioButton
    $radioExecute.Text = 'Execute - clear the cache'
    $radioExecute.Location = New-Object Drawing.Point(15, 48)
    $radioExecute.Size = New-Object Drawing.Size(465, 22)
    $radioExecute.Checked = [bool]$Execute
    $modeBox.Controls.Add($radioExecute)

    $scopeBox = New-Object Windows.Forms.GroupBox
    $scopeBox.Text = 'Scope'
    $scopeBox.Location = New-Object Drawing.Point(12, 150)
    $scopeBox.Size = New-Object Drawing.Size(496, 106)
    $form.Controls.Add($scopeBox)

    $chkFull = New-Object Windows.Forms.CheckBox
    $chkFull.Text = 'Also clear DataStore - resets the update database'
    $chkFull.Location = New-Object Drawing.Point(15, 22)
    $chkFull.Size = New-Object Drawing.Size(465, 22)
    $chkFull.Checked = [bool]$Full
    $scopeBox.Controls.Add($chkFull)

    $labelAge = New-Object Windows.Forms.Label
    $labelAge.Text = 'Only delete items untouched for this many days (0 = everything):'
    $labelAge.Location = New-Object Drawing.Point(15, 52)
    $labelAge.Size = New-Object Drawing.Size(380, 22)
    $scopeBox.Controls.Add($labelAge)

    $numAge = New-Object Windows.Forms.NumericUpDown
    $numAge.Location = New-Object Drawing.Point(400, 50)
    $numAge.Size = New-Object Drawing.Size(80, 22)
    $numAge.Minimum = 0
    $numAge.Maximum = 3650
    $numAge.Value = $OlderThanDays
    $scopeBox.Controls.Add($numAge)

    $ageNote = New-Object Windows.Forms.Label
    $ageNote.Location = New-Object Drawing.Point(15, 76)
    $ageNote.Size = New-Object Drawing.Size(465, 22)
    $ageNote.Text = 'Above 0 switches to an in-place delete, holding the services down for longer.'
    $scopeBox.Controls.Add($ageNote)

    $overrideBox = New-Object Windows.Forms.GroupBox
    $overrideBox.Text = 'Overrides - these reduce the safety margin'
    $overrideBox.Location = New-Object Drawing.Point(12, 264)
    $overrideBox.Size = New-Object Drawing.Size(496, 80)
    $form.Controls.Add($overrideBox)

    $chkNonInteractive = New-Object Windows.Forms.CheckBox
    $chkNonInteractive.Text = 'Do not ask for confirmation'
    $chkNonInteractive.Location = New-Object Drawing.Point(15, 22)
    $chkNonInteractive.Size = New-Object Drawing.Size(465, 22)
    $chkNonInteractive.Checked = [bool]$NonInteractive
    $overrideBox.Controls.Add($chkNonInteractive)

    $chkIgnore = New-Object Windows.Forms.CheckBox
    $chkIgnore.Text = 'Continue past advisory warnings (never overrides a hard stop)'
    $chkIgnore.Location = New-Object Drawing.Point(15, 48)
    $chkIgnore.Size = New-Object Drawing.Size(465, 22)
    $chkIgnore.Checked = [bool]$IgnoreAdvisories
    $overrideBox.Controls.Add($chkIgnore)

    $chkVerbose = New-Object Windows.Forms.CheckBox
    $chkVerbose.Text = 'Verbose output - show every file and step in detail'
    $chkVerbose.Location = New-Object Drawing.Point(15, 352)
    $chkVerbose.Size = New-Object Drawing.Size(493, 22)
    # Checked by default: these runs are long and mostly silent otherwise, and the
    # step-by-step detail is what makes a failure diagnosable afterwards. An explicit
    # -Verbose:$false on the command line still wins.
    $chkVerbose.Checked = $true
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        $chkVerbose.Checked = [bool]$PSBoundParameters['Verbose']
    }
    $form.Controls.Add($chkVerbose)

    $notice = New-Object Windows.Forms.Label
    $notice.Location = New-Object Drawing.Point(12, 380)
    $notice.Size = New-Object Drawing.Size(496, 72)
    $notice.ForeColor = [Drawing.Color]::FromArgb(150, 20, 20)
    $form.Controls.Add($notice)

    $buttonRun = New-Object Windows.Forms.Button
    $buttonRun.Text = 'Run'
    $buttonRun.Location = New-Object Drawing.Point(322, 505)
    $buttonRun.Size = New-Object Drawing.Size(90, 28)
    $buttonRun.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonRun)
    $form.AcceptButton = $buttonRun

    $buttonCancel = New-Object Windows.Forms.Button
    $buttonCancel.Text = 'Cancel'
    $buttonCancel.Location = New-Object Drawing.Point(418, 505)
    $buttonCancel.Size = New-Object Drawing.Size(90, 28)
    $buttonCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)
    $form.CancelButton = $buttonCancel

    $refresh = {
        $executing = $radioExecute.Checked

        # -Full needs Execute, cannot be combined with an age filter, and always asks for a
        # typed confirmation. Enforce all three by disabling rather than by failing later.
        $chkFull.Enabled = $executing -and ($numAge.Value -eq 0)
        if (-not $chkFull.Enabled) { $chkFull.Checked = $false }

        $numAge.Enabled = -not $chkFull.Checked
        $labelAge.Enabled = $numAge.Enabled
        $ageNote.Enabled = $numAge.Enabled

        $chkNonInteractive.Enabled = $executing -and -not $chkFull.Checked
        if (-not $chkNonInteractive.Enabled) { $chkNonInteractive.Checked = $false }
        $chkIgnore.Enabled = $executing

        $lines = @()
        if ($chkFull.Checked) {
            $lines += 'Clearing DataStore loses update history, the hidden and declined update list, cached WSUS or Intune metadata, and per-update retry state. A typed confirmation is required.'
        }
        elseif ($executing -and $numAge.Value -gt 0) {
            $lines += 'In-place delete. Windows Update stays stopped for the whole delete rather than milliseconds.'
        }
        elseif ($executing) {
            $lines += 'Download is renamed out of the way, Windows Update restarts immediately, then the renamed folder is deleted.'
        }
        else {
            $lines += 'Dry run. Nothing will be changed.'
        }

        $notice.Text = ($lines -join "`r`n")
    }

    $radioDry.Add_CheckedChanged($refresh)
    $radioExecute.Add_CheckedChanged($refresh)
    $chkFull.Add_CheckedChanged($refresh)
    $numAge.Add_ValueChanged($refresh)
    & $refresh

    $answer = $form.ShowDialog()
    $accepted = ($answer -eq [Windows.Forms.DialogResult]::OK)

    if ($accepted) {
        $script:Execute = [switch]$radioExecute.Checked
        $script:DryRun = [switch]$radioDry.Checked
        $script:Full = [switch]($chkFull.Enabled -and $chkFull.Checked)
        $script:OlderThanDays = [int]$numAge.Value
        $script:NonInteractive = [switch]($chkNonInteractive.Enabled -and $chkNonInteractive.Checked)
        $script:IgnoreAdvisories = [switch]($chkIgnore.Enabled -and $chkIgnore.Checked)

        # Dynamic scoping puts this in reach of Write-Verbose everywhere in the script.
        if ($chkVerbose.Checked) { $script:VerbosePreference = 'Continue' }
        else { $script:VerbosePreference = 'SilentlyContinue' }
    }

    $form.Dispose()
    return $accepted
}

function Get-PendingState {
    <#
        Splits the pending-servicing keys into hard stops and advisories.

        PackagesPending is advisory. It is a documented sticky key that can survive a
        reboot, so treating it as a hard stop locks a machine with stuck CBS state out of
        this script permanently.
    #>
    $hard = @()
    $advisory = @()
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'

    foreach ($key in @('RebootPending', 'RebootInProgress')) {
        if (Test-Path -LiteralPath (Join-Path $cbs $key)) {
            $hard += ('Component Based Servicing\{0}' -f $key)
        }
    }

    if (Test-Path -LiteralPath (Join-Path $cbs 'PackagesPending')) {
        $advisory += 'Component Based Servicing\PackagesPending is set. That key is frequently stale and survives reboots, so it is treated as advisory here.'
    }

    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $hard += 'WindowsUpdate\Auto Update\RebootRequired'
    }

    if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'WinSxS\pending.xml')) {
        $hard += 'WinSxS\pending.xml'
    }

    return [pscustomobject]@{
        HardStop = @($hard)
        Advisory = @($advisory)
    }
}

function Get-StagedUpdate {
    <#
        The check that actually answers "is it safe to delete Download". An update that is
        already downloaded and waiting to install has its payload sitting in Download, and
        sets none of the pending-reboot keys. This is the real hard stop.

        Online = $false means the local cache only. No network call is made.

        Returns Status = None | Staged | Unavailable. Unavailable is never a silent pass.
    #>
    $titles = @()

    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $false
        $result = $searcher.Search('IsInstalled=0 and IsHidden=0')

        foreach ($update in $result.Updates) {
            if ($update.IsDownloaded) { $titles += [string]$update.Title }
        }
    }
    catch {
        return [pscustomobject]@{
            Status  = 'Unavailable'
            Count   = 0
            Titles  = @()
            Message = $_.Exception.Message
        }
    }

    $status = 'None'
    if ($titles.Count -gt 0) { $status = 'Staged' }

    return [pscustomobject]@{
        Status  = $status
        Count   = $titles.Count
        Titles  = @($titles)
        Message = ''
    }
}

function Get-ServiceStartType {
    param([Parameter(Mandatory = $true)]$Service)

    try {
        return [string]$Service.StartType
    }
    catch {
        Write-Verbose ('ServiceController.StartType unavailable for {0}: {1}' -f $Service.Name, $_.Exception.Message)
    }

    try {
        $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Service.Name) -ErrorAction Stop
        return [string]$wmi.StartMode
    }
    catch {
        return 'Unknown'
    }
}

function Test-Preflight {
    Write-Log 'Running preflight checks...' -Level Step

    $hardStop = @()
    $advisory = @()

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $hardStop += 'This script only runs on Windows.'
    }

    if (-not (Test-Path -LiteralPath $script:SoftwareDistribution)) {
        $hardStop += ('{0} does not exist.' -f $script:SoftwareDistribution)
    }

    if (-not (Test-Path -LiteralPath $script:Robocopy)) {
        $hardStop += ('{0} is missing. It is required for the delete path.' -f $script:Robocopy)
    }

    # The real gate. A downloaded, ready-to-install update is what Download is holding.
    $staged = Get-StagedUpdate
    switch ($staged.Status) {
        'Staged' {
            $hardStop += ('{0} update(s) are downloaded and waiting to install. Deleting Download now discards their payload. Install them, or cancel them in Windows Update, then rerun.' -f $staged.Count)
            foreach ($title in $staged.Titles) { Write-Log ('staged: {0}' -f $title) -Level Bad }
        }
        'Unavailable' {
            Write-Log ('The Windows Update Agent query could not run: {0}' -f $staged.Message) -Level Warn
            $advisory += 'Could not confirm that no update is downloaded and waiting to install. This is the most important check in this script.'
        }
    }

    $pending = Get-PendingState
    if ($pending.HardStop.Count -gt 0) {
        $hardStop += ('Servicing is mid-flight ({0}). Reboot and rerun.' -f ($pending.HardStop -join ', '))
    }
    foreach ($reason in $pending.Advisory) { $advisory += $reason }

    # CBS mid-transaction reads payload straight out of Download. No switch overrides this,
    # which matches how ComponentCleanup.ps1 treats concurrent servicing.
    $worker = @(Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue)
    if ($worker.Count -gt 0) {
        $hardStop += ('The servicing worker (TiWorker.exe, PID {0}) is running, so CBS is mid-transaction. Wait for it to finish and rerun.' -f ($worker.Id -join ', '))
    }

    # Defence in depth only. Delivery Optimization downloads produce no BITS job, so a
    # clean result here does not mean nothing is downloading.
    try {
        $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop |
                Where-Object { @('Transferring', 'Connecting', 'Queued', 'TransientError') -contains [string]$_.JobState })
        if ($jobs.Count -gt 0) {
            $hardStop += ('BITS has {0} active transfer(s). Let them finish or cancel them first.' -f $jobs.Count)
        }
    }
    catch {
        Write-Log ('The BITS transfer check could not run: {0}' -f $_.Exception.Message) -Level Warn
        $advisory += 'The BITS transfer check did not run, so an in-flight BITS download cannot be ruled out.'
    }

    foreach ($serviceName in $script:StopOrder) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            if ($serviceName -eq 'wuauserv') {
                $hardStop += 'The Windows Update service (wuauserv) is not present on this system.'
            }
            else {
                Write-Verbose ('Service {0} is not present on this system.' -f $serviceName)
            }
            continue
        }

        # A Running service whose start type is Disabled cannot be started again once this
        # script stops it. Say so before anything is deleted, not afterwards.
        if ((Get-ServiceStartType -Service $service) -eq 'Disabled' -and [string]$service.Status -ne 'Stopped') {
            $advisory += ('{0} is {1} but its start type is Disabled, so it cannot be started again after this run. Fix it first with: Set-Service -Name {0} -StartupType Manual' -f $serviceName, $service.Status)
        }
    }

    # Checked here, before anything is renamed or stopped, rather than only at deletion
    # time. A reparse point makes the tree undeletable by either robocopy /MIR or
    # Remove-Item -Recurse without destroying whatever it points at, so there is no point
    # taking the services down to rename a folder that cannot then be removed.
    foreach ($path in @($script:DownloadPath, $script:DataStorePath)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ($path -eq $script:DataStorePath -and -not $Full) { continue }

        $links = @(Find-ReparsePoint -Path $path)
        if ($links.Count -gt 0) {
            foreach ($link in $links) { Write-Log ('reparse point: {0}' -f $link.FullName) -Level Bad }
            $hardStop += ('{0} contains a reparse point. Both robocopy /MIR and Remove-Item -Recurse delete through one to whatever it targets. Check where it points and remove it by hand first.' -f $path)
        }
    }

    foreach ($reason in $hardStop) { Write-Log $reason -Level Bad }
    foreach ($reason in $advisory) { Write-Log $reason -Level Warn }

    if ($hardStop.Count -gt 0) {
        Write-Log 'Hard stop. No switch overrides the reasons above.' -Level Bad
        return $false
    }

    if ($advisory.Count -gt 0 -and $Execute -and -not $IgnoreAdvisories) {
        Write-Log 'Advisory warnings above. Rerun with -IgnoreAdvisories to proceed anyway.' -Level Bad
        return $false
    }

    Write-Log 'Preflight passed.' -Level Good
    return $true
}

# ---------------------------------------------------------------------------
# Service handling
#
# Every record is appended before the corresponding stop is attempted, and the finally
# block reads $script:ServiceState directly.
# ---------------------------------------------------------------------------

function Add-ServiceStateRecord {
    <#
        Records one service. Returns $true when the record is new, so the dependent walk
        can use it as its recursion guard.
    #>
    param([Parameter(Mandatory = $true)]$Service)

    foreach ($existing in $script:ServiceState) {
        if ($existing.Name -eq $Service.Name) { return $false }
    }

    # The stop decision and the restore decision are different questions. StartPending and
    # ContinuePending are on their way to Running, so they are restored; StopPending and
    # Paused are not, because putting them back to Running would change the machine's state.
    $status = [string]$Service.Status
    $wasRunning = (@('Running', 'StartPending', 'ContinuePending') -contains $status)

    [void]$script:ServiceState.Add([pscustomobject]@{
            Name        = [string]$Service.Name
            Status      = $status
            WasRunning  = $wasRunning
            StartType   = (Get-ServiceStartType -Service $Service)
        })

    return $true
}

function Register-DependentService {
    <#
        Stop-Service -Force stops the whole dependent tree as a side effect. Those services
        are recorded here, before the stop, so they are restarted afterwards. The dedupe in
        Add-ServiceStateRecord doubles as the recursion guard.
    #>
    param([Parameter(Mandatory = $true)]$Service)

    $dependents = @()
    try {
        $dependents = @($Service.DependentServices)
    }
    catch {
        Write-Log ('Could not enumerate the services that depend on {0}: {1}' -f $Service.Name, $_.Exception.Message) -Level Warn
        return
    }

    foreach ($dependent in $dependents) {
        if ([string]$dependent.Status -eq 'Stopped') { continue }
        if (Add-ServiceStateRecord -Service $dependent) {
            Write-Log ('{0} depends on {1} and will be stopped with it.' -f $dependent.Name, $Service.Name) -Level Warn
            Register-DependentService -Service $dependent
        }
    }
}

function Stop-UpdateService {
    <#
        Stops each named service in order. Returns $true only when every service that is
        present is confirmed Stopped. The caller must abort on $false rather than delete
        files underneath a running service.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Name)

    $timeout = [timespan]::FromSeconds($ServiceTimeoutSeconds)

    foreach ($serviceName in $Name) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Verbose ('Service {0} is not present. Skipping.' -f $serviceName)
            continue
        }

        Register-DependentService -Service $service
        [void](Add-ServiceStateRecord -Service $service)

        # Anything that is not Stopped needs stopping. StartPending, StopPending, Paused
        # and ContinuePending are all live states with open handles.
        if ([string]$service.Status -eq 'Stopped') {
            Write-Log ('{0} is already stopped.' -f $serviceName)
            continue
        }

        Write-Log ('Stopping {0} (currently {1})...' -f $serviceName, $service.Status) -Level Step
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', $timeout)
        }
        catch {
            Write-Log ('{0} would not stop: {1}' -f $serviceName, $_.Exception.Message) -Level Bad
            return $false
        }

        $service.Refresh()
        if ([string]$service.Status -ne 'Stopped') {
            Write-Log ('{0} is {1}, not Stopped. Refusing to continue.' -f $serviceName, $service.Status) -Level Bad
            return $false
        }
    }

    return $true
}

function Get-ServiceNotStopped {
    <#
        Re-reads the services immediately before the destructive step. The orchestrator can
        bring one back between the stop and the rename.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Name)

    $offenders = @()

    foreach ($serviceName in $Name) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) { continue }
        if ([string]$service.Status -ne 'Stopped') {
            $offenders += ('{0} ({1})' -f $serviceName, $service.Status)
        }
    }

    return $offenders
}

function Restore-UpdateService {
    <#
        Restarts everything that had been running, newest record first, which is the reverse
        of both the stop order and the dependent-before-parent recording order. Always
        called from a finally block. Recomputes $script:RestoreFailures from scratch so
        calling it twice cannot double count.
    #>
    $failures = 0
    $timeout = [timespan]::FromSeconds($ServiceTimeoutSeconds)

    for ($index = $script:ServiceState.Count - 1; $index -ge 0; $index--) {
        $entry = $script:ServiceState[$index]
        if (-not $entry.WasRunning) { continue }

        $service = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            $failures++
            Write-Log ('{0} has disappeared and cannot be restarted.' -f $entry.Name) -Level Bad
            continue
        }

        if ([string]$service.Status -eq 'Running') { continue }

        if ($entry.StartType -eq 'Disabled') {
            $failures++
            Write-Log ('{0} is Disabled and cannot be started. Run: Set-Service -Name {0} -StartupType Manual; Start-Service -Name {0}' -f $entry.Name) -Level Bad
            continue
        }

        Write-Log ('Starting {0}...' -f $entry.Name) -Level Step
        try {
            Start-Service -Name $entry.Name -ErrorAction Stop
            $service.WaitForStatus('Running', $timeout)
            Write-Log ('{0} is running again.' -f $entry.Name) -Level Good
        }
        catch {
            $failures++
            Write-Log ('{0} did not restart: {1}. Start it manually.' -f $entry.Name, $_.Exception.Message) -Level Bad
        }
    }

    $script:RestoreFailures = $failures
}

# ---------------------------------------------------------------------------
# Measuring and inspection
# ---------------------------------------------------------------------------

function Find-ReparsePoint {
    <#
        Returns up to $Limit reparse points (junctions and directory symlinks) at or below
        $Path, including $Path itself.

        This is mandatory before any robocopy /MIR. /MIR walks reparse points in the
        DESTINATION and deletes through them to whatever they point at; /XJ only protects
        the source side. Windows PowerShell 5.1's Remove-Item -Recurse has the same
        problem. The ReparsePoint attribute bit is tested directly, because LinkType and
        Target are $null for system-defined junctions.

        Select-Object -First stops the upstream enumeration, so a junction loop cannot run
        this away.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Limit = 10
    )

    $found = @()

    if (-not (Test-Path -LiteralPath $Path)) { return $found }

    try {
        $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq [IO.FileAttributes]::ReparsePoint) {
            $found += $root
        }
    }
    catch {
        Write-Log ('Could not inspect {0}: {1}' -f $Path, $_.Exception.Message) -Level Warn
    }

    $found += @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq [IO.FileAttributes]::ReparsePoint } |
            Select-Object -First $Limit)

    return $found
}

function Measure-TreeFast {
    <#
        Sizes a tree by asking robocopy to list it. /L writes nothing. This is used instead
        of a recursive Get-ChildItem materialised into an array, which costs hundreds of
        megabytes of memory on a large cache.

        The summary rows are matched by shape, not by their (localised) labels: the three
        rows carrying six integers are Dirs, Files and Bytes, in that order, with columns
        Total, Copied, Skipped, Mismatch, FAILED, Extras.

        Returns $null when the summary cannot be parsed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $probe = Join-Path ([IO.Path]::GetTempPath()) ('SDCleanup-probe-{0}' -f [guid]::NewGuid().ToString('N'))
    $rows = @()

    try {
        $output = & $script:Robocopy $Path $probe /L /E /BYTES /NFL /NDL /NJH /NP /XJ /R:0 /W:0

        foreach ($line in $output) {
            if ([string]$line -match '^\s*\S+\s*:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$') {
                $rows += [pscustomobject]@{ Total = [long]$Matches[1]; Failed = [long]$Matches[5] }
            }
        }
    }
    catch {
        Write-Log ('Could not size {0}: {1}' -f $Path, $_.Exception.Message) -Level Warn
        return $null
    }
    finally {
        # /L should not create the destination. Remove it if this build of robocopy did.
        if (Test-Path -LiteralPath $probe) {
            Remove-Item -LiteralPath $probe -Force -Recurse -ErrorAction SilentlyContinue
        }
    }

    if ($rows.Count -lt 3) {
        Write-Log ('Could not parse the robocopy summary for {0}. Size will be reported as unknown.' -f $Path) -Level Warn
        return $null
    }

    return [pscustomobject]@{
        Bytes       = $rows[2].Total
        FailedDirs  = $rows[0].Failed
        FailedFiles = $rows[1].Failed
    }
}

function Measure-Subtree {
    <#
        One streaming pass per top level item, returning both the size and the MAXIMUM
        LastWriteTime found anywhere underneath it.

        The maximum matters: a directory's own timestamp does not change when a file inside
        it is written, so a feature update folder created 40 days ago whose payload is
        being resumed today still looks 40 days old from the outside.

        The accumulator is a hashtable because an assignment inside a ForEach-Object block
        would otherwise create a block-local copy.
    #>
    param([Parameter(Mandatory = $true)]$Item)

    $accumulator = @{ Size = 0L; MaxWrite = $Item.LastWriteTime }
    $unmeasured = 0

    if ($Item.PSIsContainer) {
        $walkErrors = $null
        Get-ChildItem -LiteralPath $Item.FullName -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable walkErrors |
            ForEach-Object {
                if ($_.LastWriteTime -gt $accumulator.MaxWrite) { $accumulator.MaxWrite = $_.LastWriteTime }
                if (-not $_.PSIsContainer) { $accumulator.Size += [long]$_.Length }
            }

        if ($walkErrors) { $unmeasured = @($walkErrors).Count }
    }
    else {
        $accumulator.Size = [long]$Item.Length
    }

    return [pscustomobject]@{
        Size         = [long]$accumulator.Size
        MaxLastWrite = $accumulator.MaxWrite
        Unmeasured   = $unmeasured
    }
}

function Show-ItemList {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Names,
        [int]$Preview = $script:PreviewCount
    )

    $shown = 0
    foreach ($name in $Names) {
        if ($shown -lt $Preview) { Write-Log ('would delete {0}' -f $name) }
        else { Write-Verbose ('would delete {0}' -f $name) }
        $shown++
    }

    if ($Names.Count -gt $Preview) {
        Write-Log ('... and {0} more. Rerun with -Verbose for the full list.' -f ($Names.Count - $Preview)) -Level Warn
    }
}

function Show-FreeSpaceDelta {
    <#
        Secondary observation only. On the rename path the services are running again by
        the time the delete finishes, so Windows Update can be writing to the same volume.
        The authoritative figure is what was actually deleted.
    #>
    param(
        [AllowNull()][Nullable[long]]$Before,
        [AllowNull()][Nullable[long]]$After
    )

    if ($null -eq $Before -or $null -eq $After) { return }

    $delta = $After - $Before
    if ($delta -ge 0) {
        Write-Log ('Secondary observation: free space on {0} rose by {1}.' -f $env:SystemDrive, (Format-Bytes $delta))
    }
    else {
        Write-Log ('Secondary observation: free space on {0} fell by {1} during the run. Windows Update is running again and writes to this volume, so this is not a measure of what was deleted.' -f $env:SystemDrive, (Format-Bytes ([Math]::Abs($delta)))) -Level Warn
    }
}

# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------

function Get-EmptyMirrorSource {
    <#
        One empty directory per run, not one per failed item. A systemic failure must not
        spawn thousands of temp directories and robocopy processes.
    #>
    if ($script:EmptyMirrorSource -and (Test-Path -LiteralPath $script:EmptyMirrorSource)) {
        return $script:EmptyMirrorSource
    }

    $path = Join-Path ([IO.Path]::GetTempPath()) ('SDCleanup-empty-{0}' -f [guid]::NewGuid().ToString('N'))
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    $script:EmptyMirrorSource = $path

    return $path
}

function Remove-EmptyMirrorSource {
    if ($script:EmptyMirrorSource -and (Test-Path -LiteralPath $script:EmptyMirrorSource)) {
        Remove-Item -LiteralPath $script:EmptyMirrorSource -Force -Recurse -ErrorAction SilentlyContinue
    }
    $script:EmptyMirrorSource = $null
}

function Remove-Tree {
    <#
        Mirrors an empty directory over the target, which handles paths longer than
        Remove-Item can address and is considerably faster than Remove-Item -Recurse, then
        removes the emptied directory.

        THE CALLER MUST HAVE RUN Find-ReparsePoint OVER $Path FIRST. /MIR deletes through a
        reparse point in the destination and /NFL means there would be no record of what it
        destroyed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $empty = Get-EmptyMirrorSource

    & $script:Robocopy $empty $Path /MIR /MT:16 /XJ /R:1 /W:1 /NJH /NJS /NDL /NC /NS /NP /NFL | Out-Null

    # robocopy uses a bit field. Anything under 8 is success or informational.
    if ($LASTEXITCODE -ge 8) {
        throw ('robocopy returned {0} while emptying {1}.' -f $LASTEXITCODE, $Path)
    }

    Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop
}

function Get-StaleBackup {
    <#
        A Download.<timestamp>.bak or DataStore.<timestamp>.bak left behind by an
        interrupted run. Reported at startup and deleted as part of this run.
    #>
    if (-not (Test-Path -LiteralPath $script:SoftwareDistribution)) { return @() }

    $found = @(Get-ChildItem -LiteralPath $script:SoftwareDistribution -Force -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $script:BackupPattern })

    return $found
}

function Move-ToBackup {
    <#
        The rename. O(1) metadata operation, so the services are only down for the length
        of this call. Returns the full path of the renamed folder.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $name = '{0}.{1}.bak' -f $leaf, $stamp
    $suffix = 0

    while (Test-Path -LiteralPath (Join-Path $parent $name)) {
        $suffix++
        $name = '{0}.{1}-{2}.bak' -f $leaf, $stamp, $suffix
    }

    Rename-Item -LiteralPath $Path -NewName $name -ErrorAction Stop

    return (Join-Path $parent $name)
}

function Remove-BackupDirectory {
    <#
        Deletes one renamed folder, at leisure, with the services already running.
        Returns Deleted, Bytes and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Deleted = $true; Bytes = 0L; Reason = '' }
    }

    $links = @(Find-ReparsePoint -Path $Path)
    if ($links.Count -gt 0) {
        foreach ($link in $links) { Write-Log ('reparse point: {0}' -f $link.FullName) -Level Bad }
        return [pscustomobject]@{
            Deleted = $false
            Bytes   = 0L
            Reason  = 'the tree contains a reparse point, which a mirror would delete through. Check where it points and remove it by hand.'
        }
    }

    $bytes = 0L
    $measure = Measure-TreeFast -Path $Path
    if ($null -ne $measure) {
        $bytes = $measure.Bytes
        if (($measure.FailedDirs + $measure.FailedFiles) -gt 0) {
            Write-Log ('{0} item(s) under {1} could not be measured and are not counted in the total.' -f ($measure.FailedDirs + $measure.FailedFiles), $Path) -Level Warn
        }
    }

    Write-Log ('Deleting {0} ({1})...' -f $Path, (Format-Bytes $bytes)) -Level Step

    try {
        Remove-Tree -Path $Path
        return [pscustomobject]@{ Deleted = $true; Bytes = $bytes; Reason = '' }
    }
    catch {
        return [pscustomobject]@{ Deleted = $false; Bytes = 0L; Reason = $_.Exception.Message }
    }
}

function Remove-SelectedItem {
    <#
        The -OlderThanDays path: delete selected top level items in place, while the
        services are held down. Returns Failures, BytesFailed and Aborted.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Candidates)

    $failures = 0
    $bytesFailed = 0L
    $consecutive = 0

    foreach ($candidate in $Candidates) {
        $item = $candidate.Item
        $reason = ''

        try {
            Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
            Write-Verbose ('Deleted {0}' -f $item.FullName)
            $consecutive = 0
            continue
        }
        catch {
            $reason = $_.Exception.Message
        }

        if (-not $item.PSIsContainer) {
            $failures++
            $bytesFailed += $candidate.Size
            $consecutive++
            Write-Log ('Could not delete {0}: {1}' -f $item.FullName, $reason) -Level Warn
        }
        else {
            # Remove-Item reports a long-path failure differently across versions, so any
            # directory failure retries through robocopy rather than matching the exception.
            Write-Log ('Retrying with robocopy: {0} ({1})' -f $item.FullName, $reason) -Level Warn
            try {
                Remove-Tree -Path $item.FullName
                $consecutive = 0
            }
            catch {
                $failures++
                $bytesFailed += $candidate.Size
                $consecutive++
                Write-Log ('Could not delete {0}: {1}' -f $item.FullName, $_.Exception.Message) -Level Warn
            }
        }

        if ($consecutive -ge $script:MaxConsecutiveFailures) {
            Write-Log ('{0} failures in a row. That is a systemic problem, not a long path problem. Stopping here.' -f $consecutive) -Level Bad
            return [pscustomobject]@{ Failures = $failures; BytesFailed = $bytesFailed; Aborted = $true }
        }
    }

    return [pscustomobject]@{ Failures = $failures; BytesFailed = $bytesFailed; Aborted = $false }
}

# ---------------------------------------------------------------------------
# The two cleanup paths
# ---------------------------------------------------------------------------

function Invoke-RenameCleanup {
    <#
        The default path, and the one Microsoft documents. Rename each folder out of the
        way with the services stopped, restart the services immediately, then delete the
        renamed folders with everything running again.

        Returns the process exit code.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Scope)

    $present = @()
    foreach ($path in $Scope) {
        if (Test-Path -LiteralPath $path) { $present += $path }
        else { Write-Log ('{0} does not exist. Nothing to do for it.' -f $path) }
    }

    $stale = @(Get-StaleBackup)
    foreach ($item in $stale) {
        Write-Log ('Left over from an interrupted run: {0}' -f $item.FullName) -Level Warn
    }

    if ($present.Count -eq 0 -and $stale.Count -eq 0) {
        Write-Log 'Nothing in scope. Leaving everything alone.' -Level Good
        return 0
    }

    if (-not $Execute) {
        $planned = 0L
        foreach ($path in ($present + @($stale | ForEach-Object { $_.FullName }))) {
            $measure = Measure-TreeFast -Path $path
            $bytes = $null
            if ($null -ne $measure) {
                $bytes = $measure.Bytes
                $planned += $measure.Bytes
                if (($measure.FailedDirs + $measure.FailedFiles) -gt 0) {
                    Write-Log ('{0} item(s) under {1} could not be measured.' -f ($measure.FailedDirs + $measure.FailedFiles), $path) -Level Warn
                }
            }

            Write-Log ('{0}: {1}' -f $path, (Format-Bytes $bytes)) -Level Step

            $names = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
            Show-ItemList -Names $names
        }

        Write-Log ('DRY RUN complete. About {0} would be freed. Rerun with -Execute to act.' -f (Format-Bytes $planned)) -Level Warn
        return 0
    }

    $exitCode = 0
    $backups = @()
    $freeBefore = Get-SystemDriveFree

    if ($present.Count -gt 0) {
        $action = 'Rename out of the way while Windows Update is stopped, then delete'
        if (-not $PSCmdlet.ShouldProcess(($present -join ', '), $action)) { return 0 }

        try {
            if (-not (Stop-UpdateService -Name $script:StopOrder)) {
                Write-Log 'Aborting without renaming anything, because a required service would not stop.' -Level Bad
                $exitCode = 1
            }
            else {
                # Re-verify. UsoSvc is stopped first precisely so it cannot restart the
                # others, but confirm rather than assume.
                $running = @(Get-ServiceNotStopped -Name $script:StopOrder)
                if ($running.Count -gt 0) {
                    Write-Log ('These services are running again: {0}. Aborting without renaming anything.' -f ($running -join ', ')) -Level Bad
                    $exitCode = 1
                }
                else {
                    foreach ($path in $present) {
                        try {
                            $backup = Move-ToBackup -Path $path
                            $backups += $backup
                            Write-Log ('{0} -> {1}' -f $path, (Split-Path -Leaf $backup)) -Level Good
                        }
                        catch {
                            Write-Log ('Could not rename {0}: {1}' -f $path, $_.Exception.Message) -Level Bad
                            $exitCode = 1
                            break
                        }
                    }
                }
            }
        }
        finally {
            Restore-UpdateService
        }
    }

    foreach ($item in $stale) { $backups += $item.FullName }

    if ($backups.Count -eq 0) { return $exitCode }

    Write-Log 'Windows Update is running again. Deleting the renamed folders now.' -Level Step

    $deleted = 0L
    foreach ($backup in $backups) {
        $result = Remove-BackupDirectory -Path $backup
        if ($result.Deleted) {
            $deleted += $result.Bytes
        }
        else {
            $exitCode = 1
            Write-Log ('{0} was not deleted: {1}' -f $backup, $result.Reason) -Level Bad
            Write-Log 'It is safe where it is. The next run of this script will find it and try again.' -Level Warn
        }
    }

    Write-Log ('Deleted {0}.' -f (Format-Bytes $deleted)) -Level Good
    Show-FreeSpaceDelta -Before $freeBefore -After (Get-SystemDriveFree)
    Write-Log 'Windows Update rebuilds what it needs on the next scan.' -Level Good

    return $exitCode
}

function Invoke-SelectiveCleanup {
    <#
        The -OlderThanDays path. A folder cannot be half renamed, so this deletes in place
        and the services stay down for the length of the delete.

        Returns the process exit code.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Days
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log ('{0} does not exist. Nothing to do.' -f $Path) -Level Good
        return 0
    }

    # Both Remove-Item -Recurse on 5.1 and the robocopy fallback delete through a reparse
    # point, so the whole tree is cleared before anything is measured or deleted.
    $links = @(Find-ReparsePoint -Path $Path)
    if ($links.Count -gt 0) {
        Write-Log ('{0} contains reparse point(s). Deleting through one would destroy data outside this tree.' -f $Path) -Level Bad
        foreach ($link in $links) { Write-Log ('reparse point: {0}' -f $link.FullName) -Level Bad }
        Write-Log 'Hard stop. Check where they point and remove them by hand.' -Level Bad
        return 1
    }

    $cutoff = (Get-Date).AddDays(-$Days)
    Write-Log ('Measuring {0}. Every file is walked, so this can take a few minutes.' -f $Path) -Level Step

    $candidates = @()
    $planned = 0L
    $kept = 0
    $unmeasured = 0

    foreach ($item in (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        $measure = Measure-Subtree -Item $item
        $unmeasured += $measure.Unmeasured

        if ($measure.MaxLastWrite -ge $cutoff) {
            $kept++
            Write-Verbose ('Keeping {0}: written {1:yyyy-MM-dd HH:mm}' -f $item.FullName, $measure.MaxLastWrite)
            continue
        }

        $candidates += [pscustomobject]@{
            Item      = $item
            Size      = $measure.Size
            LastWrite = $measure.MaxLastWrite
        }
        $planned += $measure.Size
    }

    if ($unmeasured -gt 0) {
        Write-Log ('{0} item(s) could not be measured and are not counted in the total.' -f $unmeasured) -Level Warn
    }

    Write-Log ('{0}: {1} item(s) older than {2} day(s), {3}. {4} item(s) kept.' -f $Path, $candidates.Count, $Days, (Format-Bytes $planned), $kept) -Level Step

    if ($candidates.Count -eq 0) {
        Write-Log 'Nothing in scope. Leaving everything alone.' -Level Good
        return 0
    }

    if (-not $Execute) {
        Show-ItemList -Names @($candidates | ForEach-Object { '{0} (last written {1:yyyy-MM-dd})' -f $_.Item.FullName, $_.LastWrite })
        Write-Log ('DRY RUN complete. {0} would be freed. Rerun with -Execute to act.' -f (Format-Bytes $planned)) -Level Warn
        return 0
    }

    $action = ('Delete {0} of Windows Update payload in place, with Windows Update stopped' -f (Format-Bytes $planned))
    if (-not $PSCmdlet.ShouldProcess($Path, $action)) { return 0 }

    $exitCode = 0
    $bytesFailed = 0L
    $failures = 0
    $freeBefore = Get-SystemDriveFree
    $freeAfter = $null

    try {
        if (-not (Stop-UpdateService -Name $script:StopOrder)) {
            Write-Log 'Aborting without deleting anything, because a required service would not stop.' -Level Bad
            return 1
        }

        $running = @(Get-ServiceNotStopped -Name $script:StopOrder)
        if ($running.Count -gt 0) {
            Write-Log ('These services are running again: {0}. Aborting without deleting anything.' -f ($running -join ', ')) -Level Bad
            return 1
        }

        Write-Log ('Clearing {0}...' -f $Path) -Level Step
        $result = Remove-SelectedItem -Candidates $candidates
        $failures = $result.Failures
        $bytesFailed = $result.BytesFailed
        if ($result.Aborted) { $exitCode = 1 }

        # Sampled here, while the services are still down. After the finally block Windows
        # Update can start downloading again and the figure goes backwards.
        $freeAfter = Get-SystemDriveFree
    }
    finally {
        Restore-UpdateService
    }

    Write-Log ('Deleted {0}.' -f (Format-Bytes ($planned - $bytesFailed))) -Level Good
    Show-FreeSpaceDelta -Before $freeBefore -After $freeAfter

    if ($failures -gt 0) {
        Write-Log ('{0} item(s) could not be deleted, holding {1}. They are usually still locked; rerun after a reboot.' -f $failures, (Format-Bytes $bytesFailed)) -Level Warn
        $exitCode = 1
    }

    Write-Log 'Windows Update rebuilds what it needs on the next scan.' -Level Good

    return $exitCode
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Confirm-FullReset {
    <#
        -Full is the most destructive mode in this script, so it gets a confirmation that
        no switch suppresses. -Full and -NonInteractive are rejected at argument validation
        for exactly this reason.
    #>
    Write-Log 'Full scope selected. Clearing DataStore resets the Windows Update database.' -Level Warn
    Write-Log 'You lose: update history.' -Level Warn
    Write-Log 'You lose: the hidden and declined update list, so hidden updates reappear and can install.' -Level Warn
    Write-Log 'You lose: cached WSUS or Intune deployment metadata and the last scan cookie, which forces a full' -Level Warn
    Write-Log '          metadata resync. That is slow on WSUS and expensive on a metered link.' -Level Warn
    Write-Log 'You lose: per-update retry and backoff state, so failing updates are retried immediately.' -Level Warn
    Write-Log 'You keep:  SusClientId, deferral and pause policy, and active hours. Those live in the registry.' -Level Warn

    $answer = Read-Host 'Type RESET to clear the update database, or anything else to abort'
    if ($answer -cne 'RESET') {
        Write-Log 'Aborted. Nothing was changed.' -Level Bad
        return $false
    }

    return $true
}

function Invoke-SoftwareDistributionCleanup {
    <#
        Returns the process exit code.
    #>
    if (-not $Execute) {
        Write-Log 'DRY RUN. Nothing will be deleted. Pass -Execute to act.' -Level Warn
    }

    if (-not (Test-Preflight)) { return 1 }

    if ($Full) {
        if ($Execute -and -not $WhatIfPreference) {
            if (-not (Confirm-FullReset)) { return 1 }
        }
        else {
            Write-Log 'Full scope selected. DataStore is in scope, which resets the update database.' -Level Warn
        }
    }

    if ($OlderThanDays -gt 0) {
        Write-Log ('Selective mode: -OlderThanDays {0} cannot use the rename path, so Windows Update stays stopped for the whole delete.' -f $OlderThanDays) -Level Warn
        return (Invoke-SelectiveCleanup -Path $script:DownloadPath -Days $OlderThanDays)
    }

    $scope = @($script:DownloadPath)
    if ($Full) { $scope += $script:DataStorePath }

    return (Invoke-RenameCleanup -Scope $scope)
}

# Before $ConfirmPreference is derived, because the dialog can change -NonInteractive.
if (Test-ShouldShowDialog) {
    if (-not (Show-OptionDialog)) {
        Write-Output 'Cancelled. Nothing was changed.'
        exit 0
    }

    # The dialog prevents invalid combinations, but verify rather than trust the UI.
    $invalid = Test-ParameterCombination
    if ($invalid) {
        Write-Error $invalid
        exit 1
    }
}

if ($NonInteractive) { $ConfirmPreference = 'None' }

$transcript = ''
$transcribing = $false

# Under -WhatIf both New-Item and Start-Transcript are no-ops, so claiming a transcript
# path here would be a lie and Stop-Transcript would fail on a host that is not recording.
if (-not $WhatIfPreference) {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    $transcript = Join-Path $LogDirectory ('SoftwareDistributionCleanup-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    try {
        Start-Transcript -Path $transcript -Force | Out-Null
        $transcribing = $true
    }
    catch {
        Write-Log ('Transcript unavailable: {0}' -f $_.Exception.Message) -Level Warn
    }
}

$mode = 'DRY RUN'
if ($Execute) { $mode = 'EXECUTE' }
Write-Log ('Mode: {0}' -f $mode) -Level Step
Write-Log ('Scope: Download{0}   Older than days: {1}' -f $(if ($Full) { ' + DataStore' } else { '' }), $OlderThanDays)
Write-Log ('Non-interactive: {0}   Ignore advisories: {1}   Verbose: {2}' -f [bool]$NonInteractive, [bool]$IgnoreAdvisories, ($VerbosePreference -ne 'SilentlyContinue'))

$result = 0

try {
    $result = Invoke-SoftwareDistributionCleanup
}
catch {
    Write-Log ('Unhandled error: {0}' -f $_.Exception.Message) -Level Bad
    $result = 1
}
finally {
    # Belt and braces. Idempotent, and a no-op when nothing was ever stopped.
    Restore-UpdateService
    Remove-EmptyMirrorSource

    if ($script:RestoreFailures -gt 0) {
        Write-Log ('{0} service(s) did not restart. Windows Update is not healthy until they do.' -f $script:RestoreFailures) -Level Bad
    }

    if ($transcribing) {
        Write-Log ('Transcript: {0}' -f $transcript)
        Stop-Transcript | Out-Null
    }
}

if ($script:RestoreFailures -gt 0 -and $result -eq 0) { $result = 1 }

Write-Output 'SoftwareDistribution cleanup complete...'
exit $result
