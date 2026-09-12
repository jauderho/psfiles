
<#
.SYNOPSIS
   Unblock StartComponentCleanup by removing jammed superseded packages first.

.DESCRIPTION
   For machines where "DISM /Online /Cleanup-Image /StartComponentCleanup" fails with
   error 1726 (RPC_S_CALL_FAILED) while AnalyzeComponentStore still works.

   WHAT THIS SCRIPT ACTUALLY DOES, AND WHAT IT DOES NOT

   Removing a superseded package with /Remove-Package de-registers the package. It does
   NOT perform component-level garbage collection, so on its own it reclaims little or no
   disk space. The step that frees the bytes is StartComponentCleanup - the step that is
   failing. This script therefore treats per-package removal as PREPARATION:

     1. Remove the individual superseded packages one at a time, in small transactions.
     2. Then run plain StartComponentCleanup, which now has far less to do.
     3. If that succeeds, verify the result with DISM /Cleanup-Image /RestoreHealth and
        then sfc /scannow. RestoreHealth comes first on purpose: sfc repairs system files
        using the component store as its source, so the store has to be sound before sfc
        can do anything useful. Use -SkipPostCleanupRepair to turn this off.

   The documented practitioner workflow is exactly this pairing: remove the package that
   is jamming cleanup, then run cleanup to recover the space. If you only run step 1 you
   will spend hours and free almost nothing, so step 1 is not offered on its own unless
   you explicitly pass -SkipFinalCleanup.

   WHY 1726 HAPPENS - THIS IS A HYPOTHESIS, NOT A DOCUMENTED MECHANISM

   The common explanation is that StartComponentCleanup removes every superseded package
   in one long servicing transaction, and on a large store that transaction outlives the
   RPC channel to TrustedInstaller. Microsoft documents no such mechanism. The better
   evidenced cause is that TiWorker.exe crashes (STATUS_STACK_OVERFLOW, 0xC00000FD) on
   specific bad component store metadata, and 1726 is the symptom the DISM client sees.

   If that is what is happening on your machine, per-package removal does not route around
   the problem - it hits the same crash on the same package. Before running this script:

     1. schtasks /Run /TN "\Microsoft\Windows\Servicing\StartComponentCleanup"
        (this script offers it as -UseScheduledTask, and it is the right first move)
     2. DISM /Online /Cleanup-Image /ScanHealth   and   sfc /scannow
     3. Read the tail of %SystemRoot%\Logs\CBS\CBS.log around the 1726 and find which
        package DISM was finalising when it died
     4. Check the Application event log for a TiWorker.exe crash at the same timestamp

   THIS SCRIPT DOES NOT MEASURE THE STORE. AnalyzeComponentStore walks the whole store and
   is by far the slowest thing it could do, for numbers that are reporting only. Run it
   yourself when you want them:

     DISM /Online /Cleanup-Image /AnalyzeComponentStore

   When you do, note that "Backups and Disabled Features" is not all superseded backups. It
   also covers disabled features whose payload is still present, component store metadata,
   and side-by-side components. Package removal touches only the first of those. Disabled
   features need DISM /Disable-Feature /Remove or capability removal instead, and the dry
   run prints those counts so you can see which part of the total is actually in scope.

   Note also that the eligible count here is not DISM's "Number of Reclaimable Packages".
   The two are defined differently and diverge in both directions, so do not expect them to
   agree.

   WINDOWS INSTALLER CACHE - OPT IN, OFF BY DEFAULT

   -IncludeInstallerCache adds a second, unrelated phase that tidies
   %SystemRoot%\Installer. That folder is not part of the component store: it holds the
   cached .msi and .msp packages Windows Installer needs in order to repair, modify, patch
   or uninstall an installed product. Deleting a package that is still referenced leaves
   that product permanently unrepairable and usually unremovable, recoverable only by
   reinstalling it.

   Because the downside is that bad, this phase is deliberately cautious:

     - The referenced set is read from the Windows Installer registry across EVERY user
       SID, not just the current user.
     - If that registry cannot be read, or yields no referenced packages at all, the phase
       refuses to run. An empty referenced set would condemn the entire cache.
     - Only top level .msi and .msp files are considered. $PatchCache$ holds the baseline
       packages used for future patching and is never touched, nor are the GUID subfolders
       that hold product icons.
     - Orphans are MOVED to %SystemRoot%\Installer.Orphaned\<timestamp>, never deleted, so
       a wrong call is reversible by moving the file back.
     - Disk space is therefore not reclaimed on the spot. A later run purges quarantine
       folders that have sat untouched for -PurgeInstallerQuarantineDays, which is what
       actually frees the space.

   The intended workflow is: run it, exercise repair/patch/uninstall on your applications
   for a few weeks, then run it again to purge.

   SAFETY

   - Dry run is the default. -Execute is required to remove anything.
   - Candidate selection is an ALLOW LIST on ReleaseType (ordinary updates only), plus a
     name deny list, plus a check that a higher-version package in the same family is
     genuinely Installed. Editions, language packs, foundation, feature packs, drivers,
     products and on-demand packages are never candidates even when superseded.
   - Nothing is ever retried. A timed-out removal has an UNKNOWN outcome: it may have
     committed, rolled back, or be mid-flight. Re-issuing it against a store in that state
     is how component stores get corrupted, so a timeout aborts the whole run.
   - Pending-reboot and concurrent-servicing are re-checked before EVERY removal, not once
     at startup.
   - Exit code 3010 (reboot required) aborts the run immediately.
   - The TrustedInstaller service is never stopped. Stopping it into an in-flight
     transaction finalize is a documented route to an unserviceable store.
   - TiWorker.exe is never killed. On timeout only the DISM client is terminated, then the
     script waits for servicing to go quiet, re-reads the real package state, and stops.
   - Image health is a HARD STOP that no switch overrides. If health cannot be determined,
     that is also a hard stop - a guard that cannot evaluate is a guard that failed.
   - /ResetBase is deliberately NOT offered. It makes every installed update permanent, it
     routinely runs over an hour on a large store, and it is not needed to reclaim space.

.PARAMETER Elevated
   Internal. Set automatically when the script relaunches itself elevated.

.PARAMETER Execute
   Perform removals and the final cleanup. Without this the script reports what it would
   do and changes nothing.

.PARAMETER DryRun
   Explicitly request a dry run. This is the default. Cannot be combined with -Execute.

.PARAMETER NonInteractive
   Do not prompt for confirmation. Intended for scheduled runs. This suppresses prompts
   only; it does not relax any safety check.

.PARAMETER IgnoreAdvisories
   Proceed past advisory warnings (low disk space, failed restore point, TrustedInstaller
   service still running). It cannot override a hard stop, and in particular it cannot
   override the image health check.

.PARAMETER SkipRestorePoint
   Do not attempt a system restore point. A restore point is weak protection for component
   store changes and failing to create one is only ever a warning, never a block.

.PARAMETER UseScheduledTask
   Skip per-package removal and instead trigger the built-in
   \Microsoft\Windows\Servicing\StartComponentCleanup scheduled task. It runs under
   TrustedInstaller at low priority with a one hour cap and often succeeds where the DISM
   command line returns 1726. Try this before anything else in this script.

.PARAMETER SkipFinalCleanup
   Remove the superseded packages but do not run StartComponentCleanup afterwards. This
   will reclaim little or no disk space - see the description. Use only when you intend to
   run cleanup yourself.

.PARAMETER NoUI
   Never show the option dialog. The dialog already suppresses itself when the session is
   not interactive, when -NonInteractive is given, or when a mode was named on the command
   line, so this is only needed to force the command line path in an interactive session.

.PARAMETER IncludeInstallerCache
   Also tidy %SystemRoot%\Installer. Off by default. Orphaned .msi and .msp packages are
   moved to a quarantine folder, not deleted. See the description for the full rationale.
   This phase is skipped if the component store phase did not finish cleanly.

.PARAMETER PurgeInstallerQuarantineDays
   How long a quarantine folder must sit untouched before a later run deletes it.
   Default 30. Only meaningful with -IncludeInstallerCache.

.PARAMETER MaxPackages
   Stop after this many successful removals. 0 (default) means no limit. Use a small
   number such as 5 for a cautious first pass.

.PARAMETER TimeoutMinutes
   Per-package DISM timeout. Default 30. Reaching it aborts the run.

.PARAMETER CleanupTimeoutMinutes
   Timeout for the final StartComponentCleanup. Default 240. Cleanup on a large store
   routinely exceeds an hour, so do not lower this to match TimeoutMinutes.

.PARAMETER MaxRunHours
   Global wall-clock budget. Default 8. The run stops cleanly at the next package boundary
   once exceeded.

.PARAMETER SkipPostCleanupRepair
   Do not run the verification pass after a successful StartComponentCleanup. By default,
   once cleanup genuinely completes, the script runs DISM /Cleanup-Image /RestoreHealth and
   then sfc /scannow, in that order. Neither removes anything, but both are long, so this
   switch turns them off.

.PARAMETER RepairTimeoutMinutes
   Timeout for each of RestoreHealth and sfc in the verification pass. Default 120.

.PARAMETER ScratchDirectory
   An existing local directory for DISM's working files, passed as /ScratchDir. By default
   DISM stages under %WINDIR%\Temp, on the same volume as the component store, which is the
   wrong place when that volume is short of space. Point this at another drive.

.PARAMETER MinimumFreeSpaceGB
   Hard floor for free space on the system drive. Default 2. Checked at preflight and again
   before every single removal, because a long run can drift a long way from where preflight
   measured. Servicing a volume to zero can corrupt the store, so the run stops rather than
   continuing into it.

.PARAMETER CleanupEvery
   Run StartComponentCleanup after every this many successful removals, to reclaim space as
   you go instead of only at the end. 0 (default) means only at the end. Useful when disk
   space is tight, because removals de-register packages but the bytes only come back when
   cleanup runs. An interim cleanup that fails is logged and the run continues, which is
   expected while the component graph is still large.

.PARAMETER StopWhenFreeSpaceGB
   Stop cleanly once free space on the system drive reaches this figure. 0 (default) means
   run to completion. Use it when you need a specific amount of headroom rather than every
   last byte.

.PARAMETER ReclaimLogSpace
   Before starting, delete archived CBS logs (CbsPersist_*.log and the .cab copies beside
   them). These are pure history and Windows recreates what it needs. On a machine that has
   been crashing repeatedly they can be worth hundreds of megabytes. The live CBS.log is
   left alone.

.PARAMETER ServicingWaitMinutes
   How long to wait at preflight for the Windows Update orchestrator to settle. Default 45.
   The orchestrator does housekeeping even when updates are paused, so waiting for it is
   normally right. A second DISM client is never waited for; that is always a hard stop.

.PARAMETER LogDirectory
   Where to write the transcript and the package inventory CSV.
   Default %SystemRoot%\Logs\ComponentCleanup.

.EXAMPLE
   .\ComponentCleanup.ps1
   Elevates, then shows an option dialog to pick dry run or execute and set the rest.
   Naming a mode on the command line skips the dialog entirely.

.EXAMPLE
   .\ComponentCleanup.ps1 -DryRun
   Dry run with no dialog. Reports the store breakdown, the candidate set, and what it
   cannot address.

.EXAMPLE
   .\ComponentCleanup.ps1 -UseScheduledTask -Execute
   Least invasive option, and the one to try first.

.EXAMPLE
   .\ComponentCleanup.ps1 -Execute -MaxPackages 5
   Cautious first pass. Removes at most five packages, then runs cleanup.

.EXAMPLE
   .\ComponentCleanup.ps1 -Execute -NonInteractive
   Unattended full pass. Still aborts on any hard stop.

.EXAMPLE
   .\ComponentCleanup.ps1 -Execute -ReclaimLogSpace -ScratchDirectory D:\DismScratch -CleanupEvery 25
   Low disk space run. Reclaims archived log space first, keeps DISM's working files off the
   system volume, and reclaims component space every 25 removals instead of only at the end.

.EXAMPLE
   .\ComponentCleanup.ps1 -Execute -CleanupEvery 25 -StopWhenFreeSpaceGB 25
   Same incremental approach, but stops as soon as there is 25 GB free rather than removing
   every eligible package.

.EXAMPLE
   .\ComponentCleanup.ps1 -IncludeInstallerCache
   Dry run that also reports which Windows Installer packages are orphaned.

.EXAMPLE
   .\ComponentCleanup.ps1 -Execute -IncludeInstallerCache
   Component store cleanup, then move orphaned installer packages to quarantine. Rerun in
   30 days to purge the quarantine and actually reclaim that space.

.NOTES
   Created by Jauder Ho
   Last modified 9/11/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   Requires PowerShell 5.1 or later, the DISM module, and an elevated session.

   If removals keep failing, read %SystemRoot%\Logs\CBS\CBS.log and
   %SystemRoot%\Logs\DISM\dism.log. Failures across many packages mean store corruption,
   not a cleanup problem; run DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow
   before trying again. This script does not run those for you - they are long operations
   that can need source media and should be a considered decision.

.LINK
   https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Elevated,
    [switch]$Execute,
    [switch]$DryRun,
    [switch]$NonInteractive,
    [switch]$IgnoreAdvisories,
    [switch]$SkipRestorePoint,
    [switch]$UseScheduledTask,
    [switch]$SkipFinalCleanup,
    [switch]$NoUI,
    [switch]$IncludeInstallerCache,
    [ValidateRange(1, 3650)]
    [int]$PurgeInstallerQuarantineDays = 30,
    [ValidateRange(0, 10000)]
    [int]$MaxPackages = 0,
    [ValidateRange(1, 480)]
    [int]$TimeoutMinutes = 30,
    [ValidateRange(1, 1440)]
    [int]$CleanupTimeoutMinutes = 240,
    [ValidateRange(1, 168)]
    [int]$MaxRunHours = 8,
    [ValidateRange(0, 480)]
    [int]$ServicingWaitMinutes = 45,
    [string]$ScratchDirectory = '',
    [ValidateRange(1, 100)]
    [int]$MinimumFreeSpaceGB = 2,
    [ValidateRange(0, 10000)]
    [int]$CleanupEvery = 0,
    [ValidateRange(0, 10000)]
    [int]$StopWhenFreeSpaceGB = 0,
    [switch]$ReclaimLogSpace,
    [switch]$SkipPostCleanupRepair,
    [ValidateRange(1, 1440)]
    [int]$RepairTimeoutMinutes = 120,
    [string]$LogDirectory = (Join-Path $env:SystemRoot 'Logs\ComponentCleanup')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Candidate selection policy
# ---------------------------------------------------------------------------

# ALLOW LIST on DismReleaseType. Only ordinary update packages are ever candidates.
# Everything else - Foundation, FeaturePack, LanguagePack, LocalPack, OnDemandPack,
# Driver, Product, ServicePack, Other - is structural and is never removed here, because
# a superseded structural package can still be the CBS parent of installed updates.
$script:AllowedReleaseTypes = @(
    'Update'
    'SecurityUpdate'
    'CriticalUpdate'
    'UpdateRollup'
    'Hotfix'
    'SoftwareUpdate'
)

# Name deny list, applied on top of the allow list as defence in depth. Edition packages
# are the parent that cumulative updates declare, and they go Superseded on every CU.
# Note that servicing stack updates on 24H2 are named Package_for_KB<n>, so the
# ServicingStack pattern does NOT catch them - only CBS's own permanence flag does. That
# is why the ReleaseType allow list above is the primary gate, not this list.
$script:NeverRemovePatterns = @(
    '(?i)ServicingStack'
    '(?i)Foundation'
    '(?i)Edition'
    '(?i)LanguagePack'
    '(?i)SecureBoot'
    '(?i)BootEnvironment'
    '(?i)WinPE'
    '(?i)OnDemand'
)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

$script:ExitRebootRequired = 3010
$script:ExitTimedOut = -1

# Codes that mean "stop the entire run now".
$script:AbortExitCodes = @{
    3010         = 'ERROR_SUCCESS_REBOOT_REQUIRED - a reboot is required before servicing can continue'
    -2146498269  = '0x800F0923 - pending servicing operations; reboot before continuing'
}

# Codes that mean "this package cannot be removed, but the run may continue".
$script:SkipExitCodes = @{
    -2146498523  = '0x800F0825 CBS_E_CANNOT_UNINSTALL - package is permanent or has dependents'
    -2146498529  = '0x800F081F CBS_E_SOURCE_MISSING - source files missing'
    112          = '112 ERROR_DISK_FULL - ran out of disk space part way through'
    -2147024784  = '0x80070070 ERROR_DISK_FULL - ran out of disk space part way through'
    -2147024891  = '0x80070005 E_ACCESSDENIED'
    1726         = '1726 RPC_S_CALL_FAILED - the servicing worker failed on this package'
    -2147023170  = '0x800706BE RPC_S_CALL_FAILED - the servicing worker failed on this package'
    1722         = '1722 RPC_S_SERVER_UNAVAILABLE'
    -2147023174  = '0x800706BA RPC_S_SERVER_UNAVAILABLE'
}

# ---------------------------------------------------------------------------
# Elevation. Matches the pattern used by the other scripts in this repo.
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
# ---------------------------------------------------------------------------

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function ConvertTo-RelaunchArgument {
    <#
        Quotes a value for CommandLineToArgvW. A trailing run of backslashes would
        otherwise escape the closing quote and swallow the following argument.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    return ('"{0}"' -f ($Value -replace '(\\*)$', '$1$1'))
}

function Test-ParameterCombination {
    <#
        Returns a message describing the first invalid combination, or $null when the
        current settings are coherent. Called before elevation, and again after the option
        dialog, because the dialog can change what was chosen.
    #>
    if ($Execute -and $DryRun) { return '-Execute and -DryRun are mutually exclusive.' }
    if ($SkipFinalCleanup -and -not $Execute) { return '-SkipFinalCleanup only has meaning with -Execute.' }
    return $null
}

# Argument validation runs before elevation so an invalid invocation cannot trigger a UAC
# prompt and then print its error into a window the caller never sees.
$invalid = Test-ParameterCombination
if ($invalid) {
    Write-Error $invalid
    exit 1
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
    $relaunch += @(
        '-File'
        (ConvertTo-RelaunchArgument -Value $PSCommandPath)
        '-Elevated'
    )

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'Elevated') { continue }
        if ($entry.Value -is [switch]) {
            # Emit the explicit boolean so -Confirm:$false and -Verbose:$false survive.
            $relaunch += ('-{0}:${1}' -f $entry.Key, $entry.Value.IsPresent)
        }
        else {
            $relaunch += ('-{0}' -f $entry.Key)
            $relaunch += (ConvertTo-RelaunchArgument -Value ([string]$entry.Value))
        }
    }

    try {
        if ($interactive) {
            Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunch | Out-Null
            exit 0
        }

        # No console to read in an automated context, so wait and report the real result.
        $child = Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunch -PassThru -Wait
        exit $child.ExitCode
    }
    catch {
        Write-Error 'Elevation was declined or failed.'
        exit 1
    }
}

Write-Output 'Running with full privileges...'

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

function Get-DismExitCodeName {
    param([AllowNull()][Nullable[int]]$ExitCode)

    if ($null -eq $ExitCode) { return 'no exit code reported' }
    if ($ExitCode -eq $script:ExitTimedOut) { return 'timed out (client terminated)' }
    if ($script:AbortExitCodes.ContainsKey($ExitCode)) { return $script:AbortExitCodes[$ExitCode] }
    if ($script:SkipExitCodes.ContainsKey($ExitCode)) { return $script:SkipExitCodes[$ExitCode] }

    return ('{0} (0x{1:X8})' -f $ExitCode, $ExitCode)
}

# ---------------------------------------------------------------------------
# Option dialog
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

    foreach ($explicit in @('Execute', 'DryRun', 'UseScheduledTask')) {
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
    $form.Text = 'Component Cleanup'
    # Tall form. Cap it to the usable screen height and let it scroll, so it still works on
    # a laptop display rather than pushing the buttons off the bottom.
    $wanted = 760
    $available = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height - 60
    $form.ClientSize = New-Object Drawing.Size(520, [Math]::Min($wanted, $available))
    $form.AutoScroll = $true
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    # The UAC transition can leave a new window behind the console otherwise.
    $form.Topmost = $true

    $intro = New-Object Windows.Forms.Label
    $intro.Location = New-Object Drawing.Point(12, 12)
    $intro.Size = New-Object Drawing.Size(496, 40)
    $intro.Text = "Removes superseded component packages one at a time, then runs StartComponentCleanup to reclaim the space.`r`nStart with a dry run, or with the scheduled task, before executing."
    $form.Controls.Add($intro)

    # --- Mode ---------------------------------------------------------------
    $modeBox = New-Object Windows.Forms.GroupBox
    $modeBox.Text = 'Mode'
    $modeBox.Location = New-Object Drawing.Point(12, 56)
    $modeBox.Size = New-Object Drawing.Size(496, 76)
    $form.Controls.Add($modeBox)

    $radioDry = New-Object Windows.Forms.RadioButton
    $radioDry.Text = 'Dry run - report only, change nothing (recommended first)'
    $radioDry.Location = New-Object Drawing.Point(15, 20)
    $radioDry.Size = New-Object Drawing.Size(465, 22)
    $radioDry.Checked = -not $Execute
    $modeBox.Controls.Add($radioDry)

    $radioExecute = New-Object Windows.Forms.RadioButton
    $radioExecute.Text = 'Execute - remove packages and reclaim space'
    $radioExecute.Location = New-Object Drawing.Point(15, 46)
    $radioExecute.Size = New-Object Drawing.Size(465, 22)
    $radioExecute.Checked = [bool]$Execute
    $modeBox.Controls.Add($radioExecute)

    # --- What to do ---------------------------------------------------------
    $actionBox = New-Object Windows.Forms.GroupBox
    $actionBox.Text = 'What to do'
    $actionBox.Location = New-Object Drawing.Point(12, 140)
    $actionBox.Size = New-Object Drawing.Size(496, 180)
    $form.Controls.Add($actionBox)

    $chkTask = New-Object Windows.Forms.CheckBox
    $chkTask.Text = 'Use the built-in servicing scheduled task instead (least invasive)'
    $chkTask.Location = New-Object Drawing.Point(15, 20)
    $chkTask.Size = New-Object Drawing.Size(465, 22)
    $chkTask.Checked = [bool]$UseScheduledTask
    $actionBox.Controls.Add($chkTask)

    $chkSkipCleanup = New-Object Windows.Forms.CheckBox
    $chkSkipCleanup.Text = 'Skip the final StartComponentCleanup (frees almost nothing)'
    $chkSkipCleanup.Location = New-Object Drawing.Point(15, 44)
    $chkSkipCleanup.Size = New-Object Drawing.Size(465, 22)
    $chkSkipCleanup.Checked = [bool]$SkipFinalCleanup
    $actionBox.Controls.Add($chkSkipCleanup)

    $chkInstaller = New-Object Windows.Forms.CheckBox
    $chkInstaller.Text = 'Also quarantine orphaned Windows Installer packages'
    $chkInstaller.Location = New-Object Drawing.Point(15, 68)
    $chkInstaller.Size = New-Object Drawing.Size(465, 22)
    $chkInstaller.Checked = [bool]$IncludeInstallerCache
    $actionBox.Controls.Add($chkInstaller)

    $chkReclaimLogs = New-Object Windows.Forms.CheckBox
    $chkReclaimLogs.Text = 'Delete archived CBS logs first (safe, often hundreds of MB)'
    $chkReclaimLogs.Location = New-Object Drawing.Point(15, 92)
    $chkReclaimLogs.Size = New-Object Drawing.Size(465, 22)
    $chkReclaimLogs.Checked = [bool]$ReclaimLogSpace
    $actionBox.Controls.Add($chkReclaimLogs)

    $chkRepair = New-Object Windows.Forms.CheckBox
    $chkRepair.Text = 'After a successful cleanup, run RestoreHealth then sfc (slow)'
    $chkRepair.Location = New-Object Drawing.Point(15, 116)
    $chkRepair.Size = New-Object Drawing.Size(465, 22)
    $chkRepair.Checked = -not $SkipPostCleanupRepair
    $actionBox.Controls.Add($chkRepair)

    $labelMax = New-Object Windows.Forms.Label
    $labelMax.Text = 'Stop after this many removals (0 = no limit):'
    $labelMax.Location = New-Object Drawing.Point(15, 146)
    $labelMax.Size = New-Object Drawing.Size(360, 22)
    $actionBox.Controls.Add($labelMax)

    $numMax = New-Object Windows.Forms.NumericUpDown
    $numMax.Location = New-Object Drawing.Point(400, 144)
    $numMax.Size = New-Object Drawing.Size(80, 22)
    $numMax.Minimum = 0
    $numMax.Maximum = 10000
    $numMax.Value = $MaxPackages
    $actionBox.Controls.Add($numMax)

    # --- Disk space ---------------------------------------------------------
    $spaceBox = New-Object Windows.Forms.GroupBox
    $spaceBox.Text = 'Disk space'
    $spaceBox.Location = New-Object Drawing.Point(12, 328)
    $spaceBox.Size = New-Object Drawing.Size(496, 162)
    $form.Controls.Add($spaceBox)

    $labelScratch = New-Object Windows.Forms.Label
    $labelScratch.Text = 'DISM working directory, ideally on another volume:'
    $labelScratch.Location = New-Object Drawing.Point(15, 20)
    $labelScratch.Size = New-Object Drawing.Size(465, 20)
    $spaceBox.Controls.Add($labelScratch)

    $txtScratch = New-Object Windows.Forms.TextBox
    $txtScratch.Location = New-Object Drawing.Point(15, 42)
    $txtScratch.Size = New-Object Drawing.Size(378, 22)
    $txtScratch.Text = [string]$ScratchDirectory
    $spaceBox.Controls.Add($txtScratch)

    $btnBrowse = New-Object Windows.Forms.Button
    $btnBrowse.Text = 'Browse...'
    $btnBrowse.Location = New-Object Drawing.Point(399, 41)
    $btnBrowse.Size = New-Object Drawing.Size(81, 24)
    $spaceBox.Controls.Add($btnBrowse)

    $labelMin = New-Object Windows.Forms.Label
    $labelMin.Text = 'Stop if free space falls below (GB):'
    $labelMin.Location = New-Object Drawing.Point(15, 76)
    $labelMin.Size = New-Object Drawing.Size(360, 22)
    $spaceBox.Controls.Add($labelMin)

    $numMin = New-Object Windows.Forms.NumericUpDown
    $numMin.Location = New-Object Drawing.Point(400, 74)
    $numMin.Size = New-Object Drawing.Size(80, 22)
    $numMin.Minimum = 1
    $numMin.Maximum = 100
    $numMin.Value = $MinimumFreeSpaceGB
    $spaceBox.Controls.Add($numMin)

    $labelEvery = New-Object Windows.Forms.Label
    $labelEvery.Text = 'Reclaim space every N removals (0 = only at end):'
    $labelEvery.Location = New-Object Drawing.Point(15, 104)
    $labelEvery.Size = New-Object Drawing.Size(360, 22)
    $spaceBox.Controls.Add($labelEvery)

    $numEvery = New-Object Windows.Forms.NumericUpDown
    $numEvery.Location = New-Object Drawing.Point(400, 102)
    $numEvery.Size = New-Object Drawing.Size(80, 22)
    $numEvery.Minimum = 0
    $numEvery.Maximum = 10000
    $numEvery.Value = $CleanupEvery
    $spaceBox.Controls.Add($numEvery)

    $labelStop = New-Object Windows.Forms.Label
    $labelStop.Text = 'Stop once free space reaches (GB, 0 = run all):'
    $labelStop.Location = New-Object Drawing.Point(15, 132)
    $labelStop.Size = New-Object Drawing.Size(360, 22)
    $spaceBox.Controls.Add($labelStop)

    $numStop = New-Object Windows.Forms.NumericUpDown
    $numStop.Location = New-Object Drawing.Point(400, 130)
    $numStop.Size = New-Object Drawing.Size(80, 22)
    $numStop.Minimum = 0
    $numStop.Maximum = 10000
    $numStop.Value = $StopWhenFreeSpaceGB
    $spaceBox.Controls.Add($numStop)

    # --- Overrides ----------------------------------------------------------
    $overrideBox = New-Object Windows.Forms.GroupBox
    $overrideBox.Text = 'Overrides - these reduce the safety margin'
    $overrideBox.Location = New-Object Drawing.Point(12, 498)
    $overrideBox.Size = New-Object Drawing.Size(496, 106)
    $form.Controls.Add($overrideBox)

    $chkNonInteractive = New-Object Windows.Forms.CheckBox
    $chkNonInteractive.Text = 'Do not ask again per package'
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

    $chkNoRestore = New-Object Windows.Forms.CheckBox
    $chkNoRestore.Text = 'Do not attempt a system restore point'
    $chkNoRestore.Location = New-Object Drawing.Point(15, 74)
    $chkNoRestore.Size = New-Object Drawing.Size(465, 22)
    $chkNoRestore.Checked = [bool]$SkipRestorePoint
    $overrideBox.Controls.Add($chkNoRestore)

    $chkVerbose = New-Object Windows.Forms.CheckBox
    $chkVerbose.Text = 'Verbose output - show every DISM command and step in detail'
    $chkVerbose.Location = New-Object Drawing.Point(15, 612)
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
    $notice.Location = New-Object Drawing.Point(12, 640)
    $notice.Size = New-Object Drawing.Size(496, 62)
    $notice.ForeColor = [Drawing.Color]::FromArgb(150, 20, 20)
    $form.Controls.Add($notice)

    $buttonRun = New-Object Windows.Forms.Button
    $buttonRun.Text = 'Run'
    $buttonRun.Location = New-Object Drawing.Point(322, 718)
    $buttonRun.Size = New-Object Drawing.Size(90, 28)
    $buttonRun.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonRun)
    $form.AcceptButton = $buttonRun

    $buttonCancel = New-Object Windows.Forms.Button
    $buttonCancel.Text = 'Cancel'
    $buttonCancel.Location = New-Object Drawing.Point(418, 718)
    $buttonCancel.Size = New-Object Drawing.Size(90, 28)
    $buttonCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)
    $form.CancelButton = $buttonCancel

    $btnBrowse.Add_Click({
            $browse = New-Object Windows.Forms.FolderBrowserDialog
            $browse.Description = 'Choose a directory for DISM working files, ideally on another volume'
            if ($browse.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
                $txtScratch.Text = $browse.SelectedPath
            }
            $browse.Dispose()
        })

    $refresh = {
        $executing = $radioExecute.Checked
        $taskMode = $chkTask.Checked

        # The scheduled task does its own thing; per-package settings do not apply to it.
        $chkSkipCleanup.Enabled = $executing -and -not $taskMode
        $numMax.Enabled = $executing -and -not $taskMode
        $labelMax.Enabled = $numMax.Enabled
        $chkInstaller.Enabled = -not $taskMode

        # The verification pass only runs after a cleanup this script performed.
        $chkRepair.Enabled = $executing -and -not $taskMode -and -not $chkSkipCleanup.Checked

        # The log reclaim reports in dry run and acts in execute, so it is always offered.
        $chkReclaimLogs.Enabled = -not $taskMode

        # Nothing in the disk space group applies to a dry run, because no DISM servicing
        # call is made and nothing is removed.
        $spaceActive = $executing -and -not $taskMode
        $spaceBox.Enabled = $spaceActive
        $numEvery.Enabled = $spaceActive -and -not $chkSkipCleanup.Checked
        $labelEvery.Enabled = $numEvery.Enabled

        $chkNonInteractive.Enabled = $executing
        $chkIgnore.Enabled = $executing
        $chkNoRestore.Enabled = $executing -and -not $taskMode

        if (-not $chkSkipCleanup.Enabled) { $chkSkipCleanup.Checked = $false }
        if ($taskMode) { $chkNoRestore.Checked = $false }
        if (-not $numEvery.Enabled) { $numEvery.Value = 0 }

        $lines = @()
        if ($taskMode) {
            $lines += 'The built-in servicing task runs under TrustedInstaller with a one hour cap. Nothing else in this script runs.'
        }
        elseif ($executing) {
            $lines += 'Packages will be removed. This is not reversible: you lose the ability to uninstall the updates that superseded them.'
            if ($chkSkipCleanup.Checked) {
                $lines += 'Skipping the final cleanup means almost no disk space will be reclaimed.'
            }
        }
        else {
            $lines += 'Dry run. Nothing will be changed.'
        }

        if ($chkInstaller.Checked) {
            $lines += 'Orphaned installer packages are moved to a quarantine folder, not deleted, so no space is freed until a later run purges it.'
        }

        $notice.Text = ($lines -join "`r`n")
    }

    $radioDry.Add_CheckedChanged($refresh)
    $radioExecute.Add_CheckedChanged($refresh)
    $chkTask.Add_CheckedChanged($refresh)
    $chkSkipCleanup.Add_CheckedChanged($refresh)
    $chkInstaller.Add_CheckedChanged($refresh)
    & $refresh

    $answer = $form.ShowDialog()
    $accepted = ($answer -eq [Windows.Forms.DialogResult]::OK)

    if ($accepted) {
        $script:Execute = [switch]$radioExecute.Checked
        $script:DryRun = [switch]$radioDry.Checked
        $script:UseScheduledTask = [switch]$chkTask.Checked
        $script:SkipFinalCleanup = [switch]($chkSkipCleanup.Enabled -and $chkSkipCleanup.Checked)
        $script:IncludeInstallerCache = [switch]($chkInstaller.Enabled -and $chkInstaller.Checked)
        $script:ReclaimLogSpace = [switch]($chkReclaimLogs.Enabled -and $chkReclaimLogs.Checked)
        $script:SkipPostCleanupRepair = [switch](-not ($chkRepair.Enabled -and $chkRepair.Checked))
        $script:NonInteractive = [switch]($chkNonInteractive.Enabled -and $chkNonInteractive.Checked)
        $script:IgnoreAdvisories = [switch]($chkIgnore.Enabled -and $chkIgnore.Checked)
        $script:SkipRestorePoint = [switch]($chkNoRestore.Enabled -and $chkNoRestore.Checked)
        $script:MaxPackages = [int]$numMax.Value

        if ($spaceBox.Enabled) {
            $script:ScratchDirectory = $txtScratch.Text.Trim()
            $script:MinimumFreeSpaceGB = [int]$numMin.Value
            $script:CleanupEvery = [int]$numEvery.Value
            $script:StopWhenFreeSpaceGB = [int]$numStop.Value
        }

        # Dynamic scoping puts this in reach of Write-Verbose everywhere in the script.
        if ($chkVerbose.Checked) { $script:VerbosePreference = 'Continue' }
        else { $script:VerbosePreference = 'SilentlyContinue' }
    }

    $form.Dispose()
    return $accepted
}

# ---------------------------------------------------------------------------
# Servicing state
# ---------------------------------------------------------------------------

function Get-SystemDriveFree {
    $drive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($drive -and $null -ne $drive.Free) { return [long]$drive.Free }
    return $null
}

function Invoke-ReclaimLogSpace {
    <#
        Servicing logs are the safest space on the disk to reclaim, and on a machine that
        has been crashing repeatedly they are often large. CbsPersist_*.log are archives of
        previous CBS.log generations and are pure history; the .cab files beside them are
        compressed copies of the same thing. Windows recreates whatever it needs.

        The live CBS.log is deliberately left alone here. Rotating it needs TrustedInstaller
        stopped, which belongs in Dism1726Repair.ps1, not in the middle of a removal run.
    #>
    $logDir = Join-Path $env:SystemRoot 'Logs\CBS'
    if (-not (Test-Path -LiteralPath $logDir)) { return }

    $stale = @(Get-ChildItem -LiteralPath $logDir -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)^CbsPersist_.*\.(log|cab)$' -or $_.Name -match '(?i)^CBS\..*\.old\.log$' })

    if ($stale.Count -eq 0) {
        Write-Log 'No archived CBS logs to reclaim.'
        return
    }

    $size = 0L
    foreach ($file in $stale) { $size += $file.Length }

    Write-Log ('{0} archived CBS log(s) totalling {1}.' -f $stale.Count, (Format-Bytes $size)) -Level Step

    if (-not $Execute) {
        Write-Log ('DRY RUN: would delete {0} of archived servicing logs.' -f (Format-Bytes $size)) -Level Warn
        return
    }

    if (-not $PSCmdlet.ShouldProcess($logDir, ('Delete {0} archived log file(s)' -f $stale.Count))) { return }

    $freed = 0L
    foreach ($file in $stale) {
        try {
            $length = $file.Length
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $freed += $length
        }
        catch {
            Write-Verbose ('Could not delete {0}: {1}' -f $file.Name, $_.Exception.Message)
        }
    }

    Write-Log ('Reclaimed {0} from archived servicing logs.' -f (Format-Bytes $freed)) -Level Good
}

function Get-PendingRebootReason {
    $reasons = @()
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'

    foreach ($key in @('RebootPending', 'RebootInProgress', 'PackagesPending')) {
        if (Test-Path (Join-Path $cbs $key)) { $reasons += ('Component Based Servicing\{0}' -f $key) }
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'WindowsUpdate\Auto Update\RebootRequired'
    }

    if (Test-Path (Join-Path $env:SystemRoot 'WinSxS\pending.xml')) {
        $reasons += 'WinSxS\pending.xml'
    }

    # Returned bare, not as ,$reasons. Every caller wraps the call in @(), which normalises
    # empty, single and multiple correctly. A leading comma would defeat that @() and make
    # .Count always 1.
    return $reasons
}

function Get-CompetingDismClient {
    <#
        Another DISM client means a second servicing transaction. That is a genuine hard
        stop and is never waited out - it is usually another copy of one of these scripts
        left running in a different window.
    #>
    $reasons = @()

    $found = @(Get-Process -Name 'dism' -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) {
        $reasons += ('dism.exe is running (PID {0})' -f ($found.Id -join ', '))
    }

    return $reasons
}

function Get-ForeignServicingReason {
    <#
        Windows Update servicing driven by the orchestrator. Windows Update installs through
        TiWorker driven by MoUsoCoreWorker and never spawns a dism.exe, so checking for dism
        alone - as an earlier version of this script did - detects almost nothing.

        This is something to WAIT for, not to abort over. The orchestrator does housekeeping
        even when updates are paused, so treating it as a hard stop makes the script
        unusable at random.
    #>
    $reasons = @()

    $found = @(Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) {
        $reasons += ('TiWorker.exe is running (PID {0})' -f ($found.Id -join ', '))
    }

    return $reasons
}

function Get-OrchestratorActivity {
    <#
        MoUsoCoreWorker is the Update Orchestrator's worker. It decides what to scan,
        download and install, and it drives TiWorker - but it does not itself touch the
        component store, so it does not conflict with a package removal.

        It is reported and never waited on. It wakes on timers and restarts frequently even
        with updates paused, so waiting for it to disappear can wait forever. If it does
        start real servicing, TiWorker appears and the per-candidate check catches it.
    #>
    $reasons = @()

    $found = @(Get-Process -Name 'MoUsoCoreWorker' -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) {
        $reasons += ('MoUsoCoreWorker.exe is running (PID {0})' -f ($found.Id -join ', '))
    }

    return $reasons
}

function Test-ServicingQuiet {
    <#
        Without -Thorough this checks only the ServicingInProgress flag, which is the
        signal that CBS is actually mid-transaction. TrustedInstaller.exe and TiWorker.exe
        linger after a completed transaction until their idle timeout, so waiting on them
        between every package would add that timeout to each of 70 iterations.

        -Thorough adds both processes, and is used on the abort path where the outcome of a
        killed transaction is unknown and the extra wait is worth it.
    #>
    param([switch]$Thorough)

    $busy = @()

    if ($Thorough) {
        foreach ($name in @('TiWorker', 'TrustedInstaller')) {
            $found = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) { $busy += ('{0}.exe' -f $name) }
        }
    }

    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    $flag = Get-ItemProperty -Path $cbs -Name 'ServicingInProgress' -ErrorAction SilentlyContinue
    if ($flag -and $flag.PSObject.Properties['ServicingInProgress'] -and $flag.ServicingInProgress -ne 0) {
        $busy += 'ServicingInProgress flag'
    }

    return $busy
}

function Wait-ServicingQuiet {
    <#
        Waits for CBS to finish whatever it is doing. This replaces the fixed sleep an
        earlier version used between packages: it returns in under a second on an idle
        machine and actually waits on a busy one.

        TiWorker is never killed, and the TrustedInstaller service is never stopped.
        Stopping it into an in-flight transaction finalize is a documented route to an
        unserviceable store.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$WaitMinutes,
        [switch]$Thorough
    )

    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $announced = $false

    while ($true) {
        $busy = @(Test-ServicingQuiet -Thorough:$Thorough)
        if ($busy.Count -eq 0) { return $true }

        if ((Get-Date) -ge $deadline) {
            Write-Log ('Servicing is still busy after {0} minute(s): {1}' -f $WaitMinutes, ($busy -join ', ')) -Level Bad
            return $false
        }

        if (-not $announced) {
            Write-Log ('Waiting for servicing to go quiet ({0})...' -f ($busy -join ', ')) -Level Warn
            $announced = $true
        }

        Start-Sleep -Seconds 10
    }
}

function Get-DismProgressPercent {
    <#
        DISM draws its progress bar by rewriting one line with backspaces. Redirected to a
        file that becomes a long run of control characters with the percentage embedded, so
        the last percentage in the tail is the current progress.

        The file is open for writing by another process, so it has to be opened with
        FileShare.ReadWrite. Get-Content would hit a sharing violation.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return '' }

        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            if ($stream.Length -gt 8192) { $stream.Position = $stream.Length - 8192 }
            $reader = New-Object IO.StreamReader($stream)
            $text = $reader.ReadToEnd()
        }
        finally {
            $stream.Dispose()
        }

        $found = [regex]::Matches($text, '(\d{1,3}(?:\.\d+)?)%')
        if ($found.Count -gt 0) { return $found[$found.Count - 1].Value }
    }
    catch {
        Write-Verbose ('Progress unavailable: {0}' -f $_.Exception.Message)
    }

    return ''
}

function Invoke-Dism {
    <#
        Runs dism.exe with the scratch directory applied. See Invoke-Native for the
        process handling.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$LimitMinutes
    )

    # DISM stages its working files under %WINDIR%\Temp by default, on the same volume as
    # the component store. On a machine that is short of space that is exactly the wrong
    # place, so -ScratchDirectory moves it to another volume.
    if (-not [string]::IsNullOrWhiteSpace($ScratchDirectory)) {
        $Arguments = $Arguments + @(('/ScratchDir:{0}' -f $ScratchDirectory))
    }

    return Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\dism.exe') -Arguments $Arguments -LimitMinutes $LimitMinutes
}

function Invoke-Native {
    <#
        Runs an executable out of process so a hung RPC channel cannot hang this script.
        Returns the exit code, the captured output, and whether the timeout fired.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$LimitMinutes
    )

    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    Write-Verbose ('{0} {1}' -f (Split-Path -Leaf $FilePath), ($Arguments -join ' '))

    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr

        # Touching Handle forces the object to cache the process handle. Without this,
        # ExitCode can come back $null after the process exits.
        try { $null = $process.Handle } catch { Write-Verbose $_.Exception.Message }

        # Poll rather than WaitForExit, so a long operation can report that it is alive.
        # Without this the console sits blank for the whole run and looks hung, because the
        # redirection that lets us parse DISM's output also hides its progress bar.
        $deadline = (Get-Date).AddMinutes($LimitMinutes)
        $started = Get-Date
        $lastReport = Get-Date
        $timedOut = $false

        while (-not $process.HasExited) {
            if ((Get-Date) -ge $deadline) {
                $timedOut = $true
                break
            }

            Start-Sleep -Milliseconds 500

            if (((Get-Date) - $lastReport).TotalSeconds -ge 20) {
                $lastReport = Get-Date
                $elapsed = (Get-Date) - $started
                $percent = Get-DismProgressPercent -Path $stdout

                if ([string]::IsNullOrWhiteSpace($percent)) {
                    Write-Log ('still running, {0:hh\:mm\:ss} elapsed...' -f $elapsed)
                }
                else {
                    Write-Log ('still running, {0:hh\:mm\:ss} elapsed, DISM reports {1}' -f $elapsed, $percent)
                }
            }
        }

        $code = $script:ExitTimedOut

        if ($timedOut) {
            Write-Log ('{0} exceeded the {1} minute limit. Terminating it.' -f (Split-Path -Leaf $FilePath), $LimitMinutes) -Level Bad
            try { $process.Kill() } catch { Write-Verbose $_.Exception.Message }
            $process.WaitForExit(30000) | Out-Null
        }
        else {
            try { $code = $process.ExitCode } catch { $code = $null }
            # Never let a $null exit code flow on and be compared against 0.
            if ($null -eq $code) { $code = $script:ExitTimedOut }
        }

        $output = @()
        foreach ($file in @($stdout, $stderr)) {
            if (-not (Test-Path $file)) { continue }
            try {
                $content = Get-Content -Path $file -ErrorAction Stop
                if ($content) { $output += $content }
            }
            catch {
                Write-Verbose ('Could not read output: {0}' -f $_.Exception.Message)
            }
        }

        return [pscustomobject]@{
            ExitCode = $code
            Output   = ($output -join [Environment]::NewLine)
            TimedOut = $timedOut
        }
    }
    finally {
        Remove-Item -Path $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Package selection
# ---------------------------------------------------------------------------

function Get-PackageInventory {
    try {
        Write-Verbose 'Enumerating packages via Get-WindowsPackage.'
        return @(Get-WindowsPackage -Online -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    PackageName  = $_.PackageName
                    PackageState = [string]$_.PackageState
                    ReleaseType  = [string]$_.ReleaseType
                    InstallTime  = $_.InstallTime
                }
            })
    }
    catch {
        throw ('Unable to enumerate packages: {0}. The DISM module is required, and this failure usually means the component store itself is inaccessible - check %SystemRoot%\Logs\CBS\CBS.log.' -f $_.Exception.Message)
    }
}

function Split-PackageIdentity {
    <#
        Package identities are Name~PublicKeyToken~Architecture~Language~Version. The
        language field is routinely empty, giving a "~~" run, which splits correctly into
        an empty element. Anything that is not five fields with a parseable version is
        treated as unparsable and is never a candidate.
    #>
    param([Parameter(Mandatory = $true)][string]$PackageName)

    $parts = $PackageName -split '~'
    if ($parts.Count -ne 5) { return $null }

    $version = $null
    if (-not [version]::TryParse($parts[4], [ref]$version)) { return $null }

    return [pscustomobject]@{
        Family  = ($parts[0..3] -join '~')
        Version = $version
    }
}

function New-InstalledFamilyIndex {
    <#
        family -> highest installed version, built in one pass. Replaces an O(n^2) scan.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$AllPackages)

    $index = @{}

    foreach ($package in $AllPackages) {
        if ($package.PackageState -ne 'Installed') { continue }

        $identity = Split-PackageIdentity -PackageName $package.PackageName
        if ($null -eq $identity) { continue }

        if ($index.ContainsKey($identity.Family)) {
            if ($identity.Version -gt $index[$identity.Family]) {
                $index[$identity.Family] = $identity.Version
            }
        }
        else {
            $index[$identity.Family] = $identity.Version
        }
    }

    return $index
}

function Select-RemovalCandidate {
    <#
        Returns candidates plus a per-reason skip breakdown. Skip reasons are kept distinct
        so the operator can tell "correctly protected" from "the parser did not understand
        this package family" - both used to land in the same bucket.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$AllPackages)

    $index = New-InstalledFamilyIndex -AllPackages $AllPackages
    $candidates = @()
    $skipped = @()

    foreach ($package in ($AllPackages | Where-Object { $_.PackageState -eq 'Superseded' })) {
        if ($script:AllowedReleaseTypes -notcontains $package.ReleaseType) {
            $skipped += [pscustomobject]@{
                PackageName = $package.PackageName
                Reason      = ('release type "{0}" is not an ordinary update' -f $package.ReleaseType)
                Category    = 'release type'
            }
            continue
        }

        $denied = $false
        foreach ($pattern in $script:NeverRemovePatterns) {
            if ($package.PackageName -match $pattern) {
                $skipped += [pscustomobject]@{
                    PackageName = $package.PackageName
                    Reason      = 'matched the never-remove deny list'
                    Category    = 'deny list'
                }
                $denied = $true
                break
            }
        }
        if ($denied) { continue }

        $identity = Split-PackageIdentity -PackageName $package.PackageName
        if ($null -eq $identity) {
            $skipped += [pscustomobject]@{
                PackageName = $package.PackageName
                Reason      = 'package identity could not be parsed'
                Category    = 'unparsable identity'
            }
            continue
        }

        if (-not $index.ContainsKey($identity.Family) -or $index[$identity.Family] -le $identity.Version) {
            $skipped += [pscustomobject]@{
                PackageName = $package.PackageName
                Reason      = 'no installed higher-version package in the same family'
                Category    = 'no successor'
            }
            continue
        }

        $candidates += $package
    }

    # Oldest first. Older backups are the least entangled.
    $sorted = @($candidates | Sort-Object -Property @{ Expression = { if ($_.InstallTime) { $_.InstallTime } else { [datetime]::MinValue } } })

    return [pscustomobject]@{
        Candidates = $sorted
        Skipped    = $skipped
    }
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

function Test-Preflight {
    Write-Log 'Running preflight checks...' -Level Step

    $hardStop = @()
    $advisory = @()

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $hardStop += 'This script only runs on Windows.'
    }

    $pending = @(Get-PendingRebootReason)
    if ($pending.Count -gt 0) {
        $hardStop += ('A reboot is pending ({0}). Reboot and rerun.' -f ($pending -join ', '))
    }

    # A second DISM client is a hard stop. It is almost always another copy of one of these
    # scripts still open in a different window.
    $competing = @(Get-CompetingDismClient)
    if ($competing.Count -gt 0) {
        $hardStop += ('Another DISM client is running: {0}. Close it, or wait for it to finish, then rerun.' -f ($competing -join ', '))
    }

    # Reported for context only. The orchestrator is almost always alive and is not a
    # reason to wait.
    $orchestrator = @(Get-OrchestratorActivity)
    if ($orchestrator.Count -gt 0) {
        Write-Log ('Update orchestrator is running ({0}). It does not touch the component store, so this is not a blocker.' -f ($orchestrator -join ', '))
    }

    # TiWorker is the CBS worker and the only thing worth waiting for. It runs for a long
    # stretch after any reboot or install.
    $foreign = @(Get-ForeignServicingReason)
    if ($foreign.Count -gt 0) {
        Write-Log ('Servicing is active: {0}.' -f ($foreign -join ', ')) -Level Warn
        Write-Log ('Waiting up to {0} minute(s) for it to settle...' -f $ServicingWaitMinutes) -Level Warn

        $deadline = (Get-Date).AddMinutes($ServicingWaitMinutes)
        while ((Get-Date) -lt $deadline -and @(Get-ForeignServicingReason).Count -gt 0) {
            Start-Sleep -Seconds 15
        }

        $foreign = @(Get-ForeignServicingReason)
        if ($foreign.Count -gt 0) {
            $advisory += ('Servicing is still active after the wait: {0}. Something may be installing; let it finish, or pass -IgnoreAdvisories if you are sure it is idle.' -f ($foreign -join ', '))
        }
        else {
            Write-Log 'Servicing has settled.' -Level Good
        }
    }

    try {
        $trustedInstaller = Get-Service -Name 'TrustedInstaller' -ErrorAction Stop
        if ($trustedInstaller.StartType -eq 'Disabled') {
            # Deliberately not changed for you. This is a service configuration change.
            $hardStop += 'The Windows Modules Installer service is Disabled, so servicing cannot run. Set it to Manual with: Set-Service -Name TrustedInstaller -StartupType Manual'
        }
        else {
            # Reported, never blocking. TrustedInstaller is demand-start with an idle
            # timeout, so it is routinely Running after any recent servicing, and every
            # /Remove-Package needs it anyway - this script starts it regardless. TiWorker
            # is the signal for work actually in progress, and that is waited on above.
            Write-Log ('Windows Modules Installer service is {0} (start type {1}).' -f $trustedInstaller.Status, $trustedInstaller.StartType)
        }
    }
    catch {
        $hardStop += 'The Windows Modules Installer service is missing.'
    }

    # Image health is a hard stop that nothing overrides, including a failure to evaluate
    # it. A guard that cannot run is a guard that failed.
    try {
        $health = [string](Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop).ImageHealthState
        if ([string]::IsNullOrWhiteSpace($health)) {
            $hardStop += 'Component store health could not be determined.'
        }
        elseif ($health -ne 'Healthy') {
            $hardStop += ('Component store health is "{0}". Run DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow before using this script.' -f $health)
        }
        else {
            Write-Log 'Component store reports Healthy.' -Level Good
        }
    }
    catch {
        $hardStop += ('Component store health check failed: {0}' -f $_.Exception.Message)
    }

    # Low disk space is the reason people run this script, so it must not block the run.
    # Only the hard floor stops it, because servicing a volume to zero can corrupt the
    # store. Everything between the floor and comfortable is just reported.
    $free = Get-SystemDriveFree
    if ($null -ne $free) {
        Write-Log ('{0} free on {1}' -f (Format-Bytes $free), $env:SystemDrive)

        if ($free -lt ($MinimumFreeSpaceGB * 1GB)) {
            $hardStop += ('Only {0} free on {1}, below the {2} GB floor. Servicing needs working space and running the volume to zero can corrupt the store. Free space first, or lower -MinimumFreeSpaceGB if you understand the risk.' -f (Format-Bytes $free), $env:SystemDrive, $MinimumFreeSpaceGB)
        }
        elseif ($free -lt 10GB) {
            Write-Log ('Working space is tight. Each removal is a small transaction, so this is workable, but the run stops if free space falls below {0} GB.' -f $MinimumFreeSpaceGB) -Level Warn
            if ([string]::IsNullOrWhiteSpace($ScratchDirectory)) {
                Write-Log 'Consider -ScratchDirectory on another volume to keep DISM working files off this one.' -Level Warn
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ScratchDirectory)) {
        if (-not (Test-Path -LiteralPath $ScratchDirectory -PathType Container)) {
            $hardStop += ('-ScratchDirectory "{0}" does not exist. DISM requires an existing local directory.' -f $ScratchDirectory)
        }
        else {
            Write-Log ('DISM scratch directory: {0}' -f $ScratchDirectory) -Level Good
        }
    }

    foreach ($reason in $hardStop) { Write-Log $reason -Level Bad }
    foreach ($reason in $advisory) { Write-Log $reason -Level Warn }

    if ($hardStop.Count -gt 0) { return $false }

    if ($advisory.Count -gt 0 -and $Execute -and -not $IgnoreAdvisories) {
        Write-Log 'Advisory warnings above. Rerun with -IgnoreAdvisories to proceed anyway.' -Level Bad
        return $false
    }

    Write-Log 'Preflight passed.' -Level Good
    return $true
}

function New-CleanupRestorePoint {
    <#
        Advisory only. System Restore is documented-unreliable for CBS transaction state,
        and System Protection is off by default on Windows 11, so failing here must never
        be the thing that teaches an operator to pass an override switch.
    #>
    if ($SkipRestorePoint) {
        Write-Log 'Restore point skipped by request.' -Level Warn
        return
    }

    # A restore point consumes shadow copy space on the very volume we are trying to free.
    # On a tight disk that is counterproductive, and it is weak protection for component
    # store changes anyway.
    $free = Get-SystemDriveFree
    if ($null -ne $free -and $free -lt 10GB) {
        Write-Log ('Skipping the restore point: only {0} free, and a restore point would consume more of it.' -f (Format-Bytes $free)) -Level Warn
        Write-Log 'Pass -SkipRestorePoint to make this explicit, or free space first if you want one.' -Level Warn
        return
    }

    try {
        Write-Log 'Creating a system restore point...' -Level Step
        Checkpoint-Computer -Description 'ComponentCleanup.ps1' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Log 'Restore point created. Note this is weak protection for component store changes.' -Level Good
    }
    catch {
        Write-Log ('Restore point not created: {0}' -f $_.Exception.Message) -Level Warn
        Write-Log 'Continuing. A restore point would not reliably undo component store changes anyway.' -Level Warn
    }
}

# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------

function Remove-SupersededPackage {
    <#
        One package, one DISM process, NO retries. A timed-out servicing operation has an
        unknown outcome and re-issuing it is unsafe, so the caller aborts instead.

        Returns: Removed | RebootRequired | Abort | Failed | TimedOut

        /NoRestart is load-bearing, not decoration: without it DISM is permitted to restart
        the machine on its own. /Quiet is deliberately NOT used - it suppresses the text
        that distinguishes one failure from another.
    #>
    param([Parameter(Mandatory = $true)][string]$PackageName)

    $result = Invoke-Dism -LimitMinutes $TimeoutMinutes -Arguments @(
        '/Online'
        '/English'
        '/NoRestart'
        '/Remove-Package'
        ('/PackageName:{0}' -f $PackageName)
    )

    if ($result.TimedOut) { return 'TimedOut' }
    if ($result.ExitCode -eq 0) { return 'Removed' }

    Write-Log ('DISM returned {0}.' -f (Get-DismExitCodeName $result.ExitCode)) -Level Warn
    if ($result.Output) { Write-Log $result.Output -Level Info }

    if ($result.ExitCode -eq $script:ExitRebootRequired) { return 'RebootRequired' }
    if ($script:AbortExitCodes.ContainsKey($result.ExitCode)) { return 'Abort' }

    return 'Failed'
}

function Invoke-PostCleanupRepair {
    <#
        Verification pass, run only after StartComponentCleanup has genuinely completed.

        DISM RestoreHealth runs BEFORE sfc, not after. SFC repairs system files using the
        component store as its source, so a damaged store leaves it unable to fix anything.
        RestoreHealth repairs the store first, which gives SFC a healthy source to work
        from. Running sfc first is the common way round and it is the wrong one.

        Both are long. Neither is destructive, and both are skipped when cleanup asked for
        a reboot, because servicing a store with a pending transaction is exactly what this
        script spends its time avoiding.
    #>
    Write-Log '' -Level Info
    Write-Log 'Post-cleanup verification' -Level Step
    Write-Log 'Cleanup succeeded, so the store is now verified and repaired if needed.'
    Write-Log ('Each step has a {0} minute limit. Both are read-mostly and neither removes anything.' -f $RepairTimeoutMinutes)

    # 1. Repair the component store first, so SFC has a good source.
    if ($PSCmdlet.ShouldProcess('component store', 'DISM /Cleanup-Image /RestoreHealth')) {
        Write-Log 'Running DISM /Online /Cleanup-Image /RestoreHealth...' -Level Step

        $restore = Invoke-Dism -LimitMinutes $RepairTimeoutMinutes -Arguments @(
            '/Online', '/English', '/NoRestart', '/Cleanup-Image', '/RestoreHealth'
        )

        if ($restore.ExitCode -eq 0) {
            Write-Log 'RestoreHealth completed. The component store is repairable and repaired.' -Level Good
        }
        elseif ($restore.ExitCode -eq $script:ExitRebootRequired) {
            Write-Log 'RestoreHealth completed and requires a reboot. Skipping sfc until after it.' -Level Warn
            return $script:ExitRebootRequired
        }
        else {
            Write-Log ('RestoreHealth returned {0}.' -f (Get-DismExitCodeName $restore.ExitCode)) -Level Bad
            if ($restore.Output) { Write-Log $restore.Output }
            Write-Log 'If it could not find source files, rerun with matching install media:' -Level Warn
            Write-Log '  DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:1 /LimitAccess' -Level Warn
            Write-Log 'Running sfc anyway, since it may still repair what it can.' -Level Warn
        }
    }

    # 2. Then the system files, now that the store behind them is sound.
    if ($PSCmdlet.ShouldProcess('system files', 'sfc /scannow')) {
        Write-Log 'Running sfc /scannow...' -Level Step

        $sfc = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\sfc.exe') -Arguments @('/scannow') -LimitMinutes $RepairTimeoutMinutes

        # sfc writes UTF-16 to the console, so the redirected capture is not worth parsing.
        # The exit code plus CBS.log is the reliable record.
        if ($sfc.TimedOut) {
            Write-Log ('sfc did not finish within {0} minutes.' -f $RepairTimeoutMinutes) -Level Bad
            return 1
        }

        if ($sfc.ExitCode -eq 0) {
            Write-Log 'sfc completed.' -Level Good
        }
        else {
            Write-Log ('sfc returned {0}.' -f $sfc.ExitCode) -Level Warn
        }

        Write-Log ('For what sfc actually found, read {0}' -f (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'))
        Write-Log '  findstr /c:"[SR]" %SystemRoot%\Logs\CBS\CBS.log > "%USERPROFILE%\Desktop\sfcdetails.txt"'
    }

    return 0
}

function Invoke-FinalComponentCleanup {
    <#
        The step that actually reclaims the bytes. Plain StartComponentCleanup only -
        /ResetBase is not offered, because it makes every installed update permanent and is
        not needed to recover space.
    #>
    if (-not $PSCmdlet.ShouldProcess('component store', 'Run StartComponentCleanup')) { return 0 }

    # Cleanup is one long transaction that stages before it frees, so it needs headroom up
    # front. The per-removal floor does not cover it: that is checked between packages, and
    # this is a single operation that can run for an hour.
    $free = Get-SystemDriveFree
    if ($null -ne $free) {
        Write-Log ('{0} free on {1} going into cleanup.' -f (Format-Bytes $free), $env:SystemDrive)
        if ($free -lt 15GB) {
            Write-Log 'That is tight for a full cleanup. It stages changes before it frees anything, so it can still fail with ERROR_DISK_FULL part way through.' -Level Warn
            Write-Log 'A partial cleanup is not wasted: it frees what it got through, and rerunning after a reboot picks up from there.' -Level Warn
        }
    }

    Write-Log 'Running StartComponentCleanup to reclaim space...' -Level Step
    Write-Log ('This is the step that frees disk space and it can take over an hour. Limit is {0} minute(s).' -f $CleanupTimeoutMinutes)

    $result = Invoke-Dism -LimitMinutes $CleanupTimeoutMinutes -Arguments @(
        '/Online', '/English', '/NoRestart', '/Cleanup-Image', '/StartComponentCleanup'
    )

    if ($result.TimedOut) {
        Write-Log 'StartComponentCleanup timed out and the client was terminated.' -Level Bad
        Write-Log 'Do not run further servicing until the machine has been rebooted.' -Level Bad
        Wait-ServicingQuiet -WaitMinutes 60 -Thorough | Out-Null
        return 1
    }

    if ($result.ExitCode -eq 0) {
        Write-Log 'StartComponentCleanup completed.' -Level Good

        if ($SkipPostCleanupRepair) {
            Write-Log 'Post-cleanup verification skipped by request.' -Level Warn
            Write-Log 'Run these yourself when convenient, in this order:'
            Write-Log '  DISM /Online /Cleanup-Image /RestoreHealth'
            Write-Log '  sfc /scannow'
            return 0
        }

        return Invoke-PostCleanupRepair
    }

    if ($result.ExitCode -eq $script:ExitRebootRequired) {
        Write-Log 'StartComponentCleanup completed and requires a reboot.' -Level Good
        Write-Log 'Skipping the post-cleanup verification. Servicing a store with a pending transaction is unsafe.' -Level Warn
        Write-Log 'Reboot, then run: DISM /Online /Cleanup-Image /RestoreHealth   followed by   sfc /scannow' -Level Warn
        return $script:ExitRebootRequired
    }

    Write-Log ('StartComponentCleanup returned {0}.' -f (Get-DismExitCodeName $result.ExitCode)) -Level Bad
    if ($result.Output) { Write-Log $result.Output -Level Info }
    Write-Log 'The removals above still reduced the reclaimable set. Rerun this script after a reboot.' -Level Warn
    return 1
}

# ---------------------------------------------------------------------------
# Windows Installer cache (%SystemRoot%\Installer)
#
# This is a DIFFERENT subsystem from the component store. It holds the cached .msi and
# .msp packages that Windows Installer needs in order to repair, modify, patch or
# uninstall an installed product. Deleting a package that is still referenced leaves the
# product permanently unrepairable and often unremovable, and there is no way to get it
# back short of reinstalling that product.
#
# Only packages that no installed product or applied patch references are touched, and
# even those are MOVED to a quarantine folder rather than deleted, so a wrong call is
# reversible. Disk space is therefore not reclaimed until the quarantine is purged, which
# a later run does once the files have sat untouched for -PurgeInstallerQuarantineDays.
# ---------------------------------------------------------------------------

function Get-InstallerCachePath {
    return (Join-Path $env:SystemRoot 'Installer')
}

function Get-InstallerQuarantineRoot {
    # Must be on the same volume as the cache so the move is a rename, not a copy.
    return (Join-Path $env:SystemRoot 'Installer.Orphaned')
}

function Get-ReferencedInstallerPackage {
    <#
        Every .msi and .msp that Windows Installer still needs, taken from the MSI
        registry under every user SID, not just the current one. Returns $null if the
        registry cannot be read at all - the caller treats that as a hard stop, because an
        empty referenced set would mark the entire cache as garbage.
    #>
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    if (-not (Test-Path $root)) { return $null }

    $referenced = @{}

    foreach ($sid in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
        $products = @(Get-ChildItem -Path (Join-Path $sid.PSPath 'Products') -ErrorAction SilentlyContinue)

        foreach ($product in $products) {
            $install = Get-ItemProperty -Path (Join-Path $product.PSPath 'InstallProperties') -Name 'LocalPackage' -ErrorAction SilentlyContinue
            if ($install -and $install.PSObject.Properties['LocalPackage'] -and $install.LocalPackage) {
                $referenced[([string]$install.LocalPackage).ToLowerInvariant()] = $true
            }

            foreach ($patch in @(Get-ChildItem -Path (Join-Path $product.PSPath 'Patches') -ErrorAction SilentlyContinue)) {
                $applied = Get-ItemProperty -Path $patch.PSPath -Name 'LocalPackage' -ErrorAction SilentlyContinue
                if ($applied -and $applied.PSObject.Properties['LocalPackage'] -and $applied.LocalPackage) {
                    $referenced[([string]$applied.LocalPackage).ToLowerInvariant()] = $true
                }
            }
        }
    }

    return $referenced
}

function Get-OrphanedInstallerPackage {
    <#
        Top level .msi/.msp files in the cache that nothing references. Deliberately not
        recursive: $PatchCache$ holds the baseline packages used for future patching and
        must never be touched, and the GUID subfolders hold product icons.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Referenced)

    $cache = Get-InstallerCachePath
    if (-not (Test-Path $cache)) { return @() }

    $orphans = @()

    foreach ($file in @(Get-ChildItem -LiteralPath $cache -File -Force -ErrorAction SilentlyContinue)) {
        if ($file.Extension.ToLowerInvariant() -notin @('.msi', '.msp')) { continue }

        # A reparse point here is unexpected. Leave it alone rather than move it.
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Write-Log ('Skipping reparse point {0}' -f $file.FullName) -Level Warn
            continue
        }

        if ($Referenced.ContainsKey($file.FullName.ToLowerInvariant())) { continue }

        $orphans += $file
    }

    return $orphans
}

function Clear-InstallerQuarantine {
    <#
        Purges quarantine folders that have sat untouched long enough to be trusted. This
        is the step that actually frees the disk space from a previous run.
    #>
    $root = Get-InstallerQuarantineRoot
    if (-not (Test-Path $root)) { return }

    $cutoff = (Get-Date).AddDays(-$PurgeInstallerQuarantineDays)
    $freed = 0L

    foreach ($folder in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($folder.LastWriteTime -ge $cutoff) {
            Write-Log ('Keeping quarantine {0} until {1:yyyy-MM-dd}.' -f $folder.Name, $folder.LastWriteTime.AddDays($PurgeInstallerQuarantineDays))
            continue
        }

        $size = 0L
        foreach ($item in @(Get-ChildItem -LiteralPath $folder.FullName -File -Force -ErrorAction SilentlyContinue)) {
            $size += $item.Length
        }

        if (-not $Execute) {
            Write-Log ('DRY RUN: would purge quarantine {0} ({1}).' -f $folder.Name, (Format-Bytes $size)) -Level Warn
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($folder.FullName, 'Purge quarantined installer packages')) { continue }

        try {
            Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction Stop
            $freed += $size
            Write-Log ('Purged quarantine {0} ({1}).' -f $folder.Name, (Format-Bytes $size)) -Level Good
        }
        catch {
            Write-Log ('Could not purge {0}: {1}' -f $folder.FullName, $_.Exception.Message) -Level Warn
        }
    }

    if ($freed -gt 0) {
        Write-Log ('Reclaimed {0} from expired quarantine.' -f (Format-Bytes $freed)) -Level Good
    }
}

function Invoke-InstallerCacheCleanup {
    <#
        Returns the process exit code contribution (0 on success).
    #>
    Write-Log 'Windows Installer cache' -Level Step

    $cache = Get-InstallerCachePath
    if (-not (Test-Path $cache)) {
        Write-Log ('{0} does not exist. Nothing to do.' -f $cache) -Level Warn
        return 0
    }

    # An MSI transaction in flight means the reference data is changing underneath us.
    $msi = Get-Service -Name 'msiserver' -ErrorAction SilentlyContinue
    if ($msi -and $msi.Status -ne 'Stopped') {
        Write-Log 'The Windows Installer service is running, so an MSI transaction is in progress.' -Level Bad
        Write-Log 'Skipping the installer cache. Rerun when no installation is active.' -Level Bad
        return 1
    }

    if (@(Get-Process -Name 'msiexec' -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-Log 'msiexec.exe is running. Skipping the installer cache.' -Level Bad
        return 1
    }

    Clear-InstallerQuarantine

    $referenced = Get-ReferencedInstallerPackage
    if ($null -eq $referenced) {
        Write-Log 'The Windows Installer registry could not be read, so referenced packages cannot be determined.' -Level Bad
        Write-Log 'Refusing to touch the installer cache. Treating every package as orphaned would be catastrophic.' -Level Bad
        return 1
    }

    Write-Log ('{0} cached package(s) are referenced by an installed product or applied patch.' -f $referenced.Count)

    # A real machine references dozens. A near-empty set means the enumeration failed
    # rather than that the cache is genuinely garbage, and acting on it would destroy the
    # ability to repair or uninstall everything on the box.
    if ($referenced.Count -eq 0) {
        Write-Log 'No referenced packages found at all. This is not credible; refusing to continue.' -Level Bad
        return 1
    }
    if ($referenced.Count -lt 10) {
        Write-Log 'Very few referenced packages were found. Verify this machine really has almost nothing installed.' -Level Warn
        if ($Execute -and -not $IgnoreAdvisories) {
            Write-Log 'Refusing to continue without -IgnoreAdvisories.' -Level Bad
            return 1
        }
    }

    $orphans = @(Get-OrphanedInstallerPackage -Referenced $referenced)
    $orphanSize = 0L
    foreach ($file in $orphans) { $orphanSize += $file.Length }

    Write-Log ('{0} orphaned package(s) totalling {1}.' -f $orphans.Count, (Format-Bytes $orphanSize)) -Level Step

    if ($orphans.Count -eq 0) {
        Write-Log 'Installer cache is clean.' -Level Good
        return 0
    }

    if (-not $Execute) {
        foreach ($file in $orphans) {
            Write-Log ('DRY RUN: would quarantine {0} ({1})' -f $file.Name, (Format-Bytes $file.Length))
        }
        Write-Log ('DRY RUN complete. {0} would be moved to quarantine, not deleted.' -f (Format-Bytes $orphanSize)) -Level Warn
        return 0
    }

    $quarantine = Join-Path (Get-InstallerQuarantineRoot) $script:RunStamp
    if (-not $PSCmdlet.ShouldProcess($quarantine, ('Quarantine {0} orphaned installer package(s)' -f $orphans.Count))) {
        return 0
    }

    if (-not $NonInteractive) {
        $yes = $false
        $no = $false
        $query = ('Move {0} orphaned package(s), {1}, out of the Windows Installer cache? They are moved, not deleted.' -f $orphans.Count, (Format-Bytes $orphanSize))
        if (-not $PSCmdlet.ShouldContinue($query, 'Quarantine installer packages', [ref]$yes, [ref]$no)) {
            Write-Log 'Declined. Installer cache left untouched.' -Level Warn
            return 0
        }
    }

    New-Item -Path $quarantine -ItemType Directory -Force | Out-Null

    $moved = 0
    $movedSize = 0L
    $failed = 0

    foreach ($file in $orphans) {
        try {
            Move-Item -LiteralPath $file.FullName -Destination (Join-Path $quarantine $file.Name) -ErrorAction Stop
            $moved++
            $movedSize += $file.Length
            Write-Verbose ('Quarantined {0}' -f $file.FullName)
        }
        catch {
            $failed++
            Write-Log ('Could not move {0}: {1}' -f $file.Name, $_.Exception.Message) -Level Warn
        }
    }

    Write-Log ('Quarantined {0} package(s), {1}. Failed {2}.' -f $moved, (Format-Bytes $movedSize), $failed) -Level Good
    Write-Log ('Quarantine: {0}' -f $quarantine)
    Write-Log 'Disk space is NOT reclaimed yet. The files are still on disk, deliberately.' -Level Warn
    Write-Log ('Exercise repair, patch and uninstall on your applications. Rerun this script after {0} day(s) to purge the quarantine,' -f $PurgeInstallerQuarantineDays) -Level Warn
    Write-Log 'or move a file back from the quarantine folder if something turns out to need it.' -Level Warn

    if ($failed -gt 0) { return 1 }
    return 0
}

function Invoke-ServicingScheduledTask {
    $taskPath = '\Microsoft\Windows\Servicing\'
    $taskName = 'StartComponentCleanup'

    try {
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
    }
    catch {
        Write-Log 'The built-in StartComponentCleanup scheduled task was not found.' -Level Bad
        return
    }

    if (-not $Execute) {
        Write-Log ('DRY RUN: would start scheduled task {0}{1} (current state: {2}).' -f $taskPath, $taskName, $task.State) -Level Warn
        return
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}{1}' -f $taskPath, $taskName), 'Start scheduled task')) { return }

    Write-Log 'Starting the built-in servicing task. It runs under TrustedInstaller with a one hour cap.' -Level Step
    Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    Start-Sleep -Seconds 5

    $state = (Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName).State
    Write-Log ('Task state: {0}. Check progress with: Get-ScheduledTask -TaskPath "{1}" -TaskName "{2}"' -f $state, $taskPath, $taskName) -Level Good
    Write-Log 'The task exits silently. Rerun this script in dry run mode afterwards to see the delta.'
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

function Show-InventoryBreakdown {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$AllPackages)

    Write-Log 'Package state breakdown' -Level Step
    foreach ($group in ($AllPackages | Group-Object PackageState | Sort-Object Count -Descending)) {
        Write-Log ('{0,-24} {1}' -f $group.Name, $group.Count)
    }
}

function Show-UnaddressedSpace {
    <#
        "Backups and Disabled Features" is not all superseded backups. Removing packages
        does nothing for the disabled-feature and capability portion, so name it rather
        than letting the operator assume the whole figure is in scope.
    #>
    try {
        $disabledFeatures = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'DisabledWithPayloadRemoved' -or $_.State -eq 'Disabled' })
        Write-Log ('Disabled optional features with payload still present: {0}' -f $disabledFeatures.Count)
    }
    catch {
        Write-Log ('Optional feature inventory unavailable: {0}' -f $_.Exception.Message) -Level Warn
    }

    try {
        $capabilities = @(Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Installed' })
        Write-Log ('Installed on-demand capabilities: {0}' -f $capabilities.Count)
    }
    catch {
        Write-Log ('Capability inventory unavailable: {0}' -f $_.Exception.Message) -Level Warn
    }

    Write-Log 'Package removal addresses only the superseded-backup part of "Backups and Disabled Features".' -Level Warn
    Write-Log 'Disabled features and unused capabilities need DISM /Disable-Feature /Remove or Remove-WindowsCapability instead.' -Level Warn
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-ComponentCleanup {
    <#
        Returns the process exit code.
    #>
    if (-not $Execute) {
        Write-Log 'DRY RUN. Nothing will be removed. Pass -Execute to act.' -Level Warn
    }

    if (-not (Test-Preflight)) { return 1 }

    # Cheap, safe space first. Doing this before the store analysis means the numbers below
    # reflect the reclaimed log space.
    if ($ReclaimLogSpace) {
        Write-Log 'Reclaiming archived servicing log space' -Level Step
        Invoke-ReclaimLogSpace
    }

    if ($UseScheduledTask) {
        Invoke-ServicingScheduledTask
        return 0
    }

    Write-Log 'Enumerating packages...' -Level Step
    $allPackages = @(Get-PackageInventory)
    Write-Log ('{0} packages present.' -f $allPackages.Count) -Level Good
    Show-InventoryBreakdown -AllPackages $allPackages

    $inventory = Join-Path $LogDirectory ('PackageInventory-{0}.csv' -f $script:RunStamp)
    if ($PSCmdlet.ShouldProcess($inventory, 'Write package inventory')) {
        $allPackages | Export-Csv -Path $inventory -NoTypeInformation -Encoding UTF8
        Write-Log ('Inventory written to {0}' -f $inventory)
    }

    $selection = Select-RemovalCandidate -AllPackages $allPackages
    $candidates = @($selection.Candidates)
    $skipped = @($selection.Skipped)

    Write-Log 'Candidate selection' -Level Step
    foreach ($group in ($skipped | Group-Object Category | Sort-Object Count -Descending)) {
        Write-Log ('{0,-42} {1}' -f ('skipped, ' + $group.Name), $group.Count)
    }
    Write-Log ('{0,-42} {1}' -f 'eligible for removal', $candidates.Count) -Level Good

    # Note the eligible count is NOT the same thing as DISM's "Number of Reclaimable
    # Packages". The two are defined differently and diverge in both directions, so do not
    # expect them to agree if you run AnalyzeComponentStore yourself.

    # Only in dry run: this is decision-support for the operator, and the capability and
    # optional-feature inventories are slow enough that they are not worth paying for on
    # the execute path.
    if (-not $Execute) { Show-UnaddressedSpace }

    if ($candidates.Count -eq 0) {
        Write-Log 'No packages are eligible for removal.' -Level Good
        if ($Execute -and -not $SkipFinalCleanup) {
            return Invoke-FinalComponentCleanup
        }
        return 0
    }

    if (-not $Execute) {
        foreach ($candidate in $candidates) {
            $when = 'unknown'
            if ($candidate.InstallTime) { $when = '{0:yyyy-MM-dd}' -f $candidate.InstallTime }
            Write-Log ('DRY RUN: would remove [{0}] [{1}] {2}' -f $when, $candidate.ReleaseType, $candidate.PackageName)
        }
        Write-Log ('DRY RUN complete. {0} package(s) would be removed, then StartComponentCleanup would run.' -f $candidates.Count) -Level Warn
        Write-Log 'Rerun with -Execute to act. Consider -UseScheduledTask -Execute first.' -Level Warn
        return 0
    }

    New-CleanupRestorePoint

    $deadline = (Get-Date).AddHours($MaxRunHours)
    $exitCode = 0
    $removed = 0
    $failed = 0
    $index = 0
    $yesToAll = $false
    $noToAll = $false

    foreach ($candidate in $candidates) {
        $index++

        if ((Get-Date) -ge $deadline) {
            Write-Log ('Reached the {0} hour budget. Stopping cleanly.' -f $MaxRunHours) -Level Step
            break
        }

        if ($MaxPackages -gt 0 -and $removed -ge $MaxPackages) {
            Write-Log ('Reached -MaxPackages {0}. Stopping.' -f $MaxPackages) -Level Step
            break
        }

        # Free space is checked before EVERY removal, not just at preflight. Servicing a
        # volume down to nothing is a good way to corrupt the store, and a long run can
        # drift a long way from where preflight measured.
        $free = Get-SystemDriveFree
        if ($null -ne $free) {
            if ($free -lt ($MinimumFreeSpaceGB * 1GB)) {
                Write-Log ('Free space fell to {0}, below the {1} GB floor. Stopping before servicing runs the volume dry.' -f (Format-Bytes $free), $MinimumFreeSpaceGB) -Level Bad
                $exitCode = 1
                break
            }

            if ($StopWhenFreeSpaceGB -gt 0 -and $free -ge ($StopWhenFreeSpaceGB * 1GB)) {
                Write-Log ('Free space has reached {0}, the -StopWhenFreeSpaceGB target. Stopping cleanly.' -f (Format-Bytes $free)) -Level Good
                break
            }
        }

        # Re-check before EVERY removal, not once at startup. A pending reboot or a
        # foreign servicing operation can appear part way through a long run.
        $pending = @(Get-PendingRebootReason)
        if ($pending.Count -gt 0) {
            Write-Log ('A reboot became pending ({0}). Stopping.' -f ($pending -join ', ')) -Level Bad
            $exitCode = $script:ExitRebootRequired
            break
        }

        # Only a competing DISM client aborts here. TiWorker is deliberately NOT checked:
        # enumerating packages opens a CBS session, so TiWorker is running because THIS
        # script started it, and it lingers between removals on its own idle timeout.
        # Treating that as a foreign operation aborted the run before the first removal.
        #
        # What actually protects the store between packages is the pending-reboot check
        # above, the ServicingInProgress wait below, and CBS serialising transactions
        # itself - a genuinely in-flight transaction makes /Remove-Package fail cleanly
        # rather than interleave.
        $competing = @(Get-CompetingDismClient)
        if ($competing.Count -gt 0) {
            Write-Log ('Another DISM client started mid-run: {0}. Stopping.' -f ($competing -join ', ')) -Level Bad
            $exitCode = 1
            break
        }

        if (-not (Wait-ServicingQuiet -WaitMinutes 15)) {
            Write-Log 'Servicing did not go quiet. Stopping rather than stacking transactions.' -Level Bad
            $exitCode = 1
            break
        }

        # Re-read state. An earlier removal can change a later candidate.
        $current = $null
        try {
            $current = Get-WindowsPackage -Online -PackageName $candidate.PackageName -ErrorAction Stop
        }
        catch {
            # Distinguish "this package is already gone" from "the store just became
            # inaccessible". The latter must stop the run, not look like 70 benign skips.
            if ($_.Exception.Message -match '(?i)not found|does not exist|0x800f0805|cannot find') {
                Write-Log ('{0} is no longer present. Skipping.' -f $candidate.PackageName) -Level Warn
                continue
            }
            Write-Log ('Could not query {0}: {1}' -f $candidate.PackageName, $_.Exception.Message) -Level Bad
            Write-Log 'Stopping: the component store may have become inaccessible.' -Level Bad
            $exitCode = 1
            break
        }

        if ([string]$current.PackageState -ne 'Superseded') {
            Write-Log ('{0} is now "{1}", not "Superseded". Skipping.' -f $candidate.PackageName, $current.PackageState) -Level Warn
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($candidate.PackageName, 'Remove superseded package')) { continue }

        if (-not $NonInteractive -and -not $yesToAll) {
            $query = ('Remove superseded package {0} ({1})?' -f $candidate.PackageName, $candidate.ReleaseType)
            if (-not $PSCmdlet.ShouldContinue($query, 'Remove superseded package', [ref]$yesToAll, [ref]$noToAll)) {
                if ($noToAll) {
                    Write-Log 'Declined for all remaining packages. Stopping.' -Level Warn
                    break
                }
                Write-Log 'Declined. Skipping this package.' -Level Warn
                continue
            }
        }

        Write-Log ('[{0}/{1}] Removing {2}' -f $index, $candidates.Count, $candidate.PackageName) -Level Step
        $status = Remove-SupersededPackage -PackageName $candidate.PackageName

        switch ($status) {
            'Removed' {
                $removed++
                Write-Log 'Removed.' -Level Good

                # Interleaved reclamation. Removals de-register packages but the bytes only
                # come back when cleanup runs, so on a tight disk it is worth reclaiming as
                # you go rather than waiting until the end. Cleanup failing here is expected
                # while the component graph is still large; it is logged and the run
                # continues.
                if ($CleanupEvery -gt 0 -and ($removed % $CleanupEvery) -eq 0) {
                    $beforeFree = Get-SystemDriveFree
                    Write-Log ('Interim cleanup after {0} removal(s)...' -f $removed) -Level Step

                    $interim = Invoke-Dism -LimitMinutes $CleanupTimeoutMinutes -Arguments @(
                        '/Online', '/English', '/NoRestart', '/Cleanup-Image', '/StartComponentCleanup'
                    )

                    if ($interim.ExitCode -eq 0 -or $interim.ExitCode -eq $script:ExitRebootRequired) {
                        $afterFree = Get-SystemDriveFree
                        if ($null -ne $beforeFree -and $null -ne $afterFree) {
                            Write-Log ('Interim cleanup reclaimed {0}.' -f (Format-Bytes ($afterFree - $beforeFree))) -Level Good
                        }
                        else {
                            Write-Log 'Interim cleanup completed.' -Level Good
                        }
                    }
                    else {
                        Write-Log ('Interim cleanup still failing ({0}). Expected while the graph is large; continuing with removals.' -f (Get-DismExitCodeName $interim.ExitCode)) -Level Warn
                    }
                }
            }
            'RebootRequired' {
                Write-Log 'DISM reported that a reboot is required. Stopping here.' -Level Bad
                Write-Log 'Reboot, then rerun this script to continue.' -Level Warn
                $exitCode = $script:ExitRebootRequired
            }
            'Abort' {
                Write-Log 'The store is not in a state where servicing can safely continue. Stopping.' -Level Bad
                $exitCode = 1
            }
            'TimedOut' {
                # The transaction may have committed, rolled back, or still be running.
                # There is no safe way to retry from here.
                Write-Log 'The removal timed out. Its outcome is UNKNOWN.' -Level Bad
                Wait-ServicingQuiet -WaitMinutes $TimeoutMinutes -Thorough | Out-Null

                try {
                    $post = Get-WindowsPackage -Online -PackageName $candidate.PackageName -ErrorAction Stop
                    Write-Log ('Package state is now "{0}".' -f $post.PackageState) -Level Warn
                }
                catch {
                    Write-Log 'The package can no longer be queried; it was probably removed.' -Level Warn
                }

                Write-Log 'Stopping. Reboot, then rerun this script.' -Level Bad
                $failed++
                $exitCode = 1
            }
            default {
                $failed++
                Write-Log 'Not removed. Continuing with the next package.' -Level Warn
            }
        }

        if ($exitCode -ne 0) { break }
    }

    Write-Log ('Removed {0}, failed {1}, of {2} eligible.' -f $removed, $failed, $candidates.Count) -Level Step

    if ($exitCode -eq 0 -and -not $SkipFinalCleanup) {
        $cleanupResult = Invoke-FinalComponentCleanup
        if ($cleanupResult -ne 0) { $exitCode = $cleanupResult }
    }
    elseif ($SkipFinalCleanup) {
        Write-Log 'Skipping StartComponentCleanup by request. Little or no disk space has been reclaimed yet.' -Level Warn
    }

    $free = Get-SystemDriveFree
    if ($null -ne $free) {
        Write-Log ('{0} free on {1} now.' -f (Format-Bytes $free), $env:SystemDrive) -Level Good
    }

    Write-Log 'For store sizes, run: DISM /Online /Cleanup-Image /AnalyzeComponentStore'

    return $exitCode
}

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

if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

$script:RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $LogDirectory ('ComponentCleanup-{0}.log' -f $script:RunStamp)
$transcribing = $false

if (-not $WhatIfPreference) {
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
Write-Log ('Scheduled task: {0}   Skip final cleanup: {1}   Installer cache: {2}' -f [bool]$UseScheduledTask, [bool]$SkipFinalCleanup, [bool]$IncludeInstallerCache)
Write-Log ('Max packages: {0}   Non-interactive: {1}   Ignore advisories: {2}   Skip restore point: {3}' -f $MaxPackages, [bool]$NonInteractive, [bool]$IgnoreAdvisories, [bool]$SkipRestorePoint)
Write-Log ('Verbose: {0}' -f ($VerbosePreference -ne 'SilentlyContinue'))

$result = 0

try {
    $result = [int](Invoke-ComponentCleanup)

    # Separate subsystem, opt in only, and only once the component store phase has
    # finished cleanly. A machine that just hard-stopped preflight is not one to start
    # moving Windows Installer packages around on.
    if ($IncludeInstallerCache) {
        if ($result -eq 0) {
            $installerResult = [int](Invoke-InstallerCacheCleanup)
            if ($installerResult -ne 0) { $result = $installerResult }
        }
        else {
            Write-Log 'Skipping the installer cache because the component store phase did not complete cleanly.' -Level Warn
        }
    }
}
catch {
    Write-Log ('Unhandled error: {0}' -f $_.Exception.Message) -Level Bad
    Write-Log ('Check {0} and {1}' -f (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'), (Join-Path $env:SystemRoot 'Logs\DISM\dism.log'))
    $result = 1
}
finally {
    if ($transcribing) {
        Write-Log ('Transcript: {0}' -f $transcript)
        Stop-Transcript | Out-Null
    }
}

Write-Output 'Component cleanup complete...'
exit $result
