
<#
.SYNOPSIS
   Diagnose and repair DISM error 1726 on StartComponentCleanup.

.DESCRIPTION
   "DISM.exe /Online /Cleanup-Image /StartComponentCleanup" failing with error 1726
   (RPC_S_CALL_FAILED, HRESULT 0x800706BE) almost never means RPC itself is broken.

   1726 is what the DISM client reports when the servicing server stops answering. The
   server is TiWorker.exe, running under the TrustedInstaller service. So the useful
   question is not "why did RPC fail" but "why did TiWorker stop answering", and the
   answer is usually one of:

     - TiWorker crashed. The signature is an Application Error event for TiWorker.exe with
       exception code 0xC00000FD (STATUS_STACK_OVERFLOW), typically caused by component
       store metadata that sends a recursive CBS walk too deep. A very large superseded
       set makes this more likely.
     - A single package with bad metadata jams finalisation. CBS.log shows the package
       being finalised when the session died.
     - The component store is corrupt.
     - A servicing operation is already pending, so the new one cannot start cleanly.
     - The TrustedInstaller service is disabled or cannot start.
     - Security software is interfering with TiWorker.

   This script works through those in order. It gathers evidence first, then walks a
   remediation ladder from least to most invasive, re-probing StartComponentCleanup after
   each step and stopping as soon as it succeeds.

   WHAT IT DOES

   StartComponentCleanup is deliberately NOT used to test progress. On an affected machine
   it dies at the same point every time, costing a long wait to learn nothing. Instead:

     - Listing packages opens and closes a real CBS servicing session in seconds without
       touching the component graph. If THAT returns 1726, the servicing host is
       unreachable and the plumbing repairs are worth trying. If it succeeds, the failure
       is inside the cleanup walk and no amount of service cycling will help.
     - AnalyzeComponentStore works on affected machines, so its reclaimable package count
       is the progress signal. It drops when cleanup gets further than it used to, even if
       the overall command still fails.
     - A new Application Error event for TiWorker proves a crash rather than a timeout.
     - CBS.log is walked backwards from the last failure to name the package CBS was
       working on when it died. A failure that is always at the same point is
       deterministic, so that name is the prime suspect and the most actionable output
       this script produces.

   StartComponentCleanup is run exactly once, at the very end, purely to confirm whether
   the repairs worked. -SkipFinalVerify turns even that off.

     Phase 1  Evidence. Read only. Service state, pending operations, disk space, image
              health, package state counts, CBS.log and dism.log analysis, TiWorker crash
              events, installed security software.
     Phase 2  Cheap probes. Servicing session health, reclaimable baseline, suspect package.
     Phase 3  Repair ladder, only with -Execute, gated by -RepairLevel:

              Safe (default)
                1. Start the RPC service trio if any is stopped
                2. Restore TrustedInstaller to Manual if it has been Disabled
                3. Cycle TrustedInstaller so the next session starts fresh
                4. Rotate an oversized CBS.log
                5. Run the built-in servicing scheduled task instead of the command line

              Standard, adds
                6. DISM /Cleanup-Image /ScanHealth
                7. DISM /Cleanup-Image /RestoreHealth
                8. sfc /scannow

              Aggressive, adds
                9. Clear WinSxS\Temp\PendingDeletes and PendingRenames, only when no
                   servicing operation is pending

     Phase 4  Result. Reclaimable delta, one StartComponentCleanup verification, then the
              ranked next actions if it is still failing.

   SAFETY

   - Diagnose only is the default. -Execute is required before any repair step runs.
   - Every repair step is individually logged with the reason it was chosen.
   - Nothing here removes a package or deletes a component. Package removal is a different
     job; see ComponentCleanup.ps1 in this repo, which is the correct tool when the
     evidence points at a specific jammed package or at a TiWorker stack overflow.
   - The probe and the repair steps are real servicing operations. They are never started
     while another servicing operation is in flight, and a pending reboot is a hard stop.
   - The script never disables security software, never edits boot configuration, and
     never starts an in-place upgrade. Where those are the right answer it says so and
     gives you the commands.

.PARAMETER Elevated
   Internal. Set automatically when the script relaunches itself elevated.

.PARAMETER Execute
   Run the repair ladder. Without this the script only gathers evidence and probes.

.PARAMETER DryRun
   Explicitly request diagnose only. This is the default. Cannot be combined with -Execute.

.PARAMETER RepairLevel
   How far up the ladder to go. Safe (default), Standard, or Aggressive. See the
   description for what each level adds. Only meaningful with -Execute.

.PARAMETER SkipFinalVerify
   Do not run StartComponentCleanup at the end to confirm whether the repairs worked. The
   verification is run exactly once, after the whole ladder, and it is the only place this
   script runs that command. Skip it if you would rather run it yourself.

.PARAMETER CbsLogTailLines
   How many lines from the end of CBS.log to analyse. Default 2000.

.PARAMETER CbsLogMaxMB
   Rotate CBS.log when it exceeds this many megabytes. Default 100.

.PARAMETER TimeoutMinutes
   Timeout for each diagnostic or repair DISM operation. Default 60.

.PARAMETER CleanupTimeoutMinutes
   Timeout for the StartComponentCleanup probe. Default 240. Cleanup on a large store
   routinely runs over an hour.

.PARAMETER ServicingWaitMinutes
   How long to wait for an in-progress servicing operation to finish before giving up.
   Default 45. TiWorker.exe routinely works for a long stretch after a reboot while it
   finalises whatever was staged, so waiting is normally the right answer rather than
   refusing to run. Evidence gathering happens regardless; only the probes wait.

.PARAMETER NonInteractive
   Suppress confirmation prompts and the option dialog. Intended for scheduled runs.

.PARAMETER IgnoreAdvisories
   Continue past advisory warnings. Never overrides a hard stop.

.PARAMETER NoUI
   Never show the option dialog.

.PARAMETER LogDirectory
   Where to write the transcript. Default %SystemRoot%\Logs\Dism1726Repair.

.EXAMPLE
   .\Dism1726Repair.ps1
   Elevates, then shows an option dialog. Gathers evidence and probes without repairing.

.EXAMPLE
   .\Dism1726Repair.ps1 -DryRun
   Evidence and probe only, no dialog.

.EXAMPLE
   .\Dism1726Repair.ps1 -Execute
   Evidence, probe, then the Safe repair steps, stopping as soon as cleanup succeeds.

.EXAMPLE
   .\Dism1726Repair.ps1 -Execute -RepairLevel Standard
   Adds ScanHealth, RestoreHealth and sfc. Expect this to take a long time.

.NOTES
   Created by Jauder Ho
   Last modified 9/11/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   Requires PowerShell 5.1 or later, the DISM module, and an elevated session.

   Companion scripts in this repo:
     ComponentCleanup.ps1            removes superseded packages one at a time, which is
                                     the right move when a single package is jamming
                                     cleanup or when TiWorker is blowing its stack
     SoftwareDistributionCleanup.ps1 clears the Windows Update working area

.LINK
   https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder

.LINK
   https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-windows-update-error-0x80070bc9
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Elevated,
    [switch]$Execute,
    [switch]$DryRun,
    [ValidateSet('Safe', 'Standard', 'Aggressive')]
    [string]$RepairLevel = 'Safe',
    [switch]$SkipFinalVerify,
    [ValidateRange(100, 100000)]
    [int]$CbsLogTailLines = 2000,
    [ValidateRange(10, 10000)]
    [int]$CbsLogMaxMB = 100,
    [ValidateRange(1, 480)]
    [int]$TimeoutMinutes = 60,
    [ValidateRange(1, 1440)]
    [int]$CleanupTimeoutMinutes = 240,
    [ValidateRange(0, 480)]
    [int]$ServicingWaitMinutes = 45,
    [switch]$NonInteractive,
    [switch]$IgnoreAdvisories,
    [switch]$NoUI,
    [string]$LogDirectory = (Join-Path $env:SystemRoot 'Logs\Dism1726Repair')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# RPC infrastructure. 1726 is an RPC error code, so rule these out even though the cause is
# almost always TiWorker rather than RPC itself.
$script:RpcServices = @('RpcEptMapper', 'DcomLaunch', 'RpcSs')

$script:CbsLogPath = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
$script:DismLogPath = Join-Path $env:SystemRoot 'Logs\DISM\dism.log'

$script:ExitRebootRequired = 3010
$script:ExitTimedOut = -1

# Patterns worth surfacing from CBS.log, most diagnostic first.
$script:CbsSignatures = [ordered]@{
    'TiWorker stack overflow'      = '(?i)c00000fd|STATUS_STACK_OVERFLOW'
    'Finalisation failure'         = '(?i)Failed finalizing changes|Internal_Finalize'
    'Deeply superseded package'    = '(?i)is a top level package and is deeply superseded'
    'Store corruption'             = '(?i)CBS_E_STORE_CORRUPTION|corrupt'
    'Cannot uninstall / permanent' = '(?i)CBS_E_CANNOT_UNINSTALL|0x800f0825'
    'Pending operations'           = '(?i)0x800f0923|CBS_E_PENDING'
    'Source missing'               = '(?i)CBS_E_SOURCE_MISSING|0x800f081f'
    'Access denied'                = '(?i)0x80070005|E_ACCESSDENIED'
    'Out of memory / resources'    = '(?i)0x8007000e|E_OUTOFMEMORY|insufficient resources'
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
        Quotes a value for CommandLineToArgvW. A trailing run of backslashes would
        otherwise escape the closing quote and swallow the following argument.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    return ('"{0}"' -f ($Value -replace '(\\*)$', '$1$1'))
}

function Test-ParameterCombination {
    if ($Execute -and $DryRun) { return '-Execute and -DryRun are mutually exclusive.' }
    if ($LogDirectory -match '"') { return '-LogDirectory must not contain a double quote character.' }
    return $null
}

# Validation runs before elevation so an invalid invocation cannot trigger a UAC prompt and
# then print its error into a window the caller never sees.
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
    $interactive = [Environment]::UserInteractive

    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($interactive) { $relaunch += '-NoExit' }
    $relaunch += @('-File', (ConvertTo-QuotedArgument $PSCommandPath), '-Elevated')

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'Elevated') { continue }
        if ($entry.Value -is [switch]) {
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

    $value = [double]$Bytes
    foreach ($unit in @('B', 'KB', 'MB', 'GB', 'TB')) {
        if ($value -lt 1024 -or $unit -eq 'TB') {
            return ('{0:N2} {1}' -f $value, $unit)
        }
        $value = $value / 1024
    }
}

# ---------------------------------------------------------------------------
# Option dialog
# ---------------------------------------------------------------------------

function Test-ShouldShowDialog {
    if ($NoUI) { return $false }
    if ($NonInteractive) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }

    foreach ($explicit in @('Execute', 'DryRun', 'RepairLevel')) {
        if ($PSBoundParameters.ContainsKey($explicit)) { return $false }
    }

    return $true
}

function Show-OptionDialog {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    }
    catch {
        Write-Log ('Windows Forms is unavailable, so the option dialog is skipped: {0}' -f $_.Exception.Message) -Level Warn
        return $true
    }

    [Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'DISM 1726 Repair'
    $form.ClientSize = New-Object Drawing.Size(520, 520)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Topmost = $true

    $intro = New-Object Windows.Forms.Label
    $intro.Location = New-Object Drawing.Point(12, 12)
    $intro.Size = New-Object Drawing.Size(496, 46)
    $intro.Text = "Diagnoses why StartComponentCleanup returns 1726, then works through repairs from least to most invasive.`r`nNo packages or components are ever removed by this script."
    $form.Controls.Add($intro)

    $modeBox = New-Object Windows.Forms.GroupBox
    $modeBox.Text = 'Mode'
    $modeBox.Location = New-Object Drawing.Point(12, 62)
    $modeBox.Size = New-Object Drawing.Size(496, 80)
    $form.Controls.Add($modeBox)

    $radioDry = New-Object Windows.Forms.RadioButton
    $radioDry.Text = 'Diagnose only - gather evidence and probe, repair nothing'
    $radioDry.Location = New-Object Drawing.Point(15, 22)
    $radioDry.Size = New-Object Drawing.Size(465, 22)
    $radioDry.Checked = -not $Execute
    $modeBox.Controls.Add($radioDry)

    $radioExecute = New-Object Windows.Forms.RadioButton
    $radioExecute.Text = 'Diagnose and repair'
    $radioExecute.Location = New-Object Drawing.Point(15, 48)
    $radioExecute.Size = New-Object Drawing.Size(465, 22)
    $radioExecute.Checked = [bool]$Execute
    $modeBox.Controls.Add($radioExecute)

    $levelBox = New-Object Windows.Forms.GroupBox
    $levelBox.Text = 'How far to go'
    $levelBox.Location = New-Object Drawing.Point(12, 150)
    $levelBox.Size = New-Object Drawing.Size(496, 106)
    $form.Controls.Add($levelBox)

    $radioSafe = New-Object Windows.Forms.RadioButton
    $radioSafe.Text = 'Safe - service state, log rotation, scheduled task'
    $radioSafe.Location = New-Object Drawing.Point(15, 22)
    $radioSafe.Size = New-Object Drawing.Size(465, 22)
    $radioSafe.Checked = ($RepairLevel -eq 'Safe')
    $levelBox.Controls.Add($radioSafe)

    $radioStandard = New-Object Windows.Forms.RadioButton
    $radioStandard.Text = 'Standard - also ScanHealth, RestoreHealth and sfc (slow)'
    $radioStandard.Location = New-Object Drawing.Point(15, 48)
    $radioStandard.Size = New-Object Drawing.Size(465, 22)
    $radioStandard.Checked = ($RepairLevel -eq 'Standard')
    $levelBox.Controls.Add($radioStandard)

    $radioAggressive = New-Object Windows.Forms.RadioButton
    $radioAggressive.Text = 'Aggressive - also clear the WinSxS pending operation queues'
    $radioAggressive.Location = New-Object Drawing.Point(15, 74)
    $radioAggressive.Size = New-Object Drawing.Size(465, 22)
    $radioAggressive.Checked = ($RepairLevel -eq 'Aggressive')
    $levelBox.Controls.Add($radioAggressive)

    $chkSkipVerify = New-Object Windows.Forms.CheckBox
    $chkSkipVerify.Text = 'Skip the final StartComponentCleanup verification at the end'
    $chkSkipVerify.Location = New-Object Drawing.Point(15, 266)
    $chkSkipVerify.Size = New-Object Drawing.Size(493, 22)
    $chkSkipVerify.Checked = [bool]$SkipFinalVerify
    $form.Controls.Add($chkSkipVerify)

    $chkIgnore = New-Object Windows.Forms.CheckBox
    $chkIgnore.Text = 'Continue past advisory warnings (never overrides a hard stop)'
    $chkIgnore.Location = New-Object Drawing.Point(15, 292)
    $chkIgnore.Size = New-Object Drawing.Size(493, 22)
    $chkIgnore.Checked = [bool]$IgnoreAdvisories
    $form.Controls.Add($chkIgnore)

    $chkNonInteractive = New-Object Windows.Forms.CheckBox
    $chkNonInteractive.Text = 'Do not ask for confirmation'
    $chkNonInteractive.Location = New-Object Drawing.Point(15, 318)
    $chkNonInteractive.Size = New-Object Drawing.Size(493, 22)
    $chkNonInteractive.Checked = [bool]$NonInteractive
    $form.Controls.Add($chkNonInteractive)

    $chkVerbose = New-Object Windows.Forms.CheckBox
    $chkVerbose.Text = 'Verbose output - show every command and step in detail'
    $chkVerbose.Location = New-Object Drawing.Point(15, 344)
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
    $notice.Location = New-Object Drawing.Point(12, 374)
    $notice.Size = New-Object Drawing.Size(496, 96)
    $notice.ForeColor = [Drawing.Color]::FromArgb(150, 20, 20)
    $form.Controls.Add($notice)

    $buttonRun = New-Object Windows.Forms.Button
    $buttonRun.Text = 'Run'
    $buttonRun.Location = New-Object Drawing.Point(322, 480)
    $buttonRun.Size = New-Object Drawing.Size(90, 28)
    $buttonRun.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonRun)
    $form.AcceptButton = $buttonRun

    $buttonCancel = New-Object Windows.Forms.Button
    $buttonCancel.Text = 'Cancel'
    $buttonCancel.Location = New-Object Drawing.Point(418, 480)
    $buttonCancel.Size = New-Object Drawing.Size(90, 28)
    $buttonCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)
    $form.CancelButton = $buttonCancel

    $refresh = {
        $executing = $radioExecute.Checked
        $levelBox.Enabled = $executing
        $chkNonInteractive.Enabled = $executing
        $chkIgnore.Enabled = $executing

        $lines = @()
        if (-not $executing) {
            $lines += 'Diagnose only. Evidence is gathered and the probe runs, but nothing is repaired.'
        }
        elseif ($radioAggressive.Checked) {
            $lines += 'Aggressive clears the WinSxS pending operation queues. That is only done when no servicing operation is pending, but it is the least reversible step here.'
        }
        elseif ($radioStandard.Checked) {
            $lines += 'RestoreHealth and sfc can each run for an hour or more, and RestoreHealth may need source media.'
        }
        else {
            $lines += 'Safe steps only. Nothing here is destructive.'
        }

        if (-not $chkSkipVerify.Checked) {
            $lines += 'At the very end, StartComponentCleanup is run once to confirm whether the repairs worked. That is a real servicing operation and may take a long time.'
        }

        $notice.Text = ($lines -join "`r`n")
    }

    $radioDry.Add_CheckedChanged($refresh)
    $radioExecute.Add_CheckedChanged($refresh)
    $radioSafe.Add_CheckedChanged($refresh)
    $radioStandard.Add_CheckedChanged($refresh)
    $radioAggressive.Add_CheckedChanged($refresh)
    $chkSkipVerify.Add_CheckedChanged($refresh)
    & $refresh

    $answer = $form.ShowDialog()
    $accepted = ($answer -eq [Windows.Forms.DialogResult]::OK)

    if ($accepted) {
        $script:Execute = [switch]$radioExecute.Checked
        $script:DryRun = [switch]$radioDry.Checked
        $script:SkipFinalVerify = [switch]$chkSkipVerify.Checked
        $script:NonInteractive = [switch]($chkNonInteractive.Enabled -and $chkNonInteractive.Checked)
        $script:IgnoreAdvisories = [switch]($chkIgnore.Enabled -and $chkIgnore.Checked)

        if ($radioAggressive.Checked) { $script:RepairLevel = 'Aggressive' }
        elseif ($radioStandard.Checked) { $script:RepairLevel = 'Standard' }
        else { $script:RepairLevel = 'Safe' }

        if ($chkVerbose.Checked) { $script:VerbosePreference = 'Continue' }
        else { $script:VerbosePreference = 'SilentlyContinue' }
    }

    $form.Dispose()
    return $accepted
}

# ---------------------------------------------------------------------------
# Servicing plumbing
# ---------------------------------------------------------------------------

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

    Write-Verbose ('{0} {1}' -f $FilePath, ($Arguments -join ' '))

    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr

        # Touching Handle forces the object to cache the process handle. Without this,
        # ExitCode can come back $null after the process exits.
        try { $null = $process.Handle } catch { Write-Verbose $_.Exception.Message }

        # Poll rather than WaitForExit, so a long operation can report that it is alive.
        # Without this the console sits blank for the whole run and looks hung, because the
        # redirection that lets us parse the output also hides the progress bar.
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
                    Write-Log ('still running, {0:hh\:mm\:ss} elapsed, reports {1}' -f $elapsed, $percent)
                }
            }
        }

        $code = $script:ExitTimedOut

        if ($timedOut) {
            Write-Log ('{0} exceeded the {1} minute limit. Terminating the client.' -f (Split-Path -Leaf $FilePath), $LimitMinutes) -Level Bad
            try { $process.Kill() } catch { Write-Verbose $_.Exception.Message }
            $process.WaitForExit(30000) | Out-Null
        }
        else {
            try { $code = $process.ExitCode } catch { $code = $null }
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

function Invoke-Dism {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$LimitMinutes
    )

    return Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\dism.exe') -Arguments $Arguments -LimitMinutes $LimitMinutes
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

    foreach ($file in @('WinSxS\pending.xml', 'WinSxS\SessionsPending.xml')) {
        if (Test-Path (Join-Path $env:SystemRoot $file)) { $reasons += $file }
    }

    # Bare return. Callers wrap in @(), which a leading comma would defeat.
    return $reasons
}

function Get-ServicingActivity {
    <#
        Servicing processes that are currently doing work. These are things to WAIT for,
        not to abort over. TiWorker in particular runs for a long stretch after every
        reboot while it finalises whatever was staged, which is normal and healthy.

        TrustedInstaller.exe is NOT in the default set. It is the service host and lingers
        idle after a transaction finishes until its own idle timeout, so treating it as
        busy would both stall the wait and block the step whose whole job is to cycle it.
        -IncludeIdleHost adds it, for reporting only.
    #>
    param([switch]$IncludeIdleHost)

    # MoUsoCoreWorker is deliberately absent. It is the Update Orchestrator's worker: it
    # decides what to scan and install and drives TiWorker, but it does not touch the
    # component store itself. It also wakes on timers and restarts constantly even with
    # updates paused, so waiting for it to disappear can wait forever.
    $active = @()
    $names = @('TiWorker')
    if ($IncludeIdleHost) { $names += 'TrustedInstaller' }

    foreach ($name in $names) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            $detail = ('{0}.exe (PID {1}' -f $name, $process.Id)
            try {
                $detail += (', started {0:HH:mm:ss}, {1:N0}s CPU' -f $process.StartTime, $process.TotalProcessorTime.TotalSeconds)
            }
            catch {
                Write-Verbose ('Process detail unavailable for {0}' -f $name)
            }
            $active += ($detail + ')')
        }
    }

    return $active
}

function Get-CompetingDismClient {
    <#
        Another DISM client means a second servicing transaction, which is a genuine hard
        stop rather than something to wait out.
    #>
    $reasons = @()

    $found = @(Get-Process -Name 'dism' -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) {
        $reasons += ('dism.exe is running (PID {0})' -f ($found.Id -join ', '))
    }

    return $reasons
}

function Wait-ServicingQuiet {
    param([Parameter(Mandatory = $true)][int]$WaitMinutes)

    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $announced = $false

    while ($true) {
        $busy = @(Get-ServicingActivity)
        if ($busy.Count -eq 0) { return $true }

        if ((Get-Date) -ge $deadline) {
            Write-Log ('Servicing is still busy after {0} minute(s): {1}' -f $WaitMinutes, ($busy -join ', ')) -Level Warn
            return $false
        }

        if (-not $announced) {
            Write-Log ('Waiting for servicing to go quiet ({0})...' -f ($busy -join ', ')) -Level Warn
            $announced = $true
        }

        Start-Sleep -Seconds 10
    }
}

# ---------------------------------------------------------------------------
# Phase 1: evidence
# ---------------------------------------------------------------------------

function Get-ServiceFacts {
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [pscustomobject]@{ Name = $Name; Present = $false; Status = 'missing'; StartType = 'missing' }
    }

    $startType = 'Unknown'
    try { $startType = [string]$service.StartType }
    catch {
        try {
            $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
            $startType = [string]$wmi.StartMode
        }
        catch { Write-Verbose ('Start type unavailable for {0}' -f $Name) }
    }

    return [pscustomobject]@{
        Name      = $Name
        Present   = $true
        Status    = [string]$service.Status
        StartType = $startType
    }
}

function Show-ServiceEvidence {
    Write-Log 'Services' -Level Step

    $findings = @()

    foreach ($name in ($script:RpcServices + @('TrustedInstaller', 'wuauserv', 'msiserver'))) {
        $facts = Get-ServiceFacts -Name $name
        $level = 'Info'

        if (-not $facts.Present) {
            $level = 'Bad'
            $findings += ('{0} is missing entirely.' -f $name)
        }
        elseif ($script:RpcServices -contains $name -and $facts.Status -ne 'Running') {
            $level = 'Bad'
            $findings += ('{0} is {1}. RPC infrastructure must be running.' -f $name, $facts.Status)
        }
        elseif ($name -eq 'TrustedInstaller' -and $facts.StartType -eq 'Disabled') {
            $level = 'Bad'
            $findings += 'TrustedInstaller is Disabled. Servicing cannot run at all in this state.'
        }

        Write-Log ('{0,-18} {1,-12} start type {2}' -f $facts.Name, $facts.Status, $facts.StartType) -Level $level
    }

    return $findings
}

function Show-PendingEvidence {
    Write-Log 'Pending servicing state' -Level Step

    $pending = @(Get-PendingRebootReason)
    if ($pending.Count -eq 0) {
        Write-Log 'No pending servicing operations.' -Level Good
    }
    else {
        foreach ($reason in $pending) { Write-Log $reason -Level Bad }
    }

    return $pending
}

function Show-DiskEvidence {
    Write-Log 'Disk space' -Level Step

    $findings = @()
    $drive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction SilentlyContinue

    if ($null -eq $drive -or $null -eq $drive.Free) {
        Write-Log 'Free space could not be determined.' -Level Warn
        return $findings
    }

    Write-Log ('{0} free on {1}' -f (Format-Bytes $drive.Free), $env:SystemDrive)

    if ($drive.Free -lt 10GB) {
        $findings += ('Only {0} free on {1}. Servicing a large component store needs considerably more headroom, and low disk space is a documented cause of servicing failures.' -f (Format-Bytes $drive.Free), $env:SystemDrive)
    }

    return $findings
}

function Show-ImageHealthEvidence {
    Write-Log 'Component store health' -Level Step

    $findings = @()

    try {
        # CheckHealth only reads the stored corruption flag, so it returns in seconds.
        $health = [string](Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop).ImageHealthState
        if ([string]::IsNullOrWhiteSpace($health)) {
            Write-Log 'Health state was not reported.' -Level Warn
        }
        elseif ($health -eq 'Healthy') {
            Write-Log 'Flagged Healthy. Note this only reflects the stored flag, not a full scan.' -Level Good
        }
        else {
            Write-Log ('Flagged {0}.' -f $health) -Level Bad
            $findings += ('The component store is flagged {0}. Repair it before expecting cleanup to work.' -f $health)
        }
    }
    catch {
        Write-Log ('Health check failed: {0}' -f $_.Exception.Message) -Level Bad
        $findings += 'The component store health flag could not be read, which itself suggests the store is not in a good state.'
    }

    return $findings
}

function Show-PackageEvidence {
    Write-Log 'Package state' -Level Step

    $findings = @()

    try {
        $packages = @(Get-WindowsPackage -Online -ErrorAction Stop)
        Write-Log ('{0} packages present.' -f $packages.Count)

        foreach ($group in ($packages | Group-Object PackageState | Sort-Object Count -Descending)) {
            Write-Log ('{0,-24} {1}' -f $group.Name, $group.Count)
        }

        $superseded = @($packages | Where-Object { [string]$_.PackageState -eq 'Superseded' })
        if ($superseded.Count -gt 50) {
            $findings += ('{0} superseded packages. A very large superseded set makes the recursive CBS walk deeper and is associated with TiWorker stack overflows. Removing them individually with ComponentCleanup.ps1 is the targeted fix.' -f $superseded.Count)
        }
    }
    catch {
        Write-Log ('Package enumeration failed: {0}' -f $_.Exception.Message) -Level Bad
        $findings += 'Packages could not be enumerated at all, which points at a component store that is inaccessible rather than merely jammed.'
    }

    return $findings
}

function Show-LogEvidence {
    <#
        Reads only the tail of CBS.log. The file is routinely hundreds of megabytes, and
        Get-Content -Tail seeks rather than reading the whole thing.
    #>
    Write-Log 'CBS.log and dism.log analysis' -Level Step

    $findings = @()

    foreach ($path in @($script:CbsLogPath, $script:DismLogPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log ('{0} not found.' -f $path) -Level Warn
            continue
        }

        $size = (Get-Item -LiteralPath $path).Length
        Write-Log ('{0}  {1}' -f $path, (Format-Bytes $size))

        if ($path -eq $script:CbsLogPath -and $size -gt ($CbsLogMaxMB * 1MB)) {
            $findings += ('CBS.log is {0}, over the {1} MB threshold. An oversized CBS.log is associated with servicing stalls and is cheap to rotate.' -f (Format-Bytes $size), $CbsLogMaxMB)
        }
    }

    if (-not (Test-Path -LiteralPath $script:CbsLogPath)) { return $findings }

    $tail = @()
    try {
        $tail = @(Get-Content -LiteralPath $script:CbsLogPath -Tail $CbsLogTailLines -ErrorAction Stop)
    }
    catch {
        Write-Log ('Could not read CBS.log: {0}' -f $_.Exception.Message) -Level Warn
        return $findings
    }

    Write-Log ('Scanning the last {0} lines of CBS.log...' -f $tail.Count)

    foreach ($signature in $script:CbsSignatures.Keys) {
        $pattern = $script:CbsSignatures[$signature]
        $hits = @($tail | Where-Object { $_ -match $pattern })
        if ($hits.Count -eq 0) { continue }

        Write-Log ('{0}: {1} hit(s)' -f $signature, $hits.Count) -Level Bad
        foreach ($line in ($hits | Select-Object -Last 3)) {
            Write-Log ('  {0}' -f $line.Trim())
        }

        switch ($signature) {
            'TiWorker stack overflow' {
                $findings += 'CBS.log shows a stack overflow signature. This is the classic 1726 cause: TiWorker dies mid-session and the DISM client reports the RPC failure. Repairs in this script will not help. Shrink the superseded set with ComponentCleanup.ps1 instead.'
            }
            'Deeply superseded package' {
                $findings += 'CBS.log names deeply superseded packages. Removing those individually with ComponentCleanup.ps1 is what unjams cleanup.'
            }
            'Store corruption' {
                $findings += 'CBS.log mentions corruption. Run RestoreHealth, which is the Standard repair level.'
            }
            'Pending operations' {
                $findings += 'CBS.log reports pending operations. Reboot first; nothing else will work until it is clear.'
            }
        }
    }

    # The package being finalised when the session died is the single most useful clue.
    $finalising = @($tail | Where-Object { $_ -match '(?i)Package_[^\s,]+' } | Select-Object -Last 5)
    if ($finalising.Count -gt 0) {
        Write-Log 'Last packages mentioned in CBS.log (a jammed one is likely among these):' -Level Warn
        foreach ($line in $finalising) {
            if ($line -match '(?i)(Package_[^\s,\]]+)') {
                Write-Log ('  {0}' -f $Matches[1])
            }
        }
    }

    return $findings
}

function Show-CrashEvidence {
    Write-Log 'TiWorker and TrustedInstaller crash events' -Level Step

    $findings = @()

    try {
        $filter = @{
            LogName   = 'Application'
            Id        = 1000, 1001
            StartTime = (Get-Date).AddDays(-30)
        }

        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                Where-Object { $_.Message -match '(?i)TiWorker\.exe|TrustedInstaller\.exe|DismHost\.exe' })

        if ($events.Count -eq 0) {
            Write-Log 'No servicing process crashes in the last 30 days.' -Level Good
            return $findings
        }

        Write-Log ('{0} servicing process crash event(s) in the last 30 days.' -f $events.Count) -Level Bad

        # The exception code and faulting module are the whole point. Read them from the
        # event properties, which are not localised, and fall back to the rendered message.
        $detail = @()

        foreach ($event in $events) {
            $module = ''
            $code = ''

            try {
                if ($event.Properties.Count -ge 7) {
                    $module = [string]$event.Properties[3].Value
                    $raw = $event.Properties[6].Value
                    if ($raw -is [string]) { $code = $raw }
                    else { $code = ('0x{0:x8}' -f [uint32]$raw) }
                }
            }
            catch {
                Write-Verbose 'Event properties unavailable; falling back to the message text.'
            }

            if ([string]::IsNullOrWhiteSpace($code) -and $event.Message -match '(?i)Exception code:\s*(0x[0-9a-f]+)') {
                $code = $Matches[1]
            }
            if ([string]::IsNullOrWhiteSpace($module) -and $event.Message -match '(?i)Faulting module name:\s*([^\s,]+)') {
                $module = $Matches[1]
            }

            $detail += [pscustomobject]@{
                Time   = $event.TimeCreated
                Module = $module
                Code   = $code.ToLowerInvariant()
            }
        }

        foreach ($item in ($detail | Select-Object -First 5)) {
            Write-Log ('  {0:yyyy-MM-dd HH:mm}  exception {1}  in {2}' -f $item.Time, $item.Code, $item.Module) -Level Bad
        }

        Write-Log 'Crash signatures seen:' -Level Warn
        foreach ($group in ($detail | Group-Object Code, Module | Sort-Object Count -Descending)) {
            Write-Log ('  {0,-4} x  {1}' -f $group.Count, $group.Name) -Level Warn
        }

        $stackOverflow = @($detail | Where-Object { $_.Code -eq '0xc00000fd' })
        $accessViolation = @($detail | Where-Object { $_.Code -eq '0xc0000005' })

        if ($stackOverflow.Count -gt 0) {
            $findings += 'TiWorker crashed with STATUS_STACK_OVERFLOW (0xC00000FD). This is the definitive 1726 signature: the recursive CBS walk runs out of stack on a large component graph. No amount of service cycling, log rotation or health repair fixes it. Shrinking the superseded package set with ComponentCleanup.ps1 is the fix.'
        }
        elseif ($accessViolation.Count -gt 0) {
            $findings += 'TiWorker crashed with an access violation (0xC0000005). That is a hard crash in the servicing worker rather than a refusal, so the cleanup walk is hitting something it cannot parse. Removing superseded packages individually with ComponentCleanup.ps1 avoids the walk that crashes; if that does not help, the store needs RestoreHealth or an in-place upgrade.'
        }
        else {
            $findings += ('A servicing process has been crashing {0} time(s). Whatever it crashes on is the real cause of the 1726, and no plumbing repair will address it.' -f $events.Count)
        }
    }
    catch {
        Write-Log ('Could not read the Application event log: {0}' -f $_.Exception.Message) -Level Warn
    }

    return $findings
}

function Show-SecuritySoftwareEvidence {
    Write-Log 'Security software' -Level Step

    $findings = @()

    try {
        $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop)
        if ($products.Count -eq 0) {
            Write-Log 'None reported.' -Level Good
            return $findings
        }

        foreach ($product in $products) {
            Write-Log ('{0}' -f $product.displayName)
        }

        $thirdParty = @($products | Where-Object { $_.displayName -notmatch '(?i)Windows Defender|Microsoft Defender' })
        if ($thirdParty.Count -gt 0) {
            $findings += ('Third party security software is installed ({0}). Real time scanning of WinSxS is a known cause of servicing failures. If everything else here fails, temporarily disabling it and retrying is worth a try. This script will not disable it for you.' -f (($thirdParty | ForEach-Object { $_.displayName }) -join ', '))
        }
    }
    catch {
        Write-Log 'Security centre query unavailable (normal on Server SKUs).' -Level Warn
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Phase 2: probe
# ---------------------------------------------------------------------------

function Test-ServicingSession {
    <#
        The cheap probe, and the one used between repair steps.

        Listing packages opens and closes a real CBS servicing session but does no work in
        the component graph, so it returns in seconds and cannot crash the way the cleanup
        walk does. That makes it a clean discriminator:

          fails with 1726  -> the servicing host cannot be reached at all, which IS the
                              kind of thing service cycling and log rotation fix
          succeeds         -> sessions are fine and the failure is inside the cleanup walk,
                              which means no amount of plumbing repair will help

        StartComponentCleanup is deliberately NOT used here. It is slow, it does real work,
        and on an affected machine it dies partway through every time, so re-running it
        after each step would cost hours and tell us nothing the cheap probe does not.
    #>
    param([int]$LimitMinutes = 10)

    $result = Invoke-Dism -LimitMinutes $LimitMinutes -Arguments @('/Online', '/English', '/Get-Packages', '/Format:Table')
    $healthy = ($result.ExitCode -eq 0)

    if ($healthy) {
        Write-Log 'Servicing session opened and closed cleanly.' -Level Good
    }
    elseif ($result.TimedOut) {
        Write-Log ('Even a package listing did not finish within {0} minutes.' -f $LimitMinutes) -Level Bad
    }
    else {
        Write-Log ('A plain package listing failed with exit code {0}.' -f $result.ExitCode) -Level Bad
        if ($result.ExitCode -eq 1726) {
            Write-Log 'Session level 1726. The servicing host itself is unreachable, not just the cleanup walk.' -Level Bad
        }
    }

    return [pscustomobject]@{
        Healthy  = $healthy
        ExitCode = $result.ExitCode
        TimedOut = $result.TimedOut
    }
}

function Get-ReclaimableSnapshot {
    <#
        AnalyzeComponentStore is read only and works on affected machines, so the
        reclaimable package count makes a good progress signal. If a repair step lets
        cleanup get further than it did before, this number drops even when the overall
        command still fails.
    #>
    param([int]$LimitMinutes = 60)

    $result = Invoke-Dism -LimitMinutes $LimitMinutes -Arguments @('/Online', '/English', '/Cleanup-Image', '/AnalyzeComponentStore')

    if ($result.ExitCode -ne 0) {
        Write-Log ('AnalyzeComponentStore returned {0}.' -f $result.ExitCode) -Level Warn
        return $null
    }

    $reclaimable = $null
    $actual = ''
    $backups = ''

    foreach ($line in ($result.Output -split "`r?`n")) {
        if ($line -match '^\s*Number of Reclaimable Packages\s*:\s*(\d+)') { $reclaimable = [int]$Matches[1] }
        elseif ($line -match '^\s*Actual Size of Component Store\s*:\s*(.+?)\s*$') { $actual = $Matches[1] }
        elseif ($line -match '^\s*Backups and Disabled Features\s*:\s*(.+?)\s*$') { $backups = $Matches[1] }
    }

    return [pscustomobject]@{
        Reclaimable = $reclaimable
        ActualSize  = $actual
        BackupsSize = $backups
    }
}

function Get-ServicingCrashSince {
    <#
        A new Application Error for a servicing process since $Since is proof that the
        failure is a crash rather than a timeout or a refusal.
    #>
    param([Parameter(Mandatory = $true)][datetime]$Since)

    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1001; StartTime = $Since } -ErrorAction Stop |
                Where-Object { $_.Message -match '(?i)TiWorker\.exe|TrustedInstaller\.exe|DismHost\.exe' })
    }
    catch {
        return @()
    }
}

function Find-JammedPackage {
    <#
        The single most useful thing this script produces. When cleanup dies at a fixed
        point every time, the failure is deterministic, and the component CBS was working
        on when it died is named in CBS.log just before the error. That name is what you
        feed to ComponentCleanup.ps1.
    #>
    if (-not (Test-Path -LiteralPath $script:CbsLogPath)) { return @() }

    $tail = @()
    try {
        $tail = @(Get-Content -LiteralPath $script:CbsLogPath -Tail $CbsLogTailLines -ErrorAction Stop)
    }
    catch {
        Write-Log ('Could not read CBS.log: {0}' -f $_.Exception.Message) -Level Warn
        return @()
    }

    # Walk backwards from the last failure marker and collect the package identities that
    # appear immediately before it.
    $failureIndex = -1
    for ($i = $tail.Count - 1; $i -ge 0; $i--) {
        if ($tail[$i] -match '(?i)Failed finalizing changes|Internal_Finalize|c00000fd|0x800706be|CBS_E_') {
            $failureIndex = $i
            break
        }
    }

    if ($failureIndex -lt 0) { return @() }

    $start = [Math]::Max(0, $failureIndex - 200)
    $names = New-Object 'System.Collections.Generic.List[string]'

    for ($i = $failureIndex; $i -ge $start; $i--) {
        if ($tail[$i] -match '(?i)((?:Package_|Microsoft-Windows-)[^\s,\]"'']+~[^\s,\]"'']+)') {
            $name = $Matches[1].TrimEnd('.', ',', ':')
            if (-not $names.Contains($name)) { $names.Add($name) }
        }
        if ($names.Count -ge 5) { break }
    }

    return $names.ToArray()
}

# ---------------------------------------------------------------------------
# Phase 3: repair steps
#
# Each returns $true if it changed anything worth re-probing after.
# ---------------------------------------------------------------------------

function Repair-RpcServices {
    Write-Log 'Repair: RPC service trio' -Level Step

    $changed = $false

    foreach ($name in $script:RpcServices) {
        $facts = Get-ServiceFacts -Name $name
        if (-not $facts.Present -or $facts.Status -eq 'Running') { continue }

        if ($facts.StartType -eq 'Disabled') {
            # Core RPC infrastructure disabled is far outside this script's remit.
            Write-Log ('{0} is Disabled. That is a system level misconfiguration; fix it deliberately, not from a cleanup script.' -f $name) -Level Bad
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($name, 'Start service')) { continue }

        try {
            Start-Service -Name $name -ErrorAction Stop
            Write-Log ('Started {0}.' -f $name) -Level Good
            $changed = $true
        }
        catch {
            Write-Log ('Could not start {0}: {1}' -f $name, $_.Exception.Message) -Level Bad
        }
    }

    if (-not $changed) { Write-Log 'RPC services were already correct. Nothing to do.' }
    return $changed
}

function Repair-TrustedInstallerStartType {
    Write-Log 'Repair: TrustedInstaller start type' -Level Step

    $facts = Get-ServiceFacts -Name 'TrustedInstaller'
    if (-not $facts.Present) {
        Write-Log 'TrustedInstaller is missing. Nothing this script can do.' -Level Bad
        return $false
    }

    if ($facts.StartType -ne 'Disabled') {
        Write-Log ('Start type is {0}, which is fine. Nothing to do.' -f $facts.StartType)
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess('TrustedInstaller', 'Set start type to Manual')) { return $false }

    try {
        # Manual is the Windows default for this service, so this restores a default rather
        # than weakening anything.
        Set-Service -Name 'TrustedInstaller' -StartupType Manual -ErrorAction Stop
        Write-Log 'Set TrustedInstaller to Manual, which is the Windows default.' -Level Good
        return $true
    }
    catch {
        Write-Log ('Could not change the start type: {0}' -f $_.Exception.Message) -Level Bad
        return $false
    }
}

function Repair-CycleTrustedInstaller {
    Write-Log 'Repair: cycle TrustedInstaller' -Level Step

    $foreign = @(Get-ServicingActivity)
    if ($foreign.Count -gt 0) {
        Write-Log ('Servicing is active ({0}). Not cycling the service into an in-flight transaction.' -f ($foreign -join ', ')) -Level Bad
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess('TrustedInstaller', 'Stop the service so the next session starts fresh')) { return $false }

    try {
        Stop-Service -Name 'TrustedInstaller' -Force -ErrorAction Stop
        Write-Log 'Stopped TrustedInstaller. It is demand-start and will come back on the next DISM call.' -Level Good
        Start-Sleep -Seconds 5
        return $true
    }
    catch {
        Write-Log ('Could not stop TrustedInstaller: {0}' -f $_.Exception.Message) -Level Warn
        return $false
    }
}

function Repair-RotateCbsLog {
    Write-Log 'Repair: rotate CBS.log' -Level Step

    if (-not (Test-Path -LiteralPath $script:CbsLogPath)) {
        Write-Log 'CBS.log not found. Nothing to do.'
        return $false
    }

    $size = (Get-Item -LiteralPath $script:CbsLogPath).Length
    if ($size -le ($CbsLogMaxMB * 1MB)) {
        Write-Log ('CBS.log is {0}, under the {1} MB threshold. Leaving it alone.' -f (Format-Bytes $size), $CbsLogMaxMB)
        return $false
    }

    $foreign = @(Get-ServicingActivity)
    if ($foreign.Count -gt 0) {
        Write-Log ('Servicing is active ({0}). Not touching CBS.log now.' -f ($foreign -join ', ')) -Level Bad
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($script:CbsLogPath, ('Rename to CBS.log.old ({0})' -f (Format-Bytes $size)))) { return $false }

    # CBS holds the file open, so the service has to be down for the rename.
    try { Stop-Service -Name 'TrustedInstaller' -Force -ErrorAction SilentlyContinue } catch { Write-Verbose $_.Exception.Message }
    Wait-ServicingQuiet -WaitMinutes 5 | Out-Null

    $target = Join-Path (Split-Path -Parent $script:CbsLogPath) ('CBS.{0}.old.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    try {
        Rename-Item -LiteralPath $script:CbsLogPath -NewName (Split-Path -Leaf $target) -ErrorAction Stop
        Write-Log ('Rotated CBS.log to {0}. CBS recreates it on the next operation.' -f (Split-Path -Leaf $target)) -Level Good
        return $true
    }
    catch {
        Write-Log ('Could not rotate CBS.log: {0}' -f $_.Exception.Message) -Level Warn
        return $false
    }
}

function Repair-ServicingScheduledTask {
    <#
        The built-in task runs under TrustedInstaller at low priority with a one hour cap,
        and frequently completes where the command line returns 1726.
    #>
    Write-Log 'Repair: run the built-in servicing scheduled task' -Level Step

    $taskPath = '\Microsoft\Windows\Servicing\'
    $taskName = 'StartComponentCleanup'

    try {
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
    }
    catch {
        Write-Log 'The built-in StartComponentCleanup task was not found.' -Level Warn
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}{1}' -f $taskPath, $taskName), 'Start scheduled task and wait')) { return $false }

    Write-Log ('Current task state: {0}' -f $task.State)
    Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName

    # The task caps itself at an hour; wait a little beyond that.
    $deadline = (Get-Date).AddMinutes(70)
    Start-Sleep -Seconds 10

    while ((Get-Date) -lt $deadline) {
        $state = (Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName).State
        if ([string]$state -ne 'Running') {
            Write-Log ('Task finished with state {0}.' -f $state) -Level Good
            return $true
        }
        Start-Sleep -Seconds 30
    }

    Write-Log 'The task is still running after 70 minutes. Leaving it to finish on its own.' -Level Warn
    return $false
}

function Repair-ScanHealth {
    Write-Log 'Repair: DISM /Cleanup-Image /ScanHealth' -Level Step
    Write-Log 'This performs a full scan of the component store and can take a long time.'

    if (-not $PSCmdlet.ShouldProcess('component store', 'ScanHealth')) { return $false }

    $result = Invoke-Dism -LimitMinutes $TimeoutMinutes -Arguments @('/Online', '/English', '/Cleanup-Image', '/ScanHealth')

    if ($result.ExitCode -eq 0) {
        Write-Log 'ScanHealth reported no corruption.' -Level Good
    }
    else {
        Write-Log ('ScanHealth returned {0}.' -f $result.ExitCode) -Level Warn
        if ($result.Output) { Write-Log $result.Output }
    }

    # Diagnostic only, so never worth re-probing on its own.
    return $false
}

function Repair-RestoreHealth {
    Write-Log 'Repair: DISM /Cleanup-Image /RestoreHealth' -Level Step
    Write-Log 'This repairs the component store and may download replacement files from Windows Update.'

    if (-not $PSCmdlet.ShouldProcess('component store', 'RestoreHealth')) { return $false }

    $result = Invoke-Dism -LimitMinutes $TimeoutMinutes -Arguments @('/Online', '/English', '/NoRestart', '/Cleanup-Image', '/RestoreHealth')

    if ($result.ExitCode -eq 0) {
        Write-Log 'RestoreHealth completed.' -Level Good
        return $true
    }

    Write-Log ('RestoreHealth returned {0}.' -f $result.ExitCode) -Level Bad
    if ($result.Output) { Write-Log $result.Output }
    Write-Log 'If it could not find source files, rerun it with /Source pointing at matching install media:' -Level Warn
    Write-Log '  DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:1 /LimitAccess' -Level Warn
    return $false
}

function Repair-Sfc {
    Write-Log 'Repair: sfc /scannow' -Level Step

    if (-not $PSCmdlet.ShouldProcess('system files', 'sfc /scannow')) { return $false }

    $result = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\sfc.exe') -Arguments @('/scannow') -LimitMinutes $TimeoutMinutes

    if ($result.ExitCode -eq 0) {
        Write-Log 'sfc completed.' -Level Good
        return $true
    }

    Write-Log ('sfc returned {0}. See %SystemRoot%\Logs\CBS\CBS.log for detail.' -f $result.ExitCode) -Level Warn
    return $false
}

function Repair-PendingQueues {
    <#
        Clearing the WinSxS pending queues is the least reversible step here, so it is
        hard-gated on there being no pending servicing operation at all.
    #>
    Write-Log 'Repair: clear the WinSxS pending operation queues' -Level Step

    $pending = @(Get-PendingRebootReason)
    if ($pending.Count -gt 0) {
        Write-Log ('There ARE pending operations ({0}). Clearing the queues now would discard real work. Reboot first.' -f ($pending -join ', ')) -Level Bad
        return $false
    }

    $foreign = @(Get-ServicingActivity)
    if ($foreign.Count -gt 0) {
        Write-Log ('Servicing is active ({0}). Not touching the queues.' -f ($foreign -join ', ')) -Level Bad
        return $false
    }

    $changed = $false

    foreach ($folder in @('WinSxS\Temp\PendingDeletes', 'WinSxS\Temp\PendingRenames')) {
        $path = Join-Path $env:SystemRoot $folder
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue)
        if ($items.Count -eq 0) {
            Write-Log ('{0} is already empty.' -f $folder)
            continue
        }

        Write-Log ('{0} holds {1} item(s).' -f $folder, $items.Count) -Level Warn

        if (-not $PSCmdlet.ShouldProcess($path, ('Delete {0} queued item(s)' -f $items.Count))) { continue }

        foreach ($item in $items) {
            try {
                Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
                $changed = $true
            }
            catch {
                Write-Log ('Could not delete {0}: {1}' -f $item.Name, $_.Exception.Message) -Level Warn
            }
        }
    }

    if ($changed) { Write-Log 'Pending queues cleared.' -Level Good }
    else { Write-Log 'Nothing was cleared.' }

    return $changed
}

# ---------------------------------------------------------------------------
# Phase 4: report
# ---------------------------------------------------------------------------

function Show-NextActions {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Findings,
        [Parameter(Mandatory = $true)][bool]$Succeeded,
        [AllowEmptyCollection()][array]$Jammed = @()
    )

    Write-Log '' -Level Info
    Write-Log 'Summary' -Level Step

    if ($Succeeded) {
        Write-Log 'StartComponentCleanup now completes. Nothing further is needed.' -Level Good
        return
    }

    if ($Findings.Count -gt 0) {
        Write-Log 'Evidence collected:' -Level Warn
        $index = 0
        foreach ($finding in $Findings) {
            $index++
            Write-Log ('{0}. {1}' -f $index, $finding) -Level Warn
        }
    }
    else {
        Write-Log 'No specific cause was identified from the available evidence.' -Level Warn
    }

    Write-Log '' -Level Info
    Write-Log 'Ranked next actions' -Level Step

    if ($Jammed.Count -gt 0) {
        Write-Log '1. Remove the suspect package individually. CBS.log named it just before the'
        Write-Log '   failure, and a cleanup that dies at the same point every time is failing'
        Write-Log '   deterministically on one item:'
        foreach ($name in $Jammed) {
            Write-Log ('     {0}' -f $name) -Level Warn
        }
        Write-Log '   Verify it is Superseded first, then let ComponentCleanup.ps1 handle it:'
        Write-Log ('     Get-WindowsPackage -Online -PackageName "{0}"' -f $Jammed[0])
        Write-Log '     .\ComponentCleanup.ps1 -Execute -MaxPackages 1'
        Write-Log '   Do not hand-remove a package that is not in the Superseded state.'
    }
    else {
        Write-Log '1. Run ComponentCleanup.ps1 from this repo. Removing superseded packages one'
        Write-Log '   at a time shrinks the set that makes CBS recurse too deep, and is the'
        Write-Log '   targeted fix for the most common cause of 1726.'
    }

    Write-Log '2. Reboot and rerun. A surprising number of servicing failures clear after the'
    Write-Log '   pending queue is flushed by a restart.'
    Write-Log '3. Retry in Safe Mode. Servicing frequently completes there because third party'
    Write-Log '   filter drivers and scanners are not loaded. Set it deliberately and clear it'
    Write-Log '   immediately afterwards, or the machine stays in Safe Mode:'
    Write-Log '     bcdedit /set {current} safeboot minimal'
    Write-Log '     (reboot, run the cleanup, then)'
    Write-Log '     bcdedit /deletevalue {current} safeboot'
    Write-Log '   This script deliberately does not do that for you. A half applied boot change'
    Write-Log '   leaves an unusable machine.'
    Write-Log '4. If third party security software was listed, disable its real time scanning'
    Write-Log '   temporarily and retry.'
    Write-Log '5. RestoreHealth with explicit source media, if it could not reach Windows Update:'
    Write-Log '     DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:1 /LimitAccess'
    Write-Log '6. Last resort: an in-place upgrade repair install, keeping files and apps. Run'
    Write-Log '   setup.exe from matching media. This rebuilds the component store wholesale.'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-Repair1726 {
    <#
        Returns the process exit code. 0 means StartComponentCleanup now works.
    #>
    $findings = @()

    Write-Log 'Phase 1: evidence' -Level Step
    $findings += @(Show-ServiceEvidence)

    $pending = @(Show-PendingEvidence)
    if ($pending.Count -gt 0) {
        # Nothing below this line can work while a servicing operation is pending.
        Write-Log 'A servicing operation is pending. Reboot and rerun; no repair here can work first.' -Level Bad
        Show-NextActions -Findings @($findings + @('A servicing operation is pending: ' + ($pending -join ', '))) -Succeeded $false
        return 1
    }

    # A competing DISM client is a second transaction and is never waited out.
    $competing = @(Get-CompetingDismClient)
    if ($competing.Count -gt 0) {
        Write-Log ('Another DISM client is running: {0}. Wait for it to finish and rerun.' -f ($competing -join ', ')) -Level Bad
        return 1
    }

    # Evidence gathering is read only, so it runs even while servicing is busy. TiWorker
    # working away after a reboot is normal, not a reason to refuse to look at anything.
    $activity = @(Get-ServicingActivity)
    if ($activity.Count -gt 0) {
        Write-Log 'Servicing is currently active:' -Level Warn
        foreach ($item in $activity) { Write-Log ('  {0}' -f $item) -Level Warn }
        Write-Log 'That is expected for a while after a reboot. Evidence gathering continues; the probes wait for it.' -Level Warn
    }

    $findings += @(Show-DiskEvidence)
    $findings += @(Show-ImageHealthEvidence)
    $findings += @(Show-PackageEvidence)
    $findings += @(Show-LogEvidence)
    $findings += @(Show-CrashEvidence)
    $findings += @(Show-SecuritySoftwareEvidence)

    if ($findings.Count -gt 0 -and -not $Execute -and -not $IgnoreAdvisories) {
        Write-Log ('{0} finding(s) recorded. They are summarised at the end.' -f $findings.Count) -Level Warn
    }

    # Now the probes need a quiet machine, so wait rather than abort.
    if (@(Get-ServicingActivity).Count -gt 0) {
        Write-Log '' -Level Info
        Write-Log ('Waiting up to {0} minute(s) for servicing to finish before probing...' -f $ServicingWaitMinutes) -Level Step

        if (-not (Wait-ServicingQuiet -WaitMinutes $ServicingWaitMinutes)) {
            Write-Log 'Servicing is still busy. It may be installing an update right now.' -Level Bad
            Write-Log 'Let it finish, or check Windows Update to see what is in progress, then rerun.' -Level Bad
            $findings += 'Servicing was still active after the wait, so the probes could not run. If an update is installing, let it complete first.'
            Show-NextActions -Findings $findings -Succeeded $false
            return 1
        }

        Write-Log 'Servicing is quiet.' -Level Good
    }

    Write-Log '' -Level Info
    Write-Log 'Phase 2: cheap probes' -Level Step

    $session = Test-ServicingSession
    if (-not $session.Healthy) {
        $findings += 'A plain package listing already fails, so the servicing host is unreachable rather than merely crashing partway through cleanup. The plumbing repairs below are the right ones to try.'
    }
    else {
        $findings += 'Servicing sessions open fine, so the failure is inside the cleanup walk itself, not in RPC or the service. Expect plumbing repairs to make no difference and the package level fix to be what works.'
    }

    $before = Get-ReclaimableSnapshot
    if ($null -ne $before) {
        Write-Log ('Reclaimable packages: {0}   Actual store: {1}   Backups: {2}' -f $before.Reclaimable, $before.ActualSize, $before.BackupsSize)
    }

    # A cleanup that dies at a fixed point is deterministic, so the package named just
    # before the failure in CBS.log is the prime suspect.
    $jammed = @(Find-JammedPackage)
    if ($jammed.Count -gt 0) {
        Write-Log '' -Level Info
        Write-Log 'Packages named immediately before the last failure in CBS.log' -Level Step
        Write-Log 'These are the prime suspects. The first is the most likely.' -Level Warn
        foreach ($name in $jammed) { Write-Log ('  {0}' -f $name) -Level Warn }
        $findings += ('CBS.log names {0} as the last package(s) touched before the failure. Removing the first of these individually with ComponentCleanup.ps1 is the most direct fix available.' -f ($jammed[0]))
    }

    if (-not $Execute) {
        Write-Log '' -Level Info
        Write-Log 'Diagnose only. Rerun with -Execute to work through the repair ladder.' -Level Warn
        Show-NextActions -Findings $findings -Succeeded $false -Jammed $jammed
        return 1
    }

    Write-Log '' -Level Info
    Write-Log ('Phase 3: repair ladder at level {0}' -f $RepairLevel) -Level Step

    $steps = @(
        @{ Name = 'RPC services'; Action = { Repair-RpcServices }; Level = 'Safe' }
        @{ Name = 'TrustedInstaller start type'; Action = { Repair-TrustedInstallerStartType }; Level = 'Safe' }
        @{ Name = 'Cycle TrustedInstaller'; Action = { Repair-CycleTrustedInstaller }; Level = 'Safe' }
        @{ Name = 'Rotate CBS.log'; Action = { Repair-RotateCbsLog }; Level = 'Safe' }
        @{ Name = 'Built-in servicing task'; Action = { Repair-ServicingScheduledTask }; Level = 'Safe' }
        @{ Name = 'ScanHealth'; Action = { Repair-ScanHealth }; Level = 'Standard' }
        @{ Name = 'RestoreHealth'; Action = { Repair-RestoreHealth }; Level = 'Standard' }
        @{ Name = 'sfc /scannow'; Action = { Repair-Sfc }; Level = 'Standard' }
        @{ Name = 'Clear pending queues'; Action = { Repair-PendingQueues }; Level = 'Aggressive' }
    )

    $allowed = switch ($RepairLevel) {
        'Safe' { @('Safe') }
        'Standard' { @('Safe', 'Standard') }
        default { @('Safe', 'Standard', 'Aggressive') }
    }

    $applied = @()

    foreach ($step in $steps) {
        if ($allowed -notcontains $step.Level) {
            Write-Verbose ('Skipping {0}: needs level {1}.' -f $step.Name, $step.Level)
            continue
        }

        Write-Log '' -Level Info
        $changed = $false
        $stepStart = Get-Date

        try {
            $changed = [bool](& $step.Action)
        }
        catch {
            Write-Log ('{0} failed: {1}' -f $step.Name, $_.Exception.Message) -Level Bad
            continue
        }

        if (-not $changed) { continue }

        $applied += $step.Name

        # Re-check, because a repair step can itself leave a pending operation behind.
        $pending = @(Get-PendingRebootReason)
        if ($pending.Count -gt 0) {
            Write-Log ('{0} left a pending operation ({1}). Reboot and rerun.' -f $step.Name, ($pending -join ', ')) -Level Bad
            $findings += ('{0} completed but requires a reboot before cleanup can run.' -f $step.Name)
            Show-NextActions -Findings $findings -Succeeded $false -Jammed $jammed
            return $script:ExitRebootRequired
        }

        Wait-ServicingQuiet -WaitMinutes 15 | Out-Null

        # Cheap probe only. StartComponentCleanup is never re-run here.
        $session = Test-ServicingSession
        $crashes = @(Get-ServicingCrashSince -Since $stepStart)
        if ($crashes.Count -gt 0) {
            Write-Log ('{0} servicing process crash(es) during this step.' -f $crashes.Count) -Level Bad
        }
    }

    Write-Log '' -Level Info
    Write-Log 'Phase 4: result' -Level Step
    Write-Log ('Repair steps that changed something: {0}' -f $(if ($applied.Count -gt 0) { $applied -join ', ' } else { 'none' }))

    $after = Get-ReclaimableSnapshot
    if ($null -ne $before -and $null -ne $after -and $null -ne $before.Reclaimable -and $null -ne $after.Reclaimable) {
        $delta = $before.Reclaimable - $after.Reclaimable
        if ($delta -gt 0) {
            Write-Log ('Reclaimable packages fell from {0} to {1}. Cleanup is getting further than it was.' -f $before.Reclaimable, $after.Reclaimable) -Level Good
        }
        else {
            Write-Log ('Reclaimable packages unchanged at {0}.' -f $after.Reclaimable) -Level Warn
        }
    }

    $succeeded = $false

    if ($SkipFinalVerify) {
        Write-Log 'Final verification skipped by request. Run the cleanup yourself to confirm.' -Level Warn
    }
    else {
        Write-Log '' -Level Info
        Write-Log 'Final verification' -Level Step
        Write-Log 'Running your actual command once, now that the repairs have been applied.'
        Write-Log 'This is the only time this script runs StartComponentCleanup. It may take a long time.' -Level Warn

        $verifyStart = Get-Date
        $result = Invoke-Dism -LimitMinutes $CleanupTimeoutMinutes -Arguments @(
            '/Online', '/English', '/NoRestart', '/Cleanup-Image', '/StartComponentCleanup'
        )

        $succeeded = ($result.ExitCode -eq 0 -or $result.ExitCode -eq $script:ExitRebootRequired)

        if ($succeeded) {
            Write-Log ('StartComponentCleanup SUCCEEDED (exit {0}).' -f $result.ExitCode) -Level Good
        }
        else {
            if ($result.TimedOut) {
                Write-Log ('It did not finish within {0} minutes.' -f $CleanupTimeoutMinutes) -Level Bad
            }
            else {
                Write-Log ('It failed with exit code {0}.' -f $result.ExitCode) -Level Bad
            }
            if ($result.Output) { Write-Log $result.Output }

            $crashes = @(Get-ServicingCrashSince -Since $verifyStart)
            if ($crashes.Count -gt 0) {
                Write-Log 'A servicing process crashed during the attempt:' -Level Bad
                foreach ($event in ($crashes | Select-Object -First 3)) {
                    Write-Log ('  {0:yyyy-MM-dd HH:mm}  {1}' -f $event.TimeCreated, (($event.Message -split "`r?`n") | Select-Object -First 1)) -Level Bad
                }
                $findings += 'A servicing process crashed during the verification attempt. That is a crash, not a timeout or a refusal, and it confirms the package level fix is the one you need.'
            }

            # Re-read the log now that there is a fresh failure to look at.
            $fresh = @(Find-JammedPackage)
            if ($fresh.Count -gt 0) { $jammed = $fresh }
        }
    }

    if (-not $succeeded -and $RepairLevel -ne 'Aggressive') {
        Write-Log ('Consider rerunning with -RepairLevel {0}.' -f $(if ($RepairLevel -eq 'Safe') { 'Standard' } else { 'Aggressive' })) -Level Warn
    }

    Show-NextActions -Findings $findings -Succeeded $succeeded -Jammed $jammed
    if ($succeeded) { return 0 }
    return 1
}

if (Test-ShouldShowDialog) {
    if (-not (Show-OptionDialog)) {
        Write-Output 'Cancelled. Nothing was changed.'
        exit 0
    }

    $invalid = Test-ParameterCombination
    if ($invalid) {
        Write-Error $invalid
        exit 1
    }
}

if ($NonInteractive) { $ConfirmPreference = 'None' }

$transcript = ''
$transcribing = $false

if (-not $WhatIfPreference) {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    $transcript = Join-Path $LogDirectory ('Dism1726Repair-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    try {
        Start-Transcript -Path $transcript -Force | Out-Null
        $transcribing = $true
    }
    catch {
        Write-Log ('Transcript unavailable: {0}' -f $_.Exception.Message) -Level Warn
    }
}

$mode = 'DIAGNOSE ONLY'
if ($Execute) { $mode = ('REPAIR, level {0}' -f $RepairLevel) }
Write-Log ('Mode: {0}' -f $mode) -Level Step
Write-Log ('Skip final verify: {0}   Non-interactive: {1}   Ignore advisories: {2}   Verbose: {3}' -f [bool]$SkipFinalVerify, [bool]$NonInteractive, [bool]$IgnoreAdvisories, ($VerbosePreference -ne 'SilentlyContinue'))

$result = 0

try {
    $result = [int](Invoke-Repair1726)
}
catch {
    Write-Log ('Unhandled error: {0}' -f $_.Exception.Message) -Level Bad
    Write-Log ('Check {0} and {1}' -f $script:CbsLogPath, $script:DismLogPath)
    $result = 1
}
finally {
    if ($transcribing) {
        Write-Log ('Transcript: {0}' -f $transcript)
        Stop-Transcript | Out-Null
    }
}

Write-Output 'DISM 1726 repair complete...'
exit $result
