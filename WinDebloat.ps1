
<#
.SYNOPSIS
   Personal Windows 11 debloater

.DESCRIPTION
   Removes the bundled applications, then sets the policies that stop Windows
   from installing them again. Also turns off Copilot, Recall, the telemetry
   collectors, Xbox and OneDrive.

   Written for Windows 11 24H2 (build 26100) and later. It runs on Windows 11
   21H2 and later and reports the settings that the older build does not have.
   Windows 10 is out of scope: too many of these values have a different name
   there, and a half applied set is worse than none.

   WARNING: Do not run this without reading through first.

.PARAMETER Elevated
   Internal. Set on the self-elevated relaunch so a failed elevation does not loop.

.PARAMETER DryRun
   Report each change but make none. Use this first.

.PARAMETER SkipCheckpoint
   Continue without a system restore point. The script refuses to make changes
   without one unless you set this.

.PARAMETER KeepRecallSnapshots
   Turn Recall off but keep the snapshots that are already on disk. Without this
   the snapshots are deleted, which cannot be undone.

.PARAMETER KeepXbox
   Retain the whole Xbox stack: the applications, the identity provider, the
   four services and the two scheduled tasks.

.PARAMETER KeepOneDrive
   Retain OneDrive, its policy value and its Explorer navigation pane entry.

.PARAMETER KeepTeams
   Retain both Teams clients and the Chat taskbar button.

.PARAMETER Verbose
   Emit step-level progress and key variable state. ON by default. Turn it off
   with -Verbose:$false.

.EXAMPLE
   .\WinDebloat.ps1 -DryRun
   Report every change without making one. Always start here.

.EXAMPLE
   .\WinDebloat.ps1
   Make a restore point, then apply the changes. Recall is removed in full,
   the snapshots on disk included.

.EXAMPLE
   .\WinDebloat.ps1 -KeepRecallSnapshots -Verbose:$false
   Apply the changes quietly but keep the Recall snapshots on disk.

.EXAMPLE
   .\WinDebloat.ps1 -KeepXbox -KeepTeams
   Remove everything except the Xbox stack and the two Teams clients.

.NOTES
   Created by Jauder Ho
   Last modified 9/12/2026
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

   SAFEGUARDS
   - A system restore point is made before the first change. The script stops if
     System Restore is turned off, unless -SkipCheckpoint is set.
   - The registry branches that the script writes to are exported to .reg files
     first. The path is reported at the start of the run.
   - A package on the protected list is never removed, whatever $apps says. This
     stops a broad wildcard from taking out the Store, the authentication broker
     or the shell.
   - A pattern that matches more than 25 packages is refused as too broad.

   IDEMPOTENCY
   Running this twice is safe and reports almost nothing the second time. Each
   step reads the current state first and skips what is already correct. The
   restore point and the registry export are the deliberate exceptions: both are
   made fresh on every run.

   SCOPE
   Xbox, OneDrive and Teams are each removed by default and each retained in
   full by its own switch. A switch covers the packages, services, tasks and
   policy values of that group together.

   The Xbox stack is removed in full, the identity provider included. Xbox Live
   will not sign in afterwards. See $xboxApps.

   Recall is removed in full. The snapshots already on disk are deleted, and a
   restore point does not bring them back. Use -KeepRecallSnapshots to keep them.

   A restart is necessary to complete the removals.

   The HKCU values apply to the account that runs the script. On a machine with
   more than one account, run it once for each account.

.LINK
   https://www.carumba.com
#>

# Elevate as needed
# https://superuser.com/questions/108207/how-to-run-a-powershell-script-as-administrator
[CmdletBinding()]
param(
	[switch]$Elevated,
	[switch]$DryRun,
	[switch]$SkipCheckpoint,
	[switch]$KeepRecallSnapshots,
	[switch]$KeepXbox,
	[switch]$KeepOneDrive,
	[switch]$KeepTeams
)

# Verbose is the default here. The script makes a lot of changes at once, so the
# step-level detail is worth more than a quiet console. Turn it off with
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

	# carry the switches across the elevation boundary
	$relaunchArgs = '-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition)
	if ($DryRun) {
		$relaunchArgs += ' -dryrun'
	}
	if ($SkipCheckpoint) {
		$relaunchArgs += ' -skipcheckpoint'
	}
	if ($KeepRecallSnapshots) {
		$relaunchArgs += ' -keeprecallsnapshots'
	}
	if ($KeepXbox) {
		$relaunchArgs += ' -keepxbox'
	}
	if ($KeepOneDrive) {
		$relaunchArgs += ' -keeponedrive'
	}
	if ($KeepTeams) {
		$relaunchArgs += ' -keepteams'
	}

	# state it either way. The relaunched copy would otherwise apply its own
	# default and undo an explicit -Verbose:$false.
	if ($VerbosePreference -eq 'Continue') {
		$relaunchArgs += ' -verbose'
	}
	else {
		$relaunchArgs += ' -verbose:$false'
	}

	Write-Verbose "Relaunching elevated: powershell.exe $relaunchArgs"
	Start-Process powershell.exe -Verb RunAs -ArgumentList $relaunchArgs

	exit
}

Write-Output 'Running with full privileges...'
if ($DryRun) {
	Write-Output 'Dry run. No change is made.'
}

############################################
############################################
#
# DO NOT BLINDLY RUN THIS
#
############################################
############################################


# ---------------------------------------------------------------------------
# Operating system detection
#
# The target is Windows 11 24H2 or later. A few values arrived in a specific
# build, so ask once here and let Set-RegistryValue gate on -MinimumBuild.
# ---------------------------------------------------------------------------

$currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osBuild = [int]$currentVersion.CurrentBuildNumber
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$osCaption = $osInfo.Caption

# the build this script is written against. Build 26100 is Windows 11 24H2.
$script:TargetBuild = 26100

# the oldest build it will run on at all. Build 22000 is Windows 11 21H2.
$script:OldestSupportedBuild = 22000

# ProductType 1 is a workstation. This script is not for a server.
if ($osInfo.ProductType -ne 1) {
	Write-Error "This script is for a client operating system. Found: $osCaption"
	exit 1
}

# Windows 10 needs a different name for half of the values below, so it is out
# of scope rather than half supported.
if ($osBuild -lt $script:OldestSupportedBuild) {
	Write-Error "Windows 11 is required. Found $osCaption (build $osBuild)."
	Write-Error 'Use an earlier revision of this script for Windows 10.'
	exit 1
}

Write-Output "$osCaption (build $osBuild)"

if ($osBuild -lt $script:TargetBuild) {
	Write-Warning "This script is written for build $script:TargetBuild (24H2) or later."
	Write-Warning 'On an older build some settings do not exist and are reported as skipped.'
}


# ---------------------------------------------------------------------------
# Protected packages
#
# A package here is never removed, whatever $apps contains. The list is the
# backstop against a broad wildcard: an entry such as "*Microsoft*" would
# otherwise take out the shell, the Store and the authentication broker and
# leave an operating system that cannot sign in or install anything.
#
# Each entry is matched with -like against the resolved package name, not
# against the pattern in $apps.
# ---------------------------------------------------------------------------

$script:ProtectedPackages = @(
	# shell and logon. Removing one of these is not recoverable in place.
	'MicrosoftWindows.Client.CBS'
	'MicrosoftWindows.Client.Core'
	'MicrosoftWindows.Client.FileExp'
	'MicrosoftWindows.Client.OOBE'
	'Microsoft.Windows.ShellExperienceHost'
	'Microsoft.Windows.StartMenuExperienceHost'
	'Microsoft.Windows.CloudExperienceHost'
	'Microsoft.Windows.PeopleExperienceHost'
	'Microsoft.Windows.ContentDeliveryManager'
	'Microsoft.LockApp'
	'Microsoft.CredDialogHost'
	'Microsoft.ECApp'
	'Microsoft.Win32WebViewHost'
	'Microsoft.Windows.PinningConfirmationDialog'
	'Windows.CBSPreview'
	'Windows.PrintDialog'

	# authentication. Removing the broker breaks every work and school sign-in.
	'Microsoft.AAD.BrokerPlugin'
	'Microsoft.Windows.AuthHost'
	'Microsoft.BioEnrollment'
	'Microsoft.AccountsControl'

	# security
	'Microsoft.SecHealthUI'
	'Microsoft.Windows.SecHealthUI'
	'Microsoft.Windows.Apprep.ChxApp'
	'Microsoft.Windows.AssignedAccessLockApp'
	'Microsoft.Windows.SecureAssessmentBrowser'
	'Microsoft.Windows.ParentalControls'

	# the Store and the installer. Removing either is hard to undo and stops
	# every remaining application from updating.
	'Microsoft.WindowsStore'
	'Microsoft.StorePurchaseApp'
	'Microsoft.DesktopAppInstaller'
	'Microsoft.Services.Store.Engagement'

	# runtimes and frameworks that other applications depend on
	'Microsoft.NET.Native.*'
	'Microsoft.UI.Xaml.*'
	'Microsoft.VCLibs.*'
	'Microsoft.WindowsAppRuntime.*'
	'Microsoft.WinAppRuntime.*'
	'Microsoft.AV1VideoExtension'
	'Microsoft.HEIFImageExtension'
	'Microsoft.HEVCVideoExtension'
	'Microsoft.VP9VideoExtensions'
	'Microsoft.WebMediaExtensions'
	'Microsoft.WebpImageExtension'
	'Microsoft.RawImageExtension'

	# accessibility
	'Microsoft.Windows.NarratorQuickStart'

	# Edge and WebView. Removal is blocked by the platform and the attempt can
	# leave a broken install behind.
	'Microsoft.MicrosoftEdge'
	'Microsoft.MicrosoftEdge.Stable'
	'Microsoft.MicrosoftEdgeDevToolsClient'
	'Microsoft.EdgeDevToolsClient'
)

# a pattern that resolves to more than this is treated as a mistake
$script:MaxMatchesPerPattern = 25


# ---------------------------------------------------------------------------
# Helpers
#
# Every change goes through one of these so that -DryRun and the summary stay
# honest. A helper reports a failure and continues. It never stops the script.
# ---------------------------------------------------------------------------

$script:Applied = [System.Collections.Generic.List[string]]::new()
$script:Skipped = [System.Collections.Generic.List[string]]::new()
$script:Failed = [System.Collections.Generic.List[string]]::new()

function Write-Step {
	param([Parameter(Mandatory)][string]$Message)

	if ($DryRun) {
		Write-Output "[dryrun] $Message"
	}
	else {
		Write-Output $Message
	}
}

function Test-ProtectedPackage {
	<#
	.SYNOPSIS
	   Report whether one resolved package name is on the protected list.
	#>
	param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)

	if ([string]::IsNullOrWhiteSpace($Name)) {
		# an unnamed package is not something to remove blind
		return $true
	}

	foreach ($pattern in $script:ProtectedPackages) {
		if ($Name -like $pattern) {
			return $true
		}
	}

	return $false
}

function Set-RegistryValue {
	<#
	.SYNOPSIS
	   Write one registry value. Create the key if it is absent.

	.PARAMETER MinimumBuild
	   Skip the write when the operating system is older than this build.
	#>
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][int]$Value,
		[int]$MinimumBuild = 0
	)

	$label = "$Path\$Name = $Value"

	if ($MinimumBuild -gt 0 -and $osBuild -lt $MinimumBuild) {
		Write-Verbose "Not applicable to build ${osBuild}: $label"
		$script:Skipped.Add("$label (needs build $MinimumBuild)")
		return
	}

	# Compare the kind as well as the number. A REG_SZ "0" and a REG_DWORD 0
	# compare equal in PowerShell, so testing the value alone would leave a
	# string where the operating system reads a number, and report it as already
	# correct on every later run.
	$current = $null
	$currentKind = $null
	try {
		$current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
		$currentKind = (Get-Item -Path $Path -ErrorAction Stop).GetValueKind($Name)
	}
	catch {
		Write-Verbose "Not currently set: $Path\$Name"
	}

	if ($null -ne $current -and $currentKind -eq 'DWord' -and $current -eq $Value) {
		Write-Verbose "Already set: $label"
		$script:Skipped.Add($label)
		return
	}

	if ($null -ne $current -and $currentKind -ne 'DWord') {
		Write-Verbose "Replacing $Path\$Name because its type is $currentKind, not DWord"
	}

	Write-Step "Setting $label"
	if ($DryRun) {
		$script:Applied.Add($label)
		return
	}

	try {
		if (-not (Test-Path -Path $Path)) {
			New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
		}
		New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
		$script:Applied.Add($label)
	}
	catch {
		# a key owned by TrustedInstaller refuses the write even to an administrator
		Write-Warning "Could not set ${label}: $($_.Exception.Message)"
		$script:Failed.Add($label)
	}
}

function Disable-ServiceIfPresent {
	<#
	.SYNOPSIS
	   Stop one service and set its start type to Disabled.
	#>
	param([Parameter(Mandatory)][string]$Name)

	$service = Get-Service -Name $Name -ErrorAction SilentlyContinue
	if (-not $service) {
		Write-Verbose "Service $Name is not present"
		$script:Skipped.Add("service $Name (absent)")
		return
	}

	$startType = $null
	try {
		$startType = $service.StartType
	}
	catch {
		Write-Verbose "Could not read the start type of $Name"
	}

	if ($startType -eq 'Disabled' -and $service.Status -eq 'Stopped') {
		Write-Verbose "Service $Name is already stopped and disabled"
		$script:Skipped.Add("service $Name")
		return
	}

	Write-Step "Disabling service $Name"
	if ($DryRun) {
		$script:Applied.Add("service $Name")
		return
	}

	try {
		if ($service.Status -ne 'Stopped') {
			Stop-Service -Name $Name -Force -ErrorAction Stop
		}
		Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
		$script:Applied.Add("service $Name")
	}
	catch {
		# a protected service refuses both calls even to an administrator
		Write-Warning "Could not disable service ${Name}: $($_.Exception.Message)"
		$script:Failed.Add("service $Name")
	}
}

function Disable-TaskIfPresent {
	<#
	.SYNOPSIS
	   Disable one scheduled task. An absent task is not an error.
	#>
	param([Parameter(Mandatory)][string]$TaskName)

	# several of these tasks do not exist on Win 11, so do not let the lookup
	# write a red error for a task that is already gone
	$found = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
	if ($found.Count -eq 0) {
		Write-Verbose "Scheduled task $TaskName is not present"
		$script:Skipped.Add("task $TaskName (absent)")
		return
	}

	foreach ($entry in $found) {
		$label = "task $($entry.TaskPath)$($entry.TaskName)"

		if ($entry.State -eq 'Disabled') {
			Write-Verbose "Already disabled: $label"
			$script:Skipped.Add($label)
			continue
		}

		Write-Step "Disabling $label"
		if ($DryRun) {
			$script:Applied.Add($label)
			continue
		}

		try {
			$entry | Disable-ScheduledTask -ErrorAction Stop | Out-Null
			$script:Applied.Add($label)
		}
		catch {
			# Microsoft Compatibility Appraiser is protected on current builds
			Write-Warning "Could not disable ${label}: $($_.Exception.Message)"
			$script:Failed.Add($label)
		}
	}
}


# ---------------------------------------------------------------------------
# Safeguards
#
# Take a restore point and export the registry branches that the script writes
# to. Both run before the first change.
# ---------------------------------------------------------------------------

function Backup-RegistryBranch {
	<#
	.SYNOPSIS
	   Export the registry branches this script writes to.
	#>
	param([Parameter(Mandatory)][string]$Destination)

	$branches = @{
		'HKLM-Policies'          = 'HKLM\SOFTWARE\Policies\Microsoft'
		'HKLM-CurrentVersion'    = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion'
		'HKLM-Autologger'        = 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
		'HKCU-Policies'          = 'HKCU\Software\Policies\Microsoft'
		'HKCU-CurrentVersion'    = 'HKCU\Software\Microsoft\Windows\CurrentVersion'
		'HKCU-InputPersonalized' = 'HKCU\Software\Microsoft\InputPersonalization'
	}

	New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Stop | Out-Null

	foreach ($name in $branches.Keys) {
		$file = Join-Path -Path $Destination -ChildPath "$name.reg"
		Write-Verbose "Exporting $($branches[$name]) to $file"

		# reg.exe writes to stderr on a missing branch, which is not fatal here
		& reg.exe export $branches[$name] $file /y 2>&1 | Out-Null
		if ($LASTEXITCODE -ne 0) {
			Write-Verbose "Export of $($branches[$name]) returned $LASTEXITCODE. The branch is probably absent."
		}
	}
}

function New-SafetyCheckpoint {
	<#
	.SYNOPSIS
	   Make a system restore point. Report whether the caller may continue.
	#>
	param([Parameter(Mandatory)][string]$Description)

	# NOTE: this function is used in a condition, so it must put nothing on the
	# output stream except the boolean. A Write-Output here would be collected
	# into the return value, the caller would test a non-empty array, and a
	# failed checkpoint would read as success. Announcements belong to the
	# caller; Write-Verbose and Write-Warning use their own streams and are safe.

	if ($DryRun) {
		Write-Verbose "[dryrun] Would create restore point: $Description"
		return $true
	}

	# Do not try to detect whether System Restore is on. Querying the existing
	# restore points reports none on a machine that has it on but has never made
	# one, which would refuse to run for the wrong reason. Attempt the
	# checkpoint and let the failure be the answer.

	$frequencyKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
	$frequencyName = 'SystemRestorePointCreationFrequency'

	# Windows drops a second restore point inside 24 hours unless this is 0.
	# Record whether the value was there so the original state can be restored.
	$previousFrequency = (Get-ItemProperty -Path $frequencyKey -Name $frequencyName -ErrorAction SilentlyContinue).$frequencyName
	$frequencyWasAbsent = $null -eq $previousFrequency

	try {
		New-ItemProperty -Path $frequencyKey -Name $frequencyName -Value 0 -PropertyType 'DWord' -Force -ErrorAction SilentlyContinue | Out-Null
		Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
		Write-Verbose 'Restore point created.'
		return $true
	}
	catch {
		Write-Warning "Could not create a restore point: $($_.Exception.Message)"
		Write-Warning 'System Restore is off on most new installs. Turn it on with:'
		Write-Warning "  Enable-ComputerRestore -Drive '$env:SystemDrive\'"
		Write-Warning 'Or run again with -SkipCheckpoint to continue without one.'
		return $false
	}
	finally {
		# leave the interval as it was found, whatever happened above
		if ($frequencyWasAbsent) {
			Remove-ItemProperty -Path $frequencyKey -Name $frequencyName -ErrorAction SilentlyContinue
		}
		else {
			New-ItemProperty -Path $frequencyKey -Name $frequencyName -Value $previousFrequency -PropertyType 'DWord' -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDir = Join-Path -Path $env:ProgramData -ChildPath "WinDebloat\Backup\$stamp"

if ($DryRun) {
	Write-Output "[dryrun] Registry backup would go to $backupDir"
}
else {
	Write-Output "Exporting the registry branches to $backupDir"
	try {
		Backup-RegistryBranch -Destination $backupDir
	}
	catch {
		Write-Error "Could not write the registry backup to ${backupDir}: $($_.Exception.Message)"
		exit 1
	}
}

if ($SkipCheckpoint) {
	Write-Warning 'Skipping the restore point because -SkipCheckpoint is set.'
}
else {
	Write-Output 'Creating a restore point...'
	$checkpointMade = New-SafetyCheckpoint -Description 'Before WinDebloat'
	if (-not $checkpointMade) {
		Write-Error 'Stopping. No restore point was made.'
		exit 1
	}
	Write-Output 'Restore point created.'
}


# See what is currently installed
# Get-AppxProvisionedPackage -Online | Format-Table DisplayName, PackageName
# Get-AppxProvisionedPackage -Online | Out-GridView -PassThru | Remove-AppxProvisionedPackage -Online
#
# Alternate package removal
# https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
# https://gist.github.com/mrik23/e8160517b19a3a9dad9c1b5e8ba0fb78

Write-Output "Uninstalling default apps..."
$apps = @(
	# default Windows 10 apps
	"Microsoft.3DBuilder"
	"Microsoft.AppConnector"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingWeather"
	"Microsoft.CommsPhone"
	"Microsoft.ConnectivityStore"
	#"Microsoft.DesktopAppInstaller"	# winget and the MSIX installer. Keep.
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"Microsoft.Microsoft3DViewer"
	#"Microsoft.MicrosoftEdgeDevToolsClient"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.MicrosoftStickyNotes"
	"Microsoft.MixedReality.Portal"
	"Microsoft.MSPaint"
	"Microsoft.Office.OneNote"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.People"
	"Microsoft.Print3D"
	"Microsoft.SkypeApp"
	#"Microsoft.StorePurchaseApp"	# needed to buy from the Store. Keep.
	"Microsoft.Tips"
	"Microsoft.Wallet"
	"Microsoft.Windows.Photos"
	"Microsoft.WindowsAlarms"
	"Microsoft.WindowsCalculator"
	"Microsoft.WindowsCamera"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsDVDPlayer"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsPhone"
	"Microsoft.WindowsSoundRecorder"
	#"Microsoft.WindowsStore"	# no way back in place. Keep.
	"Microsoft.YourPhone"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"

	# non-Microsoft
	"2FE3CB00.PicsArt-PhotoStudio"
	"46928bounde.EclipseManager"
	"4DF9E0F8.Netflix"
	"5319275A.WhatsAppDesktop"
	"6Wunderkinder.Wunderlist"
	"7EE7776C.LinkedInforWindows"
	"89006A2E.AutodeskSketchBook"
	"9E2F88E3.Twitter"
	"A278AB0D.DisneyMagicKingdoms"
	"A278AB0D.MarchofEmpires"
	"ActiproSoftwareLLC.562882FEEB491"
	"AdobeSystemsIncorporated.AdobeExpress"
	"AmazonVideo.PrimeVideo"
	"BytedancePte.Ltd.TikTok"
	"ClearChannelRadioDigital.iHeartRadio"
	"Clipchamp.Clipchamp"
	"D52A8D61.FarmVille2CountryEscape"
	"D5EA27B7.Duolingo-LearnLanguagesforFree"
	"DB6EA5DB.CyberLinkMediaSuiteEssentials"
	"Disney.37853FC22B2CE"
	"DolbyLaboratories.DolbyAccess"
	"Drawboard.DrawboardPDF"
	"Facebook.Facebook"
	"Facebook.InstagramBeta"
	"flaregamesGmbH.RoyalRevolt2"
	"Flipboard.Flipboard"
	"GAMELOFTSA.Asphalt8Airborne"
	"KeeperSecurityInc.Keeper"
	"king.com.BubbleWitch3Saga"
	"king.com.CandyCrushFriends"
	"king.com.CandyCrushSaga"
	"king.com.CandyCrushSodaSaga"
	"king.com.FarmHeroesSaga"
	"Microsoft.MinecraftUWP"
	"PandoraMediaInc.29680B314EFC2"
	"Playtika.CaesarsSlotsFreeCasino"
	"ShazamEntertainmentLtd.Shazam"
	"SpotifyAB.SpotifyMusic"
	"TheNewYorkTimes.NYTCrossword"
	"ThumbmunkeysLtd.PhototasticCollage"
	"TuneIn.TuneInRadio"
	"XINGAG.XING"

	# Wildcards
	#
	# A wildcard is a last resort here. An explicit package family name cannot
	# match something it was not meant to, so prefer one whenever the name is
	# known. Only a title whose publisher prefix varies is left as a pattern.
	#"*AAD.BrokerPlugin*"	# work and school sign-in. Keep.
	"*HiddenCityMysteryofShadows*"	# publisher prefix varies by region

	# apps which cannot be removed using Remove-AppxPackage
	#"Microsoft.BioEnrollment"	# Windows Hello enrolment. Keep.
	#"Microsoft.MicrosoftEdge"
	"Microsoft.Windows.Cortana"
	"Microsoft.WindowsFeedback"
	#"Windows.ContactSupport"	# removed as a capability further down

	# Win 2004
	"Microsoft.549981C3F5F10"

	# Copilot and AI components (Win 11 23H2 and later)
	# The Store app comes back after a feature update. The policy values set
	# further down are what keeps it off.
	"Microsoft.Copilot"
	"Microsoft.Windows.Ai.Copilot.Provider"
	"MicrosoftWindows.Client.CoPilot"

	# Win 11 apps
	"Microsoft.BingSearch"
	"Microsoft.MicrosoftJournal"
	"Microsoft.OutlookForWindows"
	#"Microsoft.PowerAutomateDesktop"
	"Microsoft.StartExperiencesApp"
	"Microsoft.Todos"
	"Microsoft.Whiteboard"
	"Microsoft.WidgetsPlatformRuntime"
	"Microsoft.Windows.DevHome"
	"MicrosoftCorporationII.MicrosoftFamily"
	"MicrosoftCorporationII.QuickAssist"
	"MicrosoftWindows.Client.WebExperience"
	"MicrosoftWindows.CrossDevice"

	# Keep. Listed only to show they were considered.
	# Microsoft.MSPaint above is Paint 3D, not classic Paint.
	#"Microsoft.Paint"
	#"Microsoft.ScreenSketch"
	#"Microsoft.WindowsNotepad"
	#"Microsoft.WindowsTerminal"
)

# ---------------------------------------------------------------------------
# Optional groups
#
# Each group is removed unless its -Keep switch is set. The switch covers the
# packages here and the matching services, tasks and policy values further
# down, so one switch retains the whole feature rather than half of it.
# ---------------------------------------------------------------------------

# Everything Xbox, the identity provider and the callable UI included.
#
# WARNING: this is the whole stack, not the applications alone. Removing
# XboxIdentityProvider ends the Xbox Live sign-in that Minecraft, Game Pass and
# any Xbox Live title needs. Use -KeepXbox to retain all of it.
$xboxApps = @(
	"Microsoft.GamingApp"
	"Microsoft.GamingServices"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameCallableUI"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxSpeechToTextOverlay"
)

# MicrosoftTeams is the personal Chat client. MSTeams is the current one.
# Use -KeepTeams to retain both and the taskbar button.
$teamsApps = @(
	"MicrosoftTeams"
	"MSTeams"
)

if ($KeepXbox) {
	Write-Output 'Keeping Xbox because -KeepXbox is set.'
	$script:Skipped.Add('Xbox (kept on request)')
}
else {
	$apps += $xboxApps
}

if ($KeepTeams) {
	Write-Output 'Keeping Teams because -KeepTeams is set.'
	$script:Skipped.Add('Teams (kept on request)')
}
else {
	$apps += $teamsApps
}

# Enumerate once. Get-AppxProvisionedPackage is a DISM call that costs seconds,
# so one call for the whole list instead of one call for each entry.
Write-Verbose 'Enumerating the installed and provisioned packages'
$installedApps = @(Get-AppxPackage -AllUsers)
$provisionedApps = @(Get-AppxProvisionedPackage -Online)
Write-Verbose "$($installedApps.Count) installed, $($provisionedApps.Count) provisioned"

foreach ($app in $apps) {
	$installed = @($installedApps | Where-Object { $_.Name -Like $app })
	$provisioned = @($provisionedApps | Where-Object { $_.DisplayName -Like $app })

	# a pattern this broad is a mistake, not an instruction
	$matchCount = $installed.Count + $provisioned.Count
	if ($matchCount -gt $script:MaxMatchesPerPattern) {
		Write-Warning "Pattern '$app' matches $matchCount packages. Refusing as too broad."
		$script:Failed.Add("app $app (pattern too broad)")
		continue
	}

	# never remove a package the operating system needs
	foreach ($blocked in @($installed | Where-Object { Test-ProtectedPackage -Name $_.Name })) {
		Write-Warning "Refusing to remove the protected package $($blocked.Name), matched by '$app'."
		$script:Skipped.Add("app $($blocked.Name) (protected)")
	}
	$installed = @($installed | Where-Object { -not (Test-ProtectedPackage -Name $_.Name) })
	$provisioned = @($provisioned | Where-Object { -not (Test-ProtectedPackage -Name $_.DisplayName) })

	if ($installed.Count -eq 0 -and $provisioned.Count -eq 0) {
		Write-Verbose "Not present: $app"
		$script:Skipped.Add("app $app (absent)")
		continue
	}

	Write-Step "Removing $app ($($installed.Count) installed, $($provisioned.Count) provisioned)"
	if ($DryRun) {
		$script:Applied.Add("app $app")
		continue
	}

	# Collect the errors rather than discard them. A system package such as
	# XboxGameCallableUI refuses removal, and counting that as applied would
	# report a change that did not happen and would repeat on every later run.
	$removeErrors = @()
	$installed | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue -ErrorVariable +removeErrors

	# -AllUsers on Remove-AppxProvisionedPackage arrived in Win 11 22H2. Asking
	# for it on an older build fails the whole call, so branch on the build.
	if ($osBuild -ge 22621) {
		$provisioned | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue -ErrorVariable +removeErrors
	}
	else {
		$provisioned | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue -ErrorVariable +removeErrors
	}

	if ($removeErrors.Count -gt 0) {
		Write-Verbose "$app reported $($removeErrors.Count) error(s): $($removeErrors[0].Exception.Message)"
		$script:Failed.Add("app $app ($($removeErrors.Count) error(s))")
	}
	else {
		$script:Applied.Add("app $app")
	}
}

# The following cannot be uninstalled using Remove-AppxPackage
foreach ($pattern in @('*ContactSupport*', '*QuickAssist*')) {
	$capabilities = @(Get-WindowsCapability -Online | Where-Object { $_.Name -like $pattern -and $_.State -eq 'Installed' })
	foreach ($capability in $capabilities) {
		Write-Step "Removing capability $($capability.Name)"
		if ($DryRun) {
			$script:Applied.Add("capability $($capability.Name)")
			continue
		}

		try {
			$capability | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
			$script:Applied.Add("capability $($capability.Name)")
		}
		catch {
			Write-Warning "Could not remove $($capability.Name): $($_.Exception.Message)"
			$script:Failed.Add("capability $($capability.Name)")
		}
	}
}


# ---------------------------------------------------------------------------
# Stop Windows from installing the applications again
#
# This is what makes the removals above permanent. Content Delivery Manager
# silently reinstalls the suggested applications after a feature update and for
# each new account, so without these values the list above comes back.
#
# DisableWindowsConsumerFeatures is ignored on Home, and recent builds narrowed
# what it covers, so set the per-user values as well.
# ---------------------------------------------------------------------------
Write-Output 'Turning off the suggested content and the silent installs...'

$cloudContent = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
Set-RegistryValue -Path $cloudContent -Name 'DisableWindowsConsumerFeatures' -Value 1
Set-RegistryValue -Path $cloudContent -Name 'DisableConsumerAccountStateContent' -Value 1
Set-RegistryValue -Path $cloudContent -Name 'DisableCloudOptimizedContent' -Value 1
Set-RegistryValue -Path $cloudContent -Name 'DisableSoftLanding' -Value 1
Set-RegistryValue -Path $cloudContent -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1

$contentDelivery = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
Set-RegistryValue -Path $contentDelivery -Name 'ContentDeliveryAllowed' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'SilentInstalledAppsEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'PreInstalledAppsEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'PreInstalledAppsEverEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'OemPreInstalledAppsEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'SystemPaneSuggestionsEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'SoftLandingEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'SubscribedContentEnabled' -Value 0
Set-RegistryValue -Path $contentDelivery -Name 'RotatingLockScreenOverlayEnabled' -Value 0

# each identifier is one surface that shows suggested content
#   310093 welcome experience    338387 lock screen facts   338388 Start
#   338389 tips                  338393 Settings            353694 Settings
#   353696 Settings              353698 task view
foreach ($id in @(310093, 338387, 338388, 338389, 338393, 353694, 353696, 353698)) {
	Set-RegistryValue -Path $contentDelivery -Name "SubscribedContent-${id}Enabled" -Value 0
}

# advertising ID. The policy value covers every account on the machine.
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Value 1
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0

# the Recommended section of the Start menu
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_IrisRecommendations' -Value 0 -MinimumBuild 22621
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'HideRecommendedSection' -Value 1 -MinimumBuild 22621


# ---------------------------------------------------------------------------
# Copilot
#
# Removing the package is not sufficient. A feature update puts Copilot back
# unless this policy is set.
# https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot
# ---------------------------------------------------------------------------
Write-Output 'Turning off Copilot...'

Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Value 1

# Hide the taskbar button. This is HKCU, so it applies to the current user only.
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -Value 0


# ---------------------------------------------------------------------------
# Recall
#
# Recall saves snapshots of the screen. The policy stops new snapshots on all
# accounts. It does not delete the snapshots that are already on disk.
# https://learn.microsoft.com/en-us/windows/client-management/manage-recall
# ---------------------------------------------------------------------------
Write-Output 'Turning off Recall...'

Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'DisableAIDataAnalysis' -Value 1

# Remove the optional feature. It is on Copilot+ PCs only, so a machine without
# one gives no error. A restart is necessary to complete the removal.
$recall = Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction SilentlyContinue
if ($recall -and $recall.State -eq 'Enabled') {
	Write-Step 'Removing the Recall optional feature'
	if (-not $DryRun) {
		try {
			Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -NoRestart -ErrorAction Stop | Out-Null
			$script:Applied.Add('feature Recall')
		}
		catch {
			Write-Warning "Could not remove the Recall feature: $($_.Exception.Message)"
			$script:Failed.Add('feature Recall')
		}
	}
	else {
		$script:Applied.Add('feature Recall')
	}
}
else {
	Write-Verbose 'Recall optional feature is not present'
	$script:Skipped.Add('feature Recall (absent)')
}

# Delete the snapshots that Recall already saved
#
# WARNING: this destroys the screen captures and the index that goes with them.
# There is no undo, and a restore point does not bring them back. The policy
# above only stops new snapshots.
#
# The store is per user, so read the profile list from the registry instead of
# an assumed C:\Users. A service profile has no store, so it is skipped.
$profilePaths = @(
	Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
		Select-Object -ExpandProperty ProfileImagePath -ErrorAction SilentlyContinue
)

$ukpStores = @(
	$profilePaths |
		ForEach-Object { Join-Path -Path $_ -ChildPath 'AppData\Local\CoreAIPlatform.00\UKP' } |
		Where-Object { Test-Path -LiteralPath $_ -PathType Container }
)

if ($KeepRecallSnapshots) {
	Write-Output 'Keeping the Recall snapshots because -KeepRecallSnapshots is set.'
	$script:Skipped.Add('Recall snapshots (kept on request)')
}
elseif ($ukpStores.Count -eq 0) {
	Write-Verbose 'No Recall snapshot store found'
	$script:Skipped.Add('Recall snapshots (absent)')
}
else {
	Write-Warning "Deleting the Recall snapshots in $($ukpStores.Count) profile(s). This cannot be undone."

	foreach ($store in $ukpStores) {
		# a junction here sends the recursive delete somewhere else
		if ((Get-Item -LiteralPath $store -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
			Write-Warning "Skipping $store because it is a reparse point."
			$script:Skipped.Add("Recall snapshots in $store (reparse point)")
			continue
		}

		$bytes = (Get-ChildItem -LiteralPath $store -Recurse -File -Force -ErrorAction SilentlyContinue |
				Measure-Object -Property Length -Sum).Sum
		Write-Step ('Deleting {0} ({1:N1} MB)' -f $store, ($bytes / 1MB))

		if ($DryRun) {
			$script:Applied.Add("Recall snapshots in $store")
			continue
		}

		try {
			Remove-Item -LiteralPath $store -Recurse -Force -ErrorAction Stop
			$script:Applied.Add("Recall snapshots in $store")
		}
		catch {
			# Recall holds the database open until the machine restarts
			Write-Warning "Could not fully delete ${store}: $($_.Exception.Message)"
			Write-Warning 'Restart, then run this script again to remove the rest.'
			$script:Failed.Add("Recall snapshots in $store")
		}
	}
}


# ---------------------------------------------------------------------------
# Telemetry and analytics
#
# On Pro, AllowTelemetry = 0 does not hold. Only Enterprise, Education and
# Server honour the Security level. Pro and Home apply a floor of 1, which is
# Required diagnostic data, and the Settings interface shows the floor.
#
# So the policy value is not the lever on Pro. These are, in the order that
# they matter:
#   1. the DiagTrack service, which is the process that uploads
#   2. the two ETW autologger sessions that feed it
#   3. the scheduled tasks that gather the payload, further down
#   4. the per-component opt-outs below
#
# Together these stop the collection rather than ask the collector to send a
# smaller payload.
# https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization
# ---------------------------------------------------------------------------
Write-Output 'Turning off the telemetry collectors...'

$dataCollection = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
Set-RegistryValue -Path $dataCollection -Name 'AllowTelemetry' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'MaxTelemetryAllowed' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'DoNotShowFeedbackNotifications' -Value 1
Set-RegistryValue -Path $dataCollection -Name 'LimitDiagnosticLogCollection' -Value 1
Set-RegistryValue -Path $dataCollection -Name 'LimitDumpCollection' -Value 1
Set-RegistryValue -Path $dataCollection -Name 'DisableOneSettingsDownloads' -Value 1
Set-RegistryValue -Path $dataCollection -Name 'AllowDeviceNameInTelemetry' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'AllowCommercialDataPipeline' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'AllowUpdateComplianceProcessing' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'AllowWUfBCloudProcessing' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'AllowDesktopAnalyticsProcessing' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Value 0
Set-RegistryValue -Path $dataCollection -Name 'EnableOneSettingsAuditing' -Value 0

# the same value is read from the non-policy branch on some builds
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0

# the two ETW sessions that feed DiagTrack. Stopping these is what actually
# reduces what is gathered on Pro. A key owned by the system may refuse the
# write, which the helper reports rather than hides.
$autologger = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
Set-RegistryValue -Path "$autologger\AutoLogger-Diagtrack-Listener" -Name 'Start' -Value 0
Set-RegistryValue -Path "$autologger\SQMLogger" -Name 'Start' -Value 0

# Customer Experience Improvement Program
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0

# Application Impact Telemetry and the compatibility inventory
$appCompat = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
Set-RegistryValue -Path $appCompat -Name 'AITEnable' -Value 0
Set-RegistryValue -Path $appCompat -Name 'DisableInventory' -Value 1
Set-RegistryValue -Path $appCompat -Name 'DisableUAR' -Value 1
Set-RegistryValue -Path $appCompat -Name 'DisablePCA' -Value 1

# Windows Error Reporting. The policy is set rather than the WerSvc service
# disabled, because WerSvc also handles the local crash plumbing.
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Value 1

# handwriting recognition error reports
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Value 1

# activity history, which is the timeline upload
$systemPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
Set-RegistryValue -Path $systemPolicy -Name 'EnableActivityFeed' -Value 0
Set-RegistryValue -Path $systemPolicy -Name 'PublishUserActivities' -Value 0
Set-RegistryValue -Path $systemPolicy -Name 'UploadUserActivities' -Value 0

# inking, typing and speech personalisation. These upload samples of what you
# type and say, and they are per user.
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Value 0
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Value 1
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Value 1
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Value 0
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' -Name 'HasAccepted' -Value 0
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'AllowInputPersonalization' -Value 0
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Speech' -Name 'AllowSpeechModelUpdate' -Value 0

# tailored experiences built from the diagnostic data
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0

# Edge telemetry. Edge reports separately from Windows.
$edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
Set-RegistryValue -Path $edgePolicy -Name 'MetricsReportingEnabled' -Value 0
Set-RegistryValue -Path $edgePolicy -Name 'SendSiteInfoToImproveServices' -Value 0
Set-RegistryValue -Path $edgePolicy -Name 'PersonalizationReportingEnabled' -Value 0
Set-RegistryValue -Path $edgePolicy -Name 'UserFeedbackAllowed' -Value 0
Set-RegistryValue -Path $edgePolicy -Name 'DiagnosticData' -Value 0
Set-RegistryValue -Path $edgePolicy -Name 'EdgeCollectionsEnabled' -Value 0

# DiagTrack is Connected User Experiences and Telemetry, the uploader itself.
# dmwappushservice is the WAP push routing service that feeds it.
# diagnosticshub.standardcollector.service is the Visual Studio trace collector.
Disable-ServiceIfPresent -Name 'DiagTrack'
Disable-ServiceIfPresent -Name 'dmwappushservice'
Disable-ServiceIfPresent -Name 'diagnosticshub.standardcollector.service'

# Deliberately NOT disabled, because each one breaks something you will want:
#   DPS, WdiServiceHost, WdiSystemHost - the network and audio troubleshooters
#   WerSvc                             - local crash handling, policy is enough
#   PcaSvc                             - application compatibility at launch
#   EventLog                           - every diagnostic you would need later


# ---------------------------------------------------------------------------
# Taskbar and search
#
# The packages removed above leave their policy surfaces behind. Removing
# Microsoft.BingSearch does not stop the web results in Start, and removing
# WidgetsPlatformRuntime does not stop the news feed.
#
# Dsh is the Widgets policy key. Windows 10 called the same feed News and
# interests and put it elsewhere, which is one reason Windows 10 is out of scope.
# ---------------------------------------------------------------------------
Write-Output 'Turning off the web search and the widgets...'

# Bing results in the Start menu search box
Set-RegistryValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions' -Value 1
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Value 0
Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Value 0

$windowsSearch = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
Set-RegistryValue -Path $windowsSearch -Name 'DisableWebSearch' -Value 1
Set-RegistryValue -Path $windowsSearch -Name 'ConnectedSearchUseWeb' -Value 0
Set-RegistryValue -Path $windowsSearch -Name 'AllowCortana' -Value 0
Set-RegistryValue -Path $windowsSearch -Name 'AllowCloudSearch' -Value 0

# Widgets
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -Value 0

# hide the Widgets taskbar button for the current user
$explorerAdvanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-RegistryValue -Path $explorerAdvanced -Name 'TaskbarDa' -Value 0

# Chat is the personal Teams button, so it belongs to the Teams group
if ($KeepTeams) {
	Write-Verbose 'Leaving the Chat button alone because -KeepTeams is set'
}
else {
	Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat' -Name 'ChatIcon' -Value 3
	Set-RegistryValue -Path $explorerAdvanced -Name 'TaskbarMn' -Value 0
}


# ---------------------------------------------------------------------------
# Xbox services and tasks
#
# The second half of the Xbox removal. The packages come out in the Xbox block
# of $apps above. These are what keeps running once they are gone.
#
# WARNING: with the identity provider removed above, this ends Xbox Live on the
# machine. Game Pass, Minecraft and any Xbox Live title will not sign in.
#
# To undo: reinstall the applications from the Store and set these four
# services back to Manual.
#   Set-Service XblAuthManager -StartupType Manual
# ---------------------------------------------------------------------------
if ($KeepXbox) {
	Write-Verbose 'Leaving the Xbox services and tasks alone because -KeepXbox is set'
}
else {
	Write-Output 'Disabling the Xbox services and tasks...'

	foreach ($name in @('XblAuthManager', 'XblGameSave', 'XboxGipSvc', 'XboxNetApiSvc')) {
		Disable-ServiceIfPresent -Name $name
	}

	foreach ($taskName in @('XblGameSaveTaskLogon', 'XblGameSaveTask')) {
		Disable-TaskIfPresent -TaskName $taskName
	}
}


# ---------------------------------------------------------------------------
# OneDrive
#
# The uninstaller does not touch the files in %UserProfile%\OneDrive. They stay
# on disk as ordinary local files.
#
# OneDrive installs per user on Win 11, so the per-user copy is the first
# candidate. Run the script once for each account to remove all of them.
#
# Use -KeepOneDrive to retain it.
# ---------------------------------------------------------------------------
if ($KeepOneDrive) {
	Write-Output 'Keeping OneDrive because -KeepOneDrive is set.'
	$script:Skipped.Add('OneDrive (kept on request)')
}
else {
	Write-Output 'Removing OneDrive...'

	# SysWOW64\OneDriveSetup.exe ships with Windows and stays there after the
	# uninstall, so its presence is not evidence that OneDrive is installed.
	# Ask the per-user install instead, or the run would start the uninstaller
	# again on every later run.
	$oneDriveExe = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\OneDrive\OneDrive.exe'
	$oneDriveInstalled = (Test-Path -LiteralPath $oneDriveExe -PathType Leaf) -or
		(Test-Path -Path 'HKCU:\Software\Microsoft\OneDrive')

	if (-not $oneDriveInstalled) {
		Write-Verbose 'OneDrive is not installed for this account'
		$script:Skipped.Add('OneDrive (absent)')
	}
	else {
		$oneDriveSetup = @(
			$oneDriveExe
			(Join-Path -Path $env:SystemRoot -ChildPath 'SysWOW64\OneDriveSetup.exe')
			(Join-Path -Path $env:SystemRoot -ChildPath 'System32\OneDriveSetup.exe')
		) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

		if (-not $oneDriveSetup) {
			Write-Warning 'OneDrive is installed but no uninstaller was found.'
			$script:Failed.Add('OneDrive')
		}
		else {
			Write-Step "Running $oneDriveSetup /uninstall"
			if ($DryRun) {
				$script:Applied.Add('OneDrive')
			}
			else {
				try {
					Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
					Start-Process -FilePath $oneDriveSetup -ArgumentList '/uninstall' -Wait -NoNewWindow -ErrorAction Stop
					$script:Applied.Add('OneDrive')
				}
				catch {
					Write-Warning "OneDrive uninstall failed: $($_.Exception.Message)"
					$script:Failed.Add('OneDrive')
				}
			}
		}
	}

	# stop the sync client from coming back
	Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1

	# hide the leftover entry in the Explorer navigation pane
	foreach ($clsid in @(
			'Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
			'Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
		)) {
		if (Test-Path -Path $clsid) {
			Set-RegistryValue -Path $clsid -Name 'System.IsPinnedToNameSpaceTree' -Value 0
		}
	}
}


# ---------------------------------------------------------------------------
# Scheduled tasks
#
# Several of these do not exist on Win 11. Disable-TaskIfPresent treats an
# absent task as nothing to do instead of writing a red error.
#
# The Appraiser task is the one that assembles the compatibility payload, so it
# matters more than the policy values on Pro. Current builds protect it, and a
# refusal is reported in the summary rather than hidden.
# ---------------------------------------------------------------------------
Write-Output 'Disabling the scheduled tasks...'

$taskNames = @(
	# Customer Experience Improvement Program
	'Consolidator'
	'UsbCeip'
	'KernelCeipTask'

	# Application Experience
	'Microsoft Compatibility Appraiser'
	'ProgramDataUpdater'
	'StartupAppTask'
	'PcaPatchDbTask'

	# feedback and error reporting
	'DmClient'
	'DmClientOnScenarioDownload'
	'QueueReporting'

	# disk and autochk telemetry
	'Proxy'
	'Microsoft-Windows-DiskDiagnosticDataCollector'

	# maps, whose application is removed above
	'MapsToastTask'
)

foreach ($taskName in $taskNames) {
	Disable-TaskIfPresent -TaskName $taskName
}


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '----------------------------------------'

if ($DryRun) {
	Write-Output "Dry run. $($script:Applied.Count) change(s) would be made."
}
else {
	Write-Output "$($script:Applied.Count) change(s) applied."
	Write-Output "Registry backup: $backupDir"
}

Write-Output "$($script:Skipped.Count) item(s) already correct, absent or protected."
$script:Skipped | ForEach-Object { Write-Verbose "  skipped: $_" }

if ($script:Failed.Count -gt 0) {
	Write-Warning "$($script:Failed.Count) change(s) failed:"
	$script:Failed | ForEach-Object { Write-Warning "  $_" }
}

Write-Output 'Restart to complete the removals.'
