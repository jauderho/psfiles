
<#
.SYNOPSIS
   Personal W10 Debloater

.DESCRIPTION
   Personal W10 Debloater

   WARNING: Do not run this without reading through first.

.NOTES
   Created by Jauder Ho
   Last modified 11/1/2019
   https://www.carumba.com

   BSD License

   Pull requests are welcome.

.LINK
   https://www.carumba.com
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

############################################
############################################
#
# DO NOT BLINDLY RUN THIS
#
############################################
############################################


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
	"Microsoft.DesktopAppInstaller"
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
	#"Microsoft.StorePurchaseApp"
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
	#"Microsoft.WindowsStore"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.YourPhone"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"

	# non-Microsoft
	"2FE3CB00.PicsArt-PhotoStudio"
	"46928bounde.EclipseManager"
	"4DF9E0F8.Netflix"
	"6Wunderkinder.Wunderlist"
	"89006A2E.AutodeskSketchBook"
	"9E2F88E3.Twitter"
	"A278AB0D.MarchofEmpires"
	"ActiproSoftwareLLC.562882FEEB491"
	"ClearChannelRadioDigital.iHeartRadio"
	"D52A8D61.FarmVille2CountryEscape"
	"D5EA27B7.Duolingo-LearnLanguagesforFree"
	"DB6EA5DB.CyberLinkMediaSuiteEssentials"
	"DolbyLaboratories.DolbyAccess"
	"Drawboard.DrawboardPDF"
	"Facebook.Facebook"
	"flaregamesGmbH.RoyalRevolt2"
	"Flipboard.Flipboard"
	"GAMELOFTSA.Asphalt8Airborne"
	"KeeperSecurityInc.Keeper"
	"king.com.*"
	"king.com.BubbleWitch3Saga"
	"king.com.CandyCrushSaga"
	"king.com.CandyCrushSodaSaga"
	"Microsoft.MinecraftUWP"
	"PandoraMediaInc.29680B314EFC2"
	"Playtika.CaesarsSlotsFreeCasino"
	"ShazamEntertainmentLtd.Shazam"
	"TheNewYorkTimes.NYTCrossword"
	"ThumbmunkeysLtd.PhototasticCollage"
	"TuneIn.TuneInRadio"
	"XINGAG.XING"

	# Wildcards
	#"*AAD.BrokerPlugin*"
	"*DisneyMagicKingdoms*"
	"*HiddenCityMysteryofShadows*"
	"*MarchofEmpires*"
	#"*PPIProjection*"

	# apps which cannot be removed using Remove-AppxPackage
	#"Microsoft.BioEnrollment"
	#"Microsoft.MicrosoftEdge"
	#"Microsoft.Windows.Cortana"
	#"Microsoft.WindowsFeedback"
	#"Microsoft.XboxGameCallableUI"
	#"Microsoft.XboxIdentityProvider"
	#"Windows.ContactSupport"

	# Win 2004
	"Microsoft.549981C3F5F10"
)

foreach ($app in $apps) {
	Write-Output "Trying to remove $app"

	Get-AppxPackage -AllUsers | Where-Object {$_.Name -Like $app} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -Like $app} | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue
}

# The following cannot be uninstalled using Remove-AppxPackage
Get-WindowsCapability -online | Where-Object {$_.Name -like '*ContactSupport*'} | Remove-WindowsCapability -Online
Get-WindowsCapability -online | Where-Object {$_.Name -like '*QuickAssist*'} | Remove-WindowsCapability -Online

# Disable scheduled tasks
Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask
Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask