
<#
.SYNOPSIS
   Search drives for jar files containing JNDI classes

.DESCRIPTION
   For CVE-2021-44228, look through drives for vulnerable files

.NOTES
   Credit to Jai Minton and Grzegorz Tworek for figuring out the invocation

   BSD License

   Pull requests are welcome.

.LINK
   https://twitter.com/CyberRaiju/status/1469505677580124160
	 https://twitter.com/0gtweet/status/1469661769547362305
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

function Find-Log4J {

	# Search through local drives for jar files containing the jndi class
	# NOTE: This will flag patched files
	gcim win32_volume | ? { $_.DriveType -eq 3 -and $_.DriveLetter -ne $null} | % {(gci ($_.DriveLetter+"\") -rec -force -include *.jar -ea 0 | % {sls "JndiLookup.class" $_} | select -exp Path)}

	# Linux version
	# find / 2>/dev/null -regex ".*.jar" -type f | xargs -I{} grep JndiLookup.class "{}"

	#Get-PSDrive -PSProvider FileSystem | foreach {(gci ($_.Root) -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path)}
}

Find-Log4J

#Write-Output 'Done...'
