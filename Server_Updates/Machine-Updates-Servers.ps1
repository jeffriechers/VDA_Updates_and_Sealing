# Script created by Jeff Riechers
# Downloaded from www.jeffriechers.com
# Contact me with questions or recommendations at jeffriechers@gmail.com

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
#Common Code
$Options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 0

Start-Transcript -Path (Join-Path $env:TEMP "Updates.log") -Append -Force
#Start Stopped Services
Write-Output "Starting stopped services"
Set-Service BITS -StartupType auto
Start-Service BITS
Set-Service wuauserv -StartupType auto
Start-Service wuauserv

#Windows Updates
Write-Output "Starting scan for Windows Updates"
$WindowsUpdateproc = Start-Process -Filepath "c:\windows\system32\usoclient.exe" -ArgumentList "scaninstallwait" -Passthru
$WindowsUpdateproc.WaitforExit()
			
#Teams Install
$TeamsScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "HelperScripts\TeamsUpdate.ps1"
If (Test-Path $TeamsScriptPath) {
    & "$TeamsScriptPath"
}

#Office 365 Updates
Write-Output "Checking for installed Office"
$OfficeInstall = 'C:\Program Files (x86)\Common Files\microsoft shared\ClickToRun\Officec2rclient.exe'
if (-not(Test-Path -Path $OfficeInstall)) {
	Write-Output "Office 32 bit not installed, skipping updates"
}
else {
	$Officeinstallproc = Start-Process -Filepath "C:\Program Files (x86)\Common Files\microsoft shared\ClickToRun\Officec2rclient.exe" -ArgumentList "/update user" -Passthru
	$Officeinstallproc.WaitforExit()
	Write-Output "Office 32 bit Updated"
}

$Office64Install = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\Officec2rclient.exe'
if (-not(Test-Path -Path $Office64Install)) {
	Write-Output "Office not installed, skipping updates"
}
else {
	$Office64installproc = Start-Process -Filepath "C:\Program Files\Common Files\microsoft shared\ClickToRun\Officec2rclient.exe" -ArgumentList "/update user" -Passthru
	$Office64installproc.WaitforExit()
	Write-Output "Office Updated"
}

#OneDrive install and Update
$OneDriveScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "HelperScripts\OneDriveUpdate.ps1"
If (Test-Path $OneDriveScriptPath) {
    & "$OneDriveScriptPath"
}


#Software Updates either by choco or by application update process
$ChocoInstall = 'C:\ProgramData\chocolatey\choco.exe'
if (-not(Test-Path -Path $ChocoInstall)) {
	Write-Output "Chocolatey not installed, manually updating."
	$FirefoxInstall = 'C:\Program Files\Mozilla Firefox\updater.exe'
	if (-not(Test-Path -Path $FirefoxInstall)) {
		Write-Output "Firefox not installed, skipping updates"
	}
	else {
		$firefoxinstallproc = Start-Process -Filepath "C:\Program Files\Mozilla Firefox\updater.exe" -Passthru
		$firefoxinstallproc.WaitforExit()
		Write-Output "Firefox Updated"
	}
	$Chrome64Install = 'C:\Program Files\Google\Update\GoogleUpdate.exe'
	if (-not(Test-Path -Path $Chrome64Install)) {
		Write-Output "Chrome not installed, skipping updates"
	}
	else {
		$Chrome64Installproc = Start-Process -Filepath "C:\Program Files\Google\Update\GoogleUpdate.exe" -ArgumentList "/ua /installsource scheduler" -Passthru
		$Chrome64Installproc.WaitforExit()
		Write-Output "Chrome Updated"
	}
	$ChromeInstall = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'
	if (-not(Test-Path -Path $ChromeInstall)) {
		Write-Output "Chrome 32 bit not installed, skipping updates"
	}
	else {
		$ChromeInstallproc = Start-Process -Filepath "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" -ArgumentList "/ua /installsource scheduler" -Passthru
		$ChromeInstallproc.WaitforExit()
		Write-Output "Chrome 32 bit Updated"
	}
}
else {
	$Chocoproc = Start-Process -FilePath "choco" -ArgumentList "upgrade all --ignore-checksums -y" -Passthru
	$Chocoproc.WaitForExit()
	Write-Output "Chocolatey Update process complete."
}


#Update Group Policy
#Try the Powershell update process first, requires gpmc feature installed.  If it isn't installed, run the traditional cmd based method.
try {Invoke-GPUpdate -Force -RandomDelayInMinutes 0}
catch {Invoke-Command -ScriptBlock {echo nn | gpupdate.exe /force}}
Write-Host "Group Policy Update process complete."

#Update Installed PowerShell modules
#If you are being prompted to approve untrusted repositories, and wish to do this silently, you can do this with the following command.
#
#Get-PSRepository #Shows the configured Repositories 
#
#Set-psrepository -name '<From list above>' -InstallationPolicy Trusted
#
#For example, using PSGallery
#Set-psrepository -name 'PSGallery' -InstallationPolicy Trusted
#
#If updates fail due to the vendor changing their signing certificate you must do a force install and tell it to skippublishercheck
#
#Install-module '<module name>' -Confirm:$false -AcceptLicense -Force -SkipPublisherCheck

#Update-Module * -Confirm:$false -AcceptLicense 

Stop-Transcript
