#Teams Install
$winver = Get-ComputerInfo | Select-Object -ExpandProperty WindowsProductName

#Download latest MSIX version
$MSIXDownloadURI = "https://go.microsoft.com/fwlink/?linkid=2196106"
$MSIXPath = Join-Path "$($env:TEMP)" "MSTeams-x64.msix"
(New-Object System.Net.WebClient).DownloadFile($MSIXDownloadURI, $MSIXPath)

$TeamsKeyTest = test-path -path "HKLM:\SOFTWARE\Microsoft\Teams"
If ($TeamsKeyTest) { $TeamUpdateRegistryTest = (Get-Item "HKLM:\SOFTWARE\Microsoft\Teams").Property -contains "disableAutoUpdate" }else {}
If ($TeamUpdateRegistryTest) { 
	Write-Output "Check to see if Teams auto update is disabled, and remove that setting."
	Write-Output "It will be re-enabled at the end of the process."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" }else {}

$TeamInstallPath = "C:\Program Files\WindowsApps\MSTeams_*"
$TeamInstallCheck = test-path -PathType container $TeamInstallPath

#Download and install Teams
# Server 2019
If ($winver -like "Windows Server 2019*") {

	#Check for DotNet 4.8 or later - required for the Teams add-in for Outlook
	if ((Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528049) {
		Write-Host "Dot Net is up to date."
	}
	else {
		Write-output "Dot Net Framework 4.8 or later is not installed."
		Write-output "This is required for the Teams add-in for Outlook"
        Write-output "Rerun this install after installing Dot Net Framework and rebooting"
        exit
	}
	New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -Value "00000001" -PropertyType DWORD -Force

	$DISM = "c:\windows\system32\Dism.exe"
	$Switches = " /Online /Add-ProvisionedAppxPackage /PackagePath:$MSIXPath /SkipLicense"
	Write-output "Installing Teams for Windows Server 2019"
	$Team2Installproc = Start-Process -FilePath $DISM -ArgumentList $Switches  -PassThru -Wait
	$Team2Installproc.WaitForExit()
    Write-output "Teams has completed installation, now installing the Teams Outlook Add-in"
    # Install latest Teams Meeting Add-in
    $UpdatedTeams = (Get-ChildItem -Path "C:\Program Files\WindowsApps" -Filter "MSTeams_*" -Directory).Fullname | Sort-Object name | Select-Object -First 1
    $installableversion = Get-AppLockerFileInformation -Path $UpdatedTeams"\MICROSOFTTEAMSMEETINGADDININSTALLER.MSI" | Select-Object -ExpandProperty Publisher | Select-Object BinaryVersion
    $getversionnumber = $installableversion.BinaryVersion.toString()
    $TeamsAddinInstall = start-process -filepath "C:\Windows\System32\msiexec.exe"-argumentList '/i MicrosoftTeamsMeetingAddinInstaller.msi /qn ALLUSERS=1 /norestart TARGETDIR="C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\', $getversionnumber, '"' -WorkingDirectory $UpdatedTeams -Passthru -Wait
    $TeamsAddinInstall.WaitForExit()
}
else {

#All other OSes

#Check for DotNet 4.8 or later - required for the Teams add-in for Outlook
	if ((Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528049) {
		Write-Host "Dot Net is up to date."
	}
	else {
		Write-output "Dot Net Framework 4.8 or later is not installed."
		Write-output "This is required for the Teams add-in for Outlook"
        Write-output "Rerun this install after installing Dot Net Framework and rebooting"
        exit
	}
		
Write-Host "Download latest Teams installer"
$TeamDownloadURI = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
$TeamPath = Join-Path "$($env:TEMP)" "teamsbootstrapper.exe"
Write-Output "Downloading Now"
(New-Object System.Net.WebClient).DownloadFile($TeamDownloadURI, $TeamPath)
$Execute2Setup = " -p -o $MSIXPath --installTMA"
Write-output "Installing Teams"
$Team2Installproc = Start-Process -FilePath $TeamPath -ArgumentList $Execute2Setup -PassThru -Wait
$Team2Installproc.WaitForExit()
}
#Disable Teams Auto-Updates for users.
$TeamsKeyTest = test-path -path "HKLM:\SOFTWARE\Microsoft\Teams"
If ($TeamsKeyTest) {New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Value "00000001" -PropertyType DWORD -Force}
else { 
	New-Item "HKLM:\SOFTWARE\Microsoft\Teams"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Value "00000001" -PropertyType DWORD -Force
}