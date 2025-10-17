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

#Remove FSLogix profile paths from registry, will be updated by next GPUpdate
$FSLogixKeyTest = Get-Item -Path "HKLM:\SOFTWARE\FSLogix" -ErrorAction SilentlyContinue 
If ($FSLogixKeyTest) { 
$CCDRegistryTest = (Get-Item "HKLM:\SOFTWARE\FSLogix\Profiles").Property -contains "CCDLocations" 
$VHDRegistryTest = (Get-Item "HKLM:\SOFTWARE\FSLogix\Profiles").Property -contains "VHDLocations" 
}else {Write-Host "FSLogix not configured"}
If ($CCDRegistryTest) {Remove-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "CCDLocations"}
If ($VHDRegistryTest) {Remove-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations"}

#UberAgent Generalization
if (Get-Service "uberAgentSvc" -ErrorAction SilentlyContinue){$UberAgentInstalled = "True"}Else{$UberAgentInstalled = "False"}
If ($UberAgentInstalled){
	$UberAgentPath = test-path -path "HKLM:\SOFTWARE\vast limits\uberAgent"
	If ($UberAgentPath) {
	Stop-Service uberAgentSvc
	Remove-Item -Path "HKLM:\SOFTWARE\vast limits\uberAgent" -recurse -force
	}
}

#Update Group Policy
#Try the Powershell update process first, requires gpmc feature installed.  If it isn't installed, run the traditional cmd based method.
try {Invoke-GPUpdate -Force -RandomDelayInMinutes 0}
catch {Invoke-Command -ScriptBlock {echo nn | gpupdate.exe /force}}
Write-Host "Group Policy Update process complete."

#Repair Registry entry for screensaver timeouts
$GraphicsKeyTest = test-path -path "HKLM:\SOFTWARE\Citrix\Graphics"
If ($GraphicsKeyTest) { $GraphicsValueTest = (Get-Item "HKLM:\SOFTWARE\Citrix\Graphics").Property -contains "SetDisplayRequiredMode"}else {}
If ($GraphicsValueTest) {}else{New-ItemProperty -Path "HKLM:\SOFTWARE\Citrix\Graphics" -Name "SetDisplayRequiredMode" -Value "00000000" -PropertyType DWORD -Force}


#Install Teams Registry entries
#Disable Teams Auto-Updates for users.
$TeamsKeyTest = test-path -path "HKLM:\SOFTWARE\Microsoft\Teams"
If ($TeamsKeyTest) {New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Value "00000001" -PropertyType DWORD -Force}
else { 
	New-Item "HKLM:\SOFTWARE\Microsoft\Teams"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Value "00000001" -PropertyType DWORD -Force
}
#Enable WebSocket for Teams in Citrix
$WebSocketKeyTest = test-path -path "HKLM:\SOFTWARE\WOW6432Node\Citrix\WebSocketService"
If ($WebSocketKeyTest) {New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Citrix\WebSocketService" -Name "ProcessWhitelist" -Value "msedgewebview2.exe" -PropertyType MultiString -Force}
else { 
	New-Item "HKLM:\SOFTWARE\WOW6432Node\Citrix\WebSocketService"
	New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Citrix\WebSocketService" -Name "ProcessWhitelist" -Value "msedgewebview2.exe" -PropertyType MultiString -Force
}

#Stop and Disable Services
Stop-Service wuauserv
Set-Service wuauserv -StartupType disabled
Stop-Service BITS
Set-Service BITS -StartupType disabled

#Run Windows Defender update and quickscan
if (Test-Path -Path "C:\Program Files\Windows Defender\MpCmdRun.exe"){$WindowsDefenderproc = Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-SignatureUpdateAndQuickScan" -Wait -Passthru}
if (Test-Path -Path "C:\Program Files\Microsoft Security Client\mpcmdrun.exe"){$WindowsDefenderproc = Start-Process -FilePath "C:\Program Files\Microsoft Security Client\mpcmdrun.exe" -ArgumentList "-SignatureUpdateAndQuickScan" -Wait -Passthru}
$WindowsDefenderproc.WaitForExit()

# WEM Cache Update if installed

if (Test-Path -Path "C:\Program Files (x86)\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe"){$WemInstallproc = Start-Process -Filepath "C:\Program Files (x86)\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" -ArgumentList "-r -S -I" -Wait -Passthru}
$WemInstallproc.WaitforExit()

#Disable Scheduled Tasks
Get-ScheduledTask -TaskPath "\" | Where-Object {$_.State -ne "Disabled"} | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\GoogleSystem\" | Where-Object {$_.State -ne "Disabled"} | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\GoogleSystem\GoogleUpdater\" | Where-Object {$_.State -ne "Disabled"} | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Mozilla\" | Where-Object {$_.State -ne "Disabled"} | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Office\" | Where-Object {$_.State -ne "Disabled"} | Disable-ScheduledTask

#Cleanup Temp files
Get-ChildItem -Path c:\windows\temp -include * -Recurse | foreach { $_.Delete()}
#Get-ChildItem -Path C:\Users\Public\Desktop -include * -Recurse | foreach { $_.Delete()}
Get-ChildItem -Path C:\ProgramData\FSLogix\Logs -include * -Recurse | foreach { $_.Delete()}

#Remove Azure Arc Setup Systray
if (Test-Path -Path "C:\Windows\AzureArcSetup"){
try {Remove-WindowsFeature AzureArcSetup}
catch {DISM /online /Remove-Capability /CapabilityName:AzureArcSetup~~~~}	
}

#Adjust Workplace Join to run at Startup for proper PRT registration
$WorkplaceJoinTaskPath = "\Microsoft\Windows\Workplace Join\Automatic-Device-Join"

# Get task XML
$xml = schtasks /Query /TN $WorkplaceJoinTaskPath /XML 2>$null
if (-not $xml) {
    Write-Warning "Task not found or access denied: $WorkplaceJoinTaskPath"
    return
}

# Load XML
[xml]$taskXml = $xml

# Display trigger types

$BootInstall = $false
$triggerNames = @()
$taskXml.Task.Triggers.ChildNodes | ForEach-Object {
    $triggerNames += $_.Name
    if ($_.Name -match "Boot") {
        $BootInstall = $true
    }
}

# Check for Boot trigger
if ($BootInstall) {

    Write-Host "Workplace Join At Startup trigger is already present." -ForegroundColor Green

} else {
        $taskPath = "\Microsoft\Windows\Workplace Join\"
        $taskName = "Automatic-Device-Join"

    # Create a new startup trigger
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    $newTrigger = New-ScheduledTaskTrigger -AtStartup

    # Register the updated task with the new trigger
    Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
        -Action $task.Actions `
        -Trigger ($task.Triggers + $newTrigger) `
        -Settings $task.Settings `
        -Principal $task.Principal `
        -Force

    Write-Output "Workplace Join At Startup trigger added successfully."
}

#SSL VDA Certificate request and install
$CertscriptPath = Join-Path -Path $PSScriptRoot -ChildPath "HelperScripts\CertificateGeneration.ps1"
If (Test-Path $CertscriptPath) {
    & "$CertscriptPath"
}

#Desktop Warmup
$WarmupScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "HelperScripts\SetupAutologon.ps1"
If (Test-Path $WarmupScriptPath) {
    & "$WarmupScriptPath"
#Set Broker services to Disabled
Stop-Service BrokerAgent
Set-Service BrokerAgent -StartupType disabled
}

#Ensure MMAgent settings are enabled and disabled for non-persistent environments
Enable-MMAgent -MemoryCompression -PageCombining
Disable-MMAgent -ApplicationLaunchPrefetching
Disable-MMAgent -ApplicationPreLaunch



#Remove Zero Machine from Hybrid Azure-AD
$LeaveAzureADproc = Start-Process -Filepath "c:\windows\system32\dsregcmd.exe" -ArgumentList "/leave" -Passthru
$LeaveAzureADproc.WaitforExit()
Write-Host "Machine has left Azure AD"

#Shutdown Computer for capture
Stop-Computer -ComputerName localhost -Force
