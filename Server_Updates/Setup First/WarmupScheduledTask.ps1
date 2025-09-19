$computerName = $env:COMPUTERNAME
$ScriptPath = "C:\MyScripts"
$targetXmlPath = Join-Path $ScriptPath AutologonWarmup.xml
$targetPath = Join-Path $ScriptPath WarmupScheduledTask.ps1

if ($computerName -eq "MaintenanceMachine") {
#Prelaunch applications into memory
#Start Processes
Start-Process -FilePath "ms-teams.exe" -PassThru
Start-Process -FilePath "msedge.exe" -PassThru
Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -PassThru

#Wait
Start-Sleep -Seconds 15

#Stop Processes
Stop-Process -name "msedge"
Stop-Process -name "ms-teams"
Stop-Process -name "chrome"

#Logout
shutdown.exe -l
}
else {

#Remove AutoLogon Settings from registry
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "0"
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $null
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $null

#Prelaunch applications into memory
#Start Processes
Start-Process -FilePath "ms-teams.exe" -PassThru
Start-Process -FilePath "msedge.exe" -PassThru
Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -PassThru

#Wait
Start-Sleep -Seconds 15

#Stop Processes
Stop-Process -name "msedge"
Stop-Process -name "ms-teams"
Stop-Process -name "chrome"

#Remove Warmup Scripts
If (Test-Path $targetPath) {Remove-Item $targetPath -Force}
If (Test-Path $targetXmlPath) {Remove-Item $targetXmlPath -Force}
#Logout
shutdown.exe -l
}