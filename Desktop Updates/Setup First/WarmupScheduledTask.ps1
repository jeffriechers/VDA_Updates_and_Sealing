$computerName = $env:COMPUTERNAME

if ($computerName -eq "MaintenanceMachine") {
#Prelaunch applications into memory
#Start Processes
Start-Process -FilePath "ms-teams.exe" -PassThru
Start-Process -FilePath "msedge.exe" -PassThru
Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -PassThru
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" -PassThru
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\excel.EXE" -PassThru
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\outlook.EXE" -PassThru
#Wait
Start-Sleep -Seconds 60

#Stop Processes
Stop-Process -name "msedge"
Stop-Process -name "ms-teams"
Stop-Process -name "chrome"
Stop-Process -name "winword"
Stop-Process -name "excel"
Stop-Process -name "outlook"

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
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" -PassThru
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\excel.EXE" -PassThru
Start-Process -FilePath "C:\Program Files\Microsoft Office\root\Office16\outlook.EXE" -PassThru
#Wait
Start-Sleep -Seconds 60

#Stop Processes
Stop-Process -name "msedge"
Stop-Process -name "ms-teams"
Stop-Process -name "chrome"
Stop-Process -name "winword"
Stop-Process -name "excel"
Stop-Process -name "outlook"


#Generate a new password for Autologon Account, then disable it
# Set username and computer target
$userName = "AutoLogonUser"
# Generate a hard password (16 chars, complex)
Add-Type -AssemblyName System.Web
$password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
# Convert plain text password to secure string
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
Set-LocalUser -Name $userName -Password $securePassword
Disable-LocalUser -Name $userName

#Set Broker services to automatic
Set-Service BrokerAgent -StartupType automatic
Start-Service BrokerAgent

#Logout
shutdown.exe -l
}