#Variables
$ScriptPath = "C:\MyScripts"
$TaskPath = "MyScripts"
# Copy run scripts to Workstation

If (-not (Test-Path $ScriptPath)) {New-Item -Path $ScriptPath -ItemType Directory}

#Create AutologonWarmup Scheduled Task for AutoLogonUser
# Define paths
$sourceXmlPath = Join-Path $PSScriptRoot AutologonWarmup.xml
$targetXmlPath = Join-Path $ScriptPath AutologonWarmup.xml
If (-not (Test-Path $targetXmlPath)) {

# Load the XML with namespace handling
[xml]$xmlDoc = Get-Content $sourceXmlPath
$nsMgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
$nsMgr.AddNamespace("ns", $xmlDoc.DocumentElement.NamespaceURI)

# Select the <Arguments> node using the correct namespace prefix
$argumentsNode = $xmlDoc.SelectSingleNode("//ns:Task/ns:Actions/ns:Exec/ns:Arguments", $nsMgr)

if ($argumentsNode -ne $null) {
    # Replace "C:\Temp" with the value of $ScriptPath
    $argumentsNode.InnerText = $argumentsNode.InnerText -replace "C:\\Temp", $ScriptPath
    $xmlDoc.Save($targetXmlPath)
    Write-Host "Updated XML saved to: $targetXmlPath"
} else {
    Write-Warning "Arguments node not found. Please double-check the XML structure."
}
}

# Set username and computer target
$userName = "AutoLogonUser"
$computerName = $env:COMPUTERNAME

#Modify Warmup Script for Maintenance Machine Name
# Define paths
$sourcewarmupscript = Join-Path $PSScriptRoot WarmupScheduledTask.ps1
$targetPath = Join-Path $ScriptPath WarmupScheduledTask.ps1
If (-not (Test-Path $targetPath)) {

# Read the original script content
$scriptContent = Get-Content -Path $sourcewarmupscript -Raw

# Replace all instances of "MaintenanceMachine" with the actual computer name
$modifiedContent = $scriptContent -replace "MaintenanceMachine", $computername

# Save the modified script
Set-Content -Path $targetPath -Value $modifiedContent
}

# Generate a hard password (16 chars, complex)
Add-Type -AssemblyName System.Web
$password = [System.Web.Security.Membership]::GeneratePassword(16, 4)

# Convert plain text password to secure string
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# Check if user exists
try {
    $userExists = Get-LocalUser -Name $userName -ErrorAction Stop
    Set-LocalUser -Name $Username -Password $securePassword
    Write-Host "User '$userName' already exists."
} catch {
    Write-Host "Creating local user '$userName'..."
    New-LocalUser -Name $userName -Password $securePassword -FullName "Autologon Account" -Description "Used for autologon"
    Add-LocalGroupMember -Group "Administrators" -Member $userName
}

# Set registry values for autologon
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $userName
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $password
Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value $null

Write-Host "`nAutologon configuration completed successfully."
Write-Host "Username: $userName"
Write-Host "Password: $password"

#Import Scheduled Tasks if they don't exist
$taskName = "AutologonWarmup"
$Warmuptask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue

if ($Warmuptask) {
    Write-Host "Task '$WarmuptaskName' exists in '$taskPath'."
} else {
    Register-ScheduledTask -TaskPath $taskPath -User $username -TaskName $taskName -Xml (Get-Content $targetXmlPath | Out-String) -Force
}

