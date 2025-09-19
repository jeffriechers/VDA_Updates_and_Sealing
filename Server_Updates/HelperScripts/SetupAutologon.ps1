# Set username and computer target
$userName = "AutoLogonUser"
$computerName = $env:COMPUTERNAME

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




