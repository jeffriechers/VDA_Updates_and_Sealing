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

asnp Citrix*

# Check to see if Citrix Powershell modules are installed.
if (-not (Get-Command Get-BrokerMachine -ErrorAction SilentlyContinue)) {
    Write-Warning "Citrix PowerShell cmdlets not available. Please run this script on a Delivery Controller or a machine with Citrix SDK installed."
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}

# Prompt for Delivery Group name and DDC

do {
    $deliveryGroup = Read-Host "Enter the Citrix Delivery Group name"
} while ([string]::IsNullOrWhiteSpace($deliveryGroup))

do {
    $adminAddress = Read-Host "Enter the Citrix DDC (AdminAddress)"
} while ([string]::IsNullOrWhiteSpace($adminAddress))

# Get FQDNs of all machines in the Delivery Group
$machines = Get-BrokerMachine -DesktopGroupName $deliveryGroup -AdminAddress $adminAddress -MaxRecordCount 10000

# Display and export DNS names
$machines | Select-Object DNSName
$machines | Select-Object DNSName | Export-Csv "C:\FQDN.csv" -NoTypeInformation

Write-Host "File created at C:\FQDN.csv"
Write-Host ""
Write-Host "Copy this file to the Server Updates folder you will be running Updates and Sealing from"
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")