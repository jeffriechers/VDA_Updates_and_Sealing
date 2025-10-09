# Script created by Jeff Riechers
# Downloaded from www.jeffriechers.com
# Contact me with questions or recommendations at jeffriechers@gmail.com

# Self-elevate the script if the machine is not running in Admin Mode
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}

$domain = $env:USERDNSDOMAIN
$computerName = $env:COMPUTERNAME
$fqdn = "$computerName.$domain"
$wildcard = "*." + $domain
$templateName = "VDATLSCertificate"
$subjectName = "CN=CVADSSL"

# Remove existing matching certificate
$storePath = "Cert:\LocalMachine\My"
$existingCerts = Get-ChildItem $storePath | Where-Object {
    $_.Subject -eq $subjectName
}

foreach ($oldCert in $existingCerts) {
    try {
        Remove-Item -LiteralPath $oldCert.PSPath -Force
        Write-Output "Removed old certificate: $($oldCert.Thumbprint)"
    } catch {
        Write-Warning "Failed to remove certificate: $($_.Exception.Message)"
    }
}

# Path to the CSV file
$fqdnCsvPath = Join-Path -Path $PSScriptRoot -ChildPath "FQDN.csv"

# Initialize DnsName and SubjectName
$dnsNames = @($wildcard, $fqdn)


if (Test-Path $fqdnCsvPath) {
    try {
        $csvFqdns = @(Import-Csv -Path $fqdnCsvPath | Select-Object -ExpandProperty DNSName)
        if ($csvFqdns.Count -gt 0) {
            $dnsNames = $csvFqdns
            $dnsNames += $fqdn
            Write-Output "Using SAN certificate with DNS names from FQDN.csv"
        } else {
            Write-Warning "FQDN.csv is present but empty. Falling back to wildcard certificate."
        }
    } catch {
        Write-Warning "Failed to read FQDN.csv: $($_.Exception.Message). Falling back to wildcard certificate."
    }
} else {
    Write-Output "FQDN.csv not found. Proceeding with wildcard certificate."
}

# Request new certificate
$params = @{
    Template          = $templateName
    DnsName           = $dnsNames
    CertStoreLocation = $storePath
    SubjectName       = $subjectName
}

$cert = Get-Certificate @params

# Output new certificate info
if ($cert.Certificate) {
    Write-Output "New certificate installed."
    Write-Output "Thumbprint: $($cert.Certificate.Thumbprint)"
    Write-Output "Subject: $($cert.Certificate.Subject)"
    Write-Output "NotBefore: $($cert.Certificate.NotBefore)"
    Write-Output "NotAfter: $($cert.Certificate.NotAfter)"
} else {
    Write-Warning "Certificate request failed. Status: $($cert.Status)"
}
$CertThumbprint = $cert.Certificate.Thumbprint

# Build the path to the target script
$ScriptToRun = Join-Path -Path $PSScriptRoot -ChildPath "\Enable-VDASSL.ps1"

# Call the script with arguments
& $ScriptToRun -Enable -CertificateThumbPrint $CertThumbprint -SSLMinVersion "TLS_1.2" 

