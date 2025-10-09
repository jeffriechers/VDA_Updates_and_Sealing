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
#
#  Modify entries in this section here
# ---------------------------------------------------

#Enter the name of your maintenance machine here.
#It should be in NETBIOSDOMAINNAME\ComputerName$ format
$MaintenanceMachine = ""

# Don't modify anything below this line if you don't know what you're doing.
# ---------------------------------------------------
#

If ($MaintenanceMachine -eq "") {
    Write-Host "Please set the MaintenanceMachine variable to your maintenance machine name in NETBIOSDOMAINNAME\ComputerName$ format before running this script."
    exit 1
}
function Get-UniqueTemplateOID {
    param (
        [string]$BaseOID = "1.3.6.1.4.1.311.21.8"
    )

    # Get the Certificate Templates container
    $configNC = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
    $templatePath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $templates = [ADSI]$templatePath

    # Get all existing OIDs
    $existingOIDs = @()
    foreach ($template in $templates.psbase.Children) {
        $oid = $template.Properties["msPKI-Cert-Template-OID"].Value
        if ($oid) { $existingOIDs += $oid }
    }

    # Loop until a unique OID is found
    do {
        $guid = [System.Guid]::NewGuid().ToByteArray()
        $suffix = ($guid | ForEach-Object { $_ }) -join "."
        $newOID = "$BaseOID.$suffix"
    } while ($existingOIDs -contains $newOID)

    return $newOID
}

function Invoke-SDProp {
    [CmdletBinding()]
    param (
        [ValidateSet('RunProtectAdminGroupsTask','FixUpInheritance')]
        [string]$TaskName = 'RunProtectAdminGroupsTask'
    )

    try {
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
        $pdc = $domain.PdcRoleOwner.Name

        Write-Verbose "Triggering SDProp on PDC Emulator: $pdc"

        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$pdc/RootDSE")
        $rootDSE.UsePropertyCache = $false
        $rootDSE.Put($TaskName, "1")
        $rootDSE.SetInfo()

        Write-Host "SDProp triggered successfully on $pdc using task '$TaskName'."
    }
    catch {
        Write-Error "Failed to trigger SDProp: $_"
    }
}

# Define template name and OID
$templateName = "VDATLSCertificate"
$templateOID = Get-UniqueTemplateOID

# Get Configuration Naming Context
$config = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$templatesPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$config"
$templates = [ADSI]$templatesPath

# Create the new template object
$newTemplate = $templates.Create("pKICertificateTemplate", "CN=$templateName")

# Basic properties
$newTemplate.Put("displayName", $templateName)
$newTemplate.Put("revision", 100)
$newTemplate.Put("flags", 0x20241)  # Enable autoenrollment
$newTemplate.Put("msPKI-Template-Schema-Version", 3)  # Version 3 template
$newTemplate.Put("msPKI-Cert-Template-OID", $templateOID)
$newTemplate.Put("msPKI-Certificate-Application-Policy", "1.3.6.1.5.5.7.3.1")
$newTemplate.Put("msPKI-Certificate-Name-Flag", "1")
$newTemplate.Put("msPKI-Enrollment-Flag", "0")
$newTemplate.Put("msPKI-Minimal-Key-Size", "2048")
$newTemplate.Put("msPKI-Private-Key-Flag", "84279312")
$newTemplate.Put("msPKI-RA-Signature", "0")
$raPolicyString = "msPKI-Asymmetric-Algorithm``PZPWSTR``RSA``msPKI-Hash-Algorithm``PZPWSTR``SHA384``msPKI-Key-Usage``DWORD``16777215``msPKI-Symmetric-Algorithm``PZPWSTR``3DES``msPKI-Symmetric-Key-Length``DWORD``168"
$newTemplate.Put("msPKI-RA-Application-Policies", $raPolicyString)
$Expiration = [byte[]](0x00, 0x80, 0xD2, 0x16, 0x47, 0xB9, 0xFF, 0xFF)
$newTemplate.Put("pKIExpirationPeriod", $Expiration)
$OverLap = [byte[]](0x00, 0xE0, 0x1D, 0x51, 0xF5, 0xCA, 0xFF, 0xFF)
$newTemplate.Put("pKIOverlapPeriod", $OverLap)
$KeyUsage = [byte[]](0xA0)
$newTemplate.Put("pKIKeyUsage", $KeyUsage)
$newTemplate.Put("pKICriticalExtensions", "2.5.29.15")
$newTemplate.Put("pKIDefaultKeySpec", "1")
$newTemplate.Put("pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.1")
$newTemplate.Put("pKIMaxIssuingDepth", "0")
$newTemplate.Put("msPKI-Template-Minor-Revision", 0)
$newTemplate.Put("objectClass", "pKICertificateTemplate")


# Enrollment permissions (optional—can be set via ACLs later)
# You can use DSACLS or Set-Acl to assign permissions after creation

# Commit the template to AD
$newTemplate.SetInfo()
Write-Host "Template '$templateName' created successfully."

Invoke-SDProp

Write-Host "Template replicated successfully"

# Publish the template to the CA
$publishCommand = "certutil -setcatemplates +$templateName"
Invoke-Expression $publishCommand

$templates = certutil -catemplates
if ($templates -match $templateName) {
    Write-Host "Template '$templateName' successfully published to the CA."
} else {
    Write-Warning "Template '$templateName' not found in CA template list."
}
# Bind to the template
$templateEntry = [ADSI]"LDAP://CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$config"
$security = $templateEntry.psbase.ObjectSecurity

# Identity for the computer
$identity = New-Object System.Security.Principal.NTAccount($MaintenanceMachine)

# Combine all relevant rights
$rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::CreateChild `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::Self `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::ListChildren `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

# Apply to entire object
$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity,
    $rights,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [Guid]::Empty,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)

# Add and commit
$security.AddAccessRule($accessRule)
$templateEntry.psbase.ObjectSecurity = $security
$templateEntry.psbase.CommitChanges()

Write-Host "Enroll granted to '$MaintenanceMachine' on template '$templateName'."