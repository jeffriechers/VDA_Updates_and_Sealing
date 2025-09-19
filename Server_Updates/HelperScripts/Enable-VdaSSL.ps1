<#
.SYNOPSIS
    Enable/Disable the TLS/DTLS listeners on the VDA

.DESCRIPTION
    Enable or disable the TLS/DTLS listeners on the VDA. 
    Optionally, the TLS/DTLS certificate, port, version and cipher suite to use can be specified.

.PARAMETER Disable
    Disables the TLS/DTLS listeners.
.PARAMETER Enable
    Enables the TLS/DTLS listeners.
.PARAMETER SSLPort
    Specifies the port to use. Default is port 443.
.PARAMETER SSLMinVersion
    Specifies the minimum TLS/DTLS version to use (allowed values are SSL_3.0, TLS_1.0, TLS_1.1, TLS_1.2 and TLS_1.3).
    Default is TLS_1.0. 
.PARAMETER SSLCipherSuite
    Specifies the cipher suite to use (allowed values are GOV, COM and ALL). Default is ALL.
.PARAMETER CertificateThumbPrint
    Specifies the certificate thumbprint to identify the certificate to use. Default is the certificate that
    matches the FQDN of the VDA.

.EXAMPLE
    To disable the TLS/DTLS listeners
    Enable-VdaSSL -Disable
.EXAMPLE
    To enable the TLS/DTLS listeners
    Enable-VdaSSL -Enable
.EXAMPLE
    To enable the TLS/DTLS listeners on port 4000
    Enable-VdaSSL -Enable -SSLPort 4000
.EXAMPLE
    To enable the TLS/DTLS listeners using TLS 1.2 with the GOV cipher suite
    Enable-VdaSSL -Enable -SSLMinVersion "TLS_1.2" -SSLCipherSuite "GOV"
.EXAMPLE
    To enable the TLS/DTLS listeners using the specified computer certificate
    Enable-VdaSSL -Enable -CertificateThumbprint "373641446CCA0343D1D5C77EB263492180B3E0FD"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
Param(
    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$False, ParameterSetName = "DisableMode")]
    [switch] $Disable,

    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [switch] $Enable,
    
    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [int] $SSLPort = 443,

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [ValidateSet("SSL_3.0", "TLS_1.0", "TLS_1.1", "TLS_1.2", "TLS_1.3")]
    [String] $SSLMinVersion = "TLS_1.0",

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [ValidateSet("GOV", "COM", "ALL")]
    [String] $SSLCipherSuite = "ALL",

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [string]$CertificateThumbPrint 
    )

    Set-StrictMode -Version 2.0
    $erroractionpreference = "Stop"

    #Check if the user is an administrator
    if(!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Host "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
        break
    }

    #Write Header
    Write-Host "Enable TLS/DTLS to the VDA"
    Write-Host "Running command Enable-VdaSSL to enable or disable TLS/DTLS to the VDA."
    Write-Host "This includes:"
    Write-Host "`ta.Disable TLS/DTLS to VDA or"
    Write-Host "`tb.Enable TLS/DTLS to VDA"
    Write-Host "`t`t1.Setting ACLs"
    Write-Host "`t`t2.Setting registry keys"
    Write-Host "`t`t3.Configuring Firewall"
    Write-Host ""
    Write-Host ""

    # Registry path constants 
    $ICA_LISTENER_PATH = 'HKLM:\system\CurrentControlSet\Control\Terminal Server\Wds\icawd'
    $ICA_CIPHER_SUITE = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
    $DHEnabled = 'Enabled'
    $BACK_DHEnabled = 'Back_Enabled'
    $ENABLE_SSL_KEY = 'SSLEnabled'
    $SSL_CERT_HASH_KEY = 'SSLThumbprint'
    $SSL_PORT_KEY = 'SSLPort'
    $SSL_MINVERSION_KEY = 'SSLMinVersion'
    $SSL_CIPHERSUITE_KEY = 'SSLCipherSuite'

    $POLICIES_PATH = 'HKLM:\SOFTWARE\Policies\Citrix\ICAPolicies'
    $ICA_LISTENER_PORT_KEY = 'IcaListenerPortNumber'
    $SESSION_RELIABILITY_PORT_KEY = 'SessionReliabilityPort'
    $WEBSOCKET_PORT_KEY = 'WebSocketPort'

    #Read ICA, CGP and HTML5 ports from the registry
    try
    {
        $IcaPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $ICA_LISTENER_PORT_KEY).IcaListenerPortNumber
    }
    catch
    {
        $IcaPort = 1494
    }

    try
    {
        $CgpPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $SESSION_RELIABILITY_PORT_KEY).SessionReliabilityPort
    }
    catch
    {
        $CgpPort = 2598
    }

    try
    {
        $Html5Port = (Get-ItemProperty -Path $POLICIES_PATH -Name $WEBSOCKET_PORT_KEY).WebSocketPort
    }
    catch
    {
        $Html5Port = 8008
    }

    if (!$IcaPort)
    {
        $IcaPort = 1494
    }
    if (!$CgpPort)
    {
        $CgpPort = 2598
    }
    if (!$Html5Port)
    {
        $Html5Port = 8008
    }

    # Determine the name of the ICA Session Manager
    if (Get-Service | Where-Object {$_.Name -eq 'porticaservice'}) 
    {
        $username = 'NT SERVICE\PorticaService'
        $serviceName = 'PortIcaService'
    }
    else
    {
        $username = 'NT SERVICE\TermService'
        $serviceName = 'TermService'
    }

    switch ($PSCmdlet.ParameterSetName)
    {
        "DisableMode"
        {
            #Replace Diffie-Hellman Enabled value to its original value
            if (Test-Path $ICA_CIPHER_SUITE)
            {
                $back_enabled_exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -ErrorAction SilentlyContinue
                if ($back_enabled_exists -ne $null)
                {
                    Set-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value $back_enabled_exists.Back_Enabled
                    Remove-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled
                }
            }

            if ($PSCmdlet.ShouldProcess("This will delete any existing firewall rules for Citrix SSL Service and enable rules for ICA, CGP and Websocket services.", "Are you sure you want to perform this action?`nThis will delete any existing firewall rules for Citrix SSL Service and enable rules for ICA, CGP and Websocket services.", "Configure Firewall"))
            {
                #Enable any existing rules for ICA, CGP and HTML5 ports
                netsh advfirewall firewall add rule name="Citrix ICA Service"        dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$IcaPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix CGP Server Service" dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$CgpPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix Websocket Service"  dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$Html5Port | Out-Null

                #Enable existing rules for UDP-ICA, UDP-CGP 
                netsh advfirewall firewall add rule name="Citrix ICA UDP" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$IcaPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix CGP UDP" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$CgpPort | Out-Null

                #Delete any existing rules for Citrix SSL Service
                netsh advfirewall firewall delete rule name="Citrix SSL Service" | Out-Null

                #Delete any existing rules for Citrix DTLS Service
                netsh advfirewall firewall delete rule name="Citrix DTLS Service" | Out-Null
            }
            else
            {
                Write-Host "Firewall configuration skipped."
            }

            #Turning off SSL by setting SSLEnabled key to 0
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $ENABLE_SSL_KEY -Value 0 -Type DWord -Confirm:$false

            Write-Host "SSL to VDA has been disabled."
        }

        "EnableMode"
        {
            $RegistryKeysSet = $ACLsSet = $FirewallConfigured = $False

            $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
            $Store.Open("ReadOnly")
        
            if ($Store.Certificates.Count -eq 0)
            {
                Write-Host "No certificates found in the Personal Local Machine Certificate Store. Please install a certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }
            elseif ($Store.Certificates.Count -eq 1)
            {
                if ($CertificateThumbPrint)
                {
                    $Certificate = $Store.Certificates[0]
                    $Thumbprint = $Certificate.GetCertHashString()
                    if ($Thumbprint -ne $CertificateThumbPrint)
                    {
                        Write-Host "No certificate found in the certificate store with thumbprint $CertificateThumbPrint"
                        Write-Host "`nEnabling SSL to VDA failed."
                        $Store.Close()
                        break
                    }
                }
                else
                {
                    $Certificate = $Store.Certificates[0]
                }
            }
            elseif ($CertificateThumbPrint)
            {
                $Certificate = $Store.Certificates | where {$_.GetCertHashString() -eq $CertificateThumbPrint}
                if (!$Certificate)
                {
                    Write-Host "No certificate found in the certificate store with thumbprint $CertificateThumbPrint"
                    Write-Host "`nEnabling SSL to VDA failed."
                    $Store.Close()
                    break
                }
            }
            else
            {
                $ComputerName = "CN="+[System.Net.Dns]::GetHostByName((hostname)).HostName
                $Certificate = $Store.Certificates | where {$_.Subject -match $ComputerName}
                if (!$Certificate)
                {
                    Write-Host "No certificate found in the certificate store with Subject $ComputerName, please specify the thumbprint using -CertificateThumbPrint option."
                    Write-Host "`nEnabling SSL to VDA failed."
                    $Store.Close()
                    break
                }
            }
                
            #Validate the certificate

            #Validate expiration date
            $ValidTo = [DateTime]::Parse($Certificate.GetExpirationDateString())
            if($ValidTo -lt [DateTime]::UtcNow)
            {
                Write-Host "The certificate is expired. Please install a valid certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            #Check certificate trust
            if(!$Certificate.Verify())
            {
                Write-Host "Verification of the certificate failed. Please install a valid certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            #Check private key availability
            try
            {
                $PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
				if (!$PrivateKey)
				{
					$PrivateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
				}
				# both legacy CSP and new KSP certificate PrivateKey object obtained as above is of type RSACng
				# the Key.UniqueName returned for CSP certificate is actually the CspKeyContainerInfo.UniqueKeyContainerName
				$UniqueName = $PrivateKey.Key.UniqueName 
				Write-Host "`nRSA CNG unique key name : $UniqueName"
            }
            catch
            {
                Write-Host "Unable to access the Private Key of the Certificate or one of its fields."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            if(!$PrivateKey -or !$UniqueName)
            {
                Write-Host "Unable to access the Private Key of the Certificate or one of its fields."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            #if ($PSCmdlet.ShouldProcess("This will grant $serviceName read access to the certificate.", "Are you sure you want to perform this action?`nThis will grant $serviceName read access to the certificate.", "Configure ACLs"))
            
				[System.Security.Cryptography.AsymmetricAlgorithm] $PrivateKey = $Certificate.PrivateKey
				if ($PrivateKey) # Legacy CSP Certificate
				{
					$unique_name = $PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
					$dir= $env:ProgramData + '\Microsoft\Crypto\RSA\MachineKeys\'
				}
				else # KSP Certificate
				{
					$PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
					if (!$PrivateKey)
					{
						$PrivateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
					}
					$unique_name = $PrivateKey.Key.UniqueName
					$dir= $env:ProgramData + '\Microsoft\Crypto\Keys\'
				}

				$keypath = $dir+$unique_name
				Write-Host "`nkeypath: $keypath"
				icacls $keypath /grant `"$username`"`:RX | Out-Null

                Write-Host "ACLs set."
                Write-Host ""
                $ACLsSet = $True
            
            #else
            #{
            #    Write-Host "ACL configuration skipped."
            #}

            #if($PSCmdlet.ShouldProcess("This will delete any existing firewall rules for port $SSLPort and disable rules for ICA, CGP and Websocket services.", "Are you sure you want to perform this action?`nThis will delete any existing firewall rules for port $SSLPort and disable rules for ICA, CGP and Websocket services.", "Configure Firewall"))
            
                #Delete any existing rules for the SSLPort
                netsh advfirewall firewall delete rule name=all protocol=tcp localport=$SSLPort | Out-Null

                #Delete any existing rules for the DTLSPort
                netsh advfirewall firewall delete rule name=all protocol=udp localport=$SSLPort | Out-Null
                        
                #Delete any existing rules for Citrix SSL Service
                netsh advfirewall firewall delete rule name="Citrix SSL Service" | Out-Null

                #Delete any existing rules for Citrix DTLS Service
                netsh advfirewall firewall delete rule name="Citrix DTLS Service" | Out-Null
                        
                #Creating firewall rule for Citrix SSL Service
                netsh advfirewall firewall add rule name="Citrix SSL Service"  dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$SSLPort | Out-Null

                #Creating firewall rule for Citrix DTLS Service
                netsh advfirewall firewall add rule name="Citrix DTLS Service" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$SSLPort | Out-Null

                #Disable any existing rules for ICA, CGP and HTML5 ports
                netsh advfirewall firewall set rule name="Citrix ICA Service"        protocol=tcp localport=$IcaPort new enable=no | Out-Null
                netsh advfirewall firewall set rule name="Citrix CGP Server Service" protocol=tcp localport=$CgpPort new enable=no | Out-Null
                netsh advfirewall firewall set rule name="Citrix Websocket Service"  protocol=tcp localport=$Html5Port new enable=no | Out-Null

                #Disable existing rules for UDP-ICA, UDP-CGP
                netsh advfirewall firewall set rule name="Citrix ICA UDP" protocol=udp localport=$IcaPort new enable=no | Out-Null          
                netsh advfirewall firewall set rule name="Citrix CGP UDP" protocol=udp localport=$CgpPort new enable=no | Out-Null

                Write-Host "Firewall configured."
                $FirewallConfigured = $True
            
            #else
            #{
            #    Write-Host "Firewall configuration skipped."
            #}

            # Create registry keys to enable SSL to the VDA
            Write-Host "Setting registry keys..."
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CERT_HASH_KEY -Value $Certificate.GetCertHash() -Type Binary -Confirm:$False 
            switch($SSLMinVersion)
            {
                "SSL_3.0"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 1 -Type DWord -Confirm:$False
                }
                "TLS_1.0"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 2 -Type DWord -Confirm:$False
                }
                "TLS_1.1"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 3 -Type DWord -Confirm:$False
                }
                "TLS_1.2"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 4 -Type DWord -Confirm:$False
                }
		        "TLS_1.3"
		        {
		            #check if this OS support TLS 1.3 or not
                    
                    $osVersion = (Get-WMIObject win32_operatingsystem) | Select Version | Out-String
                    $osVersion = $osVersion.trim()
                    $buildNum = [int]$osVersion.Split(".")[2]
                    if ($buildNum -lt 20348)
                    {
	                    Write-Host "Enabling SSL to VDA failed. TLS 1.3 is only supported in Windows 2k22 / Windows 11 and above."
                        $Store.Close()
                        Exit
                    }

                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 5 -Type DWord -Confirm:$False
		        }
            }

            switch($SSLCipherSuite)
            {
                "GOV"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 1 -Type DWord -Confirm:$False
                }    
                "COM"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 2 -Type DWord -Confirm:$False
                }
                "ALL"
                { 
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 3 -Type DWord -Confirm:$False
                }
            }

            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_PORT_KEY -Value $SSLPort -Type DWord -Confirm:$False

            #Backup DH Cipher Suite and set Enabled:0 if SSL is enabled
            if (!(Test-Path $ICA_CIPHER_SUITE))
            {
                New-Item -Path $ICA_CIPHER_SUITE -Force | Out-Null
                New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
            }
            else
            {
                $back_enabled_exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -ErrorAction SilentlyContinue
                if ($back_enabled_exists -eq $null)
                {
                    $exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -ErrorAction SilentlyContinue
                    if ($exists -ne $null)
                    {
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value $exists.Enabled -PropertyType DWORD -Force | Out-Null
                        Set-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0
                    }
                    else
                    {
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
                    }
                }
            }

            # NOTE: This must be the last thing done when enabling SSL as the Citrix Service
            #       will use this as a signal to try and start the Citrix SSL Listener!!!!
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $ENABLE_SSL_KEY -Value 1 -Type DWord -Confirm:$False
        
            Write-Host "Registry keys set."
            Write-Host ""
            $RegistryKeysSet = $True

            $Store.Close()

            if ($RegistryKeysSet -and $ACLsSet -and $FirewallConfigured)
            {
                Write-Host "`nSSL to VDA enabled.`n"
            }
            else
            {
                Write-Host "`n"

                if (!$RegistryKeysSet)
                {
                    Write-Host "Configure registry manually or re-run the script to complete enabling SSL to VDA."
                }

                if (!$ACLsSet)
                {
                    Write-Host "Configure ACLs manually or re-run the script to complete enabling SSL to VDA."
                }
                    
                if (!$FirewallConfigured)
                {
                    Write-Host "Configure firewall manually or re-run the script to complete enabling SSL to VDA."
                }
            }
        }
    }

# SIG # Begin signature block
# MIInggYJKoZIhvcNAQcCoIInczCCJ28CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5cvNvmwrUJ34u4LDyYzqQBbV
# nhuggiDzMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGsDCCBJig
# AwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjEw
# NDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# Q29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zrPYGXcMW7
# xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHMgQM+TXAk
# ZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8IrgnQnAZaf6
# mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyCEUhSaN4Q
# vRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0p6MDDnSl
# rzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQakhCBj7A7
# CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0XLyTRSiD
# NipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960IHnWmZcy7
# 40hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2FKZbS110
# YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBHX8mBUHOF
# ECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q27IwyCQLM
# bDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwHAYDVR0g
# BBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIBADojRD2N
# CHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6jfCbVN7w6
# XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmImoqKwba9
# oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtfJqGVWEjV
# Gv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrxoj7bQ7gz
# yE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3LIU/Gs4m
# 6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx4b6cpwoG
# 1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9Oj9FpsTo
# FpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+ICw2/O/TO
# HnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug0wcCampA
# MEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5Vzu0nAPt
# hkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGtDCCBJygAwIBAgIQDcesVwX/
# IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYD
# VQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcN
# MzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oR
# jzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+Qd
# SKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRu
# QL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0
# Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQV
# ESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2
# qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF
# 0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgx
# CZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9X
# r/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7O
# gWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOC
# AV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esri
# kFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEw
# vb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8
# G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40
# y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCD
# A/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADV
# ZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4E
# Wj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpV
# fHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0
# c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7Oi
# gizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2
# rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz
# 0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFt
# cGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0z
# NjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1w
# IFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwX
# cGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepEr
# vUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY6
# 1HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4
# lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPb
# cNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6TH
# uOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLH
# gDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40
# h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xE
# ehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3
# ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEw
# DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYD
# VR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0
# YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs
# 0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+w
# tJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HSh
# TrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy
# 1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54t
# px5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwS
# BXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JK
# kYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL
# +66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+Own
# cVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP
# 66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++am
# i+r3Qrx5bIbY3TVzgiFI7Gq3zWcwggcBMIIE6aADAgECAhAHzZfnAsDIt0KaoNuH
# +3uWMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNp
# Z25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjUwNzAyMDAwMDAwWhcN
# MjYwNzAxMjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGEx
# GDAWBgNVBAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3Rl
# bXMsIEluYy4xDzANBgNVBAsTBkNpdHJpeDEdMBsGA1UEAxMUQ2l0cml4IFN5c3Rl
# bXMsIEluYy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCmEvno9b7o
# aUVsi4UqTYUzQHfvNan5EKsCmjYBPvmnM9eRRzc84bcRz14h6KShfQ4KWvLj8wdp
# hB6WzmqtRApOWwHvb6BY/9PrK3HQvygrV5pBpJ2WJia6PFVGCJ1/VCS8NBPqqWbU
# e900/g0w4U0DxATmLQ+xxbEJ4WFPXF2ADhVXw+BifTtT5G9Ybqf6D1P4RFQO6wvQ
# 1MfRPYIegtVrKNftzcpCos2MUh+SsiIpxvwEux+tj6yvxBmSPI67Freduz1YUWUd
# sHVF7cDuKtzjaY/7rRXHZtGPDFhuyzGte32H9pe4wIsGV0RxQtP2qZy01DylQv3G
# /2CwC7426PCEJ6mzJzSkccfAcZnk8ibJyT5k6OyVlQLtO6td9v7CO9vm+hRxV/Hb
# 6hwrK9R/EwSVeeRtXnXs3jV9xQNqkBaBIWwRogBH61mkukRuxww4nT/6lj3Z3VX2
# EttyftuAXt14CjRZsgRqWAfGCv0h3LKL39c2XpFAweeQji/eOQKvgTUCAwEAAaOC
# AgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQW
# BBT0ZYkyfWL8ATjiXwWpXupDaUIqLTA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcG
# CCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
# TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVT
# aWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQw
# OTZTSEEzODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25p
# bmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0B
# AQsFAAOCAgEAmhxj6VjqzEUvwqhTPC3f4JrcRXqB4GB+ofxuX2VPIcFMzsJE4AG3
# 4DzFXG4w/700zWSNFfa1+uZ7P0ZaWwhA/hVtWh5KxNUvJkY3DHrG571SDqH0vsCX
# YGjIDv3a8sqWUixjwu0moV6AcMAPKHniZ8E2qx44epxsu2AMUtW5BSHFvfEVOOnu
# G9ilusNlZYXqjgbHwOXtCtmxT3BR23nOnKSmlJ6tYcZdwN3N9bj5Hb9nABMgTmEu
# 3YPmm59iPb/UJcBNX+Ohkr4Edl+aOnHIQmXLixWWSYV5W0LBM7iO2RKkpjJBsQ/e
# ypUrdzx1YszN6B0CkY+gMdRpIOHgb2oHf7eAzZUsMUtQbekznoe4QmtqyNW8zsZQ
# +YqsCl7Sev0k91dPlIMCQEJNs3WCbiUhHfAWkLn9rIsoXyyuXoEITeoGCcwrOaHb
# 2pJ51LDMQ9z3enq/A6550DMSIi4k/1HNLuweA4CnGV7AqODQSxoFpr0uneUkrFvA
# UD5Ial08FvB98Fs2y4fIxPYDqzfX2E/jLV+epihSymXlujJA3liw9g2cljd7zupO
# 5sdggAB2arcbnJk+BGJ6nv6snmWIvCSfxoAvQCy+W5vKr3jAMz5/Mv0oOvY6U52A
# 2HTXOF7ny5heMpSishSmYAWtYX0Ye9bk+naXW7Ze6OP594PwTJU35e8xggX5MIIF
# 9QIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5
# NiBTSEEzODQgMjAyMSBDQTECEAfNl+cCwMi3Qpqg24f7e5YwCQYFKw4DAhoFAKCB
# qDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUS28WI3sUruIm3S3S+flbIqzI4dow
# SAYKKwYBBAGCNwIBDDE6MDigHIAaAEUAbgBhAGIAbABlAC0AVgBkAGEAUwBTAEyh
# GIAWaHR0cDovL3d3dy5jaXRyaXguY29tIDANBgkqhkiG9w0BAQEFAASCAYCP9/4N
# cFdXMVGBnnZMuoKmvSHx66dgFhbHT1EGR/B41agERxIQZfXU8KzgZbDyE12PCUHT
# auOgyAszQOGIDSgxXo8csvvl34fCSMRYlImWx2sLUUsATc1EgRRvTJ32npmUmnsd
# +KSScWVy36/rFupcq8IZiQ+HVoyo4HniwhUefXnQUh+meFNkIpD7uj/rByBiG5Gk
# bCBL9qul3O1EQvobxXmr1Rzn49hwdMf8HWiYwK7jhIrD4exaQy+Qfia9IrIezRNA
# TpD4bSR1TMifPQS7UUmJV7ObL4DG9qPEMUuyqNQbcHdy7NeieXhwmQLqbvO9OyRo
# zschoU7Ltrh1yAsTxL0ggcAdbKORaf2T8xM2c891Cs0P3pk3+qj1LqkW4LFqfwoF
# qP+gfcCnJrkUdEYOYjtuL3zXyScNHo6VcflYz3WhAzGwXblmYY54XuP7rQKM/wqz
# ssWYVVoN7qzRHmmcNiuELtX86cBiYEat0YEgeXYSPB3BN2VfOh9DRybDVYahggMm
# MIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43x
# BYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwODE0MTYxMzA4WjAvBgkqhkiG9w0BCQQx
# IgQg61tFyeOES0DKQTvaN7tsiw6Fqiadr4sfPougyeL6t/gwDQYJKoZIhvcNAQEB
# BQAEggIAnHuAYTvezm/6kACezr1Njv4t8AEziYNEBODajkSWVVXRDIa8VpsCdahh
# 2yjd+QmnzID2z5vK4swAAYeDN6snwbg77JaQvU+Q5uXyT8K8owNyPq/GKyWj8xef
# SNlt7YvDtKXg+v3TJrfIekYA8nEr2Zi1qJwI80FT6ZH5ZAZn1q5SPz8iPnx5edwD
# lOGFpZRhn6AvY9/qr4GoHN5N2BmlbIc1JPRVOKvUJ1XZgGaoRKUBJ2c0n45dzz5u
# ZHR7EWWTii+Jxv0HWPGSwSENsNDK/k1/F8aSALp1sfu/D/iIFYwQPRq2k2kA601J
# gtjHTF3vXbTITfg3ka2ksRmY8kY2sXpFFf+bLkP/Elr1UJpbwWB7CpySjIBJ57tg
# iKM/BHlhoT3JRbjTjrrJ628LuYFZiuiCG+jRfdkYOEgM1XRm4hx42gGFsuutsqaf
# boQO14LqvckENPYG6DtIkj72mxKj15EbgW9N64/0Vp/V7LfZ87c9wsqi8XsNIJDb
# 1gtnRuSkbCxeGRJFXEmX/GzDsrhUPJDeOG69KHO6Axk9fAYTzh52oNeawOw+iQXh
# EyOK5JNsU/IWbj/dRz0gW6WOThovtSQrY148P0tx0j8ua5fTymjOTBWS10dfAjDr
# iwCJvr+uroxTl/suk2droe5nXjUtXBW8mFns3oe5Igqzq49Jssw=
# SIG # End signature block
