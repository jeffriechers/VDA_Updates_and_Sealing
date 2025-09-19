# VDA_Updates_and_Sealing
These are the latest versions of my Machine Updates and Sealing Scripts.  I have used these scripts for Windows 10 and later, and Windows 2019 and later.

# New Features Sept 19, 2025
1. Separate scripts for Single User Desktop images and Multi User Server images.  The Server Updates scripts are available now.  Desktop Scripts are coming soon.
2. Desktop Warmup process to create a local Autologon user account and application startup process to get wanted applications into memory before user logs in.  This account gets a new password on each image sealing process.  Also after the auto logon process is finished, the account gets a new random password, and gets disabled.  Also all scripts used are removed from that non-persistent image, so nothing leftover can be used nefariously.
3. VDA SSL automatic configuration script.  Works with your internal CA to generate a new certificate and key for your VDA session.  This certificate is only good for 3 months, and is replaced every time the sealing script is executed.  
    1. Will generate either a wildcard or SAN certificate based on your settings.  
    2. We use a slightly modified version of the Enable-VDASSL.ps1 script from 2507 to silently deploy the updated certificate to the VDA services.  If you wish to use the original, feel free to replace it with the same named PowerShell Script from the install ISO.
    3. Make sure to enable HDX over SSL on your Delivery Group to switch to SSL instead of 1494/2598.  ( Get-BrokerAccessPolicyRule -DesktopGroupName "YourDGHere" | Set-BrokerAccessPolicyRule -HdxSslEnabled $true)
    4. Only machines that trust your root CA will be able to access.  So load your root CA on your NetScaler if front-ending the sites.  And deploy your root CA to corporate devices.
    5. This adds another security layer.  If someone without your cert tries to access without hitting the NetScaler, they won't be able to connect.
4. Updated Teams install script to support the new --InstallTMA install switch.

