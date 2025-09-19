#OneDrive install and Update
$OneDriveDownloadURI = "https://go.microsoft.com/fwlink/p/?LinkID=2182910"
$OneDrivePath = Join-Path "$($env:TEMP)" "OneDriveSetup.exe"
$OnedriveInstalledVersion = "000"

#Start download 
Write-Output "Starting download latest OneDrive client"
(New-Object System.Net.WebClient).DownloadFile($OneDriveDownloadURI, $OneDrivePath)

#Check if downloaded version is newer than installed
$OnedriveDLVersion = Get-Item $OneDrivePath |Select-Object -ExpandProperty VersionInfo | Select-Object -Property ProductVersion | format-table -hidetableheaders | Out-String
$OnedriveInstalledVersion = get-package -Name "Microsoft Onedrive" | Select-Object -Property Version | format-table -hidetableheaders | Out-String

Write-Output "Downloaded Version"
Write-Output $OnedriveDLVersion.Trim()
Write-Output "Installed Version"
Write-Output $OnedriveInstalledVersion.Trim()

if ($OnedriveDLVersion.Trim() -gt $OnedriveInstalledVersion.Trim()) {
	#Onedrive Install or Update
	$OnedriveTitle = "Onedrive is out of date"
	$OnedriveInfo = "Do you want to update Onedrive?"
	$OnedriveOptions = $host.UI.PromptForChoice($OnedriveTitle , $OnedriveInfo , $Options,$defaultchoice)
	switch($OnedriveOptions)
		{
			0 {	
				Write-Output "Initialize OneDriveSetup with allusers argument..."
				$OneDriveSetup = (Join-Path "$($env:TEMP)" "OneDriveSetup.exe")
				Write-Output "Now time to install OneDrive in program folder $($OneDriveSetup) /allusers"
				$OneDriveproc = Start-Process -FilePath $OneDriveSetup -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
				$OneDriveproc.WaitForExit()
				Write-Output "OneDriveSetup exit code: $($OneDriveproc.ExitCode)"
			}
			1 {
				Write-Output "Skipping Upgrade as requested."
			}
		}
	}
	else {
		Write-Output "Installed version is newer than or equal to download, skipping install."
		}
