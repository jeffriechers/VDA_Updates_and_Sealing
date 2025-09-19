# Things to do to customize these scripts for your environment

1. Modify Setup First\WarmupScheduledTask.ps1 and add/remove any apps you do or don't want to launch.  Also modify the timeout if your machine needs more time to load everything.
2. If you don't want Teams or Onedrive autoupdated with the Machine-Updates-Servers.ps1, and if you aren't using VDASSL and/or AutoLogon Warmup, just delete them from the HelperScripts subdirectory.
3. In the Setup First\VDA-SetupAutologonifusingWarmup.ps1 you can modify the variables at the top to adjust where you want the powershell and scheduled tasks to go on the c:\ drive, and also adjust the folder the scheduled tasks will go to in Task Scheduler.

# How to setup for use.

1. Place all these files on a network share, keeping the supplied folder struction, and adjust the files as listed above.
2. If you want to use Autologon Warmup, modify the Setup First\VDA-SetupAutologonifusingWarmup.ps1 and execute the script.
3. Reboot the machine for it to login as the AutoLogon user and setup it's profile.
4. If you want to use the SSLVDA function, run the CA-CreateVDASSLCATemplate.ps1 on your CA and validate it creates the appropriate template.
5. If you will be using this template with multiple machines, manually add the additional Maintenance Machines to the security of the template for Enrollment.
6. If you want to use a SAN certificate, instead of a wildcard certificate, use the DDC-CreateCSVofMachinesforSANinsteadofWildCard.ps1 to query a Delivery Group and create a csv of machine names.  Place this FQDN.csv into the HelperScripts sub directory.
7. Use choco to deploy any applications you want auto updated.  I recommend anything internet deployed, such as browsers, putty, winscp, etc.  If you don't setup choco it won't be run as part of the update process.
8. Modify the Machine-Updates-Servers.ps1 and Machine-Sealing-Servers.ps1 to include any additional steps for your environment that should be run every time updates and deployments are done.  For example:
    a. Antivirus updates and scans
    b. Software package deployments
    c. Removing entries from the registry or files/folders from the file system
    d. Generalization programs for installed software packages.

# How to use this automated patching process.
1. Boot up your maintenance machine in read/write mode.
2. Login with your Domain admin build account.
3. Go to your network share and right click on Machine-Updates-Servers.ps1 and Run with Powershell.  The following steps will run for you.
    a. update Teams and Onedrive if you leave the scripts in the HelperScripts folder.
    b. update Office 365 and earlier click-to-run office.
    c. launch choco to update any apps you deployed with choco, if you are using it.
    d. if you don't use choco it will look for firefox and chrome and use their local updaters'
    e. kick off windows update detection and download, but you still need to go to windows update to do the install.
    f. Creates a transcript of the process in your profile folder for you review of what happened.
4. After those scripts finish do whatever other modifications to the image you want.  Feel free to add automated processes to that script as well to guarantee it works.
5. Once you are ready to deploy, reboot your maintenance image.
6. Log back in with your Domain admin build account.
7. Go to your network share and right click on Machine-Sealing-Servers.ps1 and Run with Powershell.  The following steps will run for you.
    a. Remove FSLogix Preference settings from the registry if they exist. (Don't worry, they latest settings will come back later with gpupdate)
    b. If you are using uberagent, it will generalize the registry for fresh booted machines.
    c. Update machine group policy to cache the latest config into the image.
    d. Repair the registry key to allow screen savers on desktop sessions.
    e. Disable Teams 2.0 autoupdate
    f. Enable Websockets for Teams 2.0
    g. Stop and disable the windows update and BITS services
    h. Run a Windows Defender scan to hash everything on the image as scanned to prevent re-scans until changed.
    i. If WEM is installed refresh the local cache in case the WEM server is unavailable on machine boots.
    j. Disable any scheduled tasks in the root of the Task Scheduler folder (always put items you want to run in a subfolder)
    k. Remove any temp files and files from the all user desktop (comment out the Desktop line if you don't want to do that)
    l. Remove Arc Setup if it is installed (comment out if you are using Arc)
    m. Runs the CertificateGeneration.ps1 to create a new certificate and bind it to the Broker Services.
    n. Runs the SetupAutoLogon.ps1 script to generate a new local AutoLogon password, and enable Autologon for the next boot.
    o. Remove machine from Azure AD so hybrid registers correctly (make sure you have modified the WorkplaceJoin Scheduled Task to run at Startup along with at Log on)
    p. Shut down the machine so it can be captured.
8. You now can deploy this image to your non-persistent catalogs.

WARNING!!!!
If you boot up the sealed machine again, the machine will attempt to rejoin Azure AD.  You must always run the Sealing PowerShell Script to ensure the machine is ready for deployment and shutdown.


This makes your update process the following easily remembered steps.
1. Boot maintenance.
2. Wait for Autologon to finish, then login with your Domain build account.
3. Run the update script, wait for it to finish.
4. Run Windows Update.
5. Reboot.
6. Run Sealing Script.
7. Deploy once shutdown.