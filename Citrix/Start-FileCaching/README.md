# Reset-WEMCache

## About
Reset-WEMCache.ps1 is a powershell script to refresh Citrix Workspace Environment Agent cache.
I took the original script from the article [CTX247927](https://support.citrix.com/article/CTX247927) and made it better.

Reset-WEMCache.xml is a schedule task that will trigger the powershell script Reset-WEMCache.ps1 when Event ID 0 'Cache sync failed with error: SyncFailed' occurs.

## Supported Powershell Versions
This has been tested with Powershell 5.1. Other versions may work but have not been tested, YMMV.

## Installation
* Download the file Reset-WEMCache.ps1 and copy it to you're master image in the folder **C:\Scripts**.
* Download the file Reset-WEMCache.xml and launch **Task Scheduler**.
* Right-click on the **Task Scheduler Library** and click **Import**.
* Select the file **Reset-WEMCache.xml** and press **OK**.

## Usage
Refresh the Citrix WEM Cache on the local computer:
```powershell
.\Reset-WEMCache.ps1
```

Refresh the Citrix WEM Cache on remote computer:
```powershell
Invoke-Command -ComputerName COMPUTER01 -FilePath C:\Scripts\Reset-WEMCache.ps1
```