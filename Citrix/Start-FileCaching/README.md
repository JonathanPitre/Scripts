# Start-FileCaching

## About
Start-FileCaching.ps1 is a powershell script to cache dll and exe files for non persistent environment like Citrix PVS/MCS IO.
I took the original script from Citrix consulting and improved it.

**Start-FileCaching.xml** is a schedule task that will trigger the powershell script Start-FileCaching.ps1 at machine startup.

## Supported Powershell Versions
This has been tested with Powershell 5.1. Other versions may work but have not been tested, YMMV.

## Installation
* Download the file Start-FileCaching.ps1 and copy it to you're master image in the folder **C:\Scripts**.
* Download the file Start-FileCaching.xml and launch **Task Scheduler**.
* Right-click on the **Task Scheduler Library** and click **Import**.
* Select the file **Start-FileCaching.xml** and press **OK**.

## Usage
Cache dll and exe of you're local computer:
```powershell
.\Start-FileCaching.ps1
```