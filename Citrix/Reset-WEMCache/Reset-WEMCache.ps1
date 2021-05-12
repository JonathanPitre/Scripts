#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Reset Citrix WEM Agent cache.

.DESCRIPTION
This script is used to troubleshoot Citrix WEM Agent refresh issues.

The following command can be used to generate the issue:
Write-EventLog -LogName 'WEM Agent Service' -Source 'WEM Agent Service' -EventId 0 -EntryType Error -Message "Cache sync failed with error: SyncFailed"

.EXAMPLE
PS> .\Reset-WEMCache.ps1

.EXAMPLE
PS> Invoke-Command -ComputerName COMPUTER01 -FilePath C:\Scripts\Reset-WEMCache.ps1

.LINK
https://support.citrix.com/article/CTX247927

.NOTES
Version:        1.0
Author:         Jonathan Pitre
Creation Date:  5/12/2021
Purpose/Change: Initial release
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ErrorActionPreference = "SilentlyContinue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$LocalDatabaseDir = '${env:CommonProgramFiles(x86)}\Citrix\Workspace Environment Management Agent\Local Databases'
$LocalDatabases = Get-ChildItem -Name "$LocalDatabaseDir\*.db"
$AlternateDatabasesDir = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host" -Name "AgentCacheAlternateLocation")
If ($AlternateDatabasesDir)
{$AlternateDatabases = Get-ChildItem -Name $AlternateDatabasesDir\*.db
}

[string]$Process = (Get-Process -Name VUEMUIAgent | Select-Object -ExpandProperty ProcessName)
$Services = "Netlogon","Citrix WEM Agent Host Service"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Stop the VUEMUIAgent.exe process if it is running
if ($Process)
{
   Stop-Process -Name $Process -Force
   Write-Verbose -Message "VUEMUIAgent has stopped." -Verbose
} else
{
   Write-Verbose -Message "VUEMUIAgent is not running." -Verbose
}

# Stop Citrix WEM Agent Host Service and Netlogon services
foreach ($Service in $Services)
{
   Stop-Service -Name $Service -Force
   Write-Verbose -Message "$Service has stopped." -Verbose
}
Start-Sleep -Seconds 3

# Delete the Citrix WEM Agent Cache
If ($LocalDatabases)
{
   Remove-Item -Path $LocalDatabasesDir\*.db -Force
   Write-Verbose -Message "Local databases have been deleted." -Verbose
}

If ($AlternateDatabases)
{
   Remove-Item -Path $AlternateDatabasesDir\*.db -Force
   Write-Verbose -Message "Alternate databases have been deleted." -Verbose
}
Start-Sleep -Seconds 3

# Start Netlogon Service which will start Citrix WEM Agent Host Service
foreach ($Service in $Services)
{
   Start-Service -Name $Service
   Write-Verbose -Message "$Service is running." -Verbose
}
Start-Sleep -Seconds 3

# Refresh Citrix WEM Agent Cache
$WEMAgent = '${env:CommonProgramFiles(x86)}\Citrix\Workspace Environment Management Agent\VUEMUIAgent.exe'
Start-Process -FilePath "${env:CommonProgramFiles(x86)}\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" -RefreshCache
Start-Process -FilePath $WEMAgent
Write-Verbose -Message "Citrix WEM cache was reinitialized." -Verbose

# Write event log
Write-EventLog -LogName 'WEM Agent Service' -Source 'WEM Agent Service' -EventId 0 -EntryType Information -Message 'Successfully reinitialize WEM cache.'