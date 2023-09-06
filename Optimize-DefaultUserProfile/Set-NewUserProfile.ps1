# Set-NewUserProfile.ps1 - (C)2023 Jonathan Pitre

# Hide powershell prompt
Add-Type -Name win -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

#Requires -Version 5.1

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("ActiveDirectory") # Modules list

Function Get-ScriptPath
{
    <#
    .SYNOPSIS
        Get-ScriptPath returns the path of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    Begin
    {
        Remove-Variable appScriptPath
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code
        ElseIf ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") { Split-Path -Path $My$MyInvocation.MyCommand.Source } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Path } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE
        ElseIf ($MyInvocation.PSScriptRoot) { $MyInvocation.PSScriptRoot } # Windows PowerShell 3.0+
        ElseIf ($MyInvocation.MyCommand.Path) { Split-Path -Path $MyInvocation.MyCommand.Path -Parent } # Windows PowerShell
        Else
        {
            Write-Host -Object "Unable to resolve script's file path!" -ForegroundColor Red
            Exit 1
        }
    }
}

Function Initialize-Module
{
    <#
    .SYNOPSIS
        Initialize-Module install and import modules from PowerShell Galllery.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Module
    )
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If ([boolean](Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }))
        {
            Import-Module -Name $Module -Force -Global -DisableNameChecking
            Write-Host -Object "Module $Module was imported." -ForegroundColor Green
        }
        Else
        {
            Write-Host -Object "Module $Module was not found!" -ForegroundColor Red
        }
    }
}

[string]$appScriptPath = Get-ScriptPath # Get the current script path

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Get user AD properties
$userProperties = Get-ADUser -Filter { SamAccountName -like

If ($null -ne $userProperties)
{
    # Detect Microsoft Outlook signature location
    If (Test-Path -Path "$($UserProperties.ProfilePath)AppData\Roaming\Microsoft\Signatures")
    {
        $OutlookSignature = "$($UserProperties.ProfilePath)AppData\Roaming\Microsoft\Signatures"
    }

    # Copy and assignMicrosoft Outlook signature
    If (Test-Path -Path $OutlookSignature\*.htm)
    {
        Copy-Item -Path $OutlookSignature -Destination "$env:APPDATA\Microsoft" -Force -Recurse
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Setup" -Name "First-Run" -Force
        $SigPath = (Get-ChildItem -Path "$env:APPDATA\Microsoft\Signatures\*.htm" | Select-Object -ExpandProperty Name).Split(".")[0]
        New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings" -Value "default value" -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings" -Name "NewSignature" -Value $SigPath -PropertyType "String" -Force
        #New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings" -Name "ReplySignature" -Value $SigPath -PropertyType "String" -Force
    }
    Else
    {
        Write-Host -Object "No Microsoft Outlook signatures was found." -ForegroundColor Green
    }
}

# Launch Microsoft Outlook
[bool]$isOutlookRunning = [bool](Get-Process -Name 'Outlook' | Where-Object { $_.SI -eq (Get-Process -PID $PID).SessionId })
$regKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE\'
$exe = (Get-ItemProperty -Path $regKey).'(default)'
If ($isOutlookRunning)
{
    Write-Host -Object "Microsoft Outlook is already running. Process will be killed." -ForegroundColor Yellow
    Stop-Process -Name 'Outlook' -Force
    Write-Host -Object "Starting Microsoft Outlook application..." -ForegroundColor Green
    Start-Process -FilePath "$exe" -ArgumentList "/resetfoldernames /recycle" -WindowStyle Minimized
}
ElseIf (Test-Path -Path $exe)
{
    Write-Host -Object "Starting Microsoft Outlook application..." -ForegroundColor Green
    Start-Process -FilePath "$exe" -ArgumentList "/resetfoldernames /recycle" -WindowStyle Minimized
}
Else
{
    Throw "Microsoft Outlook executable was not found."
}

# On Server 2019, fix Microsoft ADD Broker plugin before launching Microsoft OneDrive
[bool]$isOneDriveRunning = [bool](Get-Process -Name 'OneDrive' | Where-Object { $_.SI -eq (Get-Process -PID $PID).SessionId })
$exe = "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe"
If ($isOneDriveRunning)
{
    Write-Host -Object "Microsoft OneDrive is already running. Process will be killed." -ForegroundColor Yellow
    Stop-Process -Name 'OneDrive' -Force
    Write-Host -Object "Starting Microsoft OneDrive..." -ForegroundColor Green
    Start-Process -FilePath $exe -ArgumentList "/background /setautostart" -WindowStyle Minimized
}
ElseIf (Test-Path -Path "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe")
{
    Write-Host -Object "Starting Microsoft OneDrive..." -ForegroundColor Green
    Start-Process -FilePath $exe -ArgumentList "/background /setautostart" -WindowStyle Minimized
}
Else
{
    Throw "Path to Microsoft OneDrive executable was not found."
}

# Launch Microsoft Teams twice to avoid the notification for the new meeting experience
[bool]$isTeamsRunning = [bool](Get-Process -Name 'Teams' | Where-Object { $_.SI -eq (Get-Process -PID $PID).SessionId })
$exe = "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe"
If (($isTeamsRunning) -and (Test-Path -Path $exe))
{
    Write-Host -Object 'Teams is already running. Process will be killed.' -ForegroundColor Yellow
    Stop-Process -Name 'Teams' -Force
    Start-Sleep -Seconds 2
    Remove-Item -Path "$env:APPDATA\Microsoft\Teams\hooks.json"
    Write-Host -Object "Starting Microsoft Teams..." -ForegroundColor Green
    Start-Process -FilePath $exe -WindowStyle Minimized | Out-Null
}
ElseIf (Test-Path -Path $exe)
{
    Write-Host -Object "Starting Microsoft Teams..." -ForegroundColor Green
    Start-Process -FilePath $exe -WindowStyle Minimized | Out-Null
    Start-Sleep -Seconds 30
    Stop-Process -Name 'Teams' -Force
    Start-Sleep -Seconds 2
    Write-Host -Object "Starting Microsoft Teams..." -ForegroundColor Green
    Start-Process -FilePath $exe -WindowStyle Minimized | Out-Null
}
Else
{
    Throw "Microsoft Teams executable was not found."
}

<# Backup Mozilla Firefox bookmarks
New-Item -Path "$env:USERPROFILE\Documents\Firefox" -ItemType Directory -Force
If (Test-Path -Path "$($UserProperties.ProfilePath)AppData\Roaming\Mozilla\Firefox")
{
    $FirefoxBookmarks = "$($UserProperties.ProfilePath)AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite"
    Copy-Item -Path $FirefoxBookmarks -Destination "$env:USERPROFILE\Documents\Firefox\places.sqlite" -Force -Recurse
}
#>

# Cleanup useless Mozilla Firefox Start Menu shortcuts
If (Test-Path -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" )
{
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk" -Force
}
ElseIf (Test-Path -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Navigation privée de Firefox.lnk")
{
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Navigation privée de Firefox.lnk" -Force
}

#endregion