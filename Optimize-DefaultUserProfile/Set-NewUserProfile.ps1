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

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Get user AD properties
$UserProperties = Get-ADUser -Filter { SamAccountName -like $env:USERNAME } -Properties SamAccountName, ProfilePath | Select-Object SamAccountName, ProfilePath

If ($null -ne $UserProperties)
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
        Write-Verbose -Message "No Microsoft Outlook signatures was found."
    }
}

# Launch Microsoft Outlook
If (Get-Process | Where-Object Name -EQ Outlook)
{
    Write-Verbose -Message 'Outlook is already running. No action needed.'
}
Else
{
    $Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE\'

    If (-Not(Test-Path -Path $Key))
    {
        Throw "Microsoft Outlook executable was not found."

    }
    Else
    {
        $exe = (Get-ItemProperty -Path $Key).'(default)'
        If (Test-Path -Path $exe)
        {
            Write-Verbose -Message "Starting Microsoft Outlook application..."
            Start-Process -FilePath $exe -ArgumentList "/resetfoldernames /recycle"
        }
        Else
        {
            Throw "Microsoft Outlook executable was not found."
        }
    }
}

# Launch Microsoft Teams twice to avoid the notification for the new meeting experience
$exe = "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe"
If ((Get-Process | Where-Object Name -EQ Teams) -and (Test-Path -Path $exe))
{
    Write-Verbose -Message 'Teams is already running. Process will be killed.'
    Stop-Process -Name Teams -Force
    Start-Sleep -Seconds 2
    Write-Verbose -Message "Starting Microsoft Teams..."
    Start-Process -FilePath $exe
}
Else
{
    If (-Not(Test-Path -Path $exe))
    {
        Throw "Microsoft Teams executable was not found."

    }
    Else
    {
        Write-Verbose -Message "Starting Microsoft Teams..."
        Start-Process -FilePath $exe
        Start-Sleep -Seconds 5
        Stop-Process -Name Teams -Force
        Start-Sleep -Seconds 2
        Write-Verbose -Message "Starting Microsoft Teams..."
        Start-Process -FilePath $exe
    }
}


<# Fix Microsoft ADD Broker plugin before launching Microsoft OneDrive
If (Get-Process | Where-Object name -eq OneDrive)
{
    Write-Verbose -Message "Microsoft OneDrive is already running. Process will be killed."
    Stop-Process -Name OneDrive -Force
}

If (-Not(Test-Path -Path "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe"))
{
    Throw "Path to Microsoft OneDrive executable was not found."
}
Else
{
    Write-Verbose -Message "Starting Microsoft OneDrive..."
    Start-Process -FilePath "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/background"
}
#>

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

If (Test-Path -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Navigation privée de Firefox.lnk" ) -Force
{
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Navigation privée de Firefox.lnk"
}

#endregion