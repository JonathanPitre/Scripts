# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

# Hide powershell prompt, comment if using WEM External Task
Add-Type -Name win -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$Modules = @("") # Modules list

Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        If ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        If ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else
        {
            Write-Host -Object "Cannot resolve script file's path" -ForegroundColor Red
            Exit 1
        }
    }
    Catch
    {
        Write-Host -Object "Caught Exception: $($Error[0].Exception.Message)" -ForegroundColor Red
        Exit 2
    }
}

Function Initialize-Module
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Module
    )
    Write-Host -Object  "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object {$_.Name -eq $Module})
    {
        Write-Host -Object  "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module})
        {
            $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
            $ModuleVersion = (Find-Module -Name $Module).Version
            $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
            $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
            If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion)
            {
                Update-Module -Name $Module -Force
                Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
                Write-Host -Object "Module $Module was updated." -ForegroundColor Green
            }
            Import-Module -Name $Module -Force -Global -DisableNameChecking
            Write-Host -Object "Module $Module was imported." -ForegroundColor Green
        }
        Else
        {
            # Install Nuget
            If (-not(Get-PackageProvider -ListAvailable -Name NuGet))
            {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
                Write-Host -Object "Package provider NuGet was installed." -ForegroundColor Green
            }

            # Add the Powershell Gallery as trusted repository
            If ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted")
            {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                Write-Host -Object "PowerShell Gallery is now a trusted repository." -ForegroundColor Green
            }

            # Update PowerShellGet
            $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
            $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
            If ($PSGetVersion -gt $InstalledPSGetVersion)
            {
                Install-PackageProvider -Name PowerShellGet -Force
                Write-Host -Object "PowerShellGet Gallery was updated." -ForegroundColor Green
            }

            # If module is not imported, not available on disk, but is in online gallery then install and import
            If (Find-Module -Name $Module | Where-Object {$_.Name -eq $Module})
            {
                # Install and import module
                Install-Module -Name $Module -AllowClobber -Force -Scope AllUsers
                Import-Module -Name $Module -Force -Global -DisableNameChecking
                Write-Host -Object "Module $Module was installed and imported." -ForegroundColor Green
            }
            Else
            {
                # If the module is not imported, not available and not in the online gallery then abort
                Write-Host -Object "Module $Module was not imported, not available and not in an online gallery, exiting." -ForegroundColor Red
                EXIT 1
            }
        }
    }
}

# Get the current script directory
$appScriptDirectory = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# FSLogix should already show the app based on AD group and loading the Active Directory module is slowing down the login process
# Remote Server Administration Tools must be installed - https://adamtheautomator.com/powershell-import-active-directory
# or https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges
#Import-Module ActiveDirectory
#Import-Module .\Microsoft.ActiveDirectory.Management.dll
#$User = "$env:UserName"
#$AD_Group_AdobeAcrobat = "App-AdobeAcrobat" # Change to your AD group name
# Import Microsoft OneDrive Status Module  - https://docs.microsoft.com/en-us/archive/blogs/rodneyviana/powershell-cmdlet-to-check-onedrive-for-business-or-onedrive-personal-status
$Dsregcmd = New-Object PSObject ; Dsregcmd /status | Where-Object {$_ -match ' : '}|ForEach-Object {$Item = $_.Trim() -split '\s:\s'; $Dsregcmd|Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $Item[1]}
$AADState = ($Dsregcmd).AzureAdJoined
$AzureAdPrt = ($Dsregcmd).AzureAdPrt

If (Test-Path -Path "$env:ProgramFiles\WindowsPowershell\Modules\ODStatus\OneDriveLib.dll")
{
    Import-Module -Name "$env:ProgramFiles\WindowsPowershell\Modules\ODStatus\OneDriveLib.dll"
    Write-Host -Object "Microsoft OneDrive Status Module was imported." -ForegroundColor Green
}
Else
{
    Write-Host -Object "Microsoft OneDrive Status Module is not currently installed!" -ForegroundColor Red
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Set-Location -Path "$appScriptDirectory"

# Hybrid Azure AD join must be done at startup and user login
If (($AADState -ne "YES") -or ($AzureAdPrt -ne "YES"))
{
    Write-Host -Object "The device is not AzureAD Joigned!" -ForegroundColor Yellow
    Start-Process -FilePath "$env:windir\System32\dsregcmd.exe" -ArgumentList "/join" -WindowStyle Hidden
}

# Fix Office 365 SSO on Windows Server 2019 - https://discussions.citrix.com/topic/403721-office-365-pro-plus-shared-activation-password-screen-not-able-to-select/page/9
# https://docs.microsoft.com/en-us/office365/troubleshoot/authentication/automatic-authentication-fails
$AADPluginState = (Get-AppxPackage Microsoft.AAD.BrokerPlugin).Status
If ($AADPluginState -ne "Ok")
{
    Add-AppxPackage -Register "$env:windir\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Appxmanifest.xml" -DisableDevelopmentMode -ForceApplicationShutdown
}


# Launch OneDrive only after Microsoft AAD Broker Plugin is repaired
If ((Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") -and ($null -eq (Get-Process -Name OneDrive)))
{
    Write-Host -Object  "Starting Microsoft OneDrive..." -ForegroundColor Green
    Start-Process -FilePath "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/background" -WindowStyle Hidden
}
Else
{
    Write-Host -Object "Microsoft OneDrive is already started." -ForegroundColor Green
}


# Set User File Associations - https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user
If (Test-Path -Path "$appScriptDirectory\SetUserFTA\SetUserFTA.exe")
{

    # Set File Associations for Adobe Reader or Adobe Acrobat
    #If ((Get-ADUser $User -Properties memberof).memberof -like "CN=$AD_Group_AdobeAcrobat*" -and (Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"))

    <#
    If ((Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe") -or (Test-Path -Path "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe"))
    {
        .\SetUserFTA\SetUserFTA.exe "$appScriptDirectory\Adobe Acrobat.txt"
    }
    ElseIf (Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
    {
        .\SetUserFTA\SetUserFTA.exe "$appScriptDirectory\Adobe Acrobat Reader.txt"
    }
    ElseIf (Test-Path -Path "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    {
        .\SetUserFTA\SetUserFTA.exe "$appScriptDirectory\Microsoft Edge.txt" #Must test if file exist!
    }
    #>

    # Set File Associations for Project Libre or Microsoft Project
    If ((Test-Path -Path "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINPROJ.EXE") -or (Test-Path -Path "$env:ProgramFiles\Microsoft Office\root\Office16\WINPROJ.EXE"))
    {
        .\SetUserFTA\SetUserFTA.exe "$appScriptDirectory\Microsoft Project.txt" #Must test if file exist!
    }
    ElseIf (Test-Path -Path "$env:ProgramFiles\ProjectLibre\ProjectLibre.exe")
    {
        .\SetUserFTA\SetUserFTA.exe "$appScriptDirectory\ProjectLibre.txt" #Must test if file exist!
    }

}
Else
{
    Write-Host -Object "SetUserFTA must be downloaded first!" -ForegroundColor Red
}

# Wait for OneDrive sync to be Up To Date
$OneDriveState = (Get-ODStatus).StatusString
DO
{
    Start-Sleep -Seconds 1
    $OneDriveState = (Get-ODStatus).StatusString
    Write-Host -Object "Microsoft OneDrive is still syncing..." -ForegroundColor Yellow
} Until (($OneDriveState -eq "À jour") -or ($OneDriveState -eq "Up To Date"))
Write-Host -Object "Microsoft OneDrive sync is completed." -ForegroundColor Green

# Fix OneDrive blank icons by forcing all the files on the user desktop to "keep always on your device"
If (Test-Path -Path "$env:OneDriveCommercial\Desktop")
{
    Remove-Item -Path "$env:OneDriveCommercial\Desktop\Documents -*.lnk" -Force
    Remove-Item -Path "$env:OneDriveCommercial\Desktop\Se déconnecter -*.lnk" -Force
    Get-ChildItem "$env:OneDriveCommercial\Desktop\*.lnk" -Force -Recurse | ForEach-Object {attrib.exe $_.fullname +P +S}
    Write-Host -Object "Microsoft OneDrive blank icons were fixed." -ForegroundColor Green
}
If (Test-Path -Path "$env:OneDriveCommercial\Bureau")
{
    Remove-Item -Path "$env:OneDriveCommercial\Bureau\Documents -*.lnk" -Force
    Remove-Item -Path "$env:OneDriveCommercial\Bureau\Se déconnecter -*.lnk" -Force
    Get-ChildItem "$env:OneDriveCommercial\Bureau\*.lnk" -Force -Recurse | ForEach-Object {attrib.exe $_.fullname +P +S}
    Write-Host -Object "Microsoft OneDrive blank icons were fixed." -ForegroundColor Green
}