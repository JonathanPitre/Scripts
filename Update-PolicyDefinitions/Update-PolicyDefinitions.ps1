# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$Modules = @("PSADT") # Modules list

Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
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
Function Get-CitrixVDAServer
{
    <#
    .SYNOPSIS
    Returns latest Version and Uri for Citrix VDA Server
    #>

    try
    {
        $DownloadURL = "https://raw.githubusercontent.com/ryancbutler/Citrix_DL_Scrapper/main/ctx_dls.json"
        # Grab content
        $DownloadText = (Invoke-WebRequest -Uri $DownloadURL -DisableKeepAlive -UseBasicParsing).Content
        $RegEx = "(https.+VDAServerSetup_(\d+).exe)"
        # Grab version
        $Version = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[2].Value
        $URL = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[1].Value
        # return evergreen object
        if ($Version -and $URL)
        {
            [PSCustomObject]@{
                Version = $Version
                URI     = $URL
            }
        }
    }
    catch
    {
        Throw $_
    }
}

Function Get-ZoomADMX
{
    <#
    .SYNOPSIS
    Returns latest Version and Uri for Zoom ADMX files
    #>

    try
    {
        $DownloadURL = "https://support.zoom.us/hc/en-us/articles/360039100051-Mass-deploying-with-Group-Policy-Objects"
        # Grab content
        $DownloadText = (Invoke-WebRequest -Uri $DownloadURL -DisableKeepAlive -UseBasicParsing).Links
        # Find ADMX download
        $URL = (($DownloadText| Where-Object {$_.href -like "*msi-templates*.zip"})[-1]).href
        # Grab version
        $Version = ($URL.Split("/")[-1] | Select-String -Pattern "(\d+(\.\d+){1,4})" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }).ToString()

        # Return evergreen object
        if ($Version -and $URL)
        {
            [PSCustomObject]@{
                Version = $Version
                URI     = $URL
            }
        }
    }
    catch
    {
        Throw $_
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# Must read - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-or-windows-11-gpo-admx-which-one-to-use-for-your/ba-p/3063322
$Windows10Version = "21H2"
$Languages = @("en-US", "fr-FR")
$PolicyStore = "\\$envMachineADDomain\SYSVOL\$envMachineADDomain\Policies\PolicyDefinitions"
$IncludeProducts = @("Windows 10", "Microsoft Edge", "Microsoft OneDrive", "Microsoft Office", "FSLogix", "Adobe AcrobatReader DC", "BIS-F", "Citrix Workspace App", "Google Chrome", "Microsoft Desktop Optimization Pack", "Mozilla Firefox")
$WorkingDirectory = "C:\Install\EvergreenADMX"
$CustomPolicyStore = "$WorkingDirectory\custom"
$CitrixADMXVersion = (Get-CitrixVDAServer).Version
$CitrixADMXUrl = "https://github.com/JonathanPitre/Scripts/raw/master/Update-PolicyDefinitions/Citrix_$($CitrixADMXVersion).zip"
$CitrixADMX = Split-Path -Path $CitrixADMXUrl -Leaf
#$ZoomADMXVersion = (Get-ZoomADMX).Version
$ZoomADMXVersion = "5.10.0"
#$ZoomADMXUrl = (Get-ZoomADMX).URI
$ZoomADMXUrl = "https://github.com/JonathanPitre/Scripts/raw/master/Update-PolicyDefinitions/Zoom_$($ZoomADMXVersion).zip"
$ZoomADMX = Split-Path -Path $ZoomADMXUrl -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "Microsoft OneDrive")
$appUninstallString = ((Get-InstalledApplication -Name "Microsoft OneDrive").UninstallString).Split("/")[0]
$appUninstallParameters = "/uninstall /allusers"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Install EvergreenAdmx script - https://github.com/msfreaks/EvergreenAdmx
Install-Script -Name EvergreenAdmx -Force -Scope AllUsers
New-Folder -Path $WorkingDirectory
New-Folder -Path $CustomPolicyStore
Set-Location -Path $WorkingDirectory

# Uninstall Microsoft OneDrive if already installed
If ($IsAppInstalled)
{
    Write-Log -Message "Uninstalling Microsoft OneDrive..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path $appUninstallString -Parameters $appUninstallParameters
}

# Clean older files
If (Test-Path -Path "$WorkingDirectory\*")
{
    Write-Log -Message "Cleaning older files..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-File -Path "$WorkingDirectory\*" -Recurse -ContinueOnError $True
}

# Download custom ADMX files
Write-Log -Message "Downloading custom ADMX files..." -Severity 1 -LogType CMTrace -WriteHost $True
Invoke-WebRequest -UseBasicParsing -Uri $CitrixADMXUrl -OutFile $CitrixADMX
Invoke-WebRequest -UseBasicParsing -Uri $ZoomADMXUrl -OutFile $ZoomADMX

# Extract custom ADMX files
Write-Log -Message "Extracting custom ADMX files..." -Severity 1 -LogType CMTrace -WriteHost $True
Expand-Archive -Path $CitrixADMX -DestinationPath $CustomPolicyStore
Expand-Archive -Path $ZoomADMX -DestinationPath $CustomPolicyStore

# Cleanup
Remove-File -Path $WorkingDirectory\*.zip -ContinueOnError $True

Write-Log -Message "Copying custom ADMX files to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-Item -Path $CustomPolicyStore\* -Destination $PolicyStore -Recurse

Set-Location -Path "$envProgramFiles\WindowsPowerShell\Scripts"
Write-Log -Message "Downloading and copying ADMX files to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
.\EvergreenAdmx.ps1 -Windows10Version $Windows10Version -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts
Start-Sleep -Seconds 20

# Uninstall Microsoft OneDrive
Get-Process -Name "OneDrive" | Stop-Process -Force
Write-Log -Message "Uninstalling Microsoft OneDrive..." -Severity 1 -LogType CMTrace -WriteHost $True
$appUninstallString = ((Get-InstalledApplication -Name "Microsoft OneDrive").UninstallString).Split("/")[0]
Execute-Process -Path $appUninstallString -Parameters $appUninstallParameters

Write-Log -Message "Cleaning Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
# Fix for WinStoreUI.admx error https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/winstoreui-conflict-with-windows-10-1151-admx-file
Remove-File -Path $PolicyStore WinStoreUI.adm* -Recurse -ContinueOnError $True
# Remove non admx files
Remove-Item -Path $PolicyStore -Exclude *.admx, *.adml, $Languages[0], $Languages[1] -Recurse -Force

# Remove older Office admx files
Remove-Item -Path $PolicyStore -Include *14*.admx, *14*.adml, *15*.admx, *15*.adml -Recurse -Force

Write-Log -Message "ADMX files were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True