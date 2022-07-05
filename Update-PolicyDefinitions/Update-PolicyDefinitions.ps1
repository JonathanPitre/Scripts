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
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module })
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
            If (Find-Module -Name $Module | Where-Object { $_.Name -eq $Module })
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

Function Get-EvergreenAdmxVersion
{
    <#
    .SYNOPSIS
    Returns latest Version
    #>

    try
    {
        $GitHubRepo = "msfreaks/EvergreenAdmx"
        $Releases = "https://api.github.com/repos/$GitHubRepo/releases"
        Write-Verbose -Message "Determining latest EvergreenAdmx version..." -Verbose
        $Version = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
        return $Version
        }
    catch
    {
        Throw $_
    }
}

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

# Fix for EvergreenAdmx 2206.1, replace both Citrix Workspace App functions manually in file C:\Program Files\WindowsPowerShell\Scripts\EvergreenAdmx.ps1
function Get-CitrixWorkspaceAppAdmxOnline {
<#
    .SYNOPSIS
    Returns latest Version and Uri for Citrix Workspace App ADMX files
#>

    try {
        $ProgressPreference = 'SilentlyContinue'
        $url = "https://www.citrix.com/downloads/workspace-app/windows/workspace-app-for-windows-latest.html"
        # grab content
        $web = (Invoke-WebRequest -UseDefaultCredentials -Uri $url -UseBasicParsing -DisableKeepAlive -ErrorAction Ignore).RawContent
        # find line with ADMX download
        $str = ($web -split "`r`n" | Select-String -Pattern "_ADMX_")[0].ToString().Trim()
        # extract url from ADMX download string
        $URI = "https:$(((Select-String '(\/\/)([^\s,]+)(?=")' -Input $str).Matches.Value))"
        # grab version
        $VersionRegEx = "Version\: ((?:\d+\.)+(?:\d+)) \((.+)\)"
        $Version = ($web | Select-String -Pattern $VersionRegEx).Matches.Groups[1].Value
        $ShortVersion = ($web| Select-String -Pattern $VersionRegEx).Matches.Groups[2].Value
        # return evergreen object
        # return evergreen object
        return @{ Version = $Version; URI = $URI }
    }
    catch {
        Throw $_
    }
}

function Get-CitrixWorkspaceAppAdmx {
<#
    .SYNOPSIS
    Process Citrix Workspace App Admx files

    .PARAMETER Version
    Current Version present

    .PARAMETER PolicyStore
    Destination for the Admx files
#>

    param(
        [string]$Version,
        [string]$PolicyStore = $null,
        [string[]]$Languages = $null
    )

    $evergreen = Get-CitrixWorkspaceAppAdmxOnline
    $productname = "Citrix Workspace App"
    $productfolder = ""; if ($UseProductFolders) { $productfolder = "\$($productname)" }

    # see if this is a newer version
    if (-not $Version -or [version]$evergreen.Version -gt [version]$Version) {
        Write-Verbose "Found new version $($evergreen.Version) for '$($productname)'"

        # download and process
        $outfile = "$($WorkingDirectory)\downloads\$($evergreen.URI.Split("?")[0].Split("/")[-1])"
        try {
            # download
            $ProgressPreference = 'SilentlyContinue'
            Write-Verbose "Downloading '$($evergreen.URI)' to '$($outfile)'"
            Invoke-WebRequest -UseDefaultCredentials -Uri $evergreen.URI -UseBasicParsing -OutFile $outfile

            # extract
            Write-Verbose "Extracting '$($outfile)' to '$($env:TEMP)\citrixworkspaceapp'"
            Expand-Archive -Path $outfile -DestinationPath "$($env:TEMP)\citrixworkspaceapp" -Force

            # copy
            $sourceadmx = "$($env:TEMP)\citrixworkspaceapp\$($evergreen.URI.Split("/")[-2].Split("?")[0].SubString(0,$evergreen.URI.Split("/")[-2].Split("?")[0].IndexOf(".")))"
            $targetadmx = "$($WorkingDirectory)\admx$($productfolder)"
            Copy-Admx -SourceFolder $sourceadmx -TargetFolder $targetadmx -PolicyStore $PolicyStore -ProductName $productname -Languages $Languages

            # cleanup
            Remove-Item -Path "$($env:TEMP)\citrixworkspaceapp" -Recurse -Force

            return $evergreen
        }
        catch {
            Throw $_
        }
    } else {
        # version already processed
        return $null
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# Must read - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-or-windows-11-gpo-admx-which-one-to-use-for-your/ba-p/3063322
$Windows10Version = "21H2"
$Languages = @("en-US", "fr-FR")
$PolicyStore = "\\$envMachineADDomain\SYSVOL\$envMachineADDomain\Policies\PolicyDefinitions"
$IncludeProducts = @("Windows 10", "Microsoft Edge", "Microsoft OneDrive", "Microsoft Office", "FSLogix", "Adobe AcrobatReader DC", "BIS-F", "Citrix Workspace App", "Google Chrome", "Microsoft Desktop Optimization Pack", "Mozilla Firefox")
$WorkingDirectory = "C:\Scripts\EvergreenADMX"
$CustomPolicyStore = "$WorkingDirectory\custom"
$CitrixADMXVersion = "2206"
$CitrixADMXUrl = "https://raw.githubusercontent.com/JonathanPitre/Scripts/master/Update-PolicyDefinitions/Citrix_$($CitrixADMXVersion).zip"
$CitrixADMX = Split-Path -Path $CitrixADMXUrl -Leaf
#$ZoomADMXVersion = (Get-ZoomADMX).Version
$ZoomADMXVersion = "5.11.0"
#$ZoomADMXUrl = (Get-ZoomADMX).URI
$ZoomADMXUrl = "https://raw.githubusercontent.com/JonathanPitre/Scripts/master/Update-PolicyDefinitions/Zoom_$($ZoomADMXVersion).zip"
$ZoomADMX = Split-Path -Path $ZoomADMXUrl -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "Microsoft OneDrive")
$appUninstallString = ((Get-InstalledApplication -Name "Microsoft OneDrive").UninstallString).Split("/")[0]
$appUninstallParameters = "/uninstall /allusers"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Install EvergreenAdmx script - https://github.com/msfreaks/EvergreenAdmx
$EvergreenAdmxVersion = Get-EvergreenAdmxVersion
$ScriptInfo = Get-InstalledScript | Where-Object { $_.Name -eq "EvergreenADMX" }
[boolean]$isScriptInstalled = [boolean]$ScriptInfo
If ($isScriptInstalled)
{
    $ScriptVersion = ($ScriptInfo).Version
        If ([version]$EvergreenAdmxVersion -eq [version]2206.1)
    {
        # This version is buggy, Citrix Workspace App policdy definitions wont download properly!
        Write-Log -Message "This version is buggy, Citrix Workspace App policy definitions files wont download properly!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    If ([version]$EvergreenAdmxVersion -eq [version]$ScriptVersion)
    {
        Write-Log -Message "EvergreenAdmx script is already installed!" -Severity 1 -LogType CMTrace -WriteHost $True

    }
    Else
    {
        Write-Log -Message "Installing EvergreenAdmx script..." -Severity 1 -LogType CMTrace -WriteHost $True
        Install-Script -Name EvergreenAdmx -Force -Scope AllUsers
    }
}

New-Folder -Path $WorkingDirectory
New-Folder -Path $CustomPolicyStore
Set-Location -Path $WorkingDirectory

# Clean older files
If (Test-Path -Path "$WorkingDirectory\*")
{
    Write-Log -Message "Cleaning older files..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-File -Path "$WorkingDirectory\*" -Recurse -ContinueOnError $True
}

# Download custom policy definitions files
Write-Log -Message "Downloading custom Policy Definitions files..." -Severity 1 -LogType CMTrace -WriteHost $True
Invoke-WebRequest -UseBasicParsing -Uri $CitrixADMXUrl -OutFile $CitrixADMX
Invoke-WebRequest -UseBasicParsing -Uri $ZoomADMXUrl -OutFile $ZoomADMX

# Extract custom policy definitions files
Write-Log -Message "Extracting custom Policy Definitions files..." -Severity 1 -LogType CMTrace -WriteHost $True
Expand-Archive -Path $CitrixADMX -DestinationPath $CustomPolicyStore
Expand-Archive -Path $ZoomADMX -DestinationPath $CustomPolicyStore

# Cleanup
Remove-File -Path $WorkingDirectory\*.zip -ContinueOnError $True

# Remove older  Citrix Profile Management policy definitions files
Remove-Item -Path $PolicyStore -Include ctxprofile*.admx, ctxprofile*.adml -Recurse -Force

Write-Log -Message "Copying custom Policy Definitions files to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-Item -Path $CustomPolicyStore\* -Destination $PolicyStore -Recurse -Force

Set-Location -Path "$envProgramFiles\WindowsPowerShell\Scripts"

Write-Log -Message "Downloading and copying Policy Definitions files to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
.\EvergreenAdmx.ps1 -Windows10Version $Windows10Version -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts
Start-Sleep -Seconds 20

Write-Log -Message "Cleaning Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True

# Fix for WinStoreUI.admx error https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/winstoreui-conflict-with-windows-10-1151-admx-file
Remove-File -Path $PolicyStore WinStoreUI.adm* -Recurse -ContinueOnError $True

# Remove non policy definitions files
Remove-Item -Path $PolicyStore -Exclude *.admx, *.adml, $Languages[0], $Languages[1] -Recurse -Force

# Remove older Office policy definitions files
Remove-Item -Path $PolicyStore -Include *12*.admx, *12*.adml, *13*.admx, *13*.adml, *14*.admx, *14*.adml, *15*.admx, *15*.adml -Recurse -Force

# Remove older Adobe policy definitions files
Remove-Item -Path $PolicyStore -Include Acrobat2017.admx, Acrobat2017.adml, AcrobatReader2017.admx, AcrobatReader2017.adml, Acrobat2020.admx, Acrobat2020.adml, AcrobatReader2020.admx, AcrobatReader2020.adml -Recurse -Force

Write-Log -Message "Policy Definitions files were updated successfully!" -Severity 1 -LogType CMTrace -WriteHost $True