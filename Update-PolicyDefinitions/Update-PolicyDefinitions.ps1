# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1
#Requires -RunAsAdministrator

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
$Modules = @("PSADT") # Modules list

Function Get-ScriptPath
{
    <#
    .SYNOPSIS
        Get-ScriptPath returns the path of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([String])]
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

Function Get-ScriptName
{
    <#
    .SYNOPSIS
        Get-ScriptName returns the name of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param()
    Begin
    {
        Remove-Variable appScriptName
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path -Leaf } # Visual Studio Code Host
        ElseIf ($psEXE) { [System.Diagnotics.Process]::GetCurrentProcess.Name } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Name } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { $psISE.CurrentFile.DisplayName.Trim("*") } # Windows PowerShell ISE
        ElseIf ($MyInvocation.MyCommand.Name) { $MyInvocation.MyCommand.Name } # Windows PowerShell
        Else
        {
            Write-Host -Object "Uanble to resolve script's file name!" -ForegroundColor Red
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
        [String]$Module
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
        If ( [Boolean](Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) )

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

[String]$appScriptPath = Get-ScriptPath # Get the current script path
[String]$appScriptName = Get-ScriptName # Get the current script name

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions

Function Get-EvergreenAdmxVersion
{
    <#
    .SYNOPSIS
        Returns latest EvergreenAdmx version
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

Function Resolve-Uri
{
    <#
    .SYNOPSIS
        Resolves a URI and also returns the filename and last modified date if found.

    .DESCRIPTION
        Resolves a URI and also returns the filename and last modified date if found.

    .NOTES
        Site: https://packageology.com
        Author: Dan Gough
        Twitter: @packageologist

    .LINK
        https://github.com/DanGough/Nevergreen

    .PARAMETER Uri
        The URI resolve. Accepts an array of strings or pipeline input.

    .PARAMETER UserAgent
        Optional parameter to provide a user agent for Invoke-WebRequest to use. Examples are:

        Googlebot: 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        Microsoft Edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'

    .EXAMPLE
        Resolve-Uri -Uri 'http://somewhere.com/somefile.exe'

        Description:
        Returns the absolute redirected URI, filename and last modified date.
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^(http|https)://')]
        [Alias('Url')]
        [String[]] $Uri,
        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [String] $UserAgent
    )

    begin
    {

    }

    process
    {

        foreach ($UriToResolve in $Uri)
        {

            try
            {

                $ParamHash = @{
                    Uri              = $UriToResolve
                    Method           = 'Head'
                    UseBasicParsing  = $True
                    DisableKeepAlive = $True
                    ErrorAction      = 'Stop'
                }

                if ($UserAgent)
                {
                    $ParamHash.UserAgent = $UserAgent
                }

                $Response = Invoke-WebRequest @ParamHash

                if ($IsCoreCLR)
                {
                    $ResolvedUri = $Response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
                }
                else
                {
                    $ResolvedUri = $Response.BaseResponse.ResponseUri.AbsoluteUri
                }

                Write-Verbose "$($MyInvocation.MyCommand): URI resolved to: $ResolvedUri"

                #PowerShell 7 returns each header value as single unit arrays instead of strings which messes with the -match operator coming up, so use Select-Object:
                $ContentDisposition = $Response.Headers.'Content-Disposition' | Select-Object -First 1

                if ($ContentDisposition -match 'filename="?([^\\/:\*\?"<>\|]+)')
                {
                    $FileName = $matches[1]
                    Write-Verbose "$($MyInvocation.MyCommand): Content-Disposition header found: $ContentDisposition"
                    Write-Verbose "$($MyInvocation.MyCommand): File name determined from Content-Disposition header: $FileName"
                }
                else
                {
                    $Slug = [uri]::UnescapeDataString($ResolvedUri.Split('?')[0].Split('/')[-1])
                    if ($Slug -match '^[^\\/:\*\?"<>\|]+\.[^\\/:\*\?"<>\|]+$')
                    {
                        Write-Verbose "$($MyInvocation.MyCommand): URI slug is a valid file name: $FileName"
                        $FileName = $Slug
                    }
                    else
                    {
                        $FileName = $null
                    }
                }

                try
                {
                    $LastModified = [DateTime]($Response.Headers.'Last-Modified' | Select-Object -First 1)
                    Write-Verbose "$($MyInvocation.MyCommand): Last modified date: $LastModified"
                }
                catch
                {
                    Write-Verbose "$($MyInvocation.MyCommand): Unable to parse date from last modified header: $($Response.Headers.'Last-Modified')"
                    $LastModified = $null
                }

            }
            catch
            {
                Throw "$($MyInvocation.MyCommand): Unable to resolve URI: $($_.Exception.Message)"
            }

            if ($ResolvedUri)
            {
                [PSCustomObject]@{
                    Uri          = $ResolvedUri
                    FileName     = $FileName
                    LastModified = $LastModified
                }
            }

        }
    }

    end
    {
    }

}

Function Download-GitHubRepository
{
    Param(
        [Parameter(Mandatory = $True)]
        [string] $Name,

        [Parameter(Mandatory = $True)]
        [string] $Author,

        [Parameter(Mandatory = $False)]
        [string] $Branch = "master",

        [Parameter(Mandatory = $False)]
        [string] $Location = "$DownloadsDirectory"
    )

    # Force to create a zip file
    $ZipFile = "$location\$Name.zip"
    $null = New-Item $ZipFile -ItemType File -Force

    $RepositoryZipUrl = "https://api.github.com/repos/$Author/$Name/zipball/$Branch"

    # Download
    Invoke-RestMethod -Uri $RepositoryZipUrl -OutFile $ZipFile -UseBasicParsing

    # Extract
    Expand-Archive -Path $ZipFile -DestinationPath $location -Force

    # Remove the zip file
    #Remove-Item -Path $ZipFile -Force
}

Function Get-CitrixAdmx
{
    <#
    .SYNOPSIS
        Download latest version of the Citrix Admx files
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateLength(4, 4)]
        [string]$Version = "2303"
    )
    $productName = "Citrix"

    try
    {
        $url = "https://raw.githubusercontent.com/JonathanPitre/Scripts/master/Update-PolicyDefinitions/Citrix_$($CitrixADMXVersion).zip"
        $zip = Split-Path -Path $url -Leaf

        # download
        Write-Verbose -Message "Downloading $productName Policy Definitions files to '$($DownloadsDirectory)...'" -Verbose
        Invoke-WebRequest -Uri $url -UseBasicParsing -DisableKeepAlive -OutFile "$($DownloadsDirectory)\$zip"

        # extract
        Write-Verbose -Message "Extracting $productName Policy Definitions files to '$($CustomPolicyStore)...'" -Verbose
        Expand-Archive -Path "$($DownloadsDirectory)\$zip" -DestinationPath "$CustomPolicyStore" -Force
    }
    catch
    {
        Throw $_
    }
}

Function Get-MicrosoftAVDAdmx
{
    <#
    .SYNOPSIS
        Download latest version of the Microsoft AVD Admx files
    #>

    $productName = "Microsoft AVD"

    try
    {
        $url = Resolve-Uri -Uri "https://aka.ms/avdgpo" | Select-Object -ExpandProperty Uri
        $outFile = "$($DownloadsDirectory)\AVDGPTemplate.cab"
        $zipFile = "$($DownloadsDirectory)\AVDGPTemplate.zip"

        # download
        Write-Verbose -Message "Downloading $productName Policy Definitions files to '$($DownloadsDirectory)...'" -Verbose
        Invoke-WebRequest -Uri $url -UseBasicParsing -DisableKeepAlive -OutFile $outFile

        # extract
        Write-Verbose -Message "Extracting $productName Policy Definitions files to '$($CustomPolicyStore)...'" -Verbose
        $null = (expand "$($outFile)" -F:* "$DownloadsDirectory" $zipFile)
        Expand-Archive -Path $zipFile -DestinationPath "$CustomPolicyStore" -Force

        # cleanup
        Remove-Item -Path $outFile -Force
    }
    catch
    {
        Throw $_
    }
}

Function Get-MicrosoftDefenderATPAdmx
{
    <#
    .SYNOPSIS
        Download latest version of the Microsoft Defender ATP Admx files
    #>

    $productName = "Microsoft Defender ATP"

    try
    {
        $url = "https://raw.githubusercontent.com/JonathanPitre/Scripts/master/Update-PolicyDefinitions/MicrosoftDefenderATP.zip"
        $zip = Split-Path -Path $url -Leaf

        # download
        Write-Verbose -Message "Downloading $productName Policy Definitions files to '$($DownloadsDirectory)...'" -Verbose
        Invoke-WebRequest -Uri $url -UseBasicParsing -DisableKeepAlive -OutFile "$($DownloadsDirectory)\$zip"

        # extract
        Write-Verbose -Message "Extracting $productName Policy Definitions files to '$($CustomPolicyStore)...'" -Verbose
        Expand-Archive -Path "$($DownloadsDirectory)\$zip" -DestinationPath "$CustomPolicyStore" -Force
    }
    catch
    {
        Throw $_
    }
}

Function Get-SchannelAdmx
{
    <#
    .SYNOPSIS
        Download latest version of the Schannel Admx files

    .PARAMETER Languages
        Optionally provide an array of languages to process. Entries must be in 'xy-XY' format.
        If omitted the script will process 'en-US'.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateSet('en-US', 'fr-FR', 'de-DE', ignorecase = $False)]
        [array]$Languages = @("en-US")
    )

    $productName = "Schannel"

    try
    {
        $gitHubRepoAuthor = "Crosse"
        $gitHubRepoName = "SchannelGroupPolicy"
        $gitHubRepoBranch = "master"

        # download
        Write-Verbose -Message "Downloading $productName Policy Definitions files to '$($DownloadsDirectory)...'" -Verbose
        Download-GitHubRepository -Author $gitHubRepoAuthor -Name $gitHubRepoName -Branch $gitHubRepoBranch

        # copy
        Write-Verbose -Message "Copying $productName Policy Definitions files to '$($CustomPolicyStore)...'" -Verbose
        $outFolder = Get-ChildItem -Path $DownloadsDirectory -Include "$gitHubRepoAuthor-$gitHubRepoName-*" -Recurse | Select-Object -ExpandProperty Name
        Copy-Item -Path "$DownloadsDirectory\$outFolder\template\*" -Destination "$CustomPolicyStore" -Recurse -Force -Verbose

        # cleanup
        Remove-Item -Path "$($DownloadsDirectory)\$outFolder" -Recurse -Force
    }
    catch
    {
        Throw $_
    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#region Declarations

# Must read - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-or-windows-11-gpo-admx-which-one-to-use-for-your/ba-p/3063322
[string]$WindowsBuild = "22H2"
[array]$Languages = @("en-US", "fr-FR")
[string]$PolicyStore = "\\$envMachineADDomain\SYSVOL\$envMachineADDomain\Policies\PolicyDefinitions"
[array]$IncludeProducts = @("Windows 10", "Microsoft Edge", "Microsoft OneDrive", "Microsoft Office", "FSLogix", "Adobe Acrobat", "Adobe Reader", "Citrix Workspace App", "Google Chrome", "Microsoft Desktop Optimization Pack", "Mozilla Firefox", "Zoom Desktop Client", "Custom Policy Store")
[string]$WorkingDirectory = "C:\Scripts\EvergreenADMX"
[string]$DownloadsDirectory = "$WorkingDirectory\downloads"
[string]$CustomPolicyStore = "$WorkingDirectory\custom admx"
[string]$CitrixADMXVersion = "2303"
[boolean]$IsOneDriveInstalled = [boolean](Get-InstalledApplication -Name "Microsoft OneDrive")

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Install EvergreenAdmx script - https://github.com/msfreaks/EvergreenAdmx
$EvergreenAdmxVersion = Get-EvergreenAdmxVersion

$ScriptInfo = Get-InstalledScript | Where-Object { $_.Name -eq "EvergreenADMX" }
[boolean]$isScriptInstalled = [boolean]$ScriptInfo
If ($isScriptInstalled)
{
    $ScriptVersion = ($ScriptInfo).Version
    If ([version]$EvergreenAdmxVersion -gt [version]$ScriptVersion)
    {
        Write-Log -Message "Installing latest EvergreenAdmx script..." -Severity 1 -LogType CMTrace -WriteHost $True
        Install-Script -Name EvergreenAdmx -Force -Scope AllUsers
    }
    Else
    {
        Write-Log -Message "Latest version of EvergreenAdmx script is already installed!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
}
Else
{
    Write-Log -Message "Installing latest EvergreenAdmx script..." -Severity 1 -LogType CMTrace -WriteHost $True
    Install-Script -Name EvergreenAdmx -Force -Scope AllUsers
}

# Clean older files
If (Test-Path -Path "$WorkingDirectory\*")
{
    Write-Log -Message "Cleaning older files..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-Folder -Path "$WorkingDirectory\downloads" -ContinueOnError $True
}

# Create folders structure
New-Folder -Path $WorkingDirectory
New-Folder -Path $DownloadsDirectory
New-Folder -Path $CustomPolicyStore
Set-Location -Path $WorkingDirectory
If (-Not(Test-Path $PolicyStore)) { New-Folder -Path $PolicyStore }

# Remove older Citrix Profile Management policy definitions files
Remove-Item -Path $PolicyStore -Include ctxprofile*.admx, ctxprofile*.adml -Recurse -Force

# Download custom Policy Definitions files
Write-Log -Message "Downloading custom Policy Definitions files..." -Severity 1 -LogType CMTrace -WriteHost $True
# Citrix
Get-CitrixAdmx -Version "2303"
# Microsoft AVD
Get-MicrosoftAVDAdmx
# Microsoft Defender ATP
Get-MicrosoftDefenderATPAdmx
# SChannel
Get-SchannelAdmx

# Copy Policy Definitions files to Central Policy Store
Set-Location -Path "$envProgramFiles\WindowsPowerShell\Scripts"

$Windows10 = New-Object System.Management.Automation.Host.ChoiceDescription '&Windows 10', 'Windows 10'
$Windows11 = New-Object System.Management.Automation.Host.ChoiceDescription '&Windows 11', 'Windows 11'
$options = [System.Management.Automation.Host.ChoiceDescription[]]($Windows10, $Windows11)
$title = 'Operating System'
$message = "Which Operating System are you using for most of your endpoints ?"
$result = $host.ui.PromptForChoice($title, $message, $options, 0)
If (($result -eq 0) -and ($IsOneDriveInstalled))
{
    $choice = "Windows 10"
    Write-Log -Message "Downloading and copying Policy Definitions files for $choice to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
    .\EvergreenAdmx.ps1 -Windows10Version $WindowsBuild -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts -PreferLocalOneDrive
}
ElseIf (($result -eq 1) -and ($IsOneDriveInstalled))
{
    $choice = "Windows 11"
    Write-Log -Message "Downloading and copying Policy Definitions files for $choice to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
    $IncludeProducts = ($IncludeProducts).Replace("Windows 10", "Windows 11")
    .\EvergreenAdmx.ps1 -Windows11Version $WindowsBuild -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts -PreferLocalOneDrive
}
ElseIf (($result -eq 0) -and (-Not($IsOneDriveInstalled)))
{
    $choice = "Windows 10"
    Write-Log -Message "Downloading and copying Policy Definitions files for $choice to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
    .\EvergreenAdmx.ps1 -Windows10Version $WindowsBuild -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts
}
ElseIf (($result -eq 1) -and (-Not($IsOneDriveInstalled)))
{
    $choice = "Windows 11"
    Write-Log -Message "Downloading and copying Policy Definitions files for $choice to Central Policy Store..." -Severity 1 -LogType CMTrace -WriteHost $True
    .\EvergreenAdmx.ps1 -Windows10Version $WindowsBuild -WorkingDirectory $WorkingDirectory -PolicyStore $PolicyStore -Languages $Languages -UseProductFolders -CustomPolicyStore $CustomPolicyStore -Include $IncludeProducts
}
Else
{
    $choice = "Try again"
}

# Cleanup Central Policy Store
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

#endregion