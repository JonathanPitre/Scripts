# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Get-MicrosoftDefenderUpdates
{
    <#
.SYNOPSIS
   Get-MicrosoftDefenderUpdates
.DESCRIPTION
   Get-MicrosoftDefenderUpdates downloads the latest Microsoft Defender updates into the specified path.
   Create a scheduled task that executes powershell.exe -Ex Bypass \<scriptpath>\Get-MicrosoftDefenderUpdates.ps1
.PARAMETER Path
    The path to store the Microsof Defender updates
.EXAMPLE
   Get-MicrosoftDefenderUpdates -Path C:\MicrosoftDefender
.NOTES
    Author: Alex Verboon & Jonathan Pitre
#>

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Path where Defender updates are stored
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $Path
    )

    Begin
    {
        Write-Host -Object "Downloading latest Microsoft Defender Updates..." -ForegroundColor Green
        $vdmpathbase = "$Path\{00000000-0000-0000-0000-"
        $vdmpathtime = Get-Date -Format "yMMddHHmmss"
        $vdmpath = $vdmpathbase + $vdmpathtime + '}'
        $vdmpackage = $vdmpath + '\mpam-fe.exe'
    }
    Process
    {
        Try
        {
            Write-Host -Object "Creating directory $vdmpath..." -ForegroundColor Green
            New-Item -ItemType Directory -Force -Path $vdmpath | Out-Null
        }
        Catch
        {
            Write-Host -Object "Error creating Microsoft Defender download path $Path!" -ForegroundColor Red
            Break
        }

        Try
        {
            Write-Host -Object "Downloading Microsoft Defender update package to $vdmpackage..." -ForegroundColor Green
            Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64' -UseBasicParsing -DisableKeepAlive -OutFile $vdmpackage
        }
        Catch
        {
            Write-Host -Object "Error downloading Microsoft Defender updates!" -ForegroundColor Red
        }

        Try
        {
            Write-Host -Object "Extracting $vdmpackage to $vdmpath..." -ForegroundColor Green
            Set-Location -Path $vdmpath
            .\mpam-fe.exe /x
            Get-ChildItem -Path $Path -Filter "mpam-fe.exe" -Recurse | Remove-Item -Force -Recurse
        }
        Catch
        {
            Write-Host -Object "Error extracting Microsoft Defender update content!" -ForegroundColor Red
        }

    }
    End
    {
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$MicrosoftDefenderUpdatesPath = "C:\MicrosoftDefender"
$ShareName = "MicrosoftDefender"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Create folder to store Microsoft Defender updates
If (-Not(Test-Path -Path $MicrosoftDefenderUpdatesPath))
{
    Write-Host -Object "Creating $MicrosoftDefenderUpdatesPath folder..." -ForegroundColor Green
    New-Item -ItemType Directory -Path $MicrosoftDefenderUpdatesPath -Force | Out-Null
}
Else
{
    Write-Host -Object "Folder $MicrosoftDefenderUpdatesPath already exist." -ForegroundColor Yellow
}

# Create SMB Share
$everyoneSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$everyoneName = $everyoneSID.Translate([System.Security.Principal.NTAccount]).Value

If (-Not(Get-SmbShare -Name $ShareName))
{
    Write-Host -Object "Creating SMB Share $ShareName..." -ForegroundColor Green
    New-SmbShare -Name $ShareName -Path $MicrosoftDefenderUpdatesPath -FullAccess $everyoneName | Out-Null
}
Else
{
    Write-Host -Object "SMB Share $ShareName already exist." -ForegroundColor Yellow
}

# Clean old Microsoft Defender Updates
Write-Host -Object "Cleaning old Microsoft Defender Updates..." -ForegroundColor Green
Get-ChildItem –Path $MicrosoftDefenderUpdatesPath -Recurse | Where-Object { ($_.LastWriteTime -lt (Get-Date).AddDays(-3)) } | Remove-Item -Recurse -Force

# Download latest Microsoft Defender Updates
Get-MicrosoftDefenderUpdates -Path $MicrosoftDefenderUpdatesPath

Write-Host -Object "Microsoft Defender Updates were succesfully downloaded!" -ForegroundColor Green