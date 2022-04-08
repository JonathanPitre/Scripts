# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Download-MicrosoftDefenderUpdates
{
	<#
.SYNOPSIS
   Download-MicrosoftDefenderUpdates
.DESCRIPTION
   Download-DefenderUpdates downloads the latest defender updates into the specified path.
   Create a scheduled task that executes Powershell -ExecutionPolicy Bypass \<scriptpath>\Download-MicrosoftDefenderUpdates.ps1
.PARAMETER Path
    The path to store the Microsof Defender updates
.EXAMPLE
   Download-MicrosoftDefenderUpdates
.EXAMPLE
   Download-MicrosoftDefenderUpdates
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
		$Path = "C:\Scripts\MicrosoftDefender"
	)

	Begin
 {
		Write-Verbose -Message "Downloading Microsoft Defender updates..." -Verbose
		$vdmpathbase = "$Path\{00000000-0000-0000-0000-"
		$vdmpathtime = Get-Date -format "yMMddHHmmss"
		$vdmpath = $vdmpathbase + $vdmpathtime + '}'
		$vdmpackage = $vdmpath + '\mpam-fe.exe'
	}
	Process
 {
		Try
		{
			Write-Verbose -Message "Creating directory $vdmpath..." -Verbose
			New-Item -ItemType Directory -Force -Path $vdmpath | Out-Null
		}
		Catch
		{
			Write-Error -Message "Error creating Microsoft Defender download path $Path"
			Break
		}

		Try
		{
			Write-Verbose -Message "Downloading Microsoft Defender update package to $vdmpackage..." -Verbose
			Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64' -OutFile $vdmpackage
		}
		Catch
		{
			Write-Error -Message "Error downloading Microsoft Defender updates"
		}

		Try
		{
			Write-Verbose -Message "Extracting $vdmpackage to $vdmpath..." -Verbose
			Set-Location -Path $vdmpath
			.\mpam-fe.exe /x
		}
		Catch
		{
			Write-Error -Message "Error extracting Microsoft Defender update content"
		}

	}
	End
 {
	}
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$MicrosoftDefenderUpdatesPath = "C:\Scripts\MicrosoftDefender"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Verbose -Message "Cleaning old Microsoft Defender Updates ..." -Verbose
Get-ChildItem –Path $MicrosoftDefenderUpdatesPath -Recurse | Where-Object {($_.CreationTime -lt (Get-Date).AddDays(-3))} | Remove-Item -Recurse -Force
Download-MicrosoftDefenderUpdates -Path $MicrosoftDefenderUpdatesPath