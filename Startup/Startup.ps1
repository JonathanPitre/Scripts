#Requires -Version 5.1

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ErrorActionPreference = "SilentlyContinue"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Optimize-ScheduledTasks()
{

    Write-Title -Text "Scheduled Tasks tweaks"
    Write-Section -Text "Disabling Scheduled Tasks"

    $DisableScheduledTasks = @(
        "\Microsoft\Office\Office Automatic Updates 2.0"
        "\Microsoft\Office\Office ClickToRun Service Monitor"
        "\Microsoft\Office\Office Feature Updates"
        "\Microsoft\Office\Office Feature Updates Logon"
        "\Microsoft\Office\Office Serviceability Manager"
        "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"
        "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"
        #"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
        #"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    )

    ForEach ($ScheduledTask in $DisableScheduledTasks)
    {
        If (Get-ScheduledTaskInfo -TaskName $ScheduledTask)
        {

            Write-Host "$($EnableStatus[0]) the $ScheduledTask Task..."
            Invoke-Expression "$($Commands[0])"

        }
        Else
        {

            Write-Warning "[?][TaskScheduler] $ScheduledTask was not found."

        }
    }
    Write-Section -Text "Enabling Scheduled Tasks"

    $EnableScheduledTasks = @(
        #"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"            # It's about the Recovery before starting Windows, with Diagnostic tools and Troubleshooting when your PC isn't healthy, need this ON.
        #"\Microsoft\Windows\Windows Error Reporting\QueueReporting"     # Windows Error Reporting event, needed to improve compatibility with your hardware
    )

    ForEach ($ScheduledTask in $EnableScheduledTasks)
    {
        If (Get-ScheduledTaskInfo -TaskName $ScheduledTask)
        {

            Write-Host "[+][TaskScheduler] Enabling the $ScheduledTask Task..."
            Get-ScheduledTask -TaskName "$ScheduledTask".Split("\")[-1] | Where-Object State -Like "Disabled" | Enable-ScheduledTask

        }
        Else
        {

            Write-Warning "[?][TaskScheduler] $ScheduledTask was not found."

        }
    }
}

function Detect-CitrixDiskMode ()
{
    Write-Host "Detect the Citrix Disk Mode 'Shared' or 'Private'"
    If ( Test-Path -Path $Personality )
    {
        If ( Select-String -Path $Personality -Pattern "$DiskMode=Shared")
        {
            $DiskMode = "ReadOnly"
            Write-Host "The current Disk Mode is SHARED (Read-Only)"

        }
        ElseIf ( Select-String -Path $Personality -Pattern "$DiskMode=Private")
        {
            $DiskMode = "ReadWrite"
            Write-Host "The current Disk Mode is Private (Read/Write)"
        }
    }
    Else
    {
        Write-Host "The current machine is not a Citrix PVS nor MCS device."
    }
    Return $DiskMode
}

function Optimize-WindowsDefenderATPForNonPersistentMachines ()
{
    # Some organizations, use non-persistent virtual machines for their users
    # A non-persistent machine is created from a master image
    # Every new machine instance has a different name and these machines are available via pool
    # Every user logon \ reboot returns machine to image state loosing all user data
    # This script provides a solution for onboarding such machines
    # We would like to have sense unique id per machine name in organization
    # For that purpose, senseGuid is set prior to onboarding
    # The guid is created deterministically based on combination of orgId and machine name
    # This script is intended to be integrated in golden image startup
    Param (
        [string]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ -PathType ùContainerù })]
        $onboardingPackageLocation = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    )

    Add-Type @'
using System;
using System.Diagnostics;
using System.Diagnostics.Tracing;
namespace Sense
{
	[EventData(Name = "Onboard")]
	public struct Onboard
	{
		public string Message { get; set; }
	}
	public class Trace
	{
		public static EventSourceOptions TelemetryCriticalOption = new EventSourceOptions(){Level = EventLevel.Informational, Keywords = (EventKeywords)0x0000800000000000, Tags = (EventTags)0x0200000};
		public void WriteMessage(string message)
		{
			es.Write("OnboardNonPersistentMachine", TelemetryCriticalOption, new Onboard {Message = message});
		}
		private static readonly string[] telemetryTraits = { "ETW_GROUP", "{5ECB0BAC-B930-47F5-A8A4-E8253529EDB7}" };
		private EventSource es = new EventSource("Microsoft.Windows.Sense.Client.VDI",EventSourceSettings.EtwSelfDescribingEventFormat,telemetryTraits);
	}
}
'@

    $logger = New-Object -TypeName Sense.Trace;

    function Trace([string] $message)
    {
        $logger.WriteMessage($message)
    }

    function CreateGuidFromString([string]$str)
    {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
        $sha1CryptoServiceProvider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
        $hashedBytes = $sha1CryptoServiceProvider.ComputeHash($bytes)
        [System.Array]::Resize([ref]$hashedBytes, 16);
        return New-Object System.Guid -ArgumentList @(, $hashedBytes)
    }

    function Get-ComputerName
    {
        return [system.environment]::MachineName
    }

    function Get-OrgIdFromOnboardingScript($onboardingScript)
    {
        return Select-String -Path $onboardingScript -Pattern "orgId\\\\\\`":\\\\\\`"([^\\]+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }
    }

    function Test-Administrator
    {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

    if ((Test-Administrator) -eq $false)
    {
        Write-Host -ForegroundColor Red "The script should be executed with admin previliges"
        Trace("Script wasn't executed as admin");
        Exit 1;
    }

    Write-Host "Locating onboarding script under:" $onboardingPackageLocation

    $onboardingScript = [System.IO.Path]::Combine($onboardingPackageLocation, "WindowsDefenderATPOnboardingScript.cmd");
    if (![System.IO.File]::Exists($onboardingScript))
    {
        Write-Host -ForegroundColor Red "Onboarding script not found:" $onboardingScript
        Trace("Onboarding script not found")
        Exit 2;
    }

    $orgId = Get-OrgIdFromOnboardingScript($onboardingScript);
    if ([string]::IsNullOrEmpty($orgId))
    {
        Write-Host -ForegroundColor Red "Could not deduct organization id from onboarding script:" $onboardingScript
        Trace("Could not deduct organization id from onboarding script")
        Exit 3;
    }
    Write-Host "Identified organization id:" $orgId

    $computerName = GetComputerName;
    Write-Host "Identified computer name:" $computerName

    $id = $orgId + "_" + $computerName;
    $senseGuid = CreateGuidFromString($id);
    Write-Host "Generated senseGuid:" $senseGuid


    $senseGuidRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
    $senseGuidValueName = "senseGuid";
    $populatedSenseGuid = [Microsoft.Win32.Registry]::GetValue($senseGuidRegPath, $senseGuidValueName, $null)
    if ($populatedSenseGuid)
    {
        Write-Host -ForegroundColor Red "SenseGuid already populated:" $populatedSenseGuid
        Trace("SenseGuid already populated")
        Exit 4;
    }
    [Microsoft.Win32.Registry]::SetValue($senseGuidRegPath, $senseGuidValueName, $senseGuid)
    Write-Host "SenseGuid was set:" $senseGuid

    $vdiTagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"
    $vdiTagValueName = "VDI";
    $vdiTag = "NonPersistent";
    [Microsoft.Win32.Registry]::SetValue($vdiTagRegPath, $vdiTagValueName, $vdiTag)
    Write-Host "VDI tag was set:" $vdiTag

    Write-Host "Starting onboarding"
    &$onboardingScript
    if ($LASTEXITCODE -ne 0)
    {
        Write-Host -ForegroundColor Red "Failed to onboard sense service from: $($onboardingScript). Exit code: $($LASTEXITCODE). To troubleshoot, please read https://technet.microsoft.com/en-us/itpro/windows/keep-secure/troubleshoot-onboarding-windows-defender-advanced-threat-protection"
        Trace("Failed to onboard sense service. LASTEXITCODE=" + $LASTEXITCODE)
        Exit 5;
    }

    Write-Host -ForegroundColor Green "Onboarding completed successfully"
    Trace("SUCCESS")
}

function Main()
{

    $EnableStatus = @(
        "[-][TaskScheduler] Disabling",
        "[+][TaskScheduler] Enabling"
    )
    $Commands = @(
        { Get-ScheduledTask -TaskName "$ScheduledTask".Split("\")[-1] | Where-Object State -Like "R*" | Disable-ScheduledTask }, # R* = Ready/Running Tasks
        { Get-ScheduledTask -TaskName "$ScheduledTask".Split("\")[-1] | Where-Object State -Like "Disabled" | Enable-ScheduledTask }
    )

    if (($Revert))
    {
        Write-Warning "[<][TaskScheduler] Reverting: $Revert."

        $EnableStatus = @(
            "[<][TaskScheduler] Re-Enabling",
            "[<][TaskScheduler] Re-Disabling"
        )
        $Commands = @(
            { Get-ScheduledTask -TaskName "$ScheduledTask".Split("\")[-1] | Where-Object State -Like "Disabled" | Enable-ScheduledTask },
            { Get-ScheduledTask -TaskName "$ScheduledTask".Split("\")[-1] | Where-Object State -Like "R*" | Disable-ScheduledTask } # R* = Ready/Running Tasks
        )

    }

    Optimize-ScheduledTasks # Disable Scheduled Tasks that causes slowdowns
    Optimize-WindowsDefenderATPForNonPersistentMachines

}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$HypervisorManufacturer = (Get-WmiObject -Query 'select * from Win32_ComputerSystem').Manufacturer
$SendBufferSize = (Get-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size").DisplayValue
$Personality = "$env:SystemDrive\Personality.ini"
$DiskMode = Detect-CitrixDiskMode

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If (($HypervisorManufacturer -like "Microsoft Corporation") -and ($SendBufferSize -ne "4MB"))
{
    # https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool/blob/main/Windows_VDOT.ps1
    Write-Host "Configuring Network Adapter Buffer Size" -ForegroundColor Cyan
    Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB -NoRestart
}

#Azure AD join

# Read HKLM:\SOFTWARE\Citrix\MachineIdentityServiceAgent).CleanOnBoot = 1

# Install print drivers if image in read-only mode
# See https://github.com/kaspersmjohansen/Install-Printer-Drivers/blob/main/Install-PrinterDriver.ps1

# Disable unnecessary Scheduled Taks
Main

# Force GPupdate, useful for shitty domain
Invoke-GPUpdate -Force

# Restart FSLogix Service
Restart-Service frxsvc -Name -Force
Restart-Service frxccds -Name -Force

# Launch process if image is in read-only mode
# See https://github.com/JamesKindon/Citrix/blob/master/PreFetchStartApps.ps1
# and https://github.com/kaspersmjohansen/AutoLogon-Script/blob/main/Set-AutoLogon.ps1