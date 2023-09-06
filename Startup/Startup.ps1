# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations

$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions

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

Function Get-CitrixDiskMode
{
    <#
    .SYNOPSIS
        Get Citrix disk mode.
    .DESCRIPTION
        Get Citrix disk mode.
    .PARAMETER Personality
        Specifies Citrix personality file location.
    .EXAMPLE
        Get-CitrixDiskMode
    .INPUTS
        None.
    .OUTPUTS
        None.
    .NOTES
        Created by Jonathan Pitre.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        $Personality = (Get-ChildItem -Path "$env:SystemDrive\*Personality.ini" | Select-Object -ExpandProperty FullName)
    )

    Begin
    {
        [string]$script:citrixDiskMode = $null
    }
    Process
    {
        If (Test-Path -Path $Personality)
        {
            If (Select-String -Path $Personality -Pattern "$DiskMode=Shared")
            {
                Write-Host -Object "The current Citrix Disk Mode is Shared (Read-Only)." -ForegroundColor Red -Verbose
                Write-Log -Message "The current Citrix Disk Mode is Shared (Read-Only)." -Severity 4 -LogType CMTrace -WriteHost $True
                Write-Host -Object "This script can only be run in Private (Read/Write) mode!" -ForegroundColor Red -Verbose
                [string]$script:citrixDiskMode = "ReadOnly"
                Exit
            }
            ElseIf (Select-String -Path $Personality -Pattern "$DiskMode=Private")
            {
                Write-Host -Object "The current Citrix Disk Mode is Private (Read/Write)." -ForegroundColor Green -Verbose
                Write-Log -Message "The current Citrix Disk Mode is Private (Read/Write)." -Severity 1 -LogType CMTrace
                [string]$script:citrixDiskMode = "ReadWrite"
            }
        }
        Else
        {
            Write-Host -Object "The current machine is not running Citrix PVS nor MCS." -ForegroundColor Red -Verbose
        }

    }
    End
    {
    }
}

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

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$HypervisorManufacturer = (Get-WmiObject -Query 'select * from Win32_ComputerSystem').Manufacturer
$SendBufferSize = (Get-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size").DisplayValue
$citrixDiskMode = Get-CitrixDiskMode

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If (($HypervisorManufacturer -like "Microsoft Corporation") -and ($SendBufferSize -ne "4MB"))
{
    # https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool/blob/main/Windows_VDOT.ps1
    Write-Host "Configuring Network Adapter Buffer Size" -ForegroundColor Cyan
    Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB -NoRestart
}

# For Hybrid Azure AD joined machine catalogs, create a scheduled task in the master VM that executes the following commands at system startup using SYSTEM account.
# Azure AD join - https://docs.citrix.com/en-us/citrix-daas/install-configure/machine-identities/hybrid-azure-active-directory-joined.html
# https://support.citrix.com/article/CTX475187/windows-11-vda-machines-stuck-at-initializing-for-azure-ad-or-hybrid-azure-ad
$VirtualDesktopKeyPath = 'HKLM:\Software\AzureAD\VirtualDesktop'
$WorkplaceJoinKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin'
$MaxCount = 60

For ($count = 1; $count -le $MaxCount; $count++)
{
    If ((Test-Path -Path $VirtualDesktopKeyPath) -eq $true)
    {
        $provider = (Get-Item -Path $VirtualDesktopKeyPath).GetValue("Provider", $null)
        If ($provider -eq 'Citrix')
        {
            break;
        }

        If ($provider -eq 1)
        {
            Set-ItemProperty -Path $VirtualDesktopKeyPath -Name "Provider" -Value "Citrix" -Force
            Set-ItemProperty -Path $WorkplaceJoinKeyPath -Name "autoWorkplaceJoin" -Value 1 -Force
            Start-Sleep 5
            dsregcmd /join
            break
        }
    }

    Start-Sleep 1
}

# Read HKLM:\SOFTWARE\Citrix\MachineIdentityServiceAgent).CleanOnBoot = 1

# Install print drivers if image in read-only mode
# See https://github.com/kaspersmjohansen/Install-Printer-Drivers/blob/main/Install-PrinterDriver.ps1

# Disable unnecessary Scheduled Taks
Main

# Force GPupdate, useful for shitty domain
#Invoke-GPUpdate -Force

# Restart FSLogix Service
#Restart-Service frxsvc -Name -Force
#Restart-Service frxccds -Name -Force

# Launch process if image is in read-only mode
# See https://github.com/JamesKindon/Citrix/blob/master/PreFetchStartApps.ps1
# and https://github.com/kaspersmjohansen/AutoLogon-Script/blob/main/Set-AutoLogon.ps1