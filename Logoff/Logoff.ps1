# Hide powershell prompt
Add-Type -Name win -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

$ErrorActionPreference = 'SilentlyContinue'

# https://docs.microsoft.com/en-us/answers/questions/208676/onedrive-randomly-promting-to-removerestore-files.html?page=2&pageSize=10&sort=oldest
If (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe")
{
    If (Test-Path -Path "$env:ProgramFiles\WindowsPowershell\Modules\ODStatus\OneDriveLib.dll")
    {
        Import-Module -Name "$env:ProgramFiles\WindowsPowershell\Modules\ODStatus\OneDriveLib.dll"
        Write-Host -Object "Microsoft OneDrive Status Module was imported." -ForegroundColor Green

        # Wait for OneDrive sync to be Up To Date
        $OneDriveState = (Get-ODStatus).StatusString
        DO
        {
            Start-Sleep -Seconds 1
            $OneDriveState = (Get-ODStatus).StatusString
            Write-Host -Object "Microsoft OneDrive is still syncing..." -ForegroundColor Yellow
        } Until (($OneDriveState -eq "À jour") -or ($OneDriveState -eq "Up To Date"))
        Write-Host -Object "Microsoft OneDrive sync is completed." -ForegroundColor Green

        # Close OneDrive gracefully
        Start-Process -FilePath "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/shutdown" -WindowStyle Hidden
        Exit
    }
    Else
    {
        Write-Host -Object "Microsoft OneDrive Status Module is not currently installed!" -ForegroundColor Red
    }


    # Close OneDrive gracefully
    Start-Process -FilePath "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/shutdown" -WindowStyle Hidden
}


# Cleanup user printers
Remove-Item -Path "HKCU:\Printers" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Devices" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts" -Recurse -Force


# https://docs.microsoft.com/en-us/azure/active-directory/devices/howto-device-identity-virtual-desktop-infrastructure
Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy" -Recurse -Force
Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy" -Recurse -Force
Remove-Item -Path "$env:LOCALAPPDATA\Packages\*\AC\TokenBroker" -Recurse -Force
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\TokenBroker" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\IdentityCRL" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" -Recurse -Force

# https://docs.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/slow-logon-with-blank-screen
#Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UFH\SHC" -Recurse -Force