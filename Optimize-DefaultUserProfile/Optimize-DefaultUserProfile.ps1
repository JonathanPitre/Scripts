# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appProcesses = @("regedit", "reg")
$appTeamsConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Teams/desktop-config.json"
$appTeamsConfig = Split-Path -Path $appTeamsConfigURL -Leaf
$NewUserScript = "\\$envMachineADDomain\NETLOGON\VDI\NewUserProfile\Set-NewUserProfile.ps1" # Modify according to your environment

#-----------------------------------------------------------[Execution]------------------------------------------------------------


Get-Process -Name $appProcesses | Stop-Process -Force
Set-Location -Path $appScriptDirectory

# Backup Default User registry hive
Write-Log -Message "Saving a Default User registry hive copy..." -Severity 1 -LogType CMTrace -WriteHost $True
If (-Not(Test-Path -Path "$envSystemDrive\Users\Default\NTUSER.DAT.bak"))
{
    Copy-File -Path "$envSystemDrive\Users\Default\NTUSER.DAT" -Destination "$appScriptDirectory\NTUSER.DAT.BAK"
}

# Load the Default User registry hive
Write-Log -Message "Loading the Default User registry hive..." -Severity 1 -LogType CMTrace -WriteHost $True
Start-Sleep -Seconds 5
Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "LOAD HKLM\DefaultUser $envSystemDrive\Users\Default\NTUSER.DAT" -WindowStyle Hidden

## Language and Keyboards
# Set display language
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "PreferredUILanguages" -Type MultiString -Value "fr-CA"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "PreviousPreferredUILanguages" -Type MultiString -Value "en-US"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop\MuiCached" -Name "MachinePreferredUILanguages" -Type MultiString -Value "en-US"
#Remove-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Recurse -ContinueOnError $True
#Remove-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile System Backup" -Recurse -ContinueOnError $True

# Set display locale
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "Locale" -Type String -Value "00000C0C"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "LocaleName" -Type String -Value "fr-CA"

# Set Country
# https://www.robvanderwoude.com/icountry.php
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "iCountry" -Type String -Value "1" # Canada is 2
Remove-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sCountry" # Set to US
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sCountry" -Type String -Value "Canada"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sLanguage" -Type String -Value "FRC"

Remove-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "InputMethodOverride"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "Languages" -Type MultiString -Value "fr-CA"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "ShowAutoCorrection" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "ShowCasing" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "ShowShiftLock" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "ShowTextPrediction" -Type DWord -Value "1"
Remove-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile\en-US"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile\fr-CA" -Name "0C0C:00001009" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile\fr-CA" -Name "CachedLanguageName" -Type String -Value "@Winlangdb.dll,-1160"

# Adds an extra language when set to another country then US
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\Geo" -Name "Name" -Type String -Value "CA"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\Geo" -Name "Nation" -Type String -Value "39"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\Geo" -Name "Name" -Type String -Value "US"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\Geo" -Name "Nation" -Type String -Value "244"

# Set Keyboards
Remove-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Preload" -Recurse
Remove-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Substitutes" -Recurse

# Set French (Canada) - Canadian French keyboard layout
Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Preload" -Name "1" -Type String -Value "00000c0c"
Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Substitutes" -Name "00000c0c" -Type String -Value "00001009"

# Set English (Canada) - US keyboard layout
#Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Preload" -Name "2" -Type String -Value "00001009"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Substitutes" -Name "00001009" -Type String -Value "00000409"

# Disable input language switch hotkey -https://windowsreport.com/windows-10-switches-keyboard-language
Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Toggle" -Name "Hotkey" -Type DWord -Value "3"
Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Toggle" -Name "Language Hotkey" -Type DWord -Value "3"
Set-RegistryKey -Key "HKLM:\DefaultUser\Keyboard Layout\Toggle" -Name "Layout Hotkey" -Type DWord -Value "3"

# Hide the language bar
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\CTF\LangBar" -Name "ShowStatus" -Type DWord -Value "3"

# Set Internet Explorer language
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Internet Explorer\International" -Name "AcceptLanguage" -Value "fr-CA,en;q=0.5" -Type String
#Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Internet Explorer\International" -Name "AcceptLanguage" -Type String -Value "fr-CA,en-CA;q=0.5"

# Sets primary editing language to fr-CA - https://docs.microsoft.com/en-us/deployoffice/office2016/customize-language-setup-and-settings-for-office-2016
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\languageresources" -Name "preferrededitinglanguage" -Type String -Value "fr-CA"


## Date and Time
# Set date format
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sLongDate" -Type String -Value "dddd dd MMMM yyyy"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sShortDate" -Type String -Value "dd-MM-yyyy"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sYearMonth" -Type String -Value "MMMM, yyyy"

# Set first day of week
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "iFirstDayOfWeek" -Type String -Value "0"

# Set time format
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sTimeFormat" -Type String -Value "HH:mm:ss"
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International" -Name "sShortTime" -Type String -Value "HH:mm"

# Set Sounds scheme to none
$regKeys = Get-ChildItem -Path "HKLM:\DefaultUser\AppEvents\Schemes\Apps\.Default" -Recurse | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace "HKEY_LOCAL_MACHINE" , 'HKLM:' }
ForEach ($regItems in $regKeys)
{
    Set-RegistryKey -Key $regItems -Name "(Default)" -Value ""
}

# Disable sound beep
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Sound" -Name "Beep" -Type String -Value "no"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Sound" -Name "ExtendedSounds" -Type String -Value "no"

# Force asynchronous processing of user GPOs at first logon - https://james-rankin.com/articles/make-citrix-logons-use-asynchronous-user-group-policy-processing-mode
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Group Policy\State" -Name "NextRefreshReason" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Group Policy\State" -Name "NextRefreshMode" -Type DWord -Value "2"

# Always show alll icons and notifications on the taskbar -   https://winaero.com/blog/always-show-tray-icons-windows-10
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value "0"

# Disable the label "Shortcut To" on shortcuts - https://www.howtogeek.com/howto/windows-vista/remove-shortcut-text-from-new-shortcuts-in-vista
$regValueHex = "00,00,00,00"
$regValueHexified = $regValueHex.Split(",") | ForEach-Object { "0x$_" }
$regValueBinary = ([byte[]]$regValueHexified)
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value $regValueBinary

# https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
$regValueHex = "24,00,00,00,3C,28,00,00,00,00,00,00,00,00,00,00"
$regValueHexified = $regValueHex.Split(",") | ForEach-Object { "0x$_" }
$regValueBinary = ([byte[]]$regValueHexified)
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShellState" -Type Binary -Value $regValueBinary

# Enable Thumbnail Previews
Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableThumbnails"
Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnails"

# Always show menus
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AlwaysShowMenus" -Type DWord -Value "1"

# Visual effects - Enable "Show thumbnails instead of icons" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value "1"

# Expand to open folder
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value "1"

# Disable "Show all folders"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value "0"

# Hide Taskview button on Taskbar
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value "0"

# Disable checkboxes File Explorer
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Type DWord -Value "0"

# Visual effects - Disable "Show translucent selection rectangle" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect " -Type DWord -Value "0"

# Enable "Use drop shadows for icon labels on the desktop" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListViewShadow" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCompColor" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Type DWord -Value "1"

# Visual effects - Disable "Animations in the taskbar" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value "0"

# Show known file extensions
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value "0"

# Change default explorer view to my computer
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value "1"

# Show Taskbar on one screen and show icons where taskbar is open
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarEnabled" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarMode" -Type DWord -Value "2"

# Display Full Path in Title Bar
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value "1"

# Hide People button from Taskbar
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value "0"

# Add "This PC" to desktop
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value "0"

# Makes Citrix Director reports logons slightly faster - https://james-rankin.com/articles/how-to-get-the-fastest-possible-citrix-logon-times
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type String -Value "0"

# Visual Effects
# Settings "Visual effects to Custom" - https://support.citrix.com/article/CTX226368
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value "3"

Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Name "DefaultApplied" -Type DWord -Value "0"

# Show ribbon in File Explorer
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Name "ExplorerRibbonStartsMinimized" -Type DWord -Value "2"

# Disable action center
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value "0"

# Remove "Recently added" list from Start Menu
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value "1"

# Do not show the 'new application installed' notification
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value "1"

# https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name "Disabled" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name "Disabled" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name "DisabledByUser" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name "Disabled" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Name "Disabled" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value "0"

# Advertising ID
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value "0"

# Set wallpaper
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "WallPaper" -Type String -Value ""
#Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "WallPaperStyle" -Type String -Value "10"

# Disable peer-to-peer caching but still allows Delivery Optimization to download content over HTTP from the download's original source - https://docs.microsoft.com/en-us/windows/deployment/update/waas-delivery-optimization-reference#download-mode
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value "3"

# Show search box on the taskbar
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value "2"

# Disable Security and Maintenance Notifications
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Type DWord -Value "0"

# Hide Windows Ink Workspace Button
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Type DWord -Value "0"

# Disable Game DVR
Set-RegistryKey -Key "HKLM:\DefaultUser\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value "0"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value "0"

# Speed up logoff
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type String -Value "2000"
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "HungAppTimeout" -Type String -Value "1000"

# Optimizes Explorer and Start Menu responses Times - https://docs.citrix.com/en-us/workspace-environment-management/current-release/reference/environmental-settings-registry-values.html
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "InteractiveDelay" -Type DWord -Value "40"

# Change Windows Visual Effects - https://virtualfeller.com/2015/11/19/windows-10-optimization-part-4-user-interface
# https://superuser.com/questions/839993/find-registry-key-for-windows-8-per-application-input-method-setting
# https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
# https://www.deploymentresearch.com/fixing-borderless-windows-in-windows-server-2019-and-windows-server-2022
$regValueHex = "90,32,07,80,10,00,00,00"
# old recommendation 90,24,03,80,10,00,00,00
$regValueHexified = $regValueHex.Split(",") | ForEach-Object { "0x$_" }
$regValueBinary = ([byte[]]$regValueHexified)
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value $regValueBinary

# Specifies how much time elapses between each blink of the selection cursor
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "CursorBlinkRate" -Type String -Value "-1"

# Disable Cursor Blink
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "DisableCursorBlink" -Type DWord -Value "1"

# Visual effects - Disable "Show window contents while dragging" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value "0"

# Visual effects - Disable "Show window contents while dragging" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value "0"

# Enable Font Smoothing - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value "2"

# Disable smooth scrolling
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop" -Name "SmoothScroll" -Type DWord-Value "0"

# Visual effects - Disable "Animate windows when minimizing and maximizing" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value "0"

# Visual effects - Disable "Aero Peek" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value "0"

# Visual effects - Disable "Save taskbar thumbnail previews" - https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\DWM" -Name "AlwaysHibernateThumbnails" -Type DWord -Value "0"

# Set the Title And Border Color to blue - https://dybbugt.no/2020/1655 - https://winaero.com/blog/enable-dark-title-bars-custom-accent-color-windows-10
# Black = 1513239
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\DWM" -Name "AccentColor" -Type DWord -Value "4292311040"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\DWM" -Name "ColorizationColor" -Type DWord -Value "4292311040"

# Enable the Border and title bar coloring - https://dybbugt.no/2020/1655
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value "1"

# Internet Explorer
# Disable warning "Protected mode is turned off for the Local intranet zone" - https://www.carlstalhood.com/group-policy-objects-vda-user-settings
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Internet Explorer\Main" -Name "NoProtectedModeBanner" -Type DWord -Value "1"

# Microsoft Office 365/2016/2019
# Removes the First Things First (EULA) - https://social.technet.microsoft.com/Forums/ie/en-US/d8867a27-894b-44ff-898d-24e0d0c6838a/office-2016-proplus-first-things-first-eula-wont-go-away?forum=Office2016setupdeploy
# https://www.carlstalhood.com/group-policy-objects-vda-user-settings/#office2013
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Registration" -Name "AcceptAllEulas" -Type DWord -Value "1"

# Limit Office 365 telemetry - https://www.ghacks.net/2020/11/15/limit-office-365-telemetry-with-this-undocumented-setting
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\Common\ClientTelemetry" -Name "SendTelemetry" -Type DWord -Value "0"

# Disable "Your Privacy Option" message - http://www.edugeek.net/forums/office-software/218099-office-2019-your-privacy-option-popup.html
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common" -Name "PrivacyNoticeShown" -Type DWord -Value "2"

# Disable "Your Privacy Matters" message - https://www.reddit.com/r/sysadmin/comments/q6sesu/office_2021_your_privacy_matters_disable_via_gpo
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\Privacy\SettingsStore\Anonymous" -Name "OptionalConnectedExperiencesNoticeVersion" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\Privacy\SettingsStore\Anonymous" -Name "FRESettingsMigrated" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\Privacy\SettingsStore\Anonymous" -Name "RequiredDiagnosticDataNoticeVersion" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\Privacy\SettingsStore\Anonymous" -Name "OptionalDiagnosticDataConsentVersion" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\common\Privacy\SettingsStore\Anonymous" -Name "ConnectedExperiencesNoticeVersion" -Type DWord -Value "1"

# Disable "Show the option for Office Insider" - https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Common" -Name "InsiderSlabBehavior" -Type DWord -Value "2"
# Set Outlook's Cached Exchange Mode behavior - https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode" -Name "Enable" -Type DWord -Value "1"
# 1 month sync
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode" -Name "SyncWindowSetting" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode" -Name "CalendarSyncWindowSetting" -Type DWord -Value "1"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode" -Name "CalendarSyncWindowSettingMonths" -Type DWord -Value "1"

# Disable teaching callouts - https://docs.microsoft.com/en-us/answers/questions/186354/outlook-remove-blue-tip-boxes.html
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "AutocreateTeachingCallout_MoreLocations" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "AutoSaveFirstSaveWord" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "AutoSaveTottleOnWord" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "CloudSettingsSyncTeachingCallout" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "CommingSoonTeachingCallout" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "DataVisualizerRibbonTeachingCallout" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "ExportToWordProcessTabTeachingCallout" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "FocusedInboxTeachingCallout_2" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "MeetingAllowForwardTeachingCallout" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "Olk_SearchBoxTitleBar_SLR_Sequence" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "PreviewPlaceUpdate" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "RibbonOverflowTeachingCalloutID" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "Search.TopResults" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "SLRToggleReplaceTeachingCalloutID" -Type DWord -Value "2"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\TeachingCallouts" -Name "UseTighterSpacingTeachingCallout" -Type DWord -Value "2"

# Remove the default file types dialog - https://www.blackforce.co.uk/2016/05/11/disable-office-2016-default-file-types-dialog
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\General" -Name "ShownFileFmtPrompt" -Type DWord -Value "1"

# Remove the "Get and set up Outlook Mobile app on my phone" option from Outlook - https://support.microsoft.com/en-ca/help/4010175/disable-the-get-and-set-up-outlook-mobile-app-on-my-phone-option
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Outlook\Options\General" -Name "DisableOutlookMobileHyperlink" -Type DWord -Value "1"

# Enable Microsoft OneNote page tabs appear on the left - https://social.technet.microsoft.com/Forums/en-US/b5cad42a-83a6-4f19-96ed-70e6a3f964de/onenote-how-to-move-page-window-to-the-left-side?forum=officeitproprevious
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\onenote\Options\Other" -Name "PageTabsOnLeft" -Type DWord -Value "1"

# Open Microsoft Visio diagrams and drawings in separate windows
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Visio\Application" -Name "SingleInstanceFileOpen" -Type String -Value "0"

# Disable the Microsoft Office Upload Center notification - https://www.ghacks.net/2018/02/09/how-to-disable-the-microsoft-office-upload-center
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\FileIO" -Name "DisableNotificationIcon" -Type String -Value "1"

# Disable Micrososoft Office hardware graphics acceleration - http://shawnbass.com/psa-software-gpu-can-reduce-your-virtual-desktop-scalability
#Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\16.0\Common\Graphics" -Name "DisableHardwareAcceleration" -Type String -Value "1"

# Disable Micrososoft OneDrive Notifications - https://docs.microsoft.com/en-us/archive/blogs/platforms_lync_cloud/disabling-windows-10-action-center-notifications
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" -Name "Enabled" -Type DWord -Value "0"

# Get Micrososoft OneDrive setups run keys
$regOneDriveSetup = Get-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Value "OneDriveSetup"
$regOneDrive = Get-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Value "OneDrive"

# Remove Microsoft OneDrive setups from running on new user profile
# https://byteben.com/bb/installing-the-onedrive-sync-client-in-per-machine-mode-during-your-task-sequence-for-a-lightening-fast-first-logon-experience
If ($regOneDriveSetup) { Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" }
If ($regOneDrive) { Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" }

# Enable Storage Sense - https://james-rankin.com/all-posts/quickpost-setting-storage-sense-cloud-content-dehydration-on-server-2019
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value "1"

# Set Microsoft Teams as the default chat app for Office - https://www.msoutlook.info/question/setting-skype-or-other-im-client-to-integrate-with-outlook
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\IM Providers" -Name "DefaultIMApp" -Type String -Value "Teams"

# Open Microsoft Teams links without prompts - https://james-rankin.com/articles/microsoft-teams-on-citrix-virtual-apps-and-desktops-part-2-default-settings-and-json-wrangling
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams\shell\open\command" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`" `"%1`""
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\TeamsURL\shell\open\command" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`" `"%1`""
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams" -Name "DefaultIMApp" -Type String -Value "URL:msteams"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "msteams_msteams" -Type DWord -Value "00000000"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams" -Name "URL Protocol" -Type String -Value ""
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Internet Explorer\ProtocolExecute\msteams" -Name "WarnOnOpen" -Type String -Value "00000000"

# Download required Microsoft Teams config file
If (-Not(Test-Path -Path $appScriptDirectory\$appTeamsConfig))
{
    Write-Log -Message "Downloading Microsoft Teams config file..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appTeamsConfigURL -OutFile $appScriptDirectory\$appTeamsConfig
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Copy Microsoft Teams config file to the default profile
If (-Not(Test-Path -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Teams\$appTeamsConfig"))
{
    Copy-File -Path "$appScriptDirectory\$appTeamsConfig" -Destination "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Teams"
    Write-Log -Message "$appVendor $appName settings were configured for the Default User profile." -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "Default profile is already configured for Microsoft Teams." -Severity 1 -LogType CMTrace -WriteHost $True
}

# To validate (from the comments section)
#Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\WOW6432Node\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}\LocalServer" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`""
#Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}\LocalServer" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`""

# Prevent Microsoft Outlook from being stuck at launch due to Teams meeting addin
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\Outlook\AddIns\TeamsAddin.FastConnect" -Name "Description" -Type String -Value "Microsoft Teams Meeting Add-in for Microsoft Office"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\Outlook\AddIns\TeamsAddin.FastConnect" -Name "LoadBehavior" -Type DWord -Value "3"
Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Office\Outlook\AddIns\TeamsAddin.FastConnect" -Name "FriendlyName" -Type String -Value "Microsoft Teams Meeting Add-in for Microsoft Office"

# Add login script on new user creation
$regRunOnceKey = "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\RunOnce"
If (-not(Test-Path $regRunOnceKey))
{
    Set-RegistryKey -Key $regRunOnceKey
}
Set-RegistryKey -Key $regRunOnceKey -Name "NewUser" -Type String -Value "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -Ex ByPass -File $NewUserScript"

If (Test-Path -Path $envProgramFiles\Autodesk)
{
    # Prevent Autodesk desktop analitycs -  https://forums.autodesk.com/t5/installation-licensing/preventing-the-desktop-analytics-popup-on-first-start/td-p/5311565
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Autodesk\MC3" -Name "ADAOptIn" -Type DWord -Value "0"
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Autodesk\MC3" -Name "ADARePrompted" -Type DWord -Value "1"
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Autodesk\MC3" -Name "OverridedByHKLM" -Type DWord -Value "0"
}

# Cleanup (to prevent access denied issue unloading the registry hive)
Get-Variable reg* | Remove-Variable
[GC]::Collect()
Start-Sleep -Seconds 5

# Unload the Default User registry hive
Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "UNLOAD HKLM\DefaultUser" -WindowStyle Hidden

# https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/performance-issues-custom-default-user-profile
# https://docs.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/apps-access-admin-web-cache
Remove-File -Path "$envSystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WebCacheLock.dat"
Remove-Folder -Path "$envSystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WebCache"
Remove-Folder -Path "$envSystemDrive\Users\Default\AppData\Local\Microsoft\Windows\INetCache"
Remove-Folder -Path "$envSystemDrive\Users\Default\AppData\Local\Microsoft\Windows\INetCookies"
Remove-Folder -Path "$envSystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WebCache"

# Cleanup temp files
Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG1" -Force
Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG2" -Force
Remove-Item -Path "$envSystemDrive\Users\Default\*.blf" -Force
Remove-Item -Path "$envSystemDrive\Users\Default\*.regtrans-ms" -Force

Write-Log -Message "The default user profile was optimized!" -LogType 'CMTrace' -WriteHost $True