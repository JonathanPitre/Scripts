# Hide powershell prompt
Add-Type -Name win -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

# Hybrid Azure AD join must be done at startup and user login
Start-Process -FilePath "$env:windir\System32\dsregcmd.exe" -ArgumentList "/join" -WindowStyle Hidden

# Fix Office 365 SSO on Windows Server 2019 - https://discussions.citrix.com/topic/403721-office-365-pro-plus-shared-activation-password-screen-not-able-to-select/page/9
# https://docs.microsoft.com/en-us/office365/troubleshoot/authentication/automatic-authentication-fails
If (-not (Get-AppxPackage Microsoft.AAD.BrokerPlugin)) { Add-AppxPackage -Register "$env:windir\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Appxmanifest.xml" -DisableDevelopmentMode -ForceApplicationShutdown } Get-AppxPackage Microsoft.AAD.BrokerPlugin

# Launch OneDrive only after Microsoft AAD Broker Plugin is repaired
If (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") {
    Start-Process -FilePath "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/background" -WindowStyle Hidden
}

# FSLogix should already show the app based on AD group and loading the Active Directory module is slowing down the login process

# Remote Server Administration Tools must be installed - https://adamtheautomator.com/powershell-import-active-directory
# or https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges
#Import-Module ActiveDirectory
#$User = "$env:UserName"
#$AD_Group_AdobeAcrobat = "App-AdobeAcrobat" # Change to your AD group name

# Set File Associations for Adobe Reader or Adobe Acrobat - https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user
#If ((Get-ADUser $User -Properties memberof).memberof -like "CN=$AD_Group_AdobeAcrobat*" -and (Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"))
If ((Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe") -or (Test-Path -Path "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe"))
{
    .\SetUserFTA.exe "Adobe Acrobat.txt"
}
ElseIf (Test-Path -Path "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
{
    .\SetUserFTA.exe "Adobe Acrobat Reader.txt"
}
Else {
    .\SetUserFTA.exe "Microsoft Edge.txt"
}