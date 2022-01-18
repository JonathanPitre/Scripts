
# Hide powershell prompt
Add-Type -Name win -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

$ErrorActionPreference = 'SilentlyContinue'

# Close OneDrive gracefully
# https://docs.microsoft.com/en-us/answers/questions/208676/onedrive-randomly-promting-to-removerestore-files.html?page=2&pageSize=10&sort=oldest
If (Test-Path -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe")
{
	Start-Process -FilePath "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/shutdown" -WindowStyle Hidden
}

# Configure Microsoft Teams config file
$JsonFile = [System.IO.Path]::Combine($env:AppData, 'Microsoft', 'Teams', 'desktop-config.json')

If (Test-Path -Path $JsonFile)
{
	$ConfigFile = Get-Content -Path $JsonFile -Raw | ConvertFrom-Json
	Get-Process -Name Teams | Stop-Process -Force
	$ConfigFile.appPreferenceSettings.disableGpu = $True
	$ConfigFile.appPreferenceSettings.openAtLogin = $True
	$ConfigFile.appPreferenceSettings.openAsHidden = $True
	$ConfigFile.appPreferenceSettings.runningOnClose = $False
	$ConfigFile.appPreferenceSettings.registerAsIMProvider = $True
	$ConfigFile.currentWebLanguage = "fr-CA"
	$ConfigFile | ConvertTo-Json -Compress | Set-Content -Path $JsonFile -Force
}
Else
{
	Write-Host  "JSON file doesn't exist"
}

# From https://www.KoetzingIT.de, Thomas@koetzingit.de
# This script runs through the user OneDrive folder and set every downloaded file to free up space and
# therefore, remove them from the local system but they will still be available from the cloud.
# Storage Sense does not work with Server 2019 using script configuration, it looks like the free up of files based on time doesn't work properly.
# When this script runs, it will free up space except those files marked to be kept on the device.

$OSversion = (Get-CimInstance -class Win32_OperatingSystem).Caption

$Code = @'
using System;

[FlagsAttribute]
public enum FileAttributesEx : uint {
	Readonly = 0x00000001,
	Hidden = 0x00000002,
	System = 0x00000004,
	Directory = 0x00000010,
	Archive = 0x00000020,
	Device = 0x00000040,
	Normal = 0x00000080,
	Temporary = 0x00000100,
	SparseFile = 0x00000200,
	ReparsePoint = 0x00000400,
	Compressed = 0x00000800,
	Offline = 0x00001000,
	NotContentIndexed = 0x00002000,
	Encrypted = 0x00004000,
	IntegrityStream = 0x00008000,
	Virtual = 0x00010000,
	NoScrubData = 0x00020000,
	EA = 0x00040000,
	Pinned = 0x00080000,
	Unpinned = 0x00100000,
	U200000 = 0x00200000,
	RecallOnDataAccess = 0x00400000,
	U800000 = 0x00800000,
	U1000000 = 0x01000000,
	U2000000 = 0x02000000,
	U4000000 = 0x04000000,
	U8000000 = 0x08000000,
	U10000000 = 0x10000000,
	U20000000 = 0x20000000,
	U40000000 = 0x40000000,
	U80000000 = 0x80000000
}
'@
Add-Type $Code

If ($OSversion -match "Windows Server")
{
	Get-ChildItem $((Get-ChildItem $env:USERPROFILE -Filter "OneDrive -*").FullName) -Exclude "*.url" -Recurse |
		Where-Object {-Not $_.PSIsContainer } |
		Select-Object Fullname, @{n = 'Attributes'; e = {[fileAttributesex]$_.Attributes.Value__}} |
		where-Object { ($_.Attributes -cnotmatch "Unpinned") -or ($_.Attributes -cnotmatch "Offline") -And ($_.Attributes -cnotmatch "RecallOnDataAccess")  } |
		ForEach-Object { attrib.exe $_.fullname +U -P /S }
}
Else
{
	Write-Host "Configure Storage Sense instead!" -Verbose
}