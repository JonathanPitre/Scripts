$ErrorActionPreference = 'Stop'; # stop on all errors
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$osBitness = Get-OSArchitectureWidth
[string]$packageName= $env:ChocolateyPackageName
$version = '8.0.2110.12'
$checkreg64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $version} -ErrorAction SilentlyContinue
$checkreg32 = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $version} -ErrorAction SilentlyContinue
$validExitCodes = @(0,1605,3010)
<#
Exit Codes:
    0: Java installed successfully.
    1605: Java is not installed.
    3010: A reboot is required to finish the install.
#>

if($checkreg32 -ne $null) 
  {
     Write-Warning "Uninstalling JRE version $version 32bit"
     $32 = $checkreg32.PSChildName
     Start-ChocolateyProcessAsAdmin "/qn /norestart /X$32" -exeToRun "msiexec.exe" -validExitCodes $validExitCodes
  }
  if($checkreg64 -ne $null)
  {
     Write-Warning "Uninstalling JRE version $version $osBitness bit" #Formatted weird for x86 windows installs
     $64 = $checkreg64.PSChildName
     Start-ChocolateyProcessAsAdmin "/qn /norestart /X$64" -exeToRun "msiexec.exe" -validExitCodes $validExitCodes
  }

Write-Warning "$packageName may require a reboot to complete the uninstallation."