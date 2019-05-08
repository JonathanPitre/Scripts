$ErrorActionPreference = 'Stop'; # stop on all errors
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$osBitness = Get-OSArchitectureWidth

try {

  $arguments = @{}

    # Now we can use the $env:chocolateyPackageParameters inside the Chocolatey package
    $packageParameters = $env:chocolateyPackageParameters

    # Default value
    $exclude = $null

    # Now parse the packageParameters using good old regular expression
    if ($packageParameters) {
        $match_pattern = "\/(?<option>([a-zA-Z0-9]+)):(?<value>([`"'])?([a-zA-Z0-9- \(\)\s_\\:\.]+)([`"'])?)|\/(?<option>([a-zA-Z]+))"
        $option_name = 'option'
        $value_name = 'value'

        if ($packageParameters -match $match_pattern ){
            $results = $packageParameters | Select-String $match_pattern -AllMatches
            $results.matches | % {
              $arguments.Add(
                  $_.Groups[$option_name].Value.Trim(),
                  $_.Groups[$value_name].Value.Trim())
          }
        }
        else
        {
            Throw "Package Parameters were found but were invalid (REGEX Failure)"
        }

        if($arguments.ContainsKey("exclude")) {
            Write-Host "exclude Argument Found"
            $exclude = $arguments["exclude"]
        }

    } else {
        Write-Debug "No Package Parameters Passed in"
    }

    # Modify these values -----------------------------------------------------
    # Find download URLs at http://www.java.com/en/download/manual.jsp
    $url = 'https://javadl.oracle.com/webapps/download/AutoDL?BundleId=238727_478a62b7d4e34b78b671c754eaaf38ab'
    $checksum32 = '47DE97325B8EA90EA9F93E1595CC7F843DA0C9C6E4C9532ABEA3A194CFB621D9'
    $url64 = 'https://javadl.oracle.com/webapps/download/AutoDL?BundleId=238729_478a62b7d4e34b78b671c754eaaf38ab'
    $checksum64 = 'C18CF8F2776B69DC838440AADFAAE36F50717636F38EEC5F1E4A27A8CB4F20FB'
    $oldVersion = '8.0.2010.9'
    $version = '8.0.2110.12'
    $shortVersion = '211'
    #--------------------------------------------------------------------------
    $homepath = $version -replace "(\d+\.\d+)\.(\d\d)(.*)",'jre1.$1_$2'
    $softwareName = 'Java Runtime Environment'
    $configSourcePath ="$toolsDir\config"
    $configDestPath = "$env:windir\Sun\Java\Deployment"
    $packageName = $env:ChocolateyPackageName
    $filePath = Join-Path $env:TEMP "\$packageName"
    $fileType = 'exe' #only one of these: exe, msi, msu
    #Silent arguments listed here https://docs.oracle.com/javase/8/docs/technotes/guides/install/config.html#table_config_file_options
    $silentArgs = "INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_JAVA=1 WEB_JAVA_SECURITY_LEVEL=H WEB_ANALYTICS=0 EULA=0 REBOOT=0 NOSTARTMENU=1 SPONSORS=0 REMOVEOUTOFDATEJRES=1 REPAIRMODE=1 /L `"$env:TEMP\chocolatey\$($packageName)\$($packageName).MsiInstall.log`""
    $validExitCodes = @(0,1605,3010)

    Write-Host "The software license has changed for Java and this software must be licensed for general business use. Please ensure your licensing is compliant before installing." -ForegroundColor white -BackgroundColor red
    #This checks to see if current version is already installed
    Write-Output "Checking to see if local install is already up to date..."
    try{
    $checkreg64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $version} -ErrorAction SilentlyContinue
    $checkreg32 = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $version} -ErrorAction SilentlyContinue
    }catch{
    Write-Output "Registry check failed. This is commonly caused by corrupt keys (Do you have netbeans installed?)"
    }

      # Checks if JRE 32/64-bit in the same version is already installed and if the user excluded 32-bit Java.
      # Otherwise it downloads and installs it.
      # This is to avoid unnecessary downloads and 1603 errors.
      if ($checkreg32 -ne $null)
      {
        Write-Output "$softwareName $shortVersion (32-bit) is already installed. Skipping download and installation"
      }
      elseif ($exclude -ne "32")
      {
        Write-Output "Downloading 32-bit installer"
        Get-ChocolateyWebFile -packageName $packageName -fileFullPath "$filePath\jre8x86.exe" -url $url -checksum $checksum32 -checksumType 'SHA256'
        Write-Output "Installing $softwareName $shortVersion (32-bit)"
        Install-ChocolateyInstallPackage -packageName $packageName -fileType $fileType -silentArgs $silentArgs -file "$filePath\jre8x86.exe"
        #Install-ChocolateyInstallPackage $packageArgs
        if (-Not (Test-Path -Path $configDestPath))
        {
          New-Item -Path $configDestPath -ItemType Directory -Force
        }
        Write-Output "Copying required $softwareName configs"
        Copy-Item -Path "$configSourcePath\*" -Destination $configDestPath -Force

        Write-Output "Setting Windows file associations to open .JNLP Files properly"
        $regKey = "HKLM:\SOFTWARE\Classes\.jnlp"
        New-ItemProperty -Path $regKey -PropertyType String -Name '(Default)' -Value "JNLPFile" -Force
        New-ItemProperty -Path $regKey -PropertyType String -Name "Content Type" -Value "application/x-java-jnlp-file" -Force
        $regKey = "HKLM:\SOFTWARE\Classes\jnlp\Shell\Open\Command"
        New-ItemProperty -Path $regKey -PropertyType String -Name '(Default)' -Value '"C:\Program Files (x86)\Java\jre1.8.0_$shortVersion\bin\jp2launcher.exe" -securejws "%1"' -Force
        $regKey = "HKLM:\SOFTWARE\Classes\JNLPFile\Shell\Open\Command"
        New-ItemProperty -Path $regKey -PropertyType String -Name '(Default)' -Value '"C:\Program Files (x86)\Java\jre1.8.0_$shortVersion\bin\javaws.exe" "%1"' -Force
        $regKey = "HKLM:\SOFTWARE\Classes\Database\Content Type\application/x-java-jnlp-file"
        New-ItemProperty -Path $regKey -PropertyType String -Name "Extension" -Value ".jnlp" -Force
        $regKey = "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/x-java-jnlp-file"
        New-ItemProperty -Path $regKey -PropertyType String -Name "Extension" -Value ".jnlp" -Force

        Remove-Item -Path "$filePath\jre8x86.exe" -Force
      }
      else
      {
        Write-Output "$softwareName $shortVersion (32-bit) excluded for installation"
      }

      # Only check for the 64-bit version if the system is 64-bit

      if ($osBitness -eq 64)
      {
        if ($checkreg64 -ne $null)
        {
          Write-Output "$softwareName $shortVersion (64-bit) is already installed. Skipping download and installation"
        }
        elseif ($exclude -ne "64")
        {
          Write-Output "Downloading 64-bit installer"
          Get-ChocolateyWebFile -packageName $packageName -fileFullPath "$filePath\jre8x64.exe" -url64 $url64 -checksum64 $checksum64 -checksumType 'SHA256'
          Write-Output "Installing $softwareName $shortVersion (64-bit)"
          Install-ChocolateyInstallPackage -packageName $packageName -fileType $fileType -silentArgs $silentArgs -file64 "$filePath\jre8x64.exe"
          #Install-ChocolateyInstallPackage $packageArgs
          Remove-Item -Path "$filePath\jre8x64.exe" -Force
        }
        else
        {
          Write-Output "$softwareName $shortVersion 64-bit excluded for installation"
        }
      }

    #Uninstalls the previous version of Java if either version exists
    Write-Output "Searching if the previous version exists..."
    $checkoldreg64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $oldversion} -ErrorAction SilentlyContinue
    $checkoldreg32 = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName | Where-Object { $_.DisplayName -like '*Java 8*' -and ([Version]$_.DisplayVersion) -eq $oldversion} -ErrorAction SilentlyContinue

    if($checkoldreg32 -ne $null)
    {
       Write-Warning "Uninstalling $softwareName version $oldVersion 32-bit"
       $32 = $checkoldreg32.PSChildName
       Start-ChocolateyProcessAsAdmin "/qn /norestart /X$32" -exeToRun "msiexec.exe" -validExitCodes $validExitCodes
    }
    if($checkoldreg64 -ne $null)
    {
       Write-Warning "Uninstalling $softwareName version $oldVersion 64-bit" #Formatted weird because this is used if run on a x86 install
       $64 = $checkoldreg64.PSChildName
       Start-ChocolateyProcessAsAdmin "/qn /norestart /X$64" -exeToRun "msiexec.exe" -validExitCodes $validExitCodes
    }
  }
  catch {
    #Write-ChocolateyFailure $packageName $($_.Exception.Message)
    throw
  }