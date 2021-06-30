# Get the current script directory
Function Get-ScriptDirectory {
    Remove-Variable appScriptDirectory
    Try {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch {
        Write-Host -ForegroundColor Red "Caught Exception: $($Error[0].Exception.Message)"
        Exit 2
    }
}

# Function by Oliver Lipkau (https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file)
Function Get-IniContent ($filePath) {
    $ini = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

# Cache files
Function Start-FileCaching([string]$filename) {
    Write-Host $filename
    $Bytes = [System.IO.File]::ReadAllBytes($filename)
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory
$Personality = "$env:SystemDrive\Personality.ini"
$filelist = Get-ChildItem "$env:ProgramFiles\*.*", "${env:ProgramFiles(x86)}\*.*" -Recurse

if ( Test-Path $Personality ) {
    $iniContent = Get-IniContent $Personality;
    $value = $iniContent["StringData"];
}

if ($value.values -eq "Shared") {
    $sw = [Diagnostics.Stopwatch]::StartNew()

    foreach ($f in $filelist) {
        $ext = [IO.Path]::GetExtension($f)
        Switch ($ext) {
            {($_ -eq ".dll") -or ($_ -eq ".exe")} {Start-FileCaching($f)}
        }
    }

    $sw.Stop()
    $sw.Elapsed | Out-File -FilePath "$appScriptDirectory\CacheRunTime.log" -Force
}
else {
    write-host "The disk is in Private mode!"
    exit-pssession
}