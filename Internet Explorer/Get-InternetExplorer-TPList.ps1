# Change <domain FQDN> to your actual domain. And you might want to change the destination =)
# I put it into a scheduled task to run nightly
# Easy list references https://dayngo.com/static/filter.html
# Deployment with Group Policy https://decentsecurity.com/adblocking-for-internet-explorer-deployment

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

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory
#$appScriptDirectory = "\\<domain FQDN>\NETLOGON\IE_TP"

Set-Location -Path $appScriptDirectory

$Url1 = "https://easylist-msie.adblockplus.org/liste_fr+easylist.tpl"
$Output1 = "$appScriptDirectory\{223F8DE5-87F8-4E76-97F1-DAD0A9C8A9A3}.tpl"

$Url2 = "https://easylist-msie.adblockplus.org/easyprivacy.tpl"
$Output2 = "$appScriptDirectory\{223F8DE5-87F8-4E76-97F1-DAD0A9C8A9A4}.tpl"

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($url1, $Output1)
$WebClient.DownloadFile($url2, $Output2)