# Change <domain FQDN> to your actual domain. And you might want to change the destination =)
# I put it into a scheduled task to run nightly
# Easy list references https://dayngo.com/static/filter.html
# Deployment with Group Policy https://decentsecurity.com/adblocking-for-internet-explorer-deployment

function Get-ScriptDirectory {
    if ($psise) {
        Split-Path $psise.CurrentFile.FullPath
    }
    else {
        $global:PSScriptRoot
    }
}

$ScriptDirectory = Get-ScriptDirectory

$OutputDir = "$ScriptDirectory"
#$OutputDir = "\\<domain FQDN>\NETLOGON\IE_TP"

$Url1 = "https://easylist-msie.adblockplus.org/liste_fr+easylist.tpl"
$Output1 = "$OutputDir\{223F8DE5-87F8-4E76-97F1-DAD0A9C8A9A3}.tpl"

$Url2 = "https://easylist-msie.adblockplus.org/easyprivacy.tpl"
$Output2 = "$OutputDir\{223F8DE5-87F8-4E76-97F1-DAD0A9C8A9A4}.tpl"

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($url1, $Output1)
$WebClient.DownloadFile($url2, $Output2)
