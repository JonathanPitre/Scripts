#https://support.citrix.com/article/CTX224451

Add-PSSnapin Citrix.*
$DesktopGroups = @(Get-BrokerDesktopGroup * -MaxRecordCount 999999 | select Name, PublishedName, DeliveryType | Where-Object {(($_.PublishedName -ne $null) -and ($_.DeliveryType -eq "DesktopsOnly"))})
$Desktops = $DesktopGroups.Name

ForEach ($Desktop in $Desktops)
{
    $NewPublishedName = Read-Host -Prompt "Input your new Published Name for the Delivery Group $Desktop"
    Set-BrokerDesktopGroup -Name $Desktop -PublishedName "$NewPublishedName"
    Write-Host "The Delivery Group $Desktop published name was renamed to $NewPublishedName" -ForegroundColor Cyan `n
}
Get-BrokerMachine * -MaxRecordCount 999999 | select PublishedName | Where-Object {$_.PublishedName -ne $null} | Set-BrokerMachine -PublishedName $Null