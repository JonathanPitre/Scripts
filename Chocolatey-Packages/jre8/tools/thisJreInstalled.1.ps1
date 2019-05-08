# NOTE - THIS SCRIPT IS NO LONGER IN USE AND WILL BE REMOVED IN A FUTURE VERSION
# This function checks if the same version of JRE is already installed on the computer.
# It returns a hash map with a 'x86_32' and 'x86_64'. These values are not empty if the
# same version and bitness of JRE is already installed.
function thisJreInstalled($version) {
  $productSearch = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match '^Java \d+ Update \d+'}
   
  # The regexes for the name of the JRE registry entries (32- and 64 bit versions)
  $nameRegex32 = '^Java \d+ Update \d+$'
  $nameRegex64 = '^Java \d+ Update \d+ \(64-bit\)$'
  $versionRegex = $('^' + $version + '\d*$')
 
  $x86_32 = $productSearch | Where-Object {$_.Name -match $nameRegex32 -and $_.Version -match $versionRegex}
  $x86_64 = $productSearch | Where-Object {$_.Name -match $nameRegex64 -and $_.Version -match $versionRegex}
  if($x86_32 -eq $null)
  {
    $x86_32 = $false
  }
  if($x86_64 -eq $null)
  {
    $x86_64 = $false
  } 
  return $x86_32,$x86_64
} 