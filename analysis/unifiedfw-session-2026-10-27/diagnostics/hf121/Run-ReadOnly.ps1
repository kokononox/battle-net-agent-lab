# Windows-only diagnostic. No Apply/Restore, firewall writes, VPN changes, or network probes.
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='hf121-readonly-parity-1';diagnostic_completed=$false;sampled_image_parity=$false;full_store_parity_proven=$false;optimization_approved=$false;windows_API_attempted=$false;firewall_mutation_requested=$false;profile_mutation_requested=$false;journal_accessed=$false;VPN_change_requested=$false;network_probe_requested=$false;no_leak_certified=$false;fingerprint_prevention_certified=$false;timing_benchmark_performed=$false;powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;stage='platform_guard';stores=@();error_code='';error_type=''}
$exitCode=1;$dest=$null
try{
 # Output is bounded/sanitized and goes only to this extracted package folder.
 $root=[IO.Path]::GetFullPath($PSScriptRoot)
 $p=$root
 while($p){if(Test-Path -LiteralPath $p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'local_non_reparse_folder_required'}};$parent=[IO.Path]::GetDirectoryName($p);if($parent -eq $p){break};$p=$parent}
 if($root.StartsWith('\\')){throw 'local_non_reparse_folder_required'}
 $dest=Join-Path $root ('HF121-READONLY-PARITY-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'powershell_51_64bit_required'}
 $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator_required'}
 $report.stage='payload_guard'
 $expected=ConvertFrom-Json @'
{
  "ReadOnly.Native.ps1": "882652d79898c7badbb1ff39284c588594d22863cca4b9f8260f25de37192cc7",
  "Bulk.ReadOnly.ps1": "e4500b913b25645fa863d79432daf70c64ee9f9fdc0db3b88eebd8cd259c4d94",
  "Comparison.Core.ps1": "e53f3fe07a0f35da21a35038111cbe1d3e7f7d33d0a7faa638d7b5972494aa49"
}
'@
 foreach($item in $expected.PSObject.Properties){
  $file=Join-Path $root $item.Name
  if(([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne ([string]$item.Value).ToUpperInvariant()){throw 'payload_hash_mismatch'}
 }
 foreach($name in @('ReadOnly.Native.ps1','Bulk.ReadOnly.ps1','Comparison.Core.ps1')){. (Join-Path $root $name)}
 $report.stage='NetSecurity_import';Import-Module NetSecurity -ErrorAction Stop
 $report.stage='reading';$report.windows_API_attempted=$true
 foreach($store in @('PersistentStore','ActiveStore')){$report.stores+=,(Invoke-HF12StoreComparison $store 4)}
 $report.diagnostic_completed=(@($report.stores|Where-Object{-not $_.completed}).Count -eq 0)
 $report.sampled_image_parity=($report.diagnostic_completed -and @($report.stores|Where-Object{-not $_.sampled_parity}).Count -eq 0)
 $report.stage='completed'
 if($report.sampled_image_parity){$exitCode=0}
}catch{
 $report.error_type=$_.Exception.GetType().Name
 $safe=@('windows_required','powershell_51_64bit_required','administrator_required','payload_hash_mismatch','local_non_reparse_folder_required')
 if($safe -ccontains [string]$_.Exception.Message){$report.error_code=[string]$_.Exception.Message}else{$report.error_code='diagnostic_failed_see_stage'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.error_code)
}finally{
 if($null -ne $dest){
  try{
   $bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 16))
   $stream=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
   Write-Host ('Report: '+$dest)
  }catch{Write-Host 'Report could not be written. Send the stage/error text above.';$exitCode=1}
 }
 Write-Host ('Diagnostic completed: '+$report.diagnostic_completed)
 Write-Host ('Sampled image parity: '+$report.sampled_image_parity)
 Write-Host 'No firewall/profile/VPN/journal change was requested. No network probe was requested.'
 Write-Host 'This does NOT qualify isolation, speed, no-leak, or fingerprint prevention.'
 Write-Host 'Return only the newly generated HF121-READONLY-PARITY-*.json file, even if comparison failed.'
}
exit $exitCode
