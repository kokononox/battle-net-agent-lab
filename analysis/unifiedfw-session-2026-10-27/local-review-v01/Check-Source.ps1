param([string]$Root='/data/sstp-local-review-v01/package/SSTP-LOCAL-REVIEW-01')
$ErrorActionPreference='Stop';$checks=0;$parsed=0
$forbidden='^(Set-VpnConnection|Remove-VpnConnection|New-Net.*|Set-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Clear-Dns.*|Resolve-DnsName|Start-Service|Stop-Service|Set-ExecutionPolicy|Invoke-WebRequest|Invoke-RestMethod|Start-Process|Invoke-Expression|rasdial|reg)$'
foreach($f in Get-ChildItem -LiteralPath $Root -Filter '*.ps1'){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e)
 if($e.Count){throw 'parse_error'};$parsed++
 foreach($n in $a.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
  $name=$n.GetCommandName();$checks++
  if($name -match $forbidden -or $name -match 'NetFirewall'){throw ('unexpected_command:'+ $name)}
 }
}
$cs=[IO.File]::ReadAllText((Join-Path $Root 'RasIdentity.cs'))
$imports=@([regex]::Matches($cs,'private static extern uint ([A-Za-z0-9]+)\(')|ForEach-Object{$_.Groups[1].Value})
$expected=@('RasEnumConnectionsW','RasGetProjectionInfoW','ConvertInterfaceIndexToLuid','ConvertInterfaceLuidToIndex','ConvertInterfaceLuidToGuid')
if((($imports|Sort-Object)-join ',') -cne (($expected|Sort-Object)-join ',')){throw 'unexpected_native_API'}
if([regex]::Matches($cs,'DllImportSearchPath.System32').Count -ne 5){throw 'DLL_search_path_policy'}
foreach($name in @('Identity.ps1','IdentityPolicy.ps1','RasIdentity.cs')){
 $old=Join-Path '/data/sstp-012-inspection/Sstp-Whitelist' $name
 if((Get-FileHash $old).Hash -cne (Get-FileHash (Join-Path $Root $name)).Hash){throw 'legacy_reader_changed'}
}
@{parsed_files=$parsed;command_nodes_checked=$checks;forbidden_mutation_commands_found=$false;PInvoke_imports=$imports;System32_DLL_search_required=$true;legacy_helpers_unchanged=$true;Windows_execution_tested=$false}|ConvertTo-Json|Set-Content '/data/sstp-local-review-v01/source-checks.json'
Write-Host 'Source/API boundary checks passed.'
