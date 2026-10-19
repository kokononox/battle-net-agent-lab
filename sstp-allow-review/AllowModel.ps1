Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Ranges.ps1')
function AllowHash([string]$Text){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function AllowProp($Object,[string]$Name){$p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value};return $null}
function AllowAny($Value){return $null -ne $Value -and (@($Value)-join ',') -ceq 'Any'}
function AllowEnum($Value,[string[]]$Known){$text=[string]$Value;if($Known -ccontains $text){return $text};return 'Unknown'}
function AllowTokens($Value,[string[]]$Known){$t=@(([string]$Value -split '[,\s]+'|Where-Object{$_}));if($t.Count -eq 0){return ,@('Unknown')};foreach($x in $t){if($Known -cnotcontains $x){return ,@('Unknown')}};return ,@($t|Sort-Object -Unique)}
function AllowBool($Value){if($null -eq $Value){return $null};if([string]$Value -ceq 'True'){return $true};if([string]$Value -ceq 'False'){return $false};return $null}
function AllowPorts($Value){
 $items=@();foreach($p in @($Value)){$t=[string]$p;if($t -cmatch '^\d{1,5}(-\d{1,5})?$' -or $t -cin @('Any','RPC','RPC-EPMap','IPHTTPSIn','IPHTTPSOut','Teredo')){$items+=,$t}else{$items+=,'Unknown'}};return ,$items
}
function AllowProgram($Application){
 $value=AllowProp $Application 'Program';$text=[string]$value;$kind='unknown';$known=$null
 if(AllowAny $value){$kind='any'}elseif($text -ceq 'System'){$kind='system'}elseif($text){
  $full=[Environment]::ExpandEnvironmentVariables($text);$root=$env:SystemRoot
  if($root -and $full.StartsWith(($root.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){$kind='windows_path'}else{$kind='other_path'}
  $base=[IO.Path]::GetFileName($full).ToLowerInvariant();if($kind -ceq 'windows_path' -and $base -cin @('svchost.exe','lsass.exe','services.exe','spoolsv.exe','msiexec.exe','searchindexer.exe','wuauclt.exe','backgroundtaskhost.exe','taskhostw.exe','wininit.exe','winlogon.exe','dllhost.exe','smartscreen.exe')){$known=$base}
 }
 $package=AllowProp $Application 'Package'
 [pscustomobject]@{kind=$kind;known_windows_basename=$known;program_sha256=(AllowHash $text);package_value_available=($null -ne $package);package_restricted=($null -ne $package -and -not [string]::IsNullOrWhiteSpace([string]$package) -and [string]$package -cne 'Any')}
}
function AllowAddresses($Value,$Context){
 $items=@($Value);$single4=0;$single6=0;$ranges=0;$prefixes=0;$unknown=0;$keywords=@();$server=0;$dns=0
 $known=@('Any','LocalSubnet','LocalSubnet4','LocalSubnet6','Internet','Intranet','DNS','DHCP','WINS','DefaultGateway','CaptivePortal','PlayToDevice','RemoteCorpNetwork')
 foreach($x in $items){
  $t=[string]$x;if($known -ccontains $t){$keywords+=,$t;continue}
  try{
   $a=ParseAddressInterval $t
   if($t.Contains('/')){$prefixes++}elseif($t.Contains('-')){$ranges++}elseif($a.bits -eq 32){$single4++}else{$single6++}
   if($a.low -eq $a.high){$key=[string]$a.bits+':'+$a.low.ToString();if($null -ne $Context.server -and $Context.server.ContainsKey($key)){$server++};if($null -ne $Context.dns -and $Context.dns.ContainsKey($key)){$dns++}}
  }catch{$unknown++}
 }
 [pscustomobject]@{entry_count=$items.Count;any=(AllowAny $Value);keywords=@($keywords|Sort-Object -Unique);ipv4_single_entries=$single4;ipv6_single_entries=$single6;cidr_entries=$prefixes;range_entries=$ranges;unparsed_entries=$unknown;matching_saved_legacy_server_entries=$server;matching_current_dns_server_entries=$dns;addresses_sha256=(AllowHash ((@($items|ForEach-Object{[string]$_}|Sort-Object))-join '|'));raw_addresses_exported=$false}
}
function AllowScope($InterfaceType,$Aliases){
 $types=AllowTokens $InterfaceType @('Any','Wired','Wireless','RemoteAccess')
 $remoteOnly=$types.Count -eq 1 -and $types[0] -ceq 'RemoteAccess'
 [pscustomobject]@{interface_types=$types;remote_access_type_only=$remoteOnly;alias_any=(AllowAny $Aliases);alias_count=@($Aliases).Count;alias_values_sha256=(AllowHash ((@($Aliases|ForEach-Object{[string]$_}|Sort-Object))-join '|'));non_vpn_excluded_by_interface_type=$remoteOnly;explicit_aliases_fully_reviewed=$false;candidate_for_non_vpn_review=(-not $remoteOnly)}
}
