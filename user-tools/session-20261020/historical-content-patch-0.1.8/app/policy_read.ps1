param([Parameter(Mandatory=$true)][string]$NamesBase64)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$stage='decode_rule_names'
$ruleKind=$null
$storeKind=$null
try {
 if($NamesBase64.Length -gt 4096 -or $NamesBase64 -cnotmatch '^[A-Za-z0-9+/]+={0,2}$'){throw 'argument_encoding_invalid'}
 $decoded=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($NamesBase64))
 # Windows PowerShell 5.1 emits the JSON array as a single pipeline object.
 # Direct assignment preserves the array without wrapping it in another @(...).
 $names=ConvertFrom-Json -InputObject $decoded
 if($names -isnot [array]){throw 'argument_count_invalid'}
 if($names.Count -ne 3){throw 'argument_count_invalid'}
 foreach($name in $names){if($name -cnotmatch '^SstpWhitelistApp-[a-f0-9]{32}-(guard|v4|v6)$'){throw 'argument_rule_name_invalid'}}
 $stage='sstp_identity'
 . (Join-Path $PSScriptRoot 'Identity.ps1')
 $binding=$null;$identity=InvokeReadOnlyIdentityInspection -Binding ([ref]$binding)
 $token=$null
 if($identity.passed -and $null -ne $binding){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$token=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($binding|ConvertTo-Json -Compress))))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 }
 $out=@()
 foreach($name in $names){
  $ruleKind=($name -split '-')[-1]
  if($name -cnotmatch '^SstpWhitelistApp-[a-f0-9]{32}-(guard|v4|v6)$'){throw 'name'}
  foreach($store in @('PersistentStore','ActiveStore')){
   $storeKind=$store;$stage='read_firewall_rule'
   $rr=@(Get-NetFirewallRule -PolicyStore $store -Name $name -ErrorAction Stop)
   if($rr.Count -ne 1){throw 'count'};$r=$rr[0]
   $stage='read_address_filter'
   $a=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   $stage='read_interface_type_filter'
   $i=@(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   $stage='read_application_filter'
   $p=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   $stage='read_port_filter'
   $t=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   $stage='read_service_filter'
   $v=@(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   $stage='read_interface_filter'
   $n=@(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
   if($a.Count -ne 1 -or $i.Count -ne 1 -or $p.Count -ne 1 -or $t.Count -ne 1 -or $v.Count -ne 1 -or $n.Count -ne 1){throw 'filters'}
   $stage='serialize_rule_view'
   $out+=,[ordered]@{name=$name;store=$store;enabled=[string]$r.Enabled;direction=[string]$r.Direction;action=[string]$r.Action;profile=[string]$r.Profile;source_type=[string]$r.PolicyStoreSourceType;primary_status=[string]$r.PrimaryStatus;enforcement_status=[string]$r.EnforcementStatus;remote=@($a[0].RemoteAddress|Sort-Object);local=@($a[0].LocalAddress);interface_type=[string]$i[0].InterfaceType;program=[string]$p[0].Program;protocol=[string]$t[0].Protocol;local_port=@($t[0].LocalPort);remote_port=@($t[0].RemotePort);service=[string]$v[0].Service;alias=@($n[0].InterfaceAlias)}
  }
 }
 $ruleKind=$null;$storeKind='ActiveStore';$stage='read_firewall_profiles'
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|ForEach-Object{[ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;default_outbound=[string]$_.DefaultOutboundAction}})
 [ordered]@{identity=$identity;session_fingerprint=$token;rules=$out;profiles=$profiles;scope='selected_owned_rules_only_not_full_policy_certification'}|ConvertTo-Json -Depth 8 -Compress
} catch {
 $err=$_;$type=$err.Exception.GetType().FullName
 if($type -cnotmatch '^[A-Za-z0-9_.+]{1,180}$'){$type='unavailable'}
 $code='powershell_read_failed'
 $msg=$err.Exception.Message
 if($msg -cin @('argument_encoding_invalid','argument_count_invalid','argument_rule_name_invalid','name','count','filters')){$code=$msg}
 [ordered]@{ok=$false;error=[ordered]@{code=$code;stage=$stage;rule_kind=$ruleKind;store=$storeKind;exception_type=$type;hresult=[int]$err.Exception.HResult;category=[string]$err.CategoryInfo.Category;raw_message_exported=$false}}|ConvertTo-Json -Depth 5 -Compress
 exit 1
}
