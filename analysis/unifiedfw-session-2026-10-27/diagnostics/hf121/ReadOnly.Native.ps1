# Exact function copies from validated HF1.1 source; no mutation functions imported.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function UJson($v){ConvertTo-Json -InputObject $v -Depth 64 -Compress}
function UEqual($a,$b){(UJson $a) -ceq (UJson $b)}
$script:UParts=[ordered]@{address='Get-NetFirewallAddressFilter';application='Get-NetFirewallApplicationFilter';interface='Get-NetFirewallInterfaceFilter';interface_type='Get-NetFirewallInterfaceTypeFilter';port='Get-NetFirewallPortFilter';security='Get-NetFirewallSecurityFilter';service='Get-NetFirewallServiceFilter'}
function URaw($Cim){
 $out=[ordered]@{};$ignore=@('Status','PrimaryStatus','StatusCode','EnforcementStatus','OperationalStatus','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus')
 foreach($p in @($Cim.CimInstanceProperties|Sort-Object Name)){
  if($p.Name -in $ignore){continue};if($null -eq $p.Value){$out[$p.Name]=$null}
  elseif($p.Value -is [array]){$out[$p.Name]=@($p.Value|ForEach-Object{[string]$_})}
  elseif($p.Value -is [string] -or $p.Value.GetType().IsPrimitive -or $p.Value.GetType().IsEnum -or $p.Value -is [datetime] -or $p.Value -is [guid]){$out[$p.Name]=[string]$p.Value}
  else{throw 'unsupported_cim_image_type'}
 };return [pscustomobject]$out
}
function UGetRule([string]$Name,[string]$Store='PersistentStore'){
 # Enumerate then exact equality: wildcard -Name must not interpret untrusted input.
 $rows=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
 if($rows.Count -gt 1){throw 'duplicate_rule_identity'};if($rows.Count -eq 0){return $null};return $rows[0]
}
function UReadNative([string]$Name,[string]$Store='PersistentStore'){
 $r=UGetRule $Name $Store;if($null -eq $r){return $null}
 if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'not_local_rule'}
 $image=[ordered]@{rule=(URaw $r)}
 foreach($part in $script:UParts.Keys){$f=@($r|& $script:UParts[$part] -ErrorAction Stop);if($f.Count -ne 1){throw 'filter_coverage'};$raw=URaw $f[0];if([string]$raw.InstanceID -cne $Name){throw 'filter_identity'};$image[$part]=$raw}
 return [pscustomobject]$image
}