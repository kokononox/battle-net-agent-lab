param([string]$Root=(Join-Path $PSScriptRoot 'package/UFW-ALLOW-REVIEW-01'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'EndpointReference.ps1');. (Join-Path $Root 'AllowReview.ps1');. (Join-Path $PSScriptRoot 'GuardReference.ps1')
$n=0
function Check($ok,[string]$label){if(-not $ok){throw ('test_failed: '+$label)};$script:n++}
function Get-UfwRuntimeSystemHostPath{return 'C:\Windows\System32\svchost.exe'}
function Get-NetFirewallProfile{param($PolicyStore,$ErrorAction)foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;Enabled='True';DefaultOutboundAction='Block'}}}
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction)return $script:rule}
function Get-NetFirewallServiceFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$script:services}}
function Get-NetFirewallApplicationFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$script:apps}}
function Get-NetFirewallPortFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$script:ports}}
function Get-NetFirewallAddressFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$script:addresses}}
function Fixture([int]$bits){
 $script:rule=[pscustomobject]@{Enabled='True';Direction='Outbound';Action='Allow';Name='PRIVATE_RULE_SENTINEL';RemoteDynamicKeywordAddresses=$(if($bits -band 32){@('PRIVATE_KEYWORD')}else{@()})}
 $script:services=@([pscustomobject]@{Service=$(if($bits -band 1){'Any'}else{'SstpSvc'})})
 $script:apps=@([pscustomobject]@{Program=$(if($bits -band 2){'C:\PRIVATE_USER\other.exe'}else{'C:\Windows\System32\svchost.exe'})})
 $script:ports=@([pscustomobject]@{Protocol=$(if($bits -band 4){'UDP'}else{'TCP'});RemotePort=$(if($bits -band 8){'Any'}else{'443'})})
 $script:addresses=@([pscustomobject]@{RemoteAddress=$(if($bits -band 16){@('Any')}else{@('192.0.2.8')})})
 if($bits -band 64){$script:services=@()};if($bits -band 128){$script:ports=@()};if($bits -band 256){$script:addresses=@()}
}
for($bits=0;$bits -lt 512;$bits++){
 Fixture $bits
 $c=Get-UfwAllowClassification $rule $services $apps $ports $addresses (Get-UfwRuntimeSystemHostPath)
 $accepted=$false;try{$g=Get-UfwRuntimeFirewallGuard;$accepted=$true}catch{}
 Check ($c.matches_runtime_transport_predicate -eq $accepted) ('reference parity '+$bits)
 Check ($c.matches_runtime_transport_predicate -eq ($bits -eq 0)) ('expected predicate '+$bits)
 Check (($c.reasons.Count -eq 0) -eq $accepted) ('reason completeness '+$bits)
}
Fixture 0
foreach($text in @('8.8.8.8','10.0.0.1','::ffff:8.8.8.8','2001:db8::1','127.0.0.1','0.0.0.0','169.254.2.1','224.0.0.1','::','::1','fe80::1','ff02::1','fe80::1%3','Any','LocalSubnet','8.8.8.0/24','8.8.8.8-8.8.8.9','PRIVATE_ADDRESS')){
 $script:addresses=@([pscustomobject]@{RemoteAddress=@($text)})
 $c=Get-UfwAllowClassification $rule $services $apps $ports $addresses (Get-UfwRuntimeSystemHostPath);$accepted=$false;try{$g=Get-UfwRuntimeFirewallGuard;$accepted=$true}catch{}
 Check ($c.matches_runtime_transport_predicate -eq $accepted) ('endpoint parity '+$text)
}
foreach($which in @('services','apps','ports','addresses')){
 Fixture 0;$value=Get-Variable -Name $which -ValueOnly;Set-Variable -Name $which -Value @($value[0],$value[0]) -Scope Script
 $c=Get-UfwAllowClassification $rule $services $apps $ports $addresses (Get-UfwRuntimeSystemHostPath);Check (-not $c.matches_runtime_transport_predicate) ('duplicate filter '+$which)
}
Fixture 0
$script:mode='mixed'
$ops=@{
 Profiles={if($script:mode -ceq 'profile_error'){throw 'PRIVATE_EXCEPTION'};if($script:mode -ceq 'bad_profile'){[pscustomobject]@{Name='Public';Enabled='False';DefaultOutboundAction='Allow'}}else{Get-NetFirewallProfile}}
 Rules={if($script:mode -ceq 'rules_error'){throw 'PRIVATE_EXCEPTION'};if($script:mode -ceq 'rule_cap'){for($i=0;$i -lt 32769;$i++){$script:rule}}elseif($script:mode -ceq 'empty'){}else{
 foreach($id in 0..2){[pscustomobject]@{Id=$id;Enabled='True';Direction='Outbound';Action='Allow';Name='PRIVATE_RULE_SENTINEL';RemoteDynamicKeywordAddresses=@()}}
 [pscustomobject]@{Id=3;Enabled='False';Direction='Outbound';Action='Allow'};[pscustomobject]@{Id=4;Enabled='True';Direction='Inbound';Action='Allow'};[pscustomobject]@{Id=5;Enabled='True';Direction='Outbound';Action='Block'}
 }}
 HostPath={Get-UfwRuntimeSystemHostPath}
 Service={param($r)if($script:mode -ceq 'filter_error' -and $r.Id -eq 2){throw 'PRIVATE_EXCEPTION'};[pscustomobject]@{Service=$(if($r.Id -eq 0){'SstpSvc'}else{'Any'})}}
 App={param($r)[pscustomobject]@{Program=$(if($r.Id -eq 0){Get-UfwRuntimeSystemHostPath}else{'C:\PRIVATE_USER\other.exe'})}}
 Port={param($r)[pscustomobject]@{Protocol='TCP';RemotePort='443'}}
 Address={param($r)[pscustomobject]@{RemoteAddress=@('192.0.2.8')}}
}
foreach($mode in @('mixed','empty','bad_profile','filter_error','profile_error','rules_error','rule_cap')){
 $script:mode=$mode;$r=Invoke-UfwAllowReview $ops
 $serialized=$r|ConvertTo-Json -Depth 12
 Check (-not ($serialized -cmatch 'PRIVATE_|192\.0\.2\.8|Windows|C:\\')) ('privacy '+$mode)
 Check (-not $r.runtime_execution_authorized -and -not $r.no_leak_certified -and -not $r.snapshot_atomic) ('no authority '+$mode)
 switch($mode){
 'mixed'{Check ($r.completed -and $r.rules_examined -eq 3 -and $r.total_rules_observed -eq 6 -and $r.transport_predicate_matches -eq 1 -and $r.runtime_predicate_mismatches -eq 2) 'mixed counts';Check ($r.reason_counts.service_not_exact_sstpsvc -eq 2 -and $r.reason_counts.application_not_exact_system_svchost -eq 2) 'overlap counts'}
 'empty'{Check ($r.completed -and $r.runtime_gate_observation_matches -and $r.enabled_outbound_allow_rules -eq 0) 'empty result'}
 'bad_profile'{Check ($r.completed -and -not $r.profile_gate_matches -and $r.code -ceq 'ufw_allow_review_profile_gate_mismatch') 'bad profiles'}
 'filter_error'{Check (-not $r.completed -and $r.filter_reads_indeterminate -eq 1 -and $r.runtime_predicate_mismatches -eq 1 -and -not $r.runtime_gate_observation_matches) 'filter failures distinct'}
 'profile_error'{Check (-not $r.completed -and $r.code -ceq 'ufw_allow_review_read_unavailable') 'profile exception sanitized'}
 'rules_error'{Check (-not $r.completed -and $r.code -ceq 'ufw_allow_review_read_unavailable') 'rule exception sanitized'}
 'rule_cap'{Check (-not $r.completed -and $r.code -ceq 'ufw_allow_review_rule_cap') 'cap'}
 }
}
foreach($f in Get-ChildItem -LiteralPath $Root -Filter *.ps1){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors);Check ($errors.Count -eq 0) ('parse '+$f.Name)
 foreach($cmd in $ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)){$name=$cmd.GetCommandName();if($null -ne $name){Check ($name -notmatch '^(Set-NetFirewall|New-NetFirewall|Remove-NetFirewall|Disable-NetFirewall|Enable-NetFirewall|Start-Process|Invoke-Expression|Clear-EventLog|auditpol|netsh|wevtutil|Set-ExecutionPolicy)') ('readonly '+$name)}}
 Check (-not ([IO.File]::ReadAllText($f.FullName) -match 'Diagnostics\.Process|AuditSetSystemPolicy|EventLogReader|Invoke-WebRequest|ConnectAsync')) ('no side effects '+$f.Name)
}
$report=[ordered]@{suite='allow-review-01';passed=$true;assertions=$n;exhaustive_predicate_combinations=512;reference_endpoint_cases=18;aggregate_cases=7;Windows_native_executed=$false;firewall_writes_present=$false;audit_writes_present=$false;runtime_execution_authorized=$false}
$report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence/model-tests.json') -Encoding UTF8
$report|ConvertTo-Json -Compress
