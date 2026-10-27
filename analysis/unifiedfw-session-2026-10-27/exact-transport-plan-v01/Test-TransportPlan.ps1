$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Sstp.TransportPlan.ps1')
$script:checks=0
function Check($v,$m){$script:checks++;if(-not $v){throw $m}}
function Fixture{[pscustomobject][ordered]@{schema='sstp-endpoint-review-input-01';profile_guid='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';profile_scope='current_user';profile_owner_sid='S-1-5-21-100-200-300-1001';server='vpn.fixture.invalid';endpoint_ips=@('192.0.2.10','2001:db8::10')}}
$x=Fixture;$r=New-SstpExactTransportDraft $x
Check $r.input_valid 'valid draft'
foreach($k in @('plan_executable','ready_for_apply','firewall_mutation_requested','native_executor_implemented','no_leak_certified','external_DNS_exception_requested','server_name_rewrite_requested','TLS_validation_bypass_requested','physical_adapter_name_or_index_used')){Check ($r.$k -ceq $false) ('boundary '+$k)}
Check ($r.endpoint_approval_status -ceq 'not_verified' -and $r.blockers.Count -eq 8) 'never infer approval'
Check ($r.transport_templates.Count -eq 2) 'bounded per ip'
foreach($t in $r.transport_templates){foreach($pair in @(@('remote_port',443),@('protocol','TCP'),@('service','SstpSvc'),@('interface_alias','Any'),@('interface_type','Any'),@('enabled_by_this_module',$false))){Check ($t.($pair[0]) -ceq $pair[1]) ('template '+$pair[0])};Check ($t.program_path_token -ceq 'TRUSTED_WINDOWS_SYSTEM32_SVCHOST_REQUIRES_NATIVE_RESOLUTION') 'no guessed path'}
Check ($r.normalized_input.server -ceq $x.server) 'hostname preserved'
$x2=Fixture;$x2.endpoint_ips=@('2001:db8::10','192.0.2.10');$r2=New-SstpExactTransportDraft $x2;Check ($r2.input_digest -ceq $r.input_digest) 'set order digest'
foreach($field in @('profile_guid','profile_scope','profile_owner_sid','server','endpoint_ips')){
 $x=Fixture;switch($field){'profile_guid'{$x.profile_guid='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'};'profile_scope'{$x.profile_scope='all_users'};'profile_owner_sid'{$x.profile_owner_sid='S-1-5-21-100-200-300-1002'};'server'{$x.server='new.fixture.invalid'};'endpoint_ips'{$x.endpoint_ips=@('192.0.2.11')}}
 $b=New-SstpExactTransportDraft $x;Check ($b.input_valid -and $b.input_digest -cne $r.input_digest) ('bind digest '+$field)
}
foreach($bad in @('Any','*','192.0.2.0/24','192.0.2.10/32','2001:db8::/32','192.0.2.1-192.0.2.2','127.0.0.1','0.0.0.0','224.0.0.1','255.255.255.255','169.254.1.1','::','::1','ff02::1','fe80::1','fe80::1%11','::ffff:192.0.2.10','127.1','3221225994','192.0.002.10','192.0.2.10 ','https://vpn.invalid')){
 $x=Fixture;$x.endpoint_ips=@($bad);$b=New-SstpExactTransportDraft $x;Check (-not $b.input_valid -and $b.transport_templates.Count -eq 0 -and -not $b.ready_for_apply) ('reject '+$bad)
}
foreach($bad in @('*.invalid','https://vpn.invalid','vpn.invalid:443','a..invalid','-x.invalid','a`b.invalid','a.invalid/path','')){$x=Fixture;$x.server=$bad;$b=New-SstpExactTransportDraft $x;Check (-not $b.input_valid) 'bad server'}
foreach($pins in @(@(),@('192.0.2.10','192.0.2.10'),@('2001:db8::10','2001:0db8::10'),@(1..9|ForEach-Object{'192.0.2.'+$_}))){$x=Fixture;$x.endpoint_ips=$pins;$b=New-SstpExactTransportDraft $x;Check (-not $b.input_valid) 'bounds duplicates'}
$x=Fixture;$x.endpoint_ips='192.0.2.10';Check (-not (New-SstpExactTransportDraft $x).input_valid) 'string is not array'
$x=Fixture;$x.server='192.0.2.20';$x.endpoint_ips=@('192.0.2.10');Check ((New-SstpExactTransportDraft $x).code -ceq 'plan_literal_server_mismatch') 'literal mismatch'
$x.endpoint_ips=@('192.0.2.20');Check (New-SstpExactTransportDraft $x).input_valid 'literal exact'
$x=Fixture;$x|Add-Member -NotePropertyName approved -NotePropertyValue $true;Check (-not (New-SstpExactTransportDraft $x).input_valid) 'untrusted approval not accepted'
$x=Fixture;$x|Add-Member -NotePropertyName cache_correlated -NotePropertyValue $true;Check (-not (New-SstpExactTransportDraft $x).input_valid) 'cache proof not approval'
$x=Fixture;$x.profile_guid=[guid]$x.profile_guid;Check (-not (New-SstpExactTransportDraft $x).input_valid) 'strict type'
$x=Fixture;$x.profile_guid=[guid]::Empty.ToString('D');Check (-not (New-SstpExactTransportDraft $x).input_valid) 'empty guid'
$x=Fixture;$x.profile_scope='CurrentUser';Check (-not (New-SstpExactTransportDraft $x).input_valid) 'scope exact'
$x=Fixture;$x.profile_owner_sid='user';Check (-not (New-SstpExactTransportDraft $x).input_valid) 'owner required'
# AST allowlist: this module must remain pure and have no filesystem/network/native executor.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Sstp.TransportPlan.ps1'),[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'parse'
$allowed=@('Set-StrictMode','ConvertTo-SstpPlanIP','ConvertTo-SstpPlanServer','ForEach-Object','Sort-Object','ConvertTo-Json')
foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){Check ($node.GetCommandName() -cin $allowed) ('non pure command '+$node.GetCommandName())}
$v=[pscustomobject]@{schema='sstp-transport-plan-model-01';assertions=$script:checks;passed=$true;native_Windows_API_executed=$false;firewall_mutated=$false;executor_implemented=$false;ready_for_apply=$false}
$v|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'MODEL-RESULTS.json') -Encoding UTF8
Write-Host ('PASS '+$script:checks+' assertions')
