param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-context.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Observed-PrefillOptions','Prefill-Observed')){
 $f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq $name},$true);Check ($null -ne $f) ('function-'+$name);Invoke-Expression $f.Extent.Text
}
function Get-MonitorResultIPs([string]$Text){return @($Text -split ';'|Where-Object{$_ -match '^\d+\.\d+\.\d+\.\d+$'})}
$endpoint=[pscustomobject]@{program_id='p';pid=7;process_start_ticks='101';remote_ip='8.8.8.8'}
$event=[pscustomobject]@{kind='dns_query';program_id='p';pid=7;process_start_ticks='101';domain='query.example';query_results='8.8.8.8;1.1.1.1;'}
$old=[pscustomobject]@{program_id='p';pid=7;process_start_ticks='100';remote_ip='9.9.9.9'}
$script:liveFrame=[pscustomobject]@{endpoints=@($endpoint,$endpoint,$old);event_evidence=[pscustomobject]@{events=@($event)}}
$x=@(Observed-PrefillOptions $endpoint 'endpoint');Check ($x.Count -eq 1 -and $x[0].value -ceq '8.8.8.8') 'endpoint-only-exact-IP'
$x=@(Observed-PrefillOptions $event 'dns');Check ($x.Count -eq 3 -and $x[0].type -ceq 'domain') 'DNS-domain-and-IP-choice'
$x=@(Observed-PrefillOptions $endpoint 'process');Check ($x.Count -eq 2) 'process-dedup-and-domain'
Check (@($x|Where-Object{$_.value -ceq '9.9.9.9'}).Count -eq 0) 'reused-PID-old-birth-excluded'
$empty=[pscustomobject]@{program_id='unknown';pid=99;process_start_ticks='101'};Check (@(Observed-PrefillOptions $empty 'process').Count -eq 0) 'empty-process-no-invented-target'
function Field {
 $x=[pscustomobject]@{Text='';focused=$false};$x|Add-Member ScriptMethod Focus {$this.focused=$true};return $x
}
$target=Field;$whitelist=Field;$hostDomains=Field;$blackTab=[pscustomobject]@{name='black'};$policyTab=[pscustomobject]@{name='white'};$hostsTab=[pscustomobject]@{name='hosts'};$tabs=[pscustomobject]@{SelectedTab=$null};$status=[pscustomobject]@{Text=''}
$form=[pscustomobject]@{calls=0};$form|Add-Member ScriptMethod BringToFront {$this.calls++}
$tip=[pscustomobject]@{calls=0};$tip|Add-Member ScriptMethod SetToolTip {param($field,$message)$this.calls++}
$grid=[pscustomobject]@{SelectedRows=@([pscustomobject]@{Tag=$endpoint})}
# A running recording does not cause a save, stop or job submission. No backend command exists in this file.
$script:job=[pscustomobject]@{action='baseline_record'}
$script:staged=@();function Stage-ObservedDraft($Row,$Choice){$script:staged+=,$Choice}
Prefill-Observed $grid 'endpoint' 'blacklist'
Check ($script:staged.Count -eq 1 -and $script:staged[0].value -ceq '8.8.8.8' -and $target.Text -ceq '') 'IP-to-draft-route-not-input'
Check ($whitelist.Text -ceq '' -and $hostDomains.Text -ceq '') 'other-fields-not-touched'
Check ($script:job.action -ceq 'baseline_record') 'recording-job-not-replaced'
Prefill-Observed $grid 'endpoint' 'whitelist'
Check ($whitelist.Text -ceq '8.8.8.8' -and $tabs.SelectedTab -eq $policyTab) 'IP-to-white-field-only'
$domain=[pscustomobject]@{domain='only.example';query_results=''};$grid.SelectedRows=@([pscustomobject]@{Tag=$domain})
Prefill-Observed $grid 'dns' 'blacklist'
Check ($script:staged.Count -eq 2 -and $script:staged[1].type -ceq 'domain' -and $hostDomains.Text -ceq '') 'domain-to-shared-draft-route-no-write'
$whitelist.Text='';Prefill-Observed $grid 'dns' 'whitelist'
Check ($whitelist.Text -ceq 'only.example' -and $status.Text.Contains('فقط پیش‌نویس')) 'domain-to-white-draft-with-validator-limit'
$text=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-context.ps1'))
Check ($text -notmatch 'BeginOp|monitor_stage|observed_add|Set-Content|WriteAll|native_apply|hosts_apply|GetHostEntry') 'no-backend-file-or-network-action'
Check ($text.Contains('جایگزینی پیش‌نویس')) 'existing-draft-replacement-consent'
Check ($text.Contains('$sender.ClearSelection();if($e.RowIndex -ge 0')) 'header-right-click-clears-stale-selection'
$result=@{suite='observed-context-unsaved-transfer';passed=$true;assertions=$script:checks;environment='PowerShell 7 Linux; AST-extracted functions and fake controls';Windows_GUI_tested=$false;settings_written=$false;firewall_or_hosts_changed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/prefill-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
