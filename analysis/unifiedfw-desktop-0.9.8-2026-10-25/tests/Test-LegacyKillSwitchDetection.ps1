param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $Root 'lab/native.ps1'))
$m=[regex]::Match($source,"-match '(\(\?i\)WoWBlacklist[^']+)'");if(-not $m.Success){throw 'missing_detection_regex'};$pattern=$m.Groups[1].Value
$checks=0
foreach($name in @('SSTP Kill Switch','SstpKillSwitch','SstpIsolation','SstpWhitelist','WoWBlacklist')){if(('random-GUID '+$name) -notmatch $pattern){throw ('legacy_not_detected: '+$name)};$checks++}
foreach($name in @('UnifiedFW-LAB-ownsession','Ordinary App')){if($name -match $pattern){throw 'own_or_unrelated_misclassified'};$checks++}
if($source -notmatch 'legacy_rules_active_restore_old_tool_first'){throw 'admission_gate_missing'};$checks++
$result=@{suite='legacy-SSTP-killswitch-rule-detection';passed=$true;assertions=$checks;Windows_firewall_executed=$false;original_legacy_script_executed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/legacy-killswitch-detection-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
