param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Audit.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'audit_model_check'};$script:checks++}
$r=[ordered]@{schema='sstp-audit-model-test-1';passed=$false;checks=0;network_settings_changed=$false}
try{
 $h=AuditHosts @('# comment','127.0.0.1 localhost','');Check ($h.noncomment_entry_lines -eq 1);Check $h.markers_balanced;Check ($h.known_list_aliases -eq 0)
 $h=AuditHosts @('# --- BLIZZARD-BLOCK START ---','0.0.0.0 rum.battle.net telemetry-in.battle.net # anything','# --- BLIZZARD-BLOCK END ---');Check ($h.known_list_aliases -eq 2);Check ($h.known_aliases_outside_markers -eq 0);Check ($h.lines_inside_markers -eq 1);Check $h.markers_balanced
 $h=AuditHosts @('0.0.0.0 level3.blizzard.com','::1 level3.blizzard.com');Check $h.level3_blizzard_sinkholed;Check ($h.known_aliases_outside_markers -eq 2)
 foreach($lines in @(@('# --- BLIZZARD-BLOCK START ---'),@('# --- BLIZZARD-BLOCK END ---'),@('# --- BLIZZARD-BLOCK START ---','# --- BLIZZARD-BLOCK START ---','# --- BLIZZARD-BLOCK END ---'))){$h=AuditHosts $lines;Check (-not $h.markers_balanced)}
 $h=AuditHosts @('1.2.3.4 private.example.org secret_machine','0.0.0.0 rum.battle.net');$json=$h|ConvertTo-Json;Check (-not $json.Contains('private.example'));Check (-not $json.Contains('1.2.3.4'));Check (-not $json.Contains('secret_machine'))
 $e=AuditSection {throw 'private_IP_1.2.3.4'};Check ($e.status -ceq 'unavailable');Check (-not (($e|ConvertTo-Json).Contains('private_IP')))
 $ok=AuditSection {[pscustomobject]@{n=3}};Check ($ok.status -ceq 'ok' -and $ok.data.n -eq 3)
 $root=Join-Path ([IO.Path]::GetTempPath()) ('audit-absent-'+[guid]::NewGuid().ToString('N'));$o=AuditOverlay $root;Check ($o.status -ceq 'absent');Check (-not [IO.Directory]::Exists($root))
 $r.passed=$true
}finally{$r.checks=$script:checks;if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}}
$r|ConvertTo-Json
if(-not $r.passed){exit 1};exit 0
