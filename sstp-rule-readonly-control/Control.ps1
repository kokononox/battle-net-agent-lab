param([Parameter(Mandatory=$true)][string]$OutputPath)
# CI-only observation; no firewall mutations or imported mutation modules.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function ControlCim($Object) {
 $out=[ordered]@{};$ignored=@('Status','PrimaryStatus','StatusCode','EnforcementStatus','OperationalStatus','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus')
 foreach($p in @($Object.CimInstanceProperties | Sort-Object Name)) {
  if ($p.Name -in $ignored) { continue }
  if ($null -eq $p.Value) { $out[$p.Name]=$null }
  elseif ($p.Value -is [array]) { $out[$p.Name]=@($p.Value | ForEach-Object {[string]$_} | Sort-Object) }
  else { $out[$p.Name]=[string]$p.Value }
 };[pscustomobject]$out
}
function CaptureRules {
 $map=@{}
 foreach($r in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)) {
  $name=[string]$r.Name
  if ([string]::IsNullOrWhiteSpace($name) -or $map.ContainsKey($name)) { throw 'control_rule_identity' }
  $map[$name]=ControlCim $r
 }
 if ($map.Count -lt 1 -or $map.Count -gt 10000) { throw 'control_inventory_bounds' };return $map
}
function CaptureProfiles {
 $out=@();foreach($store in @('PersistentStore','ActiveStore')) { $out+=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name | Select-Object @{N='store';E={$store}},Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,AllowLocalIPsecRules) };ConvertTo-Json -InputObject $out -Depth 4 -Compress
}
function TextKind($Value) {
 if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) { return 'empty' }
 if ([string]$Value -match '^@') { return 'resource_reference' };return 'literal'
}
function ControlDiff($Before,$After) {
 $added=0;$removed=0;$modified=0;$fields=@();$transitions=@{};$changed=@()
 foreach($name in $Before.Keys) {
  if (-not $After.ContainsKey($name)) { $removed++;$changed+=,$name;continue }
  if (($Before[$name] | ConvertTo-Json -Depth 6 -Compress) -ceq ($After[$name] | ConvertTo-Json -Depth 6 -Compress)) { continue }
  $modified++;$changed+=,$name
  foreach($field in @((@($Before[$name].PSObject.Properties.Name)+@($After[$name].PSObject.Properties.Name)) | Sort-Object -Unique)) {
   $bp=$Before[$name].PSObject.Properties[$field];$ap=$After[$name].PSObject.Properties[$field]
   if ($null -eq $bp -or $null -eq $ap -or (ConvertTo-Json -InputObject $bp.Value -Depth 4 -Compress) -cne (ConvertTo-Json -InputObject $ap.Value -Depth 4 -Compress)) {
    $fields+=,$field
    if ($field -in @('Description','DisplayGroup','DisplayName')) {
     $bv=$null;$av=$null;if ($null -ne $bp) { $bv=$bp.Value };if ($null -ne $ap) { $av=$ap.Value }
     $key=$field+'|'+(TextKind $bv)+'|'+(TextKind $av)
     if (-not $transitions.ContainsKey($key)) { $transitions[$key]=0 };$transitions[$key]++
    }
   }
  }
 }
 foreach($name in $After.Keys) { if (-not $Before.ContainsKey($name)) { $added++;$changed+=,$name } }
 $kinds=@();foreach($key in @($transitions.Keys | Sort-Object)) { $parts=$key.Split('|');$kinds+=,[pscustomobject][ordered]@{property_name=$parts[0];before_kind=$parts[1];after_kind=$parts[2];item_count=$transitions[$key]} }
 # Changed identities stay memory-only; only the anonymous aggregate goes to the receipt.
 [pscustomobject]@{summary=[pscustomobject][ordered]@{added=$added;removed=$removed;modified=$modified;property_names=@($fields | Sort-Object -Unique);display_kind_transitions=$kinds};changed_names=$changed}
}
$watch=[Diagnostics.Stopwatch]::StartNew();$samples=@();$union=@{};$complete=$false;$errorCode=$null;$pureChecks=0
try {
 $a=@{one=[pscustomobject][ordered]@{Enabled='1';DisplayName='old'}}
 $b=@{one=[pscustomobject][ordered]@{Enabled='1';DisplayName='new'}}
 if ((ControlDiff $a $a).summary.modified -ne 0) { throw 'control_fixture' };$pureChecks++
 $d=ControlDiff $a $b;if ($d.summary.modified -ne 1 -or ($d.summary.property_names -join ',') -cne 'DisplayName') { throw 'control_fixture' };$pureChecks++
 $b.one.Enabled='2';$d=ControlDiff $a $b;if (($d.summary.property_names -join ',') -cne 'DisplayName,Enabled') { throw 'control_fixture' };$pureChecks++
 $d=ControlDiff $a @{two=$a.one};if ($d.summary.added -ne 1 -or $d.summary.removed -ne 1) { throw 'control_fixture' };$pureChecks++
 if ((TextKind '@fixture.dll,-1') -cne 'resource_reference' -or (TextKind '') -cne 'empty' -or (TextKind 'label') -cne 'literal') { throw 'control_fixture' };$pureChecks++
 $baseline=CaptureRules;$profileBaseline=CaptureProfiles;$previous=$baseline
 for($seq=0;$seq -le 12;$seq++) {
  # seq0 baseline; seq1 immediate re-read; seq2..12 at 60..660 seconds.
  if ($seq -ge 2) { $remaining=(($seq-1)*60)-$watch.Elapsed.TotalSeconds;if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) } }
  $now=$baseline;if ($seq -gt 0) { $now=CaptureRules }
  $d=ControlDiff $baseline $now;$p=ControlDiff $previous $now
  foreach($name in @($d.changed_names)+@($p.changed_names)) { $union[$name]=$true }
  $samples+=,[pscustomobject][ordered]@{sequence=$seq;elapsed_seconds=[int][Math]::Floor($watch.Elapsed.TotalSeconds);rule_count=$now.Count;baseline_delta=$d.summary;previous_delta=$p.summary;profiles_equal_to_baseline=((CaptureProfiles) -ceq $profileBaseline)}
  $previous=$now;Write-Host ('control_sample_completed_'+$seq)
 }
 if ($samples.Count -ne 13 -or $watch.Elapsed.TotalSeconds -lt 660) { throw 'control_measurement_incomplete' };$complete=$true
} catch { $errorCode='control_read_failed';Write-Host 'control_read_failed' }
$receipt=[ordered]@{schema='sstp-rule-readonly-control-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;completed=$complete;pure_checks=$pureChecks;error_code=$errorCode;elapsed_seconds=[int][Math]::Floor($watch.Elapsed.TotalSeconds);changed_rule_union_count=$union.Count;samples=$samples;tool_firewall_mutations=$false;fixture_rules_created=$false;dns_queried=$false;user_device_tested=$false;enforcement_tested=$false;ready_for_user_apply=$false}
[IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
if (-not $complete) { exit 1 };exit 0
