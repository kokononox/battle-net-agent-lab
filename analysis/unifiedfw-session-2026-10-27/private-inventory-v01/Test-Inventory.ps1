param([string]$Root=(Join-Path $PSScriptRoot 'package/UFW-PRIVATE-INVENTORY-01'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'InventoryCore.ps1');$script:n=0
function Check($ok,$name){if(-not $ok){throw ('test_failed_'+$name)};$script:n++}
function Run-Case([string]$mode){
 $script:mode=$mode;$script:rulesCalls=0;$script:actorCalls=0;$script:saves=0;$script:saved=$null
 $ops=@{
  Confirm={if($script:mode -ceq 'confirm_error'){throw 'PRIVATE_EXCEPTION'};if($script:mode -ceq 'cancel'){return $false};if($script:mode -ceq 'truthy'){return 1};return $true}
  Actor={$script:actorCalls++;if($script:mode -ceq 'actor_changed' -and $script:actorCalls -gt 1){return 'PRIVATE_ACTOR_OTHER'};return 'PRIVATE_ACTOR'}
  Clock={return 'PRIVATE_TIME'}
  Profiles={param($store)if($script:mode -ceq 'profile_error'){throw 'PRIVATE_EXCEPTION'};foreach($name in @('Domain','Private','Public')){if($script:mode -ceq 'profile_shape' -and $name -ceq 'Public'){continue};[pscustomobject]@{Name=$name;Enabled='True';DefaultOutboundAction='Block'}}}
  Rules={param($store)$script:rulesCalls++;if($script:mode -ceq 'rule_error'){throw 'PRIVATE_EXCEPTION'};if($script:mode -ceq 'empty'){return};foreach($name in @('PRIVATE_ALPHA','PRIVATE_BETA')){[pscustomobject]@{Name=$(if($script:mode -ceq 'ambiguous'){'PRIVATE_DUPLICATE'}else{$name});Enabled=$(if($script:mode -ceq 'headers_changed' -and $script:rulesCalls -eq 3){'False'}else{'True'});Direction='Outbound';Action='Allow';PolicyStoreSourceType=$(if($name -ceq 'PRIVATE_ALPHA'){'Local'}else{'GroupPolicy'})}}}
  Filters={param($kind,$r)if($script:mode -ceq 'filter_error'){throw 'PRIVATE_EXCEPTION'};if($script:mode -ceq 'filter_zero'){return};$v=[pscustomobject]@{kind=$kind;Name='PRIVATE_FILTER';Address='192.0.2.99';Path='C:\PRIVATE_USER\app.exe'};$v;if($script:mode -ceq 'filter_duplicate'){$v}}
  Serialize={param($v)if($script:mode -ceq 'serialize_error'){throw 'ufw_inventory_unsupported_value_type'};return $v}
  Save={param($d)$script:saves++;$script:saved=$d;if($script:mode -ceq 'save_error'){throw 'PRIVATE_EXCEPTION'};[pscustomobject]@{readback_verified=($script:mode -cne 'save_unverified')}}
  Progress={param($count)}
  CheckTime={if($script:mode -ceq 'timeout'){throw 'ufw_inventory_time_cap'}}
 }
 if($mode -ceq 'missing_adapter'){$ops.Remove('Save')}
 return Invoke-UfwInventoryCapture $ops
}
$cases=[ordered]@{success='ufw_inventory_private_snapshot_saved_not_apply_authority';empty='ufw_inventory_private_snapshot_saved_not_apply_authority';cancel='ufw_inventory_cancelled_no_snapshot';truthy='ufw_inventory_cancelled_no_snapshot';confirm_error='ufw_inventory_unavailable';profile_error='ufw_inventory_unavailable';profile_shape='ufw_inventory_profile_shape';rule_error='ufw_inventory_unavailable';ambiguous='ufw_inventory_rule_identity_ambiguous';filter_error='ufw_inventory_unavailable';filter_zero='ufw_inventory_filter_cardinality';filter_duplicate='ufw_inventory_filter_cardinality';serialize_error='ufw_inventory_unsupported_value_type';actor_changed='ufw_inventory_actor_changed';headers_changed='ufw_inventory_headers_changed';save_error='ufw_inventory_unavailable';save_unverified='ufw_inventory_readback_unverified';timeout='ufw_inventory_time_cap';missing_adapter='ufw_inventory_adapter_missing'}
foreach($mode in $cases.Keys){
 $r=Run-Case $mode;$text=$r|ConvertTo-Json -Depth 24
 Check ($r.code -ceq $cases[$mode]) ('code_'+$mode)
 Check (-not ($text -cmatch 'PRIVATE_|192\.0\.2\.99|C:\\\\')) ('privacy_'+$mode)
 Check (-not $r.ready_for_apply -and -not $r.target_execution_authorized -and -not $r.whole_WFP_inventory_verified -and -not $r.native_restore_qualified -and -not $r.filter_stability_verified) ('no_authority_'+$mode)
 if($mode -cin @('success','empty','save_error','save_unverified')){Check ($script:saves -eq 1 -and $r.private_write_attempted) ('write_attempt_'+$mode)}else{Check ($script:saves -eq 0 -and -not $r.private_write_attempted) ('no_write_'+$mode)}
 if($mode -ceq 'success'){
  Check ($r.completed -and $r.private_snapshot_readback_verified -and $r.stores_read -eq 2 -and $r.rules_read -eq 4 -and $r.filter_objects_read -eq 28 -and $r.header_rechecks -eq 2) 'success_counts'
  Check ($r.origins.source_counts.Local -eq 1 -and $r.origins.source_counts.GroupPolicy -eq 1 -and $r.origins.unique_local_name_candidates -eq 1) 'origin_counts'
  Check (-not $r.origins.candidate_is_semantic_equivalence -and -not $r.origins.candidate_is_write_authority) 'name_not_authority'
  Check ($script:saved.actor_sid -ceq 'PRIVATE_ACTOR' -and $script:saved.stores.Count -eq 2 -and $script:saved.stores[0].rules[0].associated_filters.PSObject.Properties.Name.Count -eq 7) 'private_payload_preserved'
 }
}
# Test a bounded CIM-like collection without pretending Linux executed the Windows MI API.
Add-Type @'
using System;using System.Collections;using System.Collections.Generic;
public class UfwFakeProperty {public string Name;public string CimType;public object Value;public UfwFakeProperty(string n,string t,object v){Name=n;CimType=t;Value=v;}}
public class UfwFakeProperties:IEnumerable {public List<UfwFakeProperty> Items=new List<UfwFakeProperty>();public UfwFakeProperty this[string s]{get{return Items.Find(x=>x.Name==s);}}public IEnumerator GetEnumerator(){return Items.GetEnumerator();}}
public class UfwFakeSystem {public string ClassName="FixtureClass";public string Namespace="FixtureNamespace";}
public class UfwFakeCim {public UfwFakeProperties CimInstanceProperties=new UfwFakeProperties();public UfwFakeSystem CimSystemProperties=new UfwFakeSystem();}
'@
$v=New-Object UfwFakeCim;$v.CimInstanceProperties.Items.Add((New-Object UfwFakeProperty('Z','String','PRIVATE_STRING')));$v.CimInstanceProperties.Items.Add((New-Object UfwFakeProperty('A','UInt32',[uint32]42)))
$b=[pscustomobject]@{nodes=0};$s=ConvertTo-UfwInventoryValue $v 0 $b
Check (($s.properties.PSObject.Properties.Name -join ',') -ceq 'A,Z') 'stable_cim_property_order'
Check ($s.properties.A.value -eq 42 -and $s.properties.Z.value -ceq 'PRIVATE_STRING' -and $s.properties.A.cim_type -ceq 'UInt32') 'typed_property_preserved'
foreach($x in @('text',$true,[uint64]18446744073709551615,[double]1.5,[datetime]::UtcNow,[timespan]::FromSeconds(2),[DayOfWeek]::Monday)){$b=[pscustomobject]@{nodes=0};$s=ConvertTo-UfwInventoryValue $x 0 $b;Check ($null -ne $s) 'supported_value'}
$b=[pscustomobject]@{nodes=0};$array=ConvertTo-UfwInventoryValue @('x','y') 0 $b;Check ($array.Count -eq 2) 'array_preserved'
foreach($x in @([double]::NaN,[double]::PositiveInfinity,[pscustomobject]@{unknown='x'})){$failed=$false;try{$b=[pscustomobject]@{nodes=0};$s=ConvertTo-UfwInventoryValue $x 0 $b}catch{$failed=$true};Check $failed 'unsupported_value_refused'}
$b=[pscustomobject]@{nodes=1000000};$failed=$false;try{$s=ConvertTo-UfwInventoryValue 'x' 0 $b}catch{$failed=$true};Check $failed 'node_budget'
$b=[pscustomobject]@{nodes=0};$failed=$false;try{$s=ConvertTo-UfwInventoryValue 'x' 13 $b}catch{$failed=$true};Check $failed 'depth_budget'
# Real Linux file IO with unchanged journal helpers; does not qualify native Windows ACLs.
$module=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-inventory-test-'+[guid]::NewGuid().ToString('N'))
try{
 $io=& $module {param($root,$temp)
  . (Join-Path $root 'InventoryCore.ps1');. (Join-Path $root 'InventoryEntry.ps1');$script:InventoryTestRoot=$temp
  function Get-UfwInventoryRoot{return $script:InventoryTestRoot}
  $data=[pscustomobject]@{schema='test';private='PRIVATE_SENTINEL'};$back=Save-UfwInventoryPrivate $data
  $files=@(Get-ChildItem -LiteralPath $temp -Recurse -Filter private-policy-snapshot.json);$en=Get-Content -LiteralPath $files[0].FullName -Raw|ConvertFrom-Json
  $collision=$false;try{$f=Open-UfwPrivateJournalFile $files[0].FullName ([IO.FileMode]::CreateNew);$f.Dispose()}catch{$collision=$true}
  [pscustomobject]@{verified=$back.readback_verified;file_count=$files.Count;hash_ok=($en.sha256 -ceq (Get-UfwJournalHash $en.payload));collision_refused=$collision;data_ok=((ConvertFrom-Json $en.payload).private -ceq 'PRIVATE_SENTINEL')}
 } $Root $temp
 Check ($io.verified -and $io.file_count -eq 1 -and $io.hash_ok -and $io.data_ok -and $io.collision_refused) 'real_private_file_roundtrip'
}finally{Remove-Module $module.Name -Force;if([IO.Directory]::Exists($temp)){[IO.Directory]::Delete($temp,$true)}}
foreach($file in @(Get-ChildItem -LiteralPath $Root -Filter *.ps1)){
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parse_'+$file.Name)
 foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){$name=$cmd.GetCommandName();if($null -ne $name){Check ($name -notmatch '^(Set-NetFirewall|New-NetFirewall|Remove-NetFirewall|Disable-NetFirewall|Enable-NetFirewall|Start-Process|Invoke-Expression|Clear-EventLog|auditpol|netsh|wevtutil|Set-ExecutionPolicy)') ('readonly_'+$name)}}
}
$report=[ordered]@{suite='private-inventory-01';passed=$true;assertions=$script:n;callback_cases=$cases.Count;real_Linux_file_IO_executed=$true;native_Windows_CIM_filters_UI_ACL_executed=$false;firewall_change_requested=$false;ready_for_apply=$false;native_restore_qualified=$false}
$report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence/model-tests.json') -Encoding UTF8
$report|ConvertTo-Json -Compress
