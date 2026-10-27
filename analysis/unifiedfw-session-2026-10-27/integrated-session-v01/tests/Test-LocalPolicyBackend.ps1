param([string]$SourceRoot,[string]$JournalModule,[string]$InventoryCore)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module $JournalModule -Force -PassThru -DisableNameChecking
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-native-backend-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try{
 $report=& $m {
  param($src,$root,$inv)
  . $inv
  foreach($file in @('Ufw.UnifiedSession.ps1','StorageBridge.ps1','SemanticComparison.ps1','NativePolicyIO.ps1','LocalPolicyBackend.ps1')){. (Join-Path $src $file)}
  $script:BackendChecks=0
  function Check($v,$name){if(-not $v){throw ('backend_test_'+$name)};$script:BackendChecks++}
  function Throws($block,$code){$msg='';try{& $block|Out-Null}catch{$msg=$_.Exception.GetBaseException().Message};Check ($msg -ceq $code) $code}
  function Get-UfwUnifiedStorageRoot{return $script:TestBackendRoot}
  function Record($name,$enabled,$action,$direction,$source){
   $p=[ordered]@{InstanceID=[pscustomobject]@{cim_type='String';value=$name};Enabled=[pscustomobject]@{cim_type='UInt16';value=$(if($enabled -ceq 'True'){1}else{2})};Action=[pscustomobject]@{cim_type='UInt16';value=$(if($action -ceq 'Allow'){2}else{4})};Direction=[pscustomobject]@{cim_type='UInt16';value=$(if($direction -ceq 'Outbound'){2}else{1})};UnknownPolicy=[pscustomobject]@{cim_type='String';value='PRIVATE_UNKNOWN'}}
   $filters=[ordered]@{};foreach($kind in @('Address','Application','Interface','InterfaceType','Port','Security','Service')){$filters[$kind]=[pscustomobject]@{class=('MSFT_'+$kind);namespace='root/StandardCimv2';properties=[pscustomobject]@{Opaque=[pscustomobject]@{cim_type='String';value='PRIVATE_FILTER'}}}}
   [pscustomobject]@{name=$name;enabled=$enabled;action=$action;direction=$direction;source_type=$source;source_path='PRIVATE_LOCAL_STORE';record=[pscustomobject]@{rule=[pscustomobject]@{class='MSFT_NetFirewallRule';namespace='root/StandardCimv2';properties=[pscustomobject]$p};associated_filters=[pscustomobject]$filters}}
  }
  function Snapshot {
   $profiles=@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;enabled='True';outbound='Block';record=[pscustomobject]@{opaque='PRIVATE_PROFILE'}}})
   $local=@((Record 'PRIVATE_ALPHA[*]' 'True' 'Allow' 'Outbound' 'Local'),(Record 'PRIVATE_BETA' 'True' 'Allow' 'Outbound' 'Local'),(Record 'PRIVATE_BLOCK' 'True' 'Block' 'Outbound' 'Local'),(Record 'PRIVATE_DISABLED' 'False' 'Allow' 'Outbound' 'Local'),(Record 'PRIVATE_INBOUND' 'True' 'Allow' 'Inbound' 'Local'))
   return [pscustomobject]@{PersistentStore=[pscustomobject]@{profiles=$profiles;records=$local};ActiveStore=[pscustomobject]@{profiles=(Copy-UfwLocalData $profiles);records=(Copy-UfwLocalData $local)}}
  }
  function StartCase($mode){
   $script:TestBackendRoot=Join-Path $root $mode
   $script:B=[pscustomobject]@{snapshot=(Snapshot);mode=$mode;reads=0;sets=0;restores=0;phase='';gateCalls=0;permit=$true;captured=$false}
   $io=@{
    Actor={return 'PRIVATE_ACTOR'};CheckTime={}
    ReadStore={param($store)
     $script:B.reads++
     $s=Copy-UfwLocalData $script:B.snapshot.$store
     $handles=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
     foreach($r in $s.records){$handles.Add($r.name,[pscustomobject]@{name=$r.name;store=$store})}
     if($script:B.mode -ceq 'unstable_filter' -and $script:B.reads -eq 4){$s.records[0].record.associated_filters.Security.properties.Opaque.value='PRIVATE_DRIFT'}
     [pscustomobject]@{profiles=$s.profiles;records=$s.records;handles=$handles}
    }
    SetEnabled={param($handle,$enabled)
     if($handle.store -cne 'PersistentStore'){throw 'test_wrong_store'}
     if($enabled -ceq 'False'){$script:B.sets++}else{$script:B.restores++}
     if($script:B.mode -ceq 'write_no_effect'){return}
     foreach($store in @('PersistentStore','ActiveStore')){foreach($r in $script:B.snapshot.$store.records){if($r.name -ceq $handle.name){$r.enabled=$enabled;$r.record.rule.properties.Enabled.value=$(if($enabled -ceq 'True'){1}else{2})}}}
     if($script:B.mode -ceq 'write_after_effect' -and $enabled -ceq 'False'){throw 'PRIVATE_AFTER_EFFECT'}
     if($script:B.mode -ceq 'restore_after_effect' -and $enabled -ceq 'True'){throw 'PRIVATE_RESTORE_AFTER_EFFECT'}
    }
   }
   $baseline=Read-UfwLocalStableSnapshot $io;$view=New-UfwLocalBackendView $baseline.snapshot;$h=New-UfwUnifiedStorage
   $ctx=New-UfwLocalBackendContext $io $h $view {param($phase,$view)$script:B.gateCalls++;$script:B.phase=$phase;return $script:B.permit}
   return [pscustomobject]@{ctx=$ctx;adapters=(New-UfwLocalCoordinatorBindings $ctx)}
  }
  # Entire unchanged session coordinator with concrete new local backend and real disk.
  $fixture=StartCase 'coordinator';$c=$fixture.ctx;$a=$fixture.adapters
  $ops=@{
   Lock={return $true};Unlock={};Pending={return $null};Recover={throw 'unused'}
   Capabilities={$v=[ordered]@{};foreach($key in @('private_snapshot_readback','live_semantic_local_effective_match','current_profile_Block','exact_SSTP_transport_review','warm_SSTP_operating_scope','network_independent_recovery','documented_threat_scope','scoped_native_policy_writer','scoped_native_restore','capture_adapter_binding')){$v[$key]='qualified'};return [pscustomobject]$v}
   Inspect={return $c.view};Review={param($v)return [pscustomobject]@{binding=$v.binding;cancelled=$false}}
   Refresh={return $true};PolicyGuard={return $true}
   Capture={$script:B.captured=$true;return [pscustomobject]@{completed=$true;capture_window_completed=$true;audit_restore_verified=$true;audit_recovery_required=$false}}
   Quiescent={return $true};ExitConsent={return $true}
  }
  foreach($key in $a.Keys){$ops[$key]=$a[$key]}
  $before=Get-UfwLocalSnapshotText $c.view.snapshot
  try{
   $r=Invoke-UfwUnifiedSession $ops
   Check ($r.completed -and $r.restore_verified -and $r.capture_completed -and -not $r.pending_recovery) 'coordinator_completed'
   Check ($script:B.sets -eq 2 -and $script:B.restores -eq 2 -and $script:B.captured) 'exact_counts'
   Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq $before) 'all_block_disabled_inbound_preserved'
   Check ((Read-UfwUnifiedStorage $c.storage).sequence -eq 10) 'real_journal_10_entries'
   Check (-not $r.ready_for_apply -and -not $r.no_leak_certified -and $r.application_grants_added -eq 0) 'not_native_qualification'
  }finally{Close-UfwUnifiedStorage $c.storage}
  # Partial forward and inverse effects, replay after a new handle, refusal boundaries.
  $modes=@('normal','write_after_effect','write_no_effect','no_intent','guard_refused','unknown_filter','unknown_rule','origin_drift','profile_drift','plan_tamper','reverse_order','restore_after_effect','journal_protocol','checkpoint_uncertain','post_restore_drift')
  foreach($mode in $modes){
   $fixture=StartCase $mode;$c=$fixture.ctx;$a=$fixture.adapters;$op=$c.view.operations[0];$script:B.mode=$mode
   try{
    $answer=[pscustomobject]@{binding=$c.view.binding};$backup=& $a.Backup $c.view $answer
    if($mode -ceq 'no_intent'){Throws {Invoke-UfwLocalForward $c $op} 'ufw_unified_native_forward_intent_missing';Check ($script:B.sets -eq 0) 'no_intent_no_effect';continue}
    if($mode -ceq 'journal_protocol'){
     Write-UfwUnifiedStorage $c.storage 'result' $op|Out-Null
     Throws {Get-UfwLocalBackendState $c} 'ufw_unified_native_result_order';continue
    }
    & $a.SaveIntent $backup $op|Out-Null
    if($mode -ceq 'checkpoint_uncertain'){$c.storage.head='0'*64;Throws {Invoke-UfwLocalForward $c $op} 'ufw_unified_native_checkpoint_head';Check ($script:B.sets -eq 0) 'uncertain_no_effect';continue}
    if($mode -ceq 'guard_refused'){$script:B.permit=$false;Throws {Invoke-UfwLocalForward $c $op} 'ufw_unified_native_bound_guard_refused';Check ($script:B.sets -eq 0) 'guard_no_effect';continue}
    if($mode -ceq 'plan_tamper'){$c.view.operations[0].name='PRIVATE_TAMPER';Throws {Invoke-UfwLocalForward $c $op} 'ufw_unified_native_plan_changed';continue}
    if($mode -cin @('unknown_filter','unknown_rule','origin_drift','profile_drift')){
     if($mode -ceq 'unknown_filter'){$script:B.snapshot.ActiveStore.records[0].record.associated_filters.Security.properties.Opaque.value='PRIVATE_CHANGED'}
     if($mode -ceq 'unknown_rule'){$script:B.snapshot.ActiveStore.records+=,(Record 'PRIVATE_FOREIGN' 'True' 'Allow' 'Outbound' 'Local')}
     if($mode -ceq 'origin_drift'){$script:B.snapshot.ActiveStore.records[0].source_path='PRIVATE_OTHER_SOURCE'}
     if($mode -ceq 'profile_drift'){$script:B.snapshot.ActiveStore.profiles[0].outbound='Allow'}
     $code='ufw_unified_native_global_policy_drift';if($mode -ceq 'profile_drift'){$code='ufw_unified_native_profiles_not_block'}
     Throws {Invoke-UfwLocalForward $c $op} $code;Check ($script:B.sets -eq 0) 'drift_no_effect';continue
    }
    if($mode -ceq 'write_after_effect'){Throws {Invoke-UfwLocalForward $c $op} 'PRIVATE_AFTER_EFFECT'}
    elseif($mode -ceq 'write_no_effect'){Throws {Invoke-UfwLocalForward $c $op} 'ufw_unified_native_forward_readback'}
    else{Invoke-UfwLocalForward $c $op;& $a.SaveResult $backup $op|Out-Null}
    if($mode -ceq 'reverse_order'){Throws {Restore-UfwLocalSavedOperation $c $c.view.operations[1]} 'ufw_unified_native_restore_saved_intent_missing';continue}
    if($mode -ceq 'post_restore_drift'){
     [void](Restore-UfwLocalSavedOperation $c $op);$script:B.snapshot.ActiveStore.records[1].source_path='PRIVATE_OTHER'
     Throws {Recover-UfwLocalBackend $c} 'ufw_unified_native_recovery_baseline_drift';continue
    }
    if($mode -ceq 'restore_after_effect'){
     Throws {Restore-UfwLocalSavedOperation $c $op} 'PRIVATE_RESTORE_AFTER_EFFECT'
     $script:B.mode='normal'
    }
    # New process-like handle: old stream closed, exclusive file reopened, fresh chain read.
    Close-UfwUnifiedStorage $c.storage
    $old=$c.storage;$lock=Open-UfwPrivateJournalFile (Join-Path $old.dir 'operation.lock') ([IO.FileMode]::Open)
    $h=[pscustomobject]@{id=$old.id;dir=$old.dir;sequence=0;head=('0'*64);total_bytes=[long]0;lock=$lock}
    $back=Read-UfwUnifiedStorage $h;$h.sequence=$back.sequence;$h.head=$back.head;$h.total_bytes=$back.total_bytes
    $view=Copy-UfwLocalData $back.records[0].data
    $c=New-UfwLocalBackendContext $c.io $h $view {param($p,$v)return $script:B.permit}
    Check (Recover-UfwLocalBackend $c) ('recover_'+$mode)
    Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)) ('baseline_'+$mode)
    $counts=$script:B.restores;Check (Recover-UfwLocalBackend $c) 'idempotent_closed';Check ($script:B.restores -eq $counts) 'no_repeat_set'
    $script:B.snapshot.ActiveStore.records[1].source_path='PRIVATE_POST_CLOSE_DRIFT'
    Throws {Recover-UfwLocalBackend $c} 'ufw_unified_native_closed_baseline_drift'
   }finally{Close-UfwUnifiedStorage $c.storage}
  }
  # Every durable boundary of a TWO-rule forward/reverse prefix. Effects are
  # memory providers, checkpoints are real files. Reopen, do not trust old RAM.
  $cuts=14
  for($cut=0;$cut -lt $cuts;$cut++){
   $fixture=StartCase ('prefix-'+$cut);$c=$fixture.ctx;$a=$fixture.adapters
   try{
    & $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})|Out-Null
    $steps=@('intent0','effect0','result0','intent1','effect1','result1','inverse_intent1','inverse_effect1','inverse_result1','inverse_intent0','inverse_effect0','inverse_result0','closed')
    for($step=0;$step -lt $cut;$step++){
     $label=$steps[$step];$op=$c.view.operations[0];if($label.EndsWith('1')){$op=$c.view.operations[1]}
     switch -Regex ($label){
      '^intent'{Write-UfwUnifiedStorage $c.storage 'intent' $op|Out-Null;break}
      '^effect'{Invoke-UfwLocalForward $c $op;break}
      '^result'{Write-UfwUnifiedStorage $c.storage 'result' $op|Out-Null;break}
      '^inverse_intent'{Write-UfwUnifiedStorage $c.storage 'restore_intent' $op|Out-Null;break}
      '^inverse_effect'{
       $read=Read-UfwLocalStableSnapshot $c.io
       & $c.io.SetEnabled $read.handles[$op.name] 'True';break
      }
      '^inverse_result'{Write-UfwUnifiedStorage $c.storage 'restore_result' $op|Out-Null;break}
      '^closed'{Write-UfwUnifiedStorage $c.storage 'restored' ([pscustomobject]@{verified=$true})|Out-Null;break}
     }
    }
    Close-UfwUnifiedStorage $c.storage;$old=$c.storage
    $lock=Open-UfwPrivateJournalFile (Join-Path $old.dir 'operation.lock') ([IO.FileMode]::Open)
    $h=[pscustomobject]@{id=$old.id;dir=$old.dir;sequence=0;head=('0'*64);total_bytes=[long]0;lock=$lock}
    $back=Read-UfwUnifiedStorage $h;$h.sequence=$back.sequence;$h.head=$back.head;$h.total_bytes=$back.total_bytes
    $c=New-UfwLocalBackendContext $c.io $h (Copy-UfwLocalData $back.records[0].data) {param($p,$v)return $true}
    Check (Recover-UfwLocalBackend $c) ('prefix_recovered_'+$cut)
    Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)) ('prefix_baseline_'+$cut)
   }finally{Close-UfwUnifiedStorage $c.storage}
  }
  # Full associated-filter stability, casefold collision, nonlocal and mismatched pair.
  $fixture=StartCase 'reader';try{
   $script:B.mode='unstable_filter';$script:B.reads=0
   Throws {Read-UfwLocalStableSnapshot $fixture.ctx.io} 'ufw_unified_native_full_filter_drift'
  }finally{Close-UfwUnifiedStorage $fixture.ctx.storage}
  $snap=Snapshot;$snap.ActiveStore.records[0].source_type='GroupPolicy';Throws {New-UfwLocalQuarantineOperations $snap} 'ufw_unified_native_allow_not_local'
  $snap=Snapshot;$snap.ActiveStore.records[0].record.associated_filters.Application.properties.Opaque.value='PRIVATE_CHANGED';Throws {New-UfwLocalQuarantineOperations $snap} 'ufw_unified_native_local_effective_mismatch'
  $snap=Snapshot;$snap.ActiveStore.records+=,(Record 'private_beta' 'True' 'Allow' 'Outbound' 'Local');Throws {New-UfwLocalQuarantineOperations $snap} 'ufw_unified_native_rule_identity'
  $snap=Snapshot;$snap.ActiveStore.records[0].record.rule.properties.Enabled.value='1';Throws {New-UfwLocalQuarantineOperations $snap} 'ufw_unified_native_enabled_projection'
  $snap=Snapshot;$snap.ActiveStore.records[0].record.rule.properties.InstanceID.value='PRIVATE_OTHER_ID';Throws {New-UfwLocalQuarantineOperations $snap} 'ufw_unified_native_rule_name_projection'
  # Execute the ACTUAL native ReadStore callback with cmdlet fixtures and the
  # unchanged CIM serializer; native Windows CIM/API execution is still FALSE.
  Add-Type @'
using System;using System.Collections;using System.Collections.Generic;
public class UfwBackendProp {public string Name;public string CimType;public object Value;public UfwBackendProp(string n,string t,object v){Name=n;CimType=t;Value=v;}}
public class UfwBackendProps:IEnumerable {public List<UfwBackendProp> Items=new List<UfwBackendProp>();public UfwBackendProp this[string s]{get{return Items.Find(x=>x.Name==s);}}public IEnumerator GetEnumerator(){return Items.GetEnumerator();}}
'@
  function NativeMock($record,$projection){
   $items=New-Object UfwBackendProps
   foreach($p in $record.properties.PSObject.Properties){$items.Items.Add((New-Object UfwBackendProp($p.Name,$p.Value.cim_type,$p.Value.value)))}
   $v=[ordered]@{CimInstanceProperties=$items;CimSystemProperties=[pscustomobject]@{ClassName=$record.class;Namespace=$record.namespace}}
   foreach($key in $projection.Keys){$v[$key]=$projection[$key]};return [pscustomobject]$v
  }
  $script:NativeFixture=Snapshot;$script:NativeCalls=[pscustomobject]@{rules=0;profiles=0;filters=0;active_trace=0;filter_mode='normal'}
  function Get-NetFirewallRule {
   [CmdletBinding()]param($PolicyStore,[switch]$TracePolicyStore)
   $script:NativeCalls.rules++;if($PolicyStore -ceq 'ActiveStore' -and $TracePolicyStore){$script:NativeCalls.active_trace++}
   foreach($r in $script:NativeFixture.$PolicyStore.records){NativeMock $r.record.rule @{Name=$r.name;Enabled=$r.enabled;Action=$r.action;Direction=$r.direction;PolicyStoreSourceType=$r.source_type;PolicyStoreSource=$r.source_path}}
  }
  function Get-NetFirewallProfile {
   [CmdletBinding()]param($PolicyStore)
   $script:NativeCalls.profiles++
   foreach($p in $script:NativeFixture.$PolicyStore.profiles){
    $record=[pscustomobject]@{class='MSFT_NetFirewallProfile';namespace='root/StandardCimv2';properties=[pscustomobject]@{Name=[pscustomobject]@{cim_type='String';value=$p.name}}}
    NativeMock $record @{Name=$p.name;Enabled=$p.enabled;DefaultOutboundAction=$p.outbound}
   }
  }
  $filterBody={
   [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
   process{
    $script:NativeCalls.filters++
    if($script:NativeCalls.filter_mode -ceq 'zero'){return}
    $r=$script:NativeFixture.PersistentStore.records[0].record.associated_filters.Address
    NativeMock $r @{}
    if($script:NativeCalls.filter_mode -ceq 'duplicate'){NativeMock $r @{}}
   }
  }
  foreach($name in @('Address','Application','Interface','InterfaceType','Port','Security','Service')){Set-Item -LiteralPath ('Function:Get-NetFirewall'+$name+'Filter') -Value $filterBody}
  $native=New-UfwWindowsLocalPolicyIO;$native.Actor={return 'PRIVATE_ACTOR'}
  $nativeRead=Read-UfwLocalStableSnapshot $native
  Check ($script:NativeCalls.rules -eq 4 -and $script:NativeCalls.profiles -eq 4 -and $script:NativeCalls.filters -eq 140 -and $script:NativeCalls.active_trace -eq 2) 'actual_native_reader_callback_all_filters_and_trace'
  Check ((New-UfwLocalQuarantineOperations $nativeRead.snapshot).Count -eq 2) 'serializer_to_planner'
  $script:NativeCalls.filter_mode='zero';Throws {Read-UfwLocalStableSnapshot $native} 'ufw_unified_native_filter_cardinality'
  $script:NativeCalls.filter_mode='duplicate';Throws {Read-UfwLocalStableSnapshot $native} 'ufw_unified_native_filter_cardinality'
  foreach($name in @('Get-NetFirewallRule','Get-NetFirewallProfile','Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter','Get-NetFirewallPortFilter','Get-NetFirewallSecurityFilter','Get-NetFirewallServiceFilter')){Remove-Item -LiteralPath ('Function:'+ $name)}
  # Dot source/construct native IO executes NO cmdlet; Linux setter cannot accept fixture.
  $native=New-UfwWindowsLocalPolicyIO
  Throws {& $native.SetEnabled ([pscustomobject]@{name='PRIVATE'}) 'False'} 'ufw_unified_native_setter_scope'
  $parsed=0;$setters=0
  foreach($file in @(Get-ChildItem -LiteralPath $src -Filter *.ps1)){
   $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
   Check ($errors.Count -eq 0) ('parse_'+$file.Name);$parsed++
   foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
    $name=$cmd.GetCommandName()
    if($null -ne $name -and $name -match '^(Set|New|Remove|Enable|Disable)-NetFirewall'){
     $params=@($cmd.CommandElements|Where-Object{$_ -is [Management.Automation.Language.CommandParameterAst]}|ForEach-Object{$_.ParameterName}|Sort-Object)
     if($name -ceq 'Set-NetFirewallRule'){
      Check ($file.Name -ceq 'NativePolicyIO.ps1') 'only_scoped_setter'
      Check (($params -join ',') -ceq 'Confirm,Enabled,ErrorAction,InputObject') 'no_name_group_profile_or_default_write';$setters++
     }elseif($name -ceq 'Remove-NetFirewallRule'){
      Check ($file.Name -ceq 'OwnedTransport.ps1') 'owned_remove_only'
      Check (($params -join ',') -ceq 'Confirm,ErrorAction,InputObject') 'remove_no_name_or_group'
     }elseif($name -ceq 'New-NetFirewallRule'){
      Check ($file.Name -ceq 'OwnedTransport.ps1') 'owned_creation_only'
      Check (($params -join ',') -ceq 'Confirm,ErrorAction') 'creation_parameters_from_fixed_dictionary'
     }else{Check $false 'unexpected_native_mutator'}
    }
   }
  }
  Check ($setters -eq 1) 'exactly_one_private_setter'
  [pscustomobject]@{passed=$true;assertions=$script:BackendChecks;PS_source_files_parsed=$parsed;private_native_setter_sites=$setters;partial_effect_cases=$modes.Count;two_rule_durable_prefix_cuts=$cuts;full_coordinator_with_local_backend=$true;actual_native_reader_with_CIM_cmdlet_fixtures=$true;real_Linux_journal_IO=$true;reopen_recovery=$true;native_Windows_cmdlets_executed=$false;SSTP_transport_exercised_in_this_suite=$false;live_entrypoint_published=$false;user_test_requested=$false;ready_for_apply=$false}
 } $SourceRoot $temp $InventoryCore
 $out=Join-Path (Split-Path $SourceRoot -Parent) 'evidence/local-policy-backend-tests.json'
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8
 $report|ConvertTo-Json -Compress
}finally{Remove-Module $m -Force -ErrorAction SilentlyContinue;if([IO.Directory]::Exists($temp)){[IO.Directory]::Delete($temp,$true)}}
