param([string]$SourceRoot,[string]$InventoryCore,[string]$TransportPlan,[string]$LocalFixture,[string]$RuntimeHarness,[string]$RuntimeRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$global:UnifiedMixedCaptureFixture={param($mode)Run-Case $mode}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-mixed-backend-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try{
 $report=& $m {
  param($src,$root,$inv,$fixture,$transportPlan,$capture)
  . $fixture -src $src -root $root -inv $inv
  . $transportPlan
  . (Join-Path $src 'NativeReadiness.ps1');. (Join-Path $src 'OwnedTransport.ps1');. (Join-Path $src 'MixedPolicyBackend.ps1')
  function Prop($Type,$Value){return [pscustomobject]@{cim_type=$Type;value=$Value}}
  function OwnedRecord($spec){
   $name=Get-UfwOwnedTransportName $spec
   $p=[ordered]@{InstanceID=(Prop 'String' $name);Enabled=(Prop 'UInt16' 2);Action=(Prop 'UInt16' 2);Direction=(Prop 'UInt16' 2);Description=(Prop 'String' (Get-UfwOwnedTransportMarker $spec));RuleGroup=(Prop 'String' ('UnifiedFW.Session.'+$spec.session_id));EdgeTraversalPolicy=(Prop 'UInt16' 0);LooseSourceMapping=(Prop 'Boolean' $false);LocalOnlyMapping=(Prop 'Boolean' $false);Profiles=(Prop 'UInt16' 0)}
   $shapes=@{
    Address=@('MSFT_NetAddressFilter',@{LocalAddress=(Prop 'StringArray' @('Any'));RemoteAddress=(Prop 'StringArray' $spec.endpoint_ips)})
    Application=@('MSFT_NetApplicationFilter',@{AppPath=(Prop 'String' $spec.system_host_path);Package=(Prop 'String' 'Any')})
    Service=@('MSFT_NetServiceFilter',@{ServiceName=(Prop 'String' 'SstpSvc')})
    Port=@('MSFT_NetProtocolPortFilter',@{Protocol=(Prop 'String' '6');RemotePort=(Prop 'StringArray' @('443'));LocalPort=(Prop 'StringArray' @('Any'));IcmpType=(Prop 'StringArray' @('Any'));DynamicTransport=(Prop 'UInt32' 0)})
    Interface=@('MSFT_NetInterfaceFilter',@{InterfaceAlias=(Prop 'StringArray' @('Any'))})
    InterfaceType=@('MSFT_NetInterfaceTypeFilter',@{InterfaceType=(Prop 'UInt32' 0)})
    Security=@('MSFT_NetNetworkLayerSecurityFilter',@{Authentication=(Prop 'UInt16' 0);Encryption=(Prop 'UInt16' 0);OverrideBlockRules=(Prop 'Boolean' $false);LocalUsers=(Prop 'String' 'Any');RemoteUsers=(Prop 'String' 'Any');RemoteMachines=(Prop 'String' 'Any')})
   }
   $filters=[ordered]@{}
   foreach($kind in @('Address','Application','Interface','InterfaceType','Port','Security','Service')){
    $props=[ordered]@{IsNegated=(Prop 'Boolean' $false);InstanceID=(Prop 'String' ('PRIVATE_FILTER_'+$kind))}
    foreach($key in @($shapes[$kind][1].Keys|Sort-Object)){$props[$key]=$shapes[$kind][1][$key]}
    $filters[$kind]=[pscustomobject]@{class=$shapes[$kind][0];namespace='root/StandardCimv2';properties=[pscustomobject]$props}
   }
   return [pscustomobject]@{name=$name;enabled='False';action='Allow';direction='Outbound';source_type='Local';source_path='PRIVATE_LOCAL_STORE';record=[pscustomobject]@{rule=[pscustomobject]@{class='MSFT_NetFirewallRule';namespace='root/StandardCimv2';properties=[pscustomobject]$p};associated_filters=[pscustomobject]$filters}}
  }
  function StartMixed($mode){
   $base=StartCase $mode;$h=$base.ctx.storage
   $spec=[pscustomobject]@{schema='ufw-owned-sstp-spec-01';session_id=$h.id;observation_binding=('a'*64);endpoint_ips=@('192.0.2.99');system_host_path='C:\Windows\System32\svchost.exe';system_host_sha256=('b'*64)}
   $script:MIX=[pscustomobject]@{mode=$mode;trace=(New-Object 'Collections.Generic.List[string]');spec=$spec;created=$false;capture=$capture;runtime=$null;removed=0;nativeSet=$base.ctx.io.SetEnabled}
   $script:S=[pscustomobject]@{policyRestricted=$false}
   $io=$base.ctx.io
   $io.CreateTransport={param($spec)
    $script:MIX.trace.Add('create-disabled')
    if($script:MIX.mode -ceq 'create_no_effect'){return}
    $r=OwnedRecord $spec
    foreach($store in @('PersistentStore','ActiveStore')){$script:B.snapshot.$store.records+=,(Copy-UfwLocalData $r)}
    $script:MIX.created=$true
    if($script:MIX.mode -ceq 'create_after_effect'){throw 'PRIVATE_CREATE_AFTER_EFFECT'}
   }
   $io.SetEnabled={param($handle,$enabled)
    $transport=$handle.name -ceq (Get-UfwOwnedTransportName $script:MIX.spec)
    $label='local-restore';if($enabled -ceq 'False'){$label='local-disable'}
    if($transport){$label='transport-disable';if($enabled -ceq 'True'){$label='transport-enable'}}
    $script:MIX.trace.Add($label)
    if($script:MIX.mode -ceq 'enable_no_effect' -and $transport -and $enabled -ceq 'True'){return}
    & $script:MIX.nativeSet $handle $enabled
    if($script:MIX.mode -ceq 'enable_after_effect' -and $transport -and $enabled -ceq 'True'){throw 'PRIVATE_ENABLE_AFTER_EFFECT'}
    if($script:MIX.mode -ceq 'disable_transport_after_effect' -and $transport -and $enabled -ceq 'False'){throw 'PRIVATE_DISABLE_TRANSPORT_AFTER_EFFECT'}
    if($script:MIX.mode -ceq 'local_after_effect' -and -not $transport -and $enabled -ceq 'False'){throw 'PRIVATE_LOCAL_AFTER_EFFECT'}
   }
   $io.RemoveOwned={param($handle)
    $script:MIX.trace.Add('remove-owned')
    if($handle.store -cne 'PersistentStore' -or $handle.name -cne (Get-UfwOwnedTransportName $script:MIX.spec)){throw 'test_remove_foreign'}
    foreach($store in @('PersistentStore','ActiveStore')){
     foreach($r in $script:B.snapshot.$store.records){if($r.name -ceq $handle.name -and $r.enabled -cne 'False'){throw 'test_remove_enabled_transport'}}
     $script:B.snapshot.$store.records=@($script:B.snapshot.$store.records|Where-Object{$_.name -cne $handle.name})
    }
    $script:MIX.removed++
    if($script:MIX.mode -ceq 'remove_after_effect'){throw 'PRIVATE_REMOVE_AFTER_EFFECT'}
   }
   $view=New-UfwMixedBackendView $base.ctx.view.snapshot $spec
   $ctx=New-UfwLocalBackendContext $io $h $view {param($phase,$v)
    if($script:MIX.mode -ceq 'disconnect_before_enable' -and $script:MIX.created -and $phase -cin @('forward','immediately_before_forward')){return $false}
    return $true
   }
   return [pscustomobject]@{ctx=$ctx;adapters=(New-UfwLocalCoordinatorBindings $ctx)}
  }
  function MixedGuard($c){
   $s=Get-UfwLocalBackendState $c
   if($s.results -ne $c.view.operations.Count -or $s.restore_started){return $false}
   $obs=Get-UfwLocalReconciledObservation $c $s
   $allows=@($script:B.snapshot.ActiveStore.records|Where-Object{$_.enabled -ceq 'True' -and $_.direction -ceq 'Outbound' -and $_.action -ceq 'Allow'})
   return $allows.Count -eq 1 -and $allows[0].name -ceq (Get-UfwOwnedTransportName $c.view.transport)
  }
  function ReopenMixed($c){
   Close-UfwUnifiedStorage $c.storage;$old=$c.storage
   $h=[pscustomobject]@{id=$old.id;dir=$old.dir;sequence=0;head=('0'*64);total_bytes=[long]0;lock=(Open-UfwPrivateJournalFile (Join-Path $old.dir 'operation.lock') ([IO.FileMode]::Open))}
   $back=Read-UfwUnifiedStorage $h;$h.sequence=$back.sequence;$h.head=$back.head;$h.total_bytes=$back.total_bytes
   return New-UfwLocalBackendContext $c.io $h (Copy-UfwLocalData $back.records[0].data) {param($p,$v)return $true}
  }
  $modes=@('normal','create_no_effect','create_after_effect','enable_no_effect','enable_after_effect','local_after_effect','disable_transport_after_effect','remove_after_effect','disconnect_before_enable')
  foreach($mode in $modes){
   $f=StartMixed $mode;$c=$f.ctx
   try{
    $ops=@{Lock={return $true};Unlock={};Pending={return $null};Recover={throw 'unused'}
     Capabilities={$v=[ordered]@{};foreach($key in (Get-UfwIntegratedNativeReadiness).PSObject.Properties.Name){$v[$key]='qualified'};return [pscustomobject]$v}
     Inspect={return $c.view};Review={param($v)return [pscustomobject]@{binding=$v.binding;cancelled=$false}};Refresh={return $true}
     PolicyGuard={$script:S.policyRestricted=MixedGuard $c;return $script:S.policyRestricted}
     Capture={$script:MIX.trace.Add('capture');$r=& $script:MIX.capture 'normal';$script:MIX.runtime=$r;return $r}
     Quiescent={return $true};ExitConsent={return $true}
    }
    foreach($key in $f.adapters.Keys){$ops[$key]=$f.adapters[$key]}
    $r=Invoke-UfwUnifiedSession $ops
    if($mode -ceq 'normal'){
     if(-not $r.completed){Write-Host ($r|ConvertTo-Json -Compress)}
     Check ($r.completed -and $r.capture_completed -and $r.restore_verified) 'mixed_coordinator_completed'
     Check ($script:MIX.runtime.blocked_events -eq 1 -and $script:MIX.runtime.suggestion_count -eq 1 -and $script:MIX.runtime.audit_restore_verified) 'actual_runtime_bridge_and_reducer'
     Check ((Read-UfwUnifiedStorage $c.storage).sequence -eq 18) 'four_ops_same_journal'
     Check ($script:MIX.trace[0] -ceq 'create-disabled' -and $script:MIX.trace[1] -ceq 'transport-enable' -and $script:MIX.trace[2] -ceq 'local-disable' -and $script:MIX.trace[-1] -ceq 'remove-owned') 'transport_before_quarantine_remove_last'
    }else{Check (-not $r.completed) ('not_fake_success_'+$mode)}
    if($r.pending_recovery){$script:MIX.mode='normal';$c=ReopenMixed $c;Check (Recover-UfwLocalBackend $c) ('recovered_'+$mode)}
    Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)) ('mixed_baseline_'+$mode)
    Check (-not $r.ready_for_apply -and -not $r.no_leak_certified -and $r.application_grants_added -eq 0) ('scope_'+$mode)
    if($mode -ceq 'disconnect_before_enable'){Check (-not $r.capture_requested -and -not $script:MIX.trace.Contains('transport-enable') -and -not $script:MIX.trace.Contains('local-disable')) 'disconnect_no_fallback_or_quarantine'}
   }finally{Close-UfwUnifiedStorage $c.storage}
  }
  # Durable prefix cuts of four heterogeneous operations, including materialization.
  $steps=@('intent0','effect0','result0','intent1','effect1','result1','intent2','effect2','result2','intent3','effect3','result3','inverse_intent3','inverse_effect3','inverse_result3','inverse_intent2','inverse_effect2','inverse_result2','inverse_intent1','inverse_effect1','inverse_result1','inverse_intent0','inverse_effect0','inverse_result0','closed')
  for($cut=0;$cut -le $steps.Count;$cut++){
   $f=StartMixed ('mixed-prefix-'+$cut);$c=$f.ctx;$a=$f.adapters
   try{
    $backup=& $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})
    for($step=0;$step -lt $cut;$step++){
     $label=$steps[$step];$index=0;if($label -cne 'closed'){$index=[int]::Parse($label.Substring($label.Length-1))};$op=$c.view.operations[$index]
     switch -Regex ($label){
      '^intent'{& $a.SaveIntent $backup $op|Out-Null;break}
      '^effect'{Invoke-UfwLocalForward $c $op;break}
      '^result'{& $a.SaveResult $backup $op|Out-Null;break}
      '^inverse_intent'{Write-UfwUnifiedStorage $c.storage 'restore_intent' $op|Out-Null;break}
      '^inverse_effect'{
       $read=Read-UfwLocalStableSnapshot $c.io
       switch -CaseSensitive ($op.kind){
        'create_disabled_transport'{& $c.io.RemoveOwned $read.handles[$op.name]}
        'enable_owned_transport'{& $c.io.SetEnabled $read.handles[$op.name] 'False'}
        'disable_reviewed_local_allow'{& $c.io.SetEnabled $read.handles[$op.name] 'True'}
       };break
      }
      '^inverse_result'{Write-UfwUnifiedStorage $c.storage 'restore_result' $op|Out-Null;break}
      '^closed'{Write-UfwUnifiedStorage $c.storage 'restored' ([pscustomobject]@{verified=$true})|Out-Null;break}
     }
    }
    $c=ReopenMixed $c
    Check (Recover-UfwLocalBackend $c) ('mixed_prefix_recovery_'+$cut)
    Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)) ('mixed_prefix_baseline_'+$cut)
   }finally{Close-UfwUnifiedStorage $c.storage}
  }
  # Materialized records pin all seven filters and unknown policy is never enabled.
  $tamperModes=@('service','program','port','address','unknown_property','bypass','negated','materialized','name_collision','spec_rewrite')
  foreach($mode in $tamperModes){
   $f=StartMixed ('tamper-'+$mode);$c=$f.ctx;$a=$f.adapters
   try{
    if($mode -ceq 'name_collision'){$script:B.snapshot.ActiveStore.records+=,(OwnedRecord $c.view.transport);Throws {New-UfwMixedBackendView $script:B.snapshot $c.view.transport} 'ufw_unified_transport_name_collision';continue}
    if($mode -ceq 'spec_rewrite'){$c.view.transport.endpoint_ips=@('192.0.2.100');Throws {Assert-UfwLocalBackendView $c.view} 'ufw_unified_transport_view_changed';continue}
    $backup=& $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding});$op=$c.view.operations[0]
    & $a.SaveIntent $backup $op|Out-Null;Invoke-UfwLocalForward $c $op
    if($mode -ceq 'materialized'){& $a.SaveResult $backup $op|Out-Null}
    foreach($store in @('PersistentStore','ActiveStore')){
     $map=Get-UfwLocalRecordMap $script:B.snapshot.$store.records;$row=$map[$op.name];$filters=$row.record.associated_filters
     switch -CaseSensitive ($mode){
      'service'{$filters.Service.properties.ServiceName.value='Any'}
      'program'{$filters.Application.properties.AppPath.value='Any'}
      'port'{$filters.Port.properties.RemotePort.value=@('Any')}
      'address'{$filters.Address.properties.RemoteAddress.value=@('Any')}
      'unknown_property'{$row.record.rule.properties|Add-Member -NotePropertyName UnknownGrantField -NotePropertyValue (Prop 'Boolean' $true)}
      'bypass'{$filters.Security.properties.OverrideBlockRules.value=$true}
      'negated'{$filters.Application.properties.IsNegated.value=$true}
      'materialized'{$filters.Application.properties.Package.value='PRIVATE_CHANGED'}
     }
    }
    $caught=$false;try{Recover-UfwLocalBackend $c|Out-Null}catch{$caught=$true}
    Check $caught ('tamper_refused_'+$mode)
    Check (-not $script:MIX.trace.Contains('transport-enable') -and $script:MIX.removed -eq 0) ('no_enable_or_blind_delete_'+$mode)
   }finally{Close-UfwUnifiedStorage $c.storage}
  }
  $f=StartMixed 'parameters';$c=$f.ctx
  try{
   $p=Get-UfwOwnedCreationParameters $c.view.transport
   Check ($p.Enabled -ceq 'False' -and $p.PolicyStore -ceq 'PersistentStore' -and $p.Program -ceq $c.view.transport.system_host_path -and $p.Service -ceq 'SstpSvc' -and $p.RemotePort -ceq '443' -and $p.Protocol -ceq 'TCP' -and -not $p.OverrideBlockRules) 'native_fixed_creation_parameters'
   $native=New-UfwWindowsOwnedTransportIO
   Throws {& $native.CreateTransport $c.view.transport} 'ufw_unified_transport_native_platform'
   Throws {& $native.RemoveOwned ([pscustomobject]@{name='PRIVATE'})} 'ufw_unified_transport_remove_scope'
   $spec=Copy-UfwLocalData $c.view.transport;$spec.endpoint_ips=@('Any');Throws {Assert-UfwOwnedTransportSpec $spec} 'plan_exact_ip_required'
  }finally{Close-UfwUnifiedStorage $c.storage}
  [pscustomobject]@{passed=$true;assertions=$script:BackendChecks;coordinator_cases=$modes.Count;mixed_durable_prefix_cuts=($steps.Count+1);tamper_cases=$tamperModes.Count;existing_runtime_coordinator_and_bridge_executed=$true;real_Linux_journal_IO=$true;materialization_before_enable_verified=$true;owned_transport_writer_implemented=$true;native_Windows_effects_executed=$false;native_connected_SSTP_observer_bound=$false;human_review_bound=$false;public_live_entrypoint_published=$false;user_test_requested=$false;ready_for_apply=$false}
 } $SourceRoot $temp $InventoryCore $LocalFixture $TransportPlan $global:UnifiedMixedCaptureFixture
 $out=Join-Path (Split-Path $SourceRoot -Parent) 'evidence/mixed-policy-backend-tests.json'
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8
 $report|ConvertTo-Json -Compress
}finally{Remove-Module $m -Force -ErrorAction SilentlyContinue;if([IO.Directory]::Exists($temp)){[IO.Directory]::Delete($temp,$true)}}
