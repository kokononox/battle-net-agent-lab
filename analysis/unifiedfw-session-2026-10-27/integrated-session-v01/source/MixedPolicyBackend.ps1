# Extends the existing backend/state machine, not a parallel transaction engine.
function New-UfwMixedBackendView($Snapshot,$Transport){
 Assert-UfwOwnedTransportSpec $Transport
 $name=Get-UfwOwnedTransportName $Transport
 foreach($store in @('PersistentStore','ActiveStore')){$map=Get-UfwLocalRecordMap $Snapshot.$store.records;if($map.ContainsKey($name)){throw 'ufw_unified_transport_name_collision'}}
 $ops=@([pscustomobject][ordered]@{id='transport-create';kind='create_disabled_transport';name=$name;before='absent';after='disabled'},[pscustomobject][ordered]@{id='transport-enable';kind='enable_owned_transport';name=$name;before='disabled';after='enabled'})
 $localOperations=New-UfwLocalQuarantineOperations $Snapshot
 foreach($op in $localOperations){$ops+=,$op}
 if($ops.Count -gt 512){throw 'ufw_unified_transport_operation_cap'}
 $binding=Get-UfwJournalHash (Get-UfwLocalJson ([pscustomobject]@{snapshot=(Get-UfwLocalSnapshotText $Snapshot);transport=$Transport}))
 return [pscustomobject]@{scope='mixed_transport_quarantine_backend_development';binding=$binding;snapshot=(Copy-UfwLocalData $Snapshot);transport=(Copy-UfwLocalData $Transport);operations=$ops}
}
function Assert-UfwMixedBackendView($View){
 $expected=New-UfwMixedBackendView $View.snapshot $View.transport
 if((Get-UfwLocalJson $expected) -cne (Get-UfwLocalJson $View)){throw 'ufw_unified_transport_view_changed'}
}
function Test-UfwMixedPrefixSnapshot($Context,$State,$Read,$Applied){
 $transportState='absent';$local=@()
 foreach($op in $Applied){switch -CaseSensitive ($op.kind){'create_disabled_transport'{$transportState='disabled'}'enable_owned_transport'{$transportState='enabled'}'disable_reviewed_local_allow'{$local+=,$op}default{throw 'ufw_unified_transport_prefix_kind'}}}
 $snapshot=Copy-UfwLocalData $Read.snapshot;$name=Get-UfwOwnedTransportName $Context.view.transport
 $l=Get-UfwLocalRecordMap $snapshot.PersistentStore.records;$a=Get-UfwLocalRecordMap $snapshot.ActiveStore.records
 $present=$l.ContainsKey($name) -and $a.ContainsKey($name);$pair=$null
 if($transportState -ceq 'absent'){
  if($l.ContainsKey($name) -or $a.ContainsKey($name)){return [pscustomobject]@{matches=$false;owned_pair=$null}}
 }else{
  if(-not $present){return [pscustomobject]@{matches=$false;owned_pair=$null}}
  $enabled='False';if($transportState -ceq 'enabled'){$enabled='True'}
  if($l[$name].enabled -cne $enabled -or $a[$name].enabled -cne $enabled){return [pscustomobject]@{matches=$false;owned_pair=$null}}
  $pair=[pscustomobject]@{local=$l[$name];effective=$a[$name]}
  Assert-UfwOwnedPair $pair $Context.view.transport $enabled
  if($State.materialized.ContainsKey($name)){
   $pinned=Copy-UfwLocalData $State.materialized[$name]
   foreach($side in @('local','effective')){$pinned.$side.enabled=$enabled;$pinned.$side.record.rule.properties.Enabled.value=$(if($enabled -ceq 'True'){1}else{2})}
   if((Get-UfwOwnedPairText $pair) -cne (Get-UfwOwnedPairText $pinned)){throw 'ufw_unified_transport_materialized_drift'}
  }elseif($transportState -ceq 'enabled'){throw 'ufw_unified_transport_enable_without_materialization'}
  foreach($store in @('PersistentStore','ActiveStore')){$snapshot.$store.records=@($snapshot.$store.records|Where-Object{$_.name -cne $name})}
 }
 $expected=Get-UfwLocalExpectedSnapshot $Context $local
 return [pscustomobject]@{matches=((Get-UfwLocalSnapshotText $snapshot) -ceq (Get-UfwLocalSnapshotText $expected));owned_pair=$pair}
}
function Get-UfwMixedReconciledObservation($Context,$State){
 $count=$State.saved.Count-$State.restored;$applied=@();for($i=0;$i -lt $count;$i++){$applied+=,$State.saved[$i]}
 $read=Read-UfwLocalStableSnapshot $Context.io;$match=Test-UfwMixedPrefixSnapshot $Context $State $read $applied
 if($match.matches){return [pscustomobject]@{read=$read;applied=$applied;tail_applied=($count -gt 0);owned_pair=$match.owned_pair}}
 if($count -gt 0 -and ($State.results -lt $State.saved.Count -or $null -ne $State.restoring)){
  $less=@();for($i=0;$i -lt $count-1;$i++){$less+=,$applied[$i]}
  $match=Test-UfwMixedPrefixSnapshot $Context $State $read $less
  if($match.matches){return [pscustomobject]@{read=$read;applied=$less;tail_applied=$false;owned_pair=$match.owned_pair}}
 }
 throw 'ufw_unified_transport_global_policy_drift'
}
