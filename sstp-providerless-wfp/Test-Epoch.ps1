# Twenty synthetic, read-only model cases. No live RAS or reboot is simulated as real.
function NewEpochFixture {
 $o=NewRasIdentityObservation
 foreach($k in $o.PSObject.Properties.Name){$o.$k=$true}
 foreach($k in @('active_sstp_count','ras_profile_guid_match_count','projection_ip_matching_interfaces')){$o.$k=1}
 return [pscustomobject][ordered]@{schema='sstp-binding-epoch-1';profile_guid=('1'*32);profile_scope='CurrentUser';ras_correlation=('2'*32);interface_guid=('3'*32);net_luid='72057594037927937';boot_marker=('a'*64);ras_observation=$o}
}
function EpochAssert($Expected,$Observed,[string]$Decision){if((GetBindingEpochDecision $Expected $Observed) -cne $Decision){throw 'epoch_model_assertion'};$script:epochModelCount++}
function TestEpochModel {
 $script:epochModelCount=0;$a=NewEpochFixture;$b=NewEpochFixture
 EpochAssert $a $b 'same_epoch_observed'
 $b.ras_observation.alias_equal_to_profile_name=$false;EpochAssert $a $b 'same_epoch_observed'
 foreach($k in @('profile_guid','profile_scope','ras_correlation','interface_guid','net_luid','boot_marker')){
  $b=NewEpochFixture
  switch($k){'profile_scope'{$b.$k='AllUsers'}'net_luid'{$b.$k='72057594037927938'}'boot_marker'{$b.$k=('b'*64)}default{$b.$k=('4'*32)}}
  EpochAssert $a $b 'hold_changed_epoch'
 }
 foreach($k in @('candidate_is_ppp','active_sstp_count','active_sstp_count','connection_stable_on_recheck')){
  $b=NewEpochFixture
  if($k -ceq 'active_sstp_count'){if($script:epochModelCount -eq 9){$b.ras_observation.$k=0}else{$b.ras_observation.$k=2}}else{$b.ras_observation.$k=$false}
  EpochAssert $a $b 'hold_unqualified_identity'
 }
 $b=NewEpochFixture;$b.ras_observation=$null;EpochAssert $a $b 'deny_invalid_epoch'
 $b=NewEpochFixture;$b.PSObject.Properties.Remove('net_luid');EpochAssert $a $b 'deny_invalid_epoch'
 $b=NewEpochFixture;$b.net_luid=[UInt64]72057594037927937;EpochAssert $a $b 'deny_invalid_epoch'
 $b=NewEpochFixture;$b.net_luid='0';EpochAssert $a $b 'deny_invalid_epoch'
 $b=NewEpochFixture;$b|Add-Member extra $true;EpochAssert $a $b 'deny_invalid_epoch'
 $b=NewEpochFixture;$b.interface_guid='not-a-guid';EpochAssert $a $b 'deny_invalid_epoch'
 EpochAssert $null (NewEpochFixture) 'deny_invalid_epoch'
 EpochAssert $a $null 'deny_invalid_epoch'
 if($script:epochModelCount -ne 20){throw 'epoch_model_count'}
 return $script:epochModelCount
}
