# Pure admission model, NOT a monitor, collector or kernel enforcement hook.
# Caller must provide fresh, trusted native observations. A matching model cannot
# prove that an exited controller will notice a later boot/session/interface reuse.
Set-StrictMode -Version Latest
. "$PSScriptRoot/../sstp-ras-identity/Policy.ps1"
function TestBindingEpochShape($Epoch) {
 if($null -eq $Epoch -or $Epoch -isnot [pscustomobject]){return $false}
 if((($Epoch.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'boot_marker,interface_guid,net_luid,profile_guid,profile_scope,ras_correlation,ras_observation,schema'){return $false}
 if($Epoch.schema -cne 'sstp-binding-epoch-1' -or $Epoch.profile_scope -cnotin @('CurrentUser','AllUsers')){return $false}
 foreach($k in @('profile_guid','interface_guid','ras_correlation')){if($Epoch.$k -isnot [string] -or $Epoch.$k -cnotmatch '^[a-f0-9]{32}$' -or $Epoch.$k -ceq ('0'*32)){return $false}}
 if($Epoch.boot_marker -isnot [string] -or $Epoch.boot_marker -cnotmatch '^[a-f0-9]{64}$' -or $Epoch.boot_marker -ceq ('0'*64)){return $false}
 if($Epoch.net_luid -isnot [string] -or $Epoch.net_luid -cnotmatch '^[1-9][0-9]{0,19}$'){return $false}
 [UInt64]$value=0;if(-not [UInt64]::TryParse($Epoch.net_luid,[ref]$value) -or $value -eq 0){return $false}
 if($null -eq $Epoch.ras_observation -or $Epoch.ras_observation -isnot [pscustomobject]){return $false}
 return $true
}
function GetBindingEpochDecision($Expected,$Observed) {
 try {
  if(-not (TestBindingEpochShape $Expected) -or -not (TestBindingEpochShape $Observed)){return 'deny_invalid_epoch'}
  if((GetRasIdentityDecision $Expected.ras_observation) -cne 'identity_chain_observed' -or (GetRasIdentityDecision $Observed.ras_observation) -cne 'identity_chain_observed'){return 'hold_unqualified_identity'}
  foreach($k in @('boot_marker','profile_guid','profile_scope','ras_correlation','interface_guid','net_luid')){if($Expected.$k -cne $Observed.$k){return 'hold_changed_epoch'}}
  return 'same_epoch_observed'
 } catch {return 'deny_invalid_epoch'}
}
