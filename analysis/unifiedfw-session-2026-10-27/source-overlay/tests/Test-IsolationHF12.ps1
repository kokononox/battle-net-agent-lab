param([string]$Root=(Join-Path $PSScriptRoot '..'))
# Reuse existing fake adapter and legacy regression checks, never Windows cmdlets.
. (Join-Path $Root 'tests/Test-IsolationCore.ps1') -Root $Root
. (Join-Path $Root 'app/isolation-native.ps1')
$script:checks=0
function Reject($Block,$Code){$caught=$false;try{& $Block|Out-Null}catch{$caught=$_.Exception.Message -ceq $Code};Assert $caught ('expected '+$Code)}
function Setup-Transport{
 Reset-Fake
 $script:plan.rules=@([pscustomobject]@{name='transport';tag='transport'},[pscustomobject]@{name='owned';tag='whitelist'})
 $script:plan|Add-Member NoteProperty pre_block_rule_names @('transport')
 # Model a tunnel collapsing if global Block arrives before exact transport Allow.
 $script:ops.ProfileSet={param($n,$d)
  if($d -ceq 'Block' -and $script:images.transport.rule.Enabled -cne '1'){throw 'modeled_tunnel_lost'}
  $script:writes+='Profile:'+$n+':'+$d;$script:profiles[$n].default_outbound=$d
 }
}
Setup-Transport;$null=Invoke-IsoArm $s $plan $ops
Assert ($s.phase -ceq 'armed') 'transport-first arm'
Assert ([array]::IndexOf($script:writes,'Enable:transport') -lt [array]::IndexOf($script:writes,'Profile:Domain:Block')) 'transport before global block'
Assert ([array]::IndexOf($script:writes,'Enable:owned') -gt [array]::IndexOf($script:writes,'Disable:foreign')) 'whitelist after quarantine'
foreach($failure in @('enable','readback','validate')){
 Setup-Transport
 if($failure -ceq 'enable'){$ops.Enable={param($n)throw 'injected_transport'}}
 elseif($failure -ceq 'readback'){$ops.Enable={param($n)$script:writes+='Enable:'+$n}}
 else{$ops.Validate={param($i,$r,$id,$en)if($en -ceq 'True'){throw 'injected_validation'}}}
 $caught=$false;try{$null=Invoke-IsoArm $s $plan $ops}catch{$caught=$true}
 Assert $caught ('fault '+$failure)
 Assert (@($script:writes|Where-Object{$_ -like 'Profile:*' -or $_ -like 'Disable:*'}).Count -eq 0) ('no global mutation after early '+$failure)
}
Setup-Transport;$plan.pre_block_rule_names=@('unknown');Reject {Invoke-IsoArm $s $plan $ops} 'iso_invalid_pre_block_rule_identity'
Assert ($script:writes.Count -eq 0) 'bad compiler metadata rejected before writes'
# Missing transport metadata in the OLD order reproduces the modeled dependency fault.
Setup-Transport;$plan.pre_block_rule_names=@();Reject {Invoke-IsoArm $s $plan $ops} 'modeled_tunnel_lost'
# Actual production compiler, mocked environment only.
function IsoAssertNoOtherEngine{param($s)@{}}
function IsoDetectSstp{[pscustomobject]@{name='fixture';svchost='C:\Windows\System32\svchost.exe';server_ips=@('192.0.2.10');dns_servers=@('192.0.2.53')}}
function IsoPrepareForeignAllows{param($s)return ,@()}
function IsoProfileRead{param($n)[pscustomobject]@{name=$n;enabled='True';default_outbound='Allow';allow_local_rules='True'}}
function Get-NetFirewallSecurityFilter{param($PolicyStore,$ErrorAction)}
$p=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);connection='vpn';whitelist=@([pscustomobject]@{remote_addresses=@('192.0.2.20');protocol='TCP';remote_port='443'})}
$compiled=IsoPrepare $p $null
Assert ($compiled.pre_block_rule_names.Count -eq 1) 'only one bootstrap transport'
$early=@($compiled.rules|Where-Object{$compiled.pre_block_rule_names -ccontains $_.name})
Assert ($early.Count -eq 1 -and $early[0].spec.service -ceq 'SstpSvc') 'not whitelist or DNS before block'
$p.connection='direct';$direct=IsoPrepare $p $null
Assert ($direct.pre_block_rule_names.Count -eq 0 -and $direct.rules.Count -eq 1) 'direct has no new exception'
# Native deletion-only validator. Exact owned DISABLED image plus alias drift only.
$owner='a'*32;$id='b'*32;$name='UnifiedFW-ISO-'+$owner+'-'+('c'*24)
$session=[pscustomobject]@{id=$id;owner=$owner}
$disabled=[pscustomobject]@{rule=[pscustomobject]@{Name=$name;Enabled='2';Action='Allow'};interface=[pscustomobject]@{InstanceID=$name;InterfaceAlias=@('fixture')};port=[pscustomobject]@{RemotePort='443'}}
$entry=[pscustomobject]@{name=$name;disabled=$disabled;spec=[pscustomobject]@{name=$name;owner=$owner}}
$script:live=IsoCopy $disabled;$script:live.interface.InterfaceAlias=@()
$script:meta=[pscustomobject]@{Name=$name;DisplayName=$name;Group=('UnifiedFW-ISO-'+$owner);Description=(IsoMarker $entry.spec $id);Enabled='False';Direction='Outbound';Action='Allow';PolicyStoreSourceType='Local'}
function UGetRule{param($n)$script:meta}
function UReadNative{param($n)IsoCopy $script:live}
$before=UJson $script:live;IsoValidateDisabledRemoval $script:live $entry $session
Assert ((UJson $script:live) -ceq $before) 'image not rebased'
Assert (-not (UEqual $script:live $entry.disabled)) 'global equality remains strict'
foreach($field in @('Name','DisplayName','Group','Description','Enabled','Direction','Action','PolicyStoreSourceType')){
 $old=$script:meta.$field;$script:meta.$field='tampered'
 Reject {IsoValidateDisabledRemoval $script:live $entry $session} 'iso_removal_native_identity';$script:meta.$field=$old
}
$script:live.rule.Enabled='1';Reject {IsoValidateDisabledRemoval $script:live $entry $session} 'iso_removal_disabled_required';$script:live.rule.Enabled='2'
$script:live.port.RemotePort='80';Reject {IsoValidateDisabledRemoval $script:live $entry $session} 'iso_removal_additional_drift';$script:live.port.RemotePort='443'
$changed=IsoCopy $script:live;$changed.port.RemotePort='80'
function UReadNative{param($n)$changed}
Reject {IsoValidateDisabledRemoval $script:live $entry $session} 'iso_removal_concurrent_change'
# Restore invokes exception once in global preflight AND again immediately before deletion.
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$script:images.owned.rule.Enabled='2';$script:images.owned.filter='alias-drift'
$script:removalChecks=0;$ops.ValidateDisabledRemoval={param($i,$e,$s)$script:removalChecks++}
$null=Restore-IsoSession $s $ops
Assert ($script:removalChecks -eq 2) 'two removal checks'
Assert ($s.phase -ceq 'restored') 'explicit restore completed'
# A callback rejection remains fail-closed before restoration starts.
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$script:images.owned.filter='changed';$before=$script:writes.Count
$ops.ValidateDisabledRemoval={param($i,$e,$s)throw 'rejected'}
Reject {Restore-IsoSession $s $ops} 'rejected'
Assert ($script:writes.Count -eq $before) 'no partial restore on rejected exception'
$result=@{suite='hf12-order-and-disabled-removal';passed=$true;assertions=$script:checks;Windows_API_executed=$false;packet_leak_tested=$false}
$result|ConvertTo-Json -Compress|Set-Content (Join-Path $Root 'evidence/hf12-order-tests.json');$result|ConvertTo-Json -Compress
