param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-core.ps1')
$script:checks=0
function Assert($Test,[string]$Message){$script:checks++;if(-not $Test){throw $Message}}
function Reset-Fake {
 $script:images=@{foreign=[pscustomobject]@{rule=[pscustomobject]@{Enabled='1';Name='foreign';Action='Allow'};filter='original'}}
 $script:profiles=@{};foreach($name in @('Domain','Private','Public')){$script:profiles[$name]=[pscustomobject]@{name=$name;default_outbound='NotConfigured';enabled='True';allow_local_rules='True'}}
 $script:writes=@();$script:saves=@();$script:fault=''
 $script:s=[pscustomobject]@{id='i';owner='a';phase='prepared';health='starting';entries=@();foreign=@();profiles=@($script:profiles.Keys|Sort-Object|ForEach-Object{[pscustomobject]@{name=$_;before=(IsoCopy $script:profiles[$_]);after=$null;intent=$false;restored=$false}});plan=$null}
 $script:plan=[pscustomobject]@{rules=@([pscustomobject]@{name='owned';tag='v1'});foreign=@([pscustomobject]@{name='foreign';image=(IsoCopy $script:images.foreign)})}
 $script:ops=@{
  Save={param($s)$script:saves+=,(IsoCopy $s)}
  Hook={param($point)if($script:fault -ceq $point){throw ('injected:'+ $point)}}
  Read={param($n)if($script:images.ContainsKey($n)){IsoCopy $script:images[$n]}else{$null}}
  Create={param($spec,$id)$script:writes+='Create:'+$spec.name;$script:images[$spec.name]=[pscustomobject]@{rule=[pscustomobject]@{Enabled='2';Name=$spec.name;Action='Allow'};filter=$spec.tag}}
  Validate={param($image,$spec,$id,$en)if($null -eq $image -or $image.filter -cne $spec.tag -or ($en -ceq 'True' -and $image.rule.Enabled -cne '1') -or ($en -ceq 'False' -and $image.rule.Enabled -cne '2')){throw 'validation'}}
  Enable={param($n)$script:writes+='Enable:'+$n;$script:images[$n].rule.Enabled='1'}
  Disable={param($n)$script:writes+='Disable:'+$n;$script:images[$n].rule.Enabled='2'}
  Remove={param($n)$script:writes+='Remove:'+$n;$script:images.Remove($n)}
  ProfileRead={param($n)IsoCopy $script:profiles[$n]}
  ProfileSet={param($n,$d)$script:writes+='Profile:'+$n+':'+$d;$script:profiles[$n].default_outbound=$d}
  Verify={param($s)foreach($p in $script:profiles.Values){if($p.default_outbound -cne 'Block'){throw 'verify-profile'}};foreach($e in @($s.entries|Where-Object{-not $_.removed})){if($script:images[$e.name].rule.Enabled -cne '1'){throw 'verify-owned'}};foreach($f in @($s.foreign|Where-Object{$_.intent})){if($script:images[$f.name].rule.Enabled -cne '2'){throw 'verify-foreign'}}}
 }
}
Reset-Fake;$original=IsoCopy $script:images.foreign;$null=Invoke-IsoArm $s $plan $ops
Assert ($s.phase -ceq 'armed') 'arm phase';Assert ($script:images.owned.rule.Enabled -ceq '1') 'owned enabled';Assert ($script:images.foreign.rule.Enabled -ceq '2') 'foreign disabled';Assert (UEqual $s.foreign[0].before $original) 'before preserved';Assert (@($script:saves|Where-Object{$_.entries.Count -gt 0 -and $null -eq $_.entries[0].disabled}).Count -gt 0) 'intent first'
$null=Restore-IsoSession $s $ops;Assert ($s.phase -ceq 'restored') 'restore phase';Assert (UEqual $script:images.foreign $original) 'foreign exact restored';Assert (-not $script:images.ContainsKey('owned')) 'owned removed';foreach($p in $script:profiles.Values){Assert ($p.default_outbound -ceq 'NotConfigured') 'NotConfigured restored not Allow'}
$writeCount=$script:writes.Count;$null=Restore-IsoSession $s $ops;Assert ($script:writes.Count -eq $writeCount) 'restore idempotent'
# Every transactional checkpoint fault leaves the original backed-up image; no implicit Allow/restore.
foreach($injectedPoint in @('arming','create_intent:owned','sealed:owned','profile_intent:Domain','profile_blocked:Domain','profile_intent:Private','profile_blocked:Private','profile_intent:Public','profile_blocked:Public','foreign_intent:foreign','foreign_disabled:foreign','enabled:owned','armed')){
 Reset-Fake;$script:fault=$injectedPoint;$caught=$false;try{$null=Invoke-IsoArm $s $plan $ops}catch{$caught=$true};Assert $caught ('fault not hit '+$injectedPoint);Assert (@($script:writes|Where-Object{$_ -like 'Profile:*:Allow' -or $_ -like 'Profile:*:NotConfigured' -or $_ -ceq 'Enable:foreign'}).Count -eq 0) ('failure released protection '+$injectedPoint)
}
# Drift: all preflighted before the first restore write.
foreach($kind in @('owned','foreign','profile','unsealed')){
 Reset-Fake;$null=Invoke-IsoArm $s $plan $ops
 if($kind -eq 'owned'){$script:images.owned.filter='changed'}elseif($kind -eq 'foreign'){$script:images.foreign.filter='changed'}elseif($kind -eq 'unsealed'){$s.entries[0].disabled=$null;$s.entries[0].enabled=$null}else{$script:profiles.Domain.default_outbound='Unexpected'}
 $before=$script:writes.Count;$caught=$false;try{$null=Restore-IsoSession $s $ops}catch{$caught=$true};Assert $caught ('drift not refused '+$kind);Assert ($script:writes.Count -eq $before) ('restore wrote before full preflight '+$kind)
}
# In-place replacement does not release profile guards or foreign Allow.
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$before=$script:writes.Count
$next=[pscustomobject]@{rules=@([pscustomobject]@{name='owned2';tag='v2'});foreign=@()};$null=Invoke-IsoUpdate $s $next $ops
Assert ($s.phase -ceq 'armed') 'update phase';Assert (-not $script:images.ContainsKey('owned')) 'old removed';Assert ($script:images.owned2.rule.Enabled -ceq '1') 'new enabled';Assert (@($script:writes|Select-Object -Skip $before|Where-Object{$_ -like 'Profile:*' -or $_ -eq 'Enable:foreign'}).Count -eq 0) 'update release gap'
$null=Restore-IsoSession $s $ops;Assert ($s.phase -ceq 'restored') 'updated restore'
# Rule collision never adopted, no overwritten foreign rule.
Reset-Fake;$script:images.owned=IsoCopy $script:images.foreign;$before=IsoCopy $script:images.owned;try{$null=Invoke-IsoArm $s $plan $ops}catch{};Assert (UEqual $before $script:images.owned) 'collision overwrite'
$result=@{suite='isolation-transaction-core-fake-native';passed=$true;assertions=$script:checks;Windows_firewall_executed=$false;packet_leak_tested=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/isolation-core-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
