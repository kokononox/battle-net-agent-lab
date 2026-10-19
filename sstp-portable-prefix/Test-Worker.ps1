param([string]$Root,[ValidateSet('Enable','Disable','Remove','Status')][string]$Action,[ValidateSet('None','BeforeSet','AfterSet')][string]$Fault='None')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
try{
 $s=OverlayLoad $Root;if($s.state.scope -cne 'Fixture'){throw 'overlay_test_scope'}
 if($Action -ceq 'Disable'){
  # Recovery must not depend on an active VPN/active-store Full status.
  $script:originalOverlayReader=${function:OverlayRead}
  function OverlayRead([string]$Name,[string]$Store='PersistentStore'){
   if($Store -ceq 'ActiveStore'){throw 'overlay_disable_unexpected_active_query'}
   & $script:originalOverlayReader $Name $Store
  }
 }
 InvokeOverlay $Root $Action -Fault $Fault|Out-Null
 [IO.File]::WriteAllText((Join-Path $Root 'worker-result.json'),'{"error_code":null,"enforcement":null}')
 exit 0
}catch{
 $code='overlay_worker_failed';if($_.Exception.Message -cmatch '^overlay_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 $enforcement=@()
 try{
  $known=OverlayLoad $Root
  foreach($o in $known.state.objects){
   $rr=OverlayRead $o.spec.name 'ActiveStore'
   if($null -ne $rr){$enforcement+=,[pscustomobject]@{statuses=@($rr.rule.CimInstanceProperties['EnforcementStatus'].Value|ForEach-Object{[int]$_});primary=[int]$rr.rule.CimInstanceProperties['PrimaryStatus'].Value}}
  }
 }catch{}
 try{[IO.File]::WriteAllText((Join-Path $Root 'worker-result.json'),([pscustomobject]@{error_code=$code;enforcement=@($enforcement)}|ConvertTo-Json -Depth 5 -Compress))}catch{}
 [Console]::Error.WriteLine($code);exit 1
}
