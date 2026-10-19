param([string]$Root,[ValidateSet('Enable','Disable','Remove','Status')][string]$Action,[ValidateSet('None','BeforeSet','AfterSet')][string]$Fault='None')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
try{
 $s=OverlayLoad $Root;if($s.state.scope -cne 'Fixture'){throw 'overlay_test_scope'}
 InvokeOverlay $Root $Action -Fault $Fault|Out-Null
 exit 0
}catch{
 $code='overlay_worker_failed';if($_.Exception.Message -cmatch '^overlay_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 [Console]::Error.WriteLine($code);exit 1
}
