param([string]$Root,[ValidateSet('None','BeforeCreate','AfterCapture')][string]$Fault='None')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
. (Join-Path $PSScriptRoot 'Resume.ps1')
try{
 $s=OverlayLoad $Root;if($s.state.scope -cne 'Fixture'){throw 'resume_test_scope'}
 ResumeOverlayPreparation $Root -Fault $Fault|Out-Null;exit 0
}catch{
 $code='resume_worker_failed';if($_.Exception.Message -cmatch '^(resume|overlay|journal)_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 [Console]::Error.WriteLine($code);exit 1
}
