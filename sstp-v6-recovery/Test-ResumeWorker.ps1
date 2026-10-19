param([string]$Root,[ValidateSet('None','BeforeCreate','AfterCapture')][string]$Fault='None')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
. (Join-Path $PSScriptRoot 'Resume.ps1')
try{
 $s=OverlayLoad $Root;if($s.state.scope -cne 'Fixture'){throw 'resume_test_scope'}
 ResumeOverlayPreparation $Root -Fault $Fault|Out-Null
 [IO.File]::WriteAllText((Join-Path $Root 'resume-worker-result.json'),'{"error_code":null}')
 exit 0
}catch{
 $code='resume_worker_failed';if($_.Exception.Message -cmatch '^(resume|overlay|journal)_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 try{[IO.File]::WriteAllText((Join-Path $Root 'resume-worker-result.json'),([pscustomobject]@{error_code=$code;line=[int]$_.InvocationInfo.ScriptLineNumber;exception_type=$_.Exception.GetType().Name}|ConvertTo-Json -Compress))}catch{}
 [Console]::Error.WriteLine($code);exit 1
}
