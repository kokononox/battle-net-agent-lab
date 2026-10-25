$ErrorActionPreference='Stop'
$approval='lab: approved two-host egress qualification G8 20261025'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:BNET_TWO_HOSTS -ne $approval -or $env:GITHUB_RUN_ATTEMPT -ne '1') { throw 'fresh_hosted_approval_required' }
# Only the fresh disposable research runner. Never run on a user workstation.
# Do not stop HTTP, WAS, WinRM, networking or runner management services.
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-two-hosts-iis-g8-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;installer_launched=$false;service='W3SVC';original_state=$null;stopped_for_test=$false;restored=$false;error_code=$null}
try{
 $s=Get-Service W3SVC -ErrorAction Stop
 if($s.Status -notin @('Running','Stopped')){throw 'iis_transitional_state'}
 $r.original_state=[string]$s.Status
 # Persist intent before the only service mutation so an always step can restore.
 $r | ConvertTo-Json | Set-Content output/two-hosts-iis-g8.json -Encoding UTF8
 if($s.Status -eq 'Running'){
  Stop-Service W3SVC -ErrorAction Stop
  (Get-Service W3SVC).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
  $r.stopped_for_test=$true
 }
 & python analysis-tools/two-host-install/qualify_gate.py
 if($LASTEXITCODE -ne 0){throw 'qualification_process_failed'}
}catch{$r.error_code='disposable_qualification_operation_failed'}
finally{
 try{
  if($r.original_state -eq 'Running'){
   Start-Service W3SVC -ErrorAction Stop
   (Get-Service W3SVC).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
  }
  $r.restored=([string](Get-Service W3SVC).Status -eq $r.original_state)
 }catch{$r.restored=$false;$r.error_code='iis_restore_failed'}
 $r | ConvertTo-Json | Set-Content output/two-hosts-iis-g8.json -Encoding UTF8
}
if(-not $r.restored -or $r.error_code){throw 'disposable_qualification_or_restore_failed'}
