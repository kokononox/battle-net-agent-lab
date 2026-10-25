# Scoped channel toggle, not Windows security audit policy. Never clear log or alter target tasks.
function Start-DiagnosticLog {
 $ErrorActionPreference='Stop';New-Item -ItemType Directory -Force output | Out-Null
 $channel='Microsoft-Windows-TaskScheduler/Operational';$log=Get-WinEvent -ListLog $channel -ErrorAction Stop
 $original=[bool]$log.IsEnabled;$changed=$false
 if(-not $original){$null=& "$env:SystemRoot\System32\wevtutil.exe" sl $channel /e:true;if($LASTEXITCODE -ne 0){throw 'diagnostic_log_enable_failed'};$changed=$true}
 $probe=@{original_enabled=$original;changed=$changed;audit_baseline=(Start-TaskAudit)}
 $probe | ConvertTo-Json -Depth 8 | Set-Content output/g34-log-probe.json -Encoding UTF8
 if(-not $probe.audit_baseline.operational_log_enabled){throw 'diagnostic_log_not_enabled'}
}
function Stop-DiagnosticLog([string]$Root){
 $path=if($Root){Join-Path $Root 'log-probe.json'}else{'output/g34-log-probe.json'}
 if(-not (Test-Path $path)){return}
 $probe=Get-Content -Raw $path | ConvertFrom-Json;$channel='Microsoft-Windows-TaskScheduler/Operational'
 $r=@{attempted=$true;original_enabled=[bool]$probe.original_enabled;changed_by_experiment=[bool]$probe.changed;restored=$false;audit_policy_changed=$false;log_cleared=$false}
 try{
  if($probe.changed -and -not $probe.original_enabled){$null=& "$env:SystemRoot\System32\wevtutil.exe" sl $channel /e:false;if($LASTEXITCODE -ne 0){throw 'diagnostic_log_restore_failed'}}
  $r.restored=([bool](Get-WinEvent -ListLog $channel -ErrorAction Stop).IsEnabled -eq [bool]$probe.original_enabled)
 }catch{$r.error_code='diagnostic_log_restore_failed'}
 if($Root){$r | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Root 'diagnostic-log-restoration.json') -Encoding UTF8}else{$r | ConvertTo-Json -Depth 4 | Set-Content output/g34-diagnostic-log-restoration.json -Encoding UTF8}
}
