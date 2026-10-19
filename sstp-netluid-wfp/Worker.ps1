param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidateSet('Install','Remove','Recover')][string]$Action,[string]$Fault='none')
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
. "$PSScriptRoot/../sstp-allowlist-backend/Journal.ps1"
try {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 # Serialize the entire operation, not just individual journal reads/writes.
 $op=New-Object IO.FileStream((Join-Path $Root 'operation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 try {
  $j=ReadJournal $Root;if($j.status -ne 'valid'){throw 'wfp_journal_unavailable'};$record=$j.record;$s=$record.state
  if((($s.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'native_hash,native_path,phase,plan,schema' -or $s.schema -cne 'sstp-wfp-state-1' -or $s.phase -cnotin @('planned','installing','installed','removing','removed')){throw 'wfp_state_schema'}
  if((($s.plan.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'app,ip,keys,luid' -or $s.plan.keys.Count -ne 5){throw 'wfp_plan_schema'}
  $native=AssertJournalPath $s.native_path;$app=AssertJournalPath $s.plan.app
  if([IO.Path]::GetFileName($native) -cne 'sstp-luid-native.exe' -or [IO.Path]::GetDirectoryName($native) -cne [IO.Path]::GetDirectoryName($app)){throw 'wfp_native_path'}
  AssertJournalAcl ([IO.Path]::GetDirectoryName($native))
  if((Get-FileHash -LiteralPath $native -Algorithm SHA256).Hash.ToLowerInvariant() -cne $s.native_hash){throw 'wfp_native_hash'}
  function InvokeNative([string]$Mode,[string]$Crash='none') {
   $a=@($Mode)+@($s.plan.keys)+@([string]$s.plan.luid,[string]$s.plan.ip,[string]$s.plan.app)
   if($Crash -ne 'none'){$a+=,$Crash}
   $out=& $native @a;$code=$LASTEXITCODE
   if($code -eq 73){exit 73};if($code -ne 0){throw 'wfp_native_failed'}
   return (($out -join "`n")|ConvertFrom-Json)
  }
  $observed=InvokeNative 'audit'
  if($Action -eq 'Recover') {
   if($s.phase -cnotin @('installing','removing')){throw 'wfp_not_pending'}
   if($s.phase -ceq 'installing') {if($observed.state -ceq 'installed'){$s.phase='installed'}else{$s.phase='planned'}}
   else {if($observed.state -ceq 'installed'){$s.phase='installed'}else{$s.phase='removed'}}
   $null=WriteJournal $Root $record.revision $s
  } else {
   if($Action -eq 'Install') {
    if($s.phase -ceq 'installed' -and $observed.state -ceq 'installed'){exit 0}
    if($s.phase -cnotin @('planned','removed') -or $observed.state -cne 'absent'){throw 'wfp_frontier_conflict'}
    $s.phase='installing';$mode='install';$done='installed'
   } else {
    if($s.phase -ceq 'removed' -and $observed.state -ceq 'absent'){exit 0}
    if($s.phase -cne 'installed' -or $observed.state -cne 'installed'){throw 'wfp_frontier_conflict'}
    $s.phase='removing';$mode='remove';$done='removed'
   }
   $record=WriteJournal $Root $record.revision $s
   if($Fault -ceq 'before-native'){exit 73}
   $null=InvokeNative $mode $Fault;$s.phase=$done;$null=WriteJournal $Root $record.revision $s
  }
 } finally {if($null -ne $op){$op.Dispose()}}
 exit 0
} catch {Write-Host 'wfp_worker_stopped';exit 1}
