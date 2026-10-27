# Diagnostic only; observe the current state without disconnecting or dialing the VPN.
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='sstp-local-review-diagnostic-01';diagnostic_completed=$false;stage='platform_guard';error_code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;candidate_count=0;selection_mode='none';selection_is_firewall_approval=$false;native_API_attempted=$false;observation=$null;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;credentials_read=$false;private_binding_saved=$false;guardian_integration=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'observer_local_folder_required'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 if($root.StartsWith('\\')){throw 'observer_local_folder_required'}
 $dest=Join-Path $root ('SSTP-LOCAL-REVIEW-01-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'observer_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'observer_ps51_64bit_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
 if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'observer_administrator_required'}
 $report.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Observer.ps1": "cf4eedff5a619a1606b6db32e8e61d1803f821ec1521ce71712af605a7aed9d8",
  "Identity.ps1": "dd85d5b2c94c10569fb3d213857b66055124e50545bfe5ff11f972c5ef369d52",
  "IdentityPolicy.ps1": "e65311433807a83f41b36f3e78a183b63fb5e719a1016afb61fe14fac5cd1fdf",
  "RasIdentity.cs": "7ef16ae763ec52223f30986a375b32d3027a0e8b276c231bb17fbc39cd2de88e",
  "Endpoint.ps1": "0ab4e8344002a47072d721eb2b115237e955025863e48e74f0a80a56054a705d",
  "Sstp.TransportPlan.ps1": "ac3c24824324110fe5a1ee6e93f6deb974570abc2b36c3d27f3f3ab6fd9a8409",
  "LocalReview.ps1": "7c8120a9886a54dd15a8af3ce609355ac09adf420f77b3d40d612a4d0800742c"
}
'@
 foreach($item in $hashes.PSObject.Properties){
  $f=Join-Path $root $item.Name
  if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $item.Value){throw 'observer_payload_mismatch'}
 }
 $report.payload_verified=$true;. (Join-Path $root 'LocalReview.ps1')
 $report.stage='candidate_inventory';$report.native_API_attempted=$true
 $profiles=Read-SstpObserverProfiles
 $candidates=@($profiles|Where-Object{$_.tunnel -ceq 'Sstp'})
 $report.candidate_count=$candidates.Count
 if($candidates.Count -ne 1){throw 'observer_unique_candidate_required'}
 $selected=$candidates[0]
 # This is an ephemeral diagnostic selection, NOT policy approval or persisted identity.
 $expected=[pscustomobject][ordered]@{schema='sstp-observer-selection-1';profile_guid=$selected.guid;profile_scope=$selected.scope;profile_name=$selected.name;server=$selected.server;owner_sid=(Read-SstpObserverCallerSid)}
 $report.selection_mode='single_visible_SSTP_for_memory_only_draft_review'
 Write-Host 'Reviewing one SSTP candidate locally. This is NOT firewall approval.'
 Write-Host 'No VPN dial/disconnect, DNS lookup, firewall change, or network probe will be requested.'
 $report.stage='local_review';$binding=$null
 $report.observation=Invoke-SstpLocalEndpointReview $expected
 # Private names/IP/GUID/session tokens remain memory-only and are never serialized.
 $binding=$null;$expected=$null;$profiles=$null;$candidates=$null;$selected=$null
 $report.diagnostic_completed=$report.observation.completed
 $report.stage='completed'
 Write-Host ('Draft review acknowledged: '+$report.observation.draft_review_acknowledged)
 Write-Host ('Fresh revalidation passed: '+$report.observation.fresh_revalidation_passed)
 Write-Host ('Observation code: '+$report.observation.code)
 if($report.diagnostic_completed){$rc=0}
}catch{
 $message=[string]$_.Exception.GetBaseException().Message
 if($message -cmatch '^observer_[a-z_0-9]{1,90}$'){$report.error_code=$message}else{$report.error_code='observer_diagnostic_unavailable'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.error_code)
}finally{
 if($null -ne $dest){
  try{
   $bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 24))
   $stream=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
   Write-Host ('Report: '+$dest)
  }catch{Write-Host 'Report could not be saved. Send the stage/code text instead.';$rc=1}
 }
 Write-Host ('Diagnostic completed: '+$report.diagnostic_completed)
 Write-Host 'Return only the new SSTP-LOCAL-REVIEW-01-*.json file. Do NOT send the local review screen.'
 Write-Host 'This does NOT approve isolation, TLS/DNS bootstrap, reconnection, or no-leak.'
}
exit $rc
