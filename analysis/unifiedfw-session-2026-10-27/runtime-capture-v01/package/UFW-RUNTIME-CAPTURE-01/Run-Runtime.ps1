$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$r=[ordered]@{schema='ufw-runtime-capture-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;runtime=$null;selected_program_execution_requested=$false;diagnostic_child_execution_requested=$false;diagnostic_tcp_connect_requested=$false;authenticode_verification_requested=$false;firewall_change_requested=$false;baseline_journal_access_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$module=$null;$privilege=$null;$mutex=$null;$ownsMutex=$false;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_program_local_package_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_program_package_reparse'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 $dest=Join-Path $root ('UFW-RUNTIME-CAPTURE-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_runtime_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_runtime_ps51_x64_required'}
 if([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA){throw 'ufw_program_file_picker_sta_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_runtime_admin_required'}
 $r.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "ProgramReader.cs": "2575193326d3225672d1206c5ec75f51ca5a84683079d6294e5e6d30201c0019",
  "ProgramReview.ps1": "f810f48d53b208b0389236fb4d6fa7b146dd789839dcea5f26c12ae1d099f175",
  "CandidateEntry.ps1": "835361366a3dd61b24e7ea252db42a38631f86dbfc299f8fb3ff57d114164a54",
  "ObserverEntry.ps1": "851904b067be350ac2c945f963a624dee2e6db9f864ba2d26d9f5b678e1ddbf7",
  "RuntimeNative.cs": "f38f64596d4f64719fd9ea652d6ff261335367370e8e1b4b26e8c5d95e2158c6",
  "RuntimeCore.ps1": "87286d8d219064777eb1c86168c6ff1eb00cd061ed6a0ed4931c88120af4283a",
  "RuntimeEntry.ps1": "c0cc3d4d7501245b31f086aefd412b56d07ecb95ef427a034760f8d6f880cb2b"
}
'@
 foreach($v in $hashes.PSObject.Properties){$f=Join-Path $root $v.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $v.Value){throw 'ufw_program_payload_mismatch'}}
 $r.payload_verified=$true;$r.stage='load_native_file_reader'
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'ProgramReader.cs'))) -Language CSharp -ErrorAction Stop
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'RuntimeNative.cs'))) -Language CSharp -ErrorAction Stop
 $r.stage='native_privilege_and_capture_lock';$privilege=New-Object UfwRuntime01.SecurityPrivilege
 $mutex=New-Object Threading.Mutex($false,'Global\UnifiedFW-RuntimeCapture-01');try{$ownsMutex=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$ownsMutex=$true};if(-not $ownsMutex){throw 'ufw_runtime_another_session_active'}
 $r.stage='load_pinned_storage_helpers'
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 $r.stage='runtime_events_and_scoped_audit_recovery'
 $r.runtime=& $module {param($root). (Join-Path $root 'ProgramReview.ps1');. (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'ObserverEntry.ps1');. (Join-Path $root 'RuntimeCore.ps1');. (Join-Path $root 'RuntimeEntry.ps1');Invoke-UfwRuntimeNative} $root
 $r.code=$r.runtime.code;$r.diagnostic_child_execution_requested=$r.runtime.selftest_requested;$r.diagnostic_tcp_connect_requested=$r.runtime.selftest_requested
 if($r.runtime.completed){$r.completed=$true;$r.stage='completed';$rc=0}
 Write-Host ('Result: '+$r.code);Write-Host ('Selected starts: '+$r.runtime.root_start_events+'; descendants: '+$r.runtime.descendant_start_events+'; blocked events: '+$r.runtime.blocked_events+'; unapproved endpoints: '+$r.runtime.suggestion_count);Write-Host ('Audit restored: '+$r.runtime.audit_restore_verified+'; recovery required: '+$r.runtime.audit_recovery_required)
 Write-Host 'Close any installer yourself; this tool never kills or rolls back it. Do not open firewall to fill results.'
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^(ufw_runtime|ufw_observer|ufw_program|ufw_candidate|ufw_journal)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_runtime_unavailable'}
 Write-Host ('Stopped at '+$r.stage+': '+$r.code)
}finally{
 if($null -ne $privilege){try{$privilege.Dispose()}catch{$r.completed=$false;$r.code='ufw_runtime_privilege_restore_failed';$rc=1}}
 if($ownsMutex){try{$mutex.ReleaseMutex()}catch{}};if($null -ne $mutex){$mutex.Dispose()}
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 16));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only stage/code without private paths.';$rc=1}}
 Write-Host 'Return only NEW UFW-RUNTIME-CAPTURE-01-*.json, including failure or cancellation.'
 Write-Host 'Do NOT share private review paths, hashes, file IDs or screenshots/transcripts.'
 Write-Host 'Existing candidate is READ ONLY; runtime proposals are NOT approved grants. Audit journal is NOT the older firewall baseline. Re-run same package for explicit audit recovery if pending. Do not delete private files or send Security log exports.'
}
exit $rc
