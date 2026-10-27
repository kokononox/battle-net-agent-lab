$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$r=[ordered]@{schema='ufw-program-observer-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;observer=$null;program_execution_requested=$false;authenticode_verification_requested=$false;firewall_change_requested=$false;baseline_journal_access_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$module=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_program_local_package_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_program_package_reparse'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 $dest=Join-Path $root ('UFW-PROGRAM-OBSERVER-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_observer_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_observer_ps51_x64_required'}
 if([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA){throw 'ufw_program_file_picker_sta_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_observer_admin_required'}
 $r.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "ProgramReader.cs": "2575193326d3225672d1206c5ec75f51ca5a84683079d6294e5e6d30201c0019",
  "ProgramReview.ps1": "f810f48d53b208b0389236fb4d6fa7b146dd789839dcea5f26c12ae1d099f175",
  "CandidateEntry.ps1": "835361366a3dd61b24e7ea252db42a38631f86dbfc299f8fb3ff57d114164a54",
  "ObserverEntry.ps1": "851904b067be350ac2c945f963a624dee2e6db9f864ba2d26d9f5b678e1ddbf7"
}
'@
 foreach($v in $hashes.PSObject.Properties){$f=Join-Path $root $v.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $v.Value){throw 'ufw_program_payload_mismatch'}}
 $r.payload_verified=$true;$r.stage='load_native_file_reader'
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'ProgramReader.cs'))) -Language CSharp -ErrorAction Stop
 $r.stage='load_pinned_storage_helpers'
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 $r.stage='select_existing_candidate_and_passive_observation'
 $r.observer=& $module {param($root). (Join-Path $root 'ProgramReview.ps1');. (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'ObserverEntry.ps1');Invoke-UfwObserverNative} $root
 $r.code=$r.observer.code
 if($r.observer.completed){$r.completed=$true;$r.stage='completed';$rc=0}
 Write-Host ('Result: '+$r.code);Write-Host ('Samples: '+$r.observer.samples_completed+'; unapproved suggestions: '+$r.observer.suggestion_count);Write-Host ('Private write status: '+$r.observer.private_write_status)
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^(ufw_observer|ufw_program|ufw_candidate|ufw_journal)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_observer_unavailable'}
 Write-Host ('Stopped at '+$r.stage+': '+$r.code)
}finally{
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 16));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only stage/code without private paths.';$rc=1}}
 Write-Host 'Return only NEW UFW-PROGRAM-OBSERVER-01-*.json, including failure or cancellation.'
 Write-Host 'Do NOT share private review paths, hashes, file IDs or screenshots/transcripts.'
 Write-Host 'Existing candidate is READ ONLY. Private IP suggestions are saved only after local Observe consent. No trust, execution or Apply authority.'
}
exit $rc
