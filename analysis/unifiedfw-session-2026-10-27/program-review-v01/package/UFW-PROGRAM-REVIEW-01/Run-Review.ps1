$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$r=[ordered]@{schema='ufw-program-review-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;review=$null;program_execution_requested=$false;program_config_saved=$false;authenticode_verification_requested=$false;firewall_change_requested=$false;journal_access_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_program_local_package_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_program_package_reparse'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 $dest=Join-Path $root ('UFW-PROGRAM-REVIEW-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_program_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_program_ps51_x64_required'}
 $r.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "ProgramReader.cs": "2575193326d3225672d1206c5ec75f51ca5a84683079d6294e5e6d30201c0019",
  "ProgramReview.ps1": "631dc92b32d3bd4c56a58188a0217a7b2098149f6487846fa97f6e10273020a3"
}
'@
 foreach($v in $hashes.PSObject.Properties){$f=Join-Path $root $v.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $v.Value){throw 'ufw_program_payload_mismatch'}}
 $r.payload_verified=$true;$r.stage='load_native_file_reader'
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'ProgramReader.cs'))) -Language CSharp -ErrorAction Stop
 . (Join-Path $root 'ProgramReview.ps1')
 $r.stage='local_file_selection_and_observation';$r.review=Invoke-UfwProgramLocalReview;$r.code=$r.review.code
 if($r.review.completed){$r.completed=$true;$r.stage='completed';$rc=0}
 Write-Host ('Result: '+$r.code)
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^ufw_program_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_program_review_unavailable'}
 Write-Host ('Stopped at '+$r.stage+': '+$r.code)
}finally{
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 16));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only stage/code without private paths.';$rc=1}}
 Write-Host 'Return only NEW UFW-PROGRAM-REVIEW-01-*.json, including failure or cancellation.'
 Write-Host 'Do NOT share private review paths, hashes, file IDs or screenshots/transcripts.'
 Write-Host 'No program config saved; no trust/approval/Apply or firewall protection established.'
}
exit $rc
