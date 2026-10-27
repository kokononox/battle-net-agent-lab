$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$r=[ordered]@{schema='ufw-allow-review-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;payload_verified=$false;review=$null;firewall_change_requested=$false;audit_change_requested=$false;candidate_access_requested=$false;baseline_access_requested=$false;security_log_access_requested=$false;target_execution_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;raw_rule_identity_exported=$false;runtime_execution_authorized=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);if($root.StartsWith('\')){throw 'ufw_allow_review_local_folder_required'};$p=$root
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_allow_review_reparse_path'};$q=[IO.Path]::GetDirectoryName($p);if($p -eq $q){break};$p=$q}
 $dest=Join-Path $root ('UFW-ALLOW-REVIEW-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_allow_review_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_allow_review_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_allow_review_admin_required'}
 $r.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "EndpointReference.ps1": "9830a81c5e3206fe6fef5ea3f731403b326ed93174eeaf298403c3b5c6b696b6",
  "AllowReview.ps1": "fd2cb82f27bf941c1e01e70fb2e590365166e6515c6697673356e337d1075fb8"
}
'@
 foreach($v in $hashes.PSObject.Properties){$f=Join-Path $root $v.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $v.Value){throw 'ufw_allow_review_payload_mismatch'}}
 $r.payload_verified=$true;. (Join-Path $root 'EndpointReference.ps1');. (Join-Path $root 'AllowReview.ps1')
 $r.stage='read_only_ActiveStore_review';$r.review=Invoke-UfwAllowReviewNative;$r.code=$r.review.code
 if($r.review.completed){$r.completed=$true;$r.stage='completed';$rc=0}
 Write-Host ('Result: '+$r.code)
 if($null -ne $r.review){Write-Host ('Outbound Allow examined: '+$r.review.rules_examined+'; matches: '+$r.review.transport_predicate_matches+'; mismatches: '+$r.review.runtime_predicate_mismatches+'; indeterminate: '+$r.review.filter_reads_indeterminate)}
}catch{$msg=[string]$_.Exception.GetBaseException().Message;if($msg -cmatch '^ufw_allow_review_[a-z_0-9]{1,80}$'){$r.code=$msg}else{$r.code='ufw_allow_review_unavailable'};Write-Host ('Stopped: '+$r.code)}
finally{
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 12));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report save failed; return only the short stage/code, without private paths.';$rc=1}}
 Write-Host 'Return only NEW UFW-ALLOW-REVIEW-01-*.json. No installer launch, audit changes or firewall changes are authorized. No screenshots or raw rule exports.'
}
exit $rc
