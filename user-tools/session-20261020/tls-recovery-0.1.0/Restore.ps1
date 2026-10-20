$ErrorActionPreference='Stop'
$report=[ordered]@{schema='game-tls-recovery-1';version='0.1.0';status='checking';runs=@();notes=@();windows_runtime_tested_by_builder=$false}
$knownHash='36a45aadeb842185b8064b8f0be3730e079c9f9c125bc8be22363332969857bf'
$root=Join-Path $env:LOCALAPPDATA 'WowIngestTLS'
function No-Reparse([string]$path) {
 $v=Get-Item -LiteralPath $path
 while($null -ne $v) {
  if ($v.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_path_refused' }
  $v=$v.Parent
 }
}
try {
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if (!(Test-Path -LiteralPath $root)) { $report.notes+= 'no_test_state_for_this_windows_user';$report.status='no_owned_state_found';return }
 No-Reparse $root
 foreach($dir in @(Get-ChildItem -LiteralPath $root -Directory)) {
  if ($dir.Name -notmatch '^run-[a-f0-9]{32}$') { continue }
  $row=[ordered]@{run=$dir.Name;root_removal_requested=$false;root_absence_verified=$false;certificate_removed=$false;proxy_actions=@();error_code=$null}
  $report.runs+=,$row
  try {
   No-Reparse $dir.FullName
   $file=Join-Path $dir.FullName 'cleanup-state.json'
   No-Reparse $file
   $s=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
   if ($s.schema -ne 'ingest-cleanup-1' -or $s.user_sid -ne $sid) { throw 'state_owner_mismatch' }
   # Certificate removal is FIRST and independent of proxy enumeration or shutdown.
   if ($s.remove_root -eq $true) {
    $row.root_removal_requested=$true
    if ([string]$s.thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'invalid_owned_thumbprint' }
    $pemPath=Join-Path $dir.FullName 'ca\mitmproxy-ca-cert.pem'
    No-Reparse $pemPath
    $pem=Get-Content -LiteralPath $pemPath -Raw
    $der=[Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''))
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    if ($cert.Thumbprint -ne [string]$s.thumbprint) { throw 'owned_certificate_state_mismatch' }
    $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    try {
     $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
     $matches=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false)
     foreach($c in $matches) { $store.Remove($c);$row.certificate_removed=$true }
    } finally { $store.Close() }
    # Reopen, rather than relying on a prior snapshot of the certificate collection.
    $verify=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    try {
     $verify.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
     $row.root_absence_verified=($verify.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false).Count -eq 0)
    } finally { $verify.Close() }
    if (!$row.root_absence_verified) { throw 'owned_root_removal_not_verified' }
   }
   foreach($folder in @($dir.FullName,(Join-Path $dir.FullName 'bootstrap'))) {
    if (Test-Path -LiteralPath $folder) {
     No-Reparse $folder
     'stop' | Set-Content -LiteralPath (Join-Path $folder 'stop.flag') -Encoding ASCII
    }
   }
  } catch {
   $msg=$_.Exception.Message
   $row.error_code=if ($msg -cmatch '^[a-z0-9_]{1,100}$') { $msg } else { 'state_or_certificate_operation_failed' }
   $row.exception_type=$_.Exception.GetType().Name
  }
  # Optional orphan cleanup. Errors here NEVER prevent the certificate step above.
  try {
   $owned=@()
   foreach($cim in @(Get-CimInstance Win32_Process -Filter "Name='mitmdump.exe'")) {
    if (!$cim.ExecutablePath -or !$cim.CommandLine) { continue }
    $needle=$dir.FullName+'\ca'
    if ($cim.CommandLine.IndexOf($needle,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
    $owner=Invoke-CimMethod -InputObject $cim -MethodName GetOwnerSid
    if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $sid) { continue }
    if ((Get-FileHash -LiteralPath $cim.ExecutablePath -Algorithm SHA256).Hash -ne $knownHash) { continue }
    $proc=Get-Process -Id ([int]$cim.ProcessId) -ErrorAction SilentlyContinue
    if ($null -eq $proc -or $proc.Path -ne $cim.ExecutablePath) { continue }
    # Cache process handle and start ticks while alive; never sort live StartTime getters after exit.
    $null=$proc.Handle
    $owned+=,[pscustomobject]@{process=$proc;start_ticks=$proc.StartTime.ToUniversalTime().Ticks}
   }
   if ($owned.Count -gt 0) { Start-Sleep -Seconds 2 }
   foreach($v in @($owned | Sort-Object start_ticks -Descending)) {
    try {
     if (!$v.process.HasExited) { $v.process.Kill() }
     if ($v.process.WaitForExit(5000)) { $row.proxy_actions+='verified_owned_proxy_stopped' } else { $row.proxy_actions+='proxy_stop_not_verified' }
    } catch { $row.proxy_actions+='proxy_stop_not_verified' }
   }
   if ($owned.Count -eq 0) { $row.proxy_actions+='no_matching_owned_proxy_found_not_a_global_absence_proof' }
  } catch { $row.proxy_actions+='proxy_scan_failed_certificate_step_already_attempted' }
 }
 $pending=@($report.runs | Where-Object { $_.error_code -or ($_.root_removal_requested -and !$_.root_absence_verified) })
 $report.status=if ($pending.Count -gt 0) { 'attention_required' } elseif ($report.runs.Count -eq 0) { 'no_owned_state_found' } else { 'owned_certificate_cleanup_checked' }
} catch {
 $report.status='attention_required';$report.notes+='local_recovery_error';$report.exception_type=$_.Exception.GetType().Name
} finally {
 $out=Join-Path $PSScriptRoot 'recovery-result.json'
 $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $out -Encoding UTF8
 Write-Host ('Status: '+$report.status)
 foreach($r in $report.runs) { Write-Host ($r.run+' root_absence_verified='+$r.root_absence_verified+' error='+$r.error_code) }
 Write-Host ('Send ONLY: '+$out) -ForegroundColor Cyan
 Write-Host 'No game, hosts, firewall, VPN setting, or unrelated root certificate was changed.'
}
