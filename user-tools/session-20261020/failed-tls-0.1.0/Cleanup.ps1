param([Parameter(Mandatory=$true)][string]$RunDir,[switch]$Watch)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'WowIngestTLS'))
$run=[IO.Path]::GetFullPath($RunDir)
if ((Split-Path $run -Parent) -ne $root -or (Split-Path $run -Leaf) -notmatch '^run-[a-f0-9]{32}$') { throw 'invalid_cleanup_directory' }
foreach($p in @($root,$run)) { if ((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_path_refused' } }
if ($Watch) {
 $deadline=[DateTime]::UtcNow.AddSeconds(210)
 while([DateTime]::UtcNow -lt $deadline -and !(Test-Path -LiteralPath (Join-Path $run 'cleanup-now.flag'))) { Start-Sleep -Milliseconds 500 }
}
$statePath=Join-Path $run 'cleanup-state.json'
if (!(Test-Path -LiteralPath $statePath)) { exit 0 }
$s=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($s.schema -ne 'ingest-cleanup-1' -or $s.user_sid -ne $sid) { throw 'cleanup_owner_mismatch' }
$binary=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'bin\mitmdump.exe'))
$results=@();$stopsVerified=$true;$verified=@{};$backendEnumeration=$true
foreach($entry in @($s.processes)) {
 try {
  $p=Get-Process -Id ([int]$entry.pid) -ErrorAction SilentlyContinue
  if ($null -eq $p) { continue }
  if ($p.StartTime.ToUniversalTime().Ticks.ToString() -ne [string]$entry.start_ticks -or $p.Path -ne $binary) {
   $results+='process_identity_changed_not_stopped';continue
  }
  $verified[$p.Id]=$p
 } catch { $results+='proxy_identity_unverified';$stopsVerified=$false }
}
# A portable PyInstaller binary may have an owned backend child with the SAME image.
# Discover only descendants of verified recorded proxies, never the game or a name wildcard kill.
if ($verified.Count -gt 0) {
 try {
  $rows=@(Get-CimInstance Win32_Process -Filter "Name='mitmdump.exe'")
  for($i=0;$i -lt 4;$i++) {
   foreach($row in $rows) {
    if ($verified.ContainsKey([int]$row.ParentProcessId) -and !$verified.ContainsKey([int]$row.ProcessId) -and $row.ExecutablePath -eq $binary) {
     $child=Get-Process -Id ([int]$row.ProcessId) -ErrorAction SilentlyContinue
     if ($null -ne $child -and $child.Path -eq $binary -and $child.StartTime -ge $verified[[int]$row.ParentProcessId].StartTime) {
      $verified[$child.Id]=$child
     }
    }
   }
  }
 } catch { $backendEnumeration=$false;$stopsVerified=$false }
}
# Ask the addon to shut down gracefully before any fallback stop.
foreach($folder in @($run,(Join-Path $run 'bootstrap'))) {
 if (Test-Path -LiteralPath $folder) { 'stop' | Set-Content -LiteralPath (Join-Path $folder 'stop.flag') -Encoding ASCII }
}
$until=[DateTime]::UtcNow.AddSeconds(8)
while([DateTime]::UtcNow -lt $until -and @($verified.Values | Where-Object { !$_.HasExited }).Count -gt 0) { Start-Sleep -Milliseconds 200 }
# Child backends first; all retained Process objects were path/lineage verified above.
foreach($p in @($verified.Values | Sort-Object StartTime -Descending)) {
 try {
  if (!$p.HasExited) { $p.Kill() }
  if ($p.WaitForExit(5000)) { $results+='owned_proxy_stopped' } else { $results+='proxy_stop_unverified';$stopsVerified=$false }
 } catch { $results+='proxy_stop_unverified';$stopsVerified=$false }
}
$removed=$false;$absent=$false
if ($s.remove_root -eq $true -and [string]$s.thumbprint -match '^[A-Fa-f0-9]{40}$') {
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
 try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $certs=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,[string]$s.thumbprint,$false)
  foreach($c in $certs) { $store.Remove($c);$removed=$true }
  $absent=($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,[string]$s.thumbprint,$false).Count -eq 0)
 } finally { $store.Close() }
}
$result=[ordered]@{schema='ingest-cleanup-result-1';root_absence_verified=$absent;root_removed=$removed;owned_proxy_stops_verified=$stopsVerified;backend_child_enumeration_succeeded=$backendEnumeration;process_actions=$results;checked_utc=[DateTime]::UtcNow.ToString('o')}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'cleanup-result.json') -Encoding UTF8
if (!$absent -and $s.remove_root -eq $true) { throw 'temporary_root_removal_not_verified' }
