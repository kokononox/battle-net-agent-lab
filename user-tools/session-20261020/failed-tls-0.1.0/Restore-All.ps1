$ErrorActionPreference='Stop'
$root=Join-Path $env:LOCALAPPDATA 'WowIngestTLS'
if (!(Test-Path -LiteralPath $root)) { Write-Host 'No test state found for this Windows user.';exit 0 }
if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_private_path_refused' }
foreach($d in Get-ChildItem -LiteralPath $root -Directory) {
 if ($d.Name -match '^run-[a-f0-9]{32}$') {
  try {
   if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_run_path_refused' }
   'cleanup' | Set-Content -LiteralPath (Join-Path $d.FullName 'cleanup-now.flag') -Encoding ASCII
   & (Join-Path $PSScriptRoot 'Cleanup.ps1') -RunDir $d.FullName
   Write-Host ($d.Name+': cleanup checked')
  } catch { Write-Host ($d.Name+': cleanup NOT verified') -ForegroundColor Red }
 }
}
Write-Host 'No unrelated trusted certificate or game process was intentionally removed.'
