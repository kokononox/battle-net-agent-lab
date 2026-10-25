$ErrorActionPreference='Stop'
# Read-only policy export diagnostic: never import or change firewall settings.
$root=Join-Path (Join-Path $env:ProgramData 'BNetOnlineG41') ([guid]::NewGuid().ToString('N'))
$quarantine=Join-Path $root 'quarantine'
$init=& $env:G41_STORE_HELPER init $quarantine
if($LASTEXITCODE -ne 0){throw 'private_root_init_failed'}
$temp=Join-Path $env:RUNNER_TEMP ('g41-export-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp | Out-Null
$results=@()
foreach($item in @(@{label='private_root';path=(Join-Path $root 'probe.wfw')},@{label='runner_temp';path=(Join-Path $temp 'probe.wfw')})){
 $native=& "$env:SystemRoot\System32\netsh.exe" advfirewall export $item.path 2>&1
 $code=$LASTEXITCODE;$exists=Test-Path -LiteralPath $item.path;$size=0
 if($exists){$size=(Get-Item -LiteralPath $item.path).Length}
 $text=($native | Out-String)
 # No native text, filesystem path, rule, or policy exported into public evidence.
 $results+=@{label=$item.label;exit_code=$code;exists=$exists;length=$size;access_denied_wording=($text -match '(?i)access.*denied|error.*5\b');path_missing_wording=($text -match '(?i)path.*not.*found|file.*not.*found');success_wording=($text -match '(?i)ok\.')}
}
$svc=Get-CimInstance Win32_Service -Filter "Name='mpssvc'"
$r=@{source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;firewall_mutation_attempted=$false;service_is_localservice=($svc.StartName -eq 'NT AUTHORITY\LocalService');exports=$results}
$j=$r|ConvertTo-Json -Depth 6 -Compress
[IO.File]::WriteAllText((Join-Path (Get-Location) 'output/export-diagnostic.json'),$j)
'G41_EXPORT_DIAGNOSTIC_B64='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
# Only private temporary backups are removed; no firewall import/reset is called.
Remove-Item -LiteralPath $root -Recurse -Force
Remove-Item -LiteralPath $temp -Recurse -Force
