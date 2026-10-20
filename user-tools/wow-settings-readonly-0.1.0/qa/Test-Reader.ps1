$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\Read-WtfSettings.ps1') -FunctionsOnly
$passed=0
function Check($condition,$label) { if (-not $condition) { throw ('FAIL: '+$label) }; $script:passed++ }
$r=@(Get-ScopedWtfSettings -Text ''); Check ($r.Count -eq 7) 'seven explicit keys'; Check ((@($r | Where-Object present)).Count -eq 0) 'absence not values'
$r=@(Get-ScopedWtfSettings -Text "SET engineSurvey `"123`"`nSET engineSurveyPatch `"45`""); Check ($r[0].explicit_values[0].value -eq '123') 'numeric value'; Check ($r[1].explicit_values[0].value -eq '45') 'numeric patch'
$r=@(Get-ScopedWtfSettings -Text "SET accountName `"SECRET`"`nSET unrelated `"SECRET`""); Check (($r | ConvertTo-Json -Depth 8) -notmatch 'SECRET') 'unrelated excluded'
$r=@(Get-ScopedWtfSettings -Text "SET engineSurvey `"SECRET`""); Check ($r[0].explicit_values[0].redacted -and $null -eq $r[0].explicit_values[0].value) 'unexpected content redacted'
$r=@(Get-ScopedWtfSettings -Text "SET engineSurvey `"1`"`nSET engineSurvey `"2`""); Check ($r[0].occurrences -eq 2) 'duplicate retained'; Check (-not $r[0].runtime_effective_value_proven) 'runtime not inferred'
$r=@(Get-ScopedWtfSettings -Text '  set "TelemetryWowPackage" "Blizzard.Telemetry.Wow_Mainline"  '); Check ($r[2].explicit_values[0].value -eq 'Blizzard.Telemetry.Wow_Mainline') 'case and quoted key'
$r=@(Get-ScopedWtfSettings -Text 'SET telemetryWowlabsPackage ""'); Check ($r[3].present -and $r[3].explicit_values[0].value -eq '') 'empty package retained'
$r=@(Get-ScopedWtfSettings -Text 'SET optOutIngameSurveys "1"'); Check ($r[6].explicit_values[0].value -eq '1') 'survey explicit bool'
$r=@(Get-ScopedWtfSettings -Text ('SET engineSurvey "4"' + [Environment]::NewLine + 'not a valid SET line')); Check ($r[0].occurrences -eq 1) 'invalid syntax ignored'
$d=Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N')); [void][System.IO.Directory]::CreateDirectory($d)
try {
 $p=Join-Path $d 'Config.wtf'; [System.IO.File]::WriteAllText($p,'SET engineSurvey "123"'); $before=[System.IO.File]::ReadAllBytes($p); $t=Read-BoundedWtfText -Path $p; Check ($t -eq 'SET engineSurvey "123"') 'bounded read'; Check ([Convert]::ToBase64String($before) -eq [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($p))) 'source unchanged'
 [System.IO.File]::WriteAllText($p,'SET engineSurvey "123"',[System.Text.Encoding]::Unicode); Check ((Read-BoundedWtfText -Path $p) -eq 'SET engineSurvey "123"') 'UTF16 BOM read'; $fs=[System.IO.File]::Create($p); $fs.SetLength(1048577); $fs.Dispose(); $refused=$false;try {$null=Read-BoundedWtfText -Path $p} catch {$refused=$true}; Check $refused 'oversize refused'
} finally {[System.IO.Directory]::Delete($d,$true)}
Write-Output ('PASS checks='+$passed)
