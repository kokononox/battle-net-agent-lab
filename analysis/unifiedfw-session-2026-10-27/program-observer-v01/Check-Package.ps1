param([string]$Root=(Join-Path $PSScriptRoot 'package/UFW-PROGRAM-OBSERVER-01'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$files=@(Get-ChildItem -LiteralPath $Root -Filter *.ps1)+@(Get-ChildItem -LiteralPath $Root -Filter *.psm1)
if($files.Count -ne 7){throw 'package_PS_count'}
foreach($f in $files){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e);if($e.Count){throw 'package_PS_parse'}}
$cmd=[IO.File]::ReadAllText((Join-Path $Root 'Run-Observer.cmd'));$marker=' -Command "';$i=$cmd.IndexOf($marker);if($i -lt 0){throw 'missing_bootstrap'};$tail=$cmd.Substring($i+$marker.Length);$code=$tail.Substring(0,$tail.IndexOf('"'))
$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($code,[ref]$t,[ref]$e);if($e.Count){throw 'bootstrap_parse'}
$path=Join-Path $Root 'PAYLOAD-SHA256.json';$manifest=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
if(-not $code.Contains((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant())){throw 'manifest_pin'}
foreach($v in $manifest.PSObject.Properties){if((Get-FileHash -LiteralPath (Join-Path $Root $v.Name)).Hash -ne $v.Value){throw 'payload_hash'}}
$run=[IO.File]::ReadAllText((Join-Path $Root 'Run-Observer.ps1'))
# Parse embedded dependency map with literal markers rather than executing the wrapper.
$start=$run.IndexOf("`$hashes=ConvertFrom-Json @'");if($start -lt 0){throw 'runner_pin_map'};$body=$run.Substring($start);$first=$body.IndexOf("`n")+1;$last=$body.IndexOf("'@",$first);$pins=ConvertFrom-Json $body.Substring($first,$last-$first)
if(@($pins.PSObject.Properties).Count -ne 7){throw 'runner_dep_count'}
foreach($v in $pins.PSObject.Properties){if((Get-FileHash -LiteralPath (Join-Path $Root $v.Name)).Hash -ne $v.Value){throw 'runner_pin_mismatch'}}
if(-not $cmd.Contains('-STA') -or -not $cmd.Contains('-ExecutionPolicy RemoteSigned') -or $cmd.Contains('Bypass') -or $cmd.Contains('Run-Candidate.ps1')){throw 'bootstrap_contract'}
[pscustomobject][ordered]@{passed=$true;package_PS_files_parsed=7;bootstrap_parsed=$true;manifest_verified=$true;embedded_dependency_hashes_verified=7;Windows_native_executed=$false}|ConvertTo-Json -Compress
