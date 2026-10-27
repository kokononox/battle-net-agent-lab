$ErrorActionPreference='Stop';$root='/data/ufw-program-review-v011/package/UFW-PROGRAM-REVIEW-011'
$cmd=[IO.File]::ReadAllText((Join-Path $root 'Run-Review.cmd'));$marker=' -Command "';$i=$cmd.IndexOf($marker);if($i -lt 0){throw 'missing_command'};$tail=$cmd.Substring($i+$marker.Length);$code=$tail.Substring(0,$tail.IndexOf('"'))
$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($code,[ref]$t,[ref]$e);if($e.Count){throw 'bootstrap_parse'}
$manifest=Join-Path $root 'PAYLOAD-SHA256.json';if(-not $code.Contains((Get-FileHash $manifest).Hash.ToLowerInvariant())){throw 'pin'}
$items=Get-Content $manifest -Raw|ConvertFrom-Json;foreach($p in $items.PSObject.Properties){if((Get-FileHash -LiteralPath (Join-Path $root $p.Name)).Hash -ne $p.Value){throw 'payload_hash'}}
Write-Host 'Bootstrap parsed; pinned manifest and all payload files verified.'
