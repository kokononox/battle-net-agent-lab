param([string]$Helper,[string]$Work)
$ErrorActionPreference='Stop';. $Helper
[void][IO.Directory]::CreateDirectory($Work)
if((Read-WLabDumpHeader (Join-Path $Work 'missing.dmp')).exists){throw 'Missing dump accepted'}
$short=Join-Path $Work 'short.dmp';[IO.File]::WriteAllBytes($short,(New-Object byte[] 10))
if((Read-WLabDumpHeader $short).basic_header_valid){throw 'Short dump accepted'}
$b=New-Object byte[] 64;[Text.Encoding]::ASCII.GetBytes('MDMP').CopyTo($b,0)
[BitConverter]::GetBytes([UInt32]1).CopyTo($b,8);[BitConverter]::GetBytes([UInt32]32).CopyTo($b,12)
$p=Join-Path $Work 'valid-header.dmp';[IO.File]::WriteAllBytes($p,$b)
if(!(Read-WLabDumpHeader $p).basic_header_valid){throw 'Basic valid header rejected'}
$b[0]=0;[IO.File]::WriteAllBytes($p,$b);if((Read-WLabDumpHeader $p).basic_header_valid){throw 'Bad signature accepted'}
$b[0]=[byte][char]'M';[BitConverter]::GetBytes([UInt32]100).CopyTo($b,12);[IO.File]::WriteAllBytes($p,$b)
if((Read-WLabDumpHeader $p).basic_header_valid){throw 'Out-of-bounds directory accepted'}
[BitConverter]::GetBytes([UInt32]32).CopyTo($b,12);[BitConverter]::GetBytes([UInt32]0).CopyTo($b,8);[IO.File]::WriteAllBytes($p,$b)
if((Read-WLabDumpHeader $p).basic_header_valid){throw 'Zero streams accepted'}
$probe=Invoke-WLabWriteProbe $Work;if(!$probe.passed -or $probe.size_bytes -ne 1MB){throw 'Write probe failed'}
if(@(Get-ChildItem -LiteralPath $Work -Filter 'write-probe-*.tmp').Count -ne 0){throw 'Probe not removed'}
$src=Join-Path $Work 'unicode.txt';$dest=Join-Path $Work 'decoded.txt'
$text='ProcDump: آزمون UTF16';[IO.File]::WriteAllBytes($src,[Text.Encoding]::Unicode.GetBytes($text));Convert-WLabProcDumpLog $src $dest
if([IO.File]::ReadAllText($dest) -cne $text){throw 'UTF16 decoding failed'}
# Validate the concrete List[object]/ordered dictionary JSON report shape.
$r=[ordered]@{cases=(New-Object 'Collections.Generic.List[object]')};$c=[ordered]@{name='control-clone';result=$null};$r.cases.Add($c);$c.result=[pscustomobject]@{status='failed';exit_code=1};$j=($r|ConvertTo-Json -Depth 10)|ConvertFrom-Json
if($j.cases[0].result.exit_code -ne 1){throw 'Case result serialization lost'}
[pscustomobject]@{header_cases_passed=6;header_scope='basic header only';one_MiB_flush_readback_passed=$true;write_probe_cleanup_passed=$true;UTF16LE_without_BOM_decoded=$true;case_list_JSON_preserved=$true;windows_ProcDump_executed=$false}|ConvertTo-Json
