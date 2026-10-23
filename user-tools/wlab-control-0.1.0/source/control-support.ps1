function Read-WLabDumpHeader([string]$path){
$r=[ordered]@{exists=$false;size_bytes=$null;signature=$null;stream_count=$null;directory_rva=$null;basic_header_valid=$false;scope='32-byte header and directory bounds only; not full dump validation';error=$null}
if(!(Test-Path -LiteralPath $path -PathType Leaf)){return [pscustomobject]$r}
$r.exists=$true;$f=$null
try{
$f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
$r.size_bytes=$f.Length
if($f.Length -lt 32){throw 'Dump shorter than 32-byte header'}
$b=New-Object byte[] 32;if($f.Read($b,0,32) -ne 32){throw 'Short header read'}
$r.signature=[Text.Encoding]::ASCII.GetString($b,0,4)
$r.stream_count=[BitConverter]::ToUInt32($b,8);$r.directory_rva=[BitConverter]::ToUInt32($b,12)
$r.basic_header_valid=($r.signature -eq 'MDMP' -and $r.stream_count -gt 0 -and $r.stream_count -le 65536 -and $r.directory_rva -ge 32 -and ([UInt64]$r.directory_rva+([UInt64]$r.stream_count*12)) -le [UInt64]$f.Length)
}catch{$r.error=$_.Exception.Message}finally{if($null -ne $f){$f.Dispose()}}
return [pscustomobject]$r
}
function Invoke-WLabWriteProbe([string]$dir){
$path=Join-Path $dir ('write-probe-'+[Guid]::NewGuid().ToString('N')+'.tmp')
$b=New-Object byte[] (1MB);$f=$null
try{
$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$f.Write($b,0,$b.Length);$f.Flush($true);$f.Dispose();$f=$null
$sha=[Security.Cryptography.SHA256]::Create()
try{$expected=([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
if($actual -ne $expected -or (Get-Item -LiteralPath $path).Length -ne 1MB){throw 'Probe readback mismatch'}
return [pscustomobject]@{passed=$true;size_bytes=1MB;sha256=$actual;scope='one MiB flush/readback only; not a disk health test or full-dump capacity guarantee'}
}finally{if($null -ne $f){$f.Dispose()};if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue}}
}
function Convert-WLabProcDumpLog([string]$src,[string]$dest){
$b=[IO.File]::ReadAllBytes($src)
if($b.Length -ge 2 -and $b[1] -eq 0){$t=[Text.Encoding]::Unicode.GetString($b).TrimStart([char]0xFEFF)}else{$t=[Text.Encoding]::UTF8.GetString($b)}
[IO.File]::WriteAllText($dest,$t,[Text.UTF8Encoding]::new($false))
}
