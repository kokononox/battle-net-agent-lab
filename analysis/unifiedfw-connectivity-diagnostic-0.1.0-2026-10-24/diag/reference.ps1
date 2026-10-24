param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
function SafePath([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 for($v=$p;$v;$v=[IO.Path]::GetDirectoryName($v)){
  if(Test-Path -LiteralPath $v){if(((Get-Item -LiteralPath $v -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'reparse_path_rejected'}}
 }
 return $p
}
function UJson($x){return (ConvertTo-Json -InputObject $x -Depth 12 -Compress)}
function TAssertPublicIPv4([string]$Text){
 $ip=[Net.IPAddress]::Parse($Text)
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Text){throw 'literal_ipv4_required'}
 function N($a){$v=[long]0;foreach($b in $a.GetAddressBytes()){$v=$v*256+[long]$b};return $v}
 $number=N $ip
 foreach($cidr in @('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3')){
  $s=$cidr.Split('/');$low=N ([Net.IPAddress]::Parse($s[0]));$size=[Math]::Pow(2,32-[int]$s[1]);if($number -ge $low -and $number -lt ($low+$size)){throw 'special_use_ipv4_rejected'}
 }
}
$root=Split-Path $PSScriptRoot -Parent
$base=(SafePath (Join-Path $root 'private-state/jobs'))+[IO.Path]::DirectorySeparatorChar
$req=SafePath $Request;$out=SafePath $Output
if(-not $req.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or -not $out.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetDirectoryName($req) -cne [IO.Path]::GetDirectoryName($out) -or (Get-Item -LiteralPath $req).Length -gt 8192){throw 'request_scope_or_size'}
$q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($req))
if(@($q.PSObject.Properties).Count -ne 3 -or $null -eq $q.url -or $null -eq $q.address -or $null -eq $q.challenge){throw 'request_keys'}
$c=$q.challenge
if(@($c.PSObject.Properties).Count -ne 4 -or $c.role -cne 'REF' -or $c.kind -cne 'unifiedfw-traffic-1' -or $c.nonce -cnotmatch '^[a-f0-9]{64}$' -or $c.request_id -cnotmatch '^[a-f0-9]{32}$'){throw 'challenge_schema'}
. (Join-Path $PSScriptRoot 'https-tools.ps1')
$result=HReference $q.url $q.address $c
Add-Member -InputObject $result -NotePropertyName client_version -NotePropertyValue ([string]$PSVersionTable.PSVersion)
$tmp=$out+'.next-'+[guid]::NewGuid().ToString('N')
try{[IO.File]::WriteAllText($tmp,(UJson $result),(New-Object Text.UTF8Encoding($false)));[IO.File]::Move($tmp,$out)}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
